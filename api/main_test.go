package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const testEndpoint = "https://s3.us-west-004.backblazeb2.com"

func testConfig(endpoint string) config {
	return config{
		keyID:        "0000000000000000000000001",
		appKey:       "K0000000000000000000000000000000",
		endpoint:     endpoint,
		region:       "us-west-004",
		bucket:       "test-bucket",
		quotaBytes:   500 << 20,
		cookieSecure: true,
	}
}

// newTestServer builds the real handler stack on a fresh database. Presigning
// is done locally, so tests that only sign URLs never contact the endpoint.
func newTestServer(t *testing.T, cfg config) (*server, http.Handler) {
	t.Helper()
	db, err := openDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("openDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := newServer(context.Background(), cfg, db)
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s, s.routes()
}

type reqOpt func(*http.Request)

func withCookie(c *http.Cookie) reqOpt { return func(r *http.Request) { r.AddCookie(c) } }
func withOrigin(o string) reqOpt       { return func(r *http.Request) { r.Header.Set("Origin", o) } }
func withRemoteAddr(a string) reqOpt   { return func(r *http.Request) { r.RemoteAddr = a } }

func do(t *testing.T, h http.Handler, method, target, body string, opts ...reqOpt) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for _, o := range opts {
		o(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func creds(user, pass string) string {
	return fmt.Sprintf(`{"username":%q,"password":%q}`, user, pass)
}

func sessionFrom(t *testing.T, rec *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie && c.Value != "" {
			return c
		}
	}
	t.Fatalf("no session cookie in response (status %d, body %s)", rec.Code, rec.Body)
	return nil
}

// signup registers a user and returns their session cookie.
func signup(t *testing.T, h http.Handler, username string) *http.Cookie {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/auth/signup", creds(username, "correct horse battery"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup %s: status %d, body %s", username, rec.Code, rec.Body)
	}
	return sessionFrom(t, rec)
}

func decode[T any](t *testing.T, rec *httptest.ResponseRecorder) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return v
}

/* ---------- Names and keys ---------- */

func TestCleanFilename(t *testing.T) {
	tests := []struct{ in, want string }{
		{"report.pdf", "report.pdf"},
		{"../../etc/passwd", "passwd"},
		{`C:\Users\me\photo.jpg`, "photo.jpg"},
		{"my file (1).txt", "my-file-1-.txt"},
		{"...hidden", "hidden"},
		{"my..file.txt", "my..file.txt"},
		{"ünïcode.md", "n-code.md"},
		{"", ""},
		{"///", ""},
		{strings.Repeat("a", 200) + ".tar", strings.Repeat("a", 116) + ".tar"},
	}
	for _, tt := range tests {
		got := cleanFilename(tt.in)
		if got != tt.want {
			t.Errorf("cleanFilename(%q) = %q, want %q", tt.in, got, tt.want)
		}
		if len(got) > maxNameLen {
			t.Errorf("cleanFilename(%q) is %d bytes, over the %d limit", tt.in, len(got), maxNameLen)
		}
	}
}

// Every key the upload handler can issue must pass validKey; an old ".." check
// once broke this for names like "my..file.txt".
func TestIssuedKeysAreValid(t *testing.T) {
	for _, in := range []string{"my..file.txt", "a.b.c", "x", strings.Repeat("z", 300) + ".gz", "a-_.b"} {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		key := userPrefix(42) + id + "-" + cleanFilename(in)
		if !validKey(key) {
			t.Errorf("key %q built from %q is rejected by validKey", key, in)
		}
		if got := displayName(key); got != cleanFilename(in) {
			t.Errorf("displayName(%q) = %q, want %q", key, got, cleanFilename(in))
		}
	}
}

func TestValidKeyRejects(t *testing.T) {
	for _, key := range []string{
		"", "report.pdf",
		"0123456789abcdef-a",        // pre-accounts key with no user folder
		"u/0/0123456789abcdef-a",    // user ids start at 1
		"u/01/0123456789abcdef-a",   // no leading zeros
		"u/1/../0123456789abcdef-a", // no extra path segments
		"u/1/0123456789ABCDEF-a",    // lowercase hex only
		"u/1/0123456789abcdef-",     // empty name
		"u/1/0123456789abcdef-a/b",  // no slash in the name
		"u/1/0123456789abcdef-a b",  // no spaces
		"/u/1/0123456789abcdef-a",   // no leading slash
		"u/1/0123456789abcdef-" + strings.Repeat("a", 121),
	} {
		if validKey(key) {
			t.Errorf("validKey(%q) = true, want false", key)
		}
	}
}

/* ---------- Accounts and sessions ---------- */

func TestSignupLoginLogout(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))

	rec := do(t, h, http.MethodPost, "/auth/signup", creds("Alice", "correct horse battery"))
	if rec.Code != http.StatusCreated {
		t.Fatalf("signup: status %d, body %s", rec.Code, rec.Body)
	}
	c := sessionFrom(t, rec)
	if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteLaxMode || c.Path != "/" {
		t.Errorf("cookie flags: HttpOnly=%v Secure=%v SameSite=%v Path=%q", c.HttpOnly, c.Secure, c.SameSite, c.Path)
	}

	rec = do(t, h, http.MethodGet, "/auth/me", "", withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("me: status %d, body %s", rec.Code, rec.Body)
	}
	me := decode[meResponse](t, rec)
	if me.Username != "alice" || me.UsedBytes != 0 || me.QuotaBytes != 500<<20 {
		t.Errorf("me = %+v", me)
	}

	// Usernames are case-insensitive.
	if rec := do(t, h, http.MethodPost, "/auth/signup", creds("ALICE", "another password")); rec.Code != http.StatusConflict {
		t.Errorf("duplicate signup: status %d, want 409", rec.Code)
	}

	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "wrong password")); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong password: status %d, want 401", rec.Code)
	}
	rec = do(t, h, http.MethodPost, "/auth/login", creds("nobody", "whatever123"))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("unknown user: status %d, want 401", rec.Code)
	}
	// The message must not reveal whether the username exists.
	unknownMsg := rec.Body.String()
	wrongPassMsg := do(t, h, http.MethodPost, "/auth/login", creds("alice", "wrong password")).Body.String()
	if unknownMsg != wrongPassMsg {
		t.Errorf("unknown-user and wrong-password messages differ: %q vs %q", unknownMsg, wrongPassMsg)
	}

	rec = do(t, h, http.MethodPost, "/auth/login", creds("ALICE", "correct horse battery"))
	if rec.Code != http.StatusOK {
		t.Fatalf("login: status %d, body %s", rec.Code, rec.Body)
	}
	second := sessionFrom(t, rec)

	if rec := do(t, h, http.MethodPost, "/auth/logout", "", withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("logout: status %d", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("me after logout: status %d, want 401", rec.Code)
	}
	// Logging out one session leaves the others alone.
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(second)); rec.Code != http.StatusOK {
		t.Errorf("other session after logout: status %d, want 200", rec.Code)
	}
}

func TestSignupValidation(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	tests := []struct{ name, body string }{
		{"malformed", `{`},
		{"short username", creds("ab", "long enough pass")},
		{"long username", creds(strings.Repeat("a", 33), "long enough pass")},
		{"bad characters", creds("al ice", "long enough pass")},
		{"short password", creds("alice", "1234567")},
		{"long password", creds("alice", strings.Repeat("p", 73))},
	}
	for _, tt := range tests {
		if rec := do(t, h, http.MethodPost, "/auth/signup", tt.body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400 (body %s)", tt.name, rec.Code, rec.Body)
		}
	}
	if rec := do(t, h, http.MethodGet, "/auth/signup", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /auth/signup: status %d, want 405", rec.Code)
	}
}

func TestMaxUsers(t *testing.T) {
	cfg := testConfig(testEndpoint)
	cfg.maxUsers = 1
	_, h := newTestServer(t, cfg)

	signup(t, h, "first")
	if rec := do(t, h, http.MethodPost, "/auth/signup", creds("second", "long enough pass")); rec.Code != http.StatusForbidden {
		t.Errorf("signup past the limit: status %d, want 403", rec.Code)
	}
}

func TestProtectedRoutesNeedSession(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	bogus := &http.Cookie{Name: sessionCookie, Value: "not-a-real-token"}
	for _, path := range []string{"/auth/me", "/files", "/download-url?key=x", "/upload-url"} {
		if rec := do(t, h, http.MethodGet, path, ""); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without cookie: status %d, want 401", path, rec.Code)
		}
		if rec := do(t, h, http.MethodGet, path, "", withCookie(bogus)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s with bogus cookie: status %d, want 401", path, rec.Code)
		}
	}
}

func TestExpiredSessionRejected(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")
	if _, err := s.db.Exec(`UPDATE sessions SET expires_at = ?`, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
		t.Errorf("expired session: status %d, want 401", rec.Code)
	}
}

func TestCrossOriginRefused(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")

	// httptest requests have Host "example.com".
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery"),
		withOrigin("https://evil.example")); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin login: status %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"a","size":1}`,
		withCookie(c), withOrigin("https://evil.example")); rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin upload-url: status %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery"),
		withOrigin("http://example.com")); rec.Code != http.StatusOK {
		t.Errorf("same-origin login: status %d, want 200", rec.Code)
	}
}

func TestLoginRateLimited(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	body := creds("nobody", "whatever123")
	for i := 0; i < 10; i++ {
		if rec := do(t, h, http.MethodPost, "/auth/login", body, withRemoteAddr("192.0.2.7:1000")); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: status %d, want 401", i+1, rec.Code)
		}
	}
	rec := do(t, h, http.MethodPost, "/auth/login", body, withRemoteAddr("192.0.2.7:1000"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("11th attempt: status %d, Retry-After %q; want 429 with Retry-After", rec.Code, rec.Header().Get("Retry-After"))
	}
	// Another client is unaffected.
	if rec := do(t, h, http.MethodPost, "/auth/login", body, withRemoteAddr("192.0.2.8:1000")); rec.Code != http.StatusUnauthorized {
		t.Errorf("other IP: status %d, want 401", rec.Code)
	}
}

func TestClientIPTrustProxy(t *testing.T) {
	s, _ := newTestServer(t, testConfig(testEndpoint))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.1:5000"
	req.Header.Set("X-Forwarded-For", "6.6.6.6, 203.0.113.9")

	if got := s.clientIP(req); got != "10.0.0.1" {
		t.Errorf("without TRUST_PROXY: clientIP = %q, want 10.0.0.1", got)
	}
	s.cfg.trustProxy = true
	if got := s.clientIP(req); got != "203.0.113.9" {
		t.Errorf("with TRUST_PROXY: clientIP = %q, want the proxy-appended 203.0.113.9", got)
	}
}

/* ---------- Fake bucket ---------- */

type fakeObject struct {
	size     int64
	modified time.Time
}

// fakeB2 answers just enough of the S3 API for ListObjectsV2 (with a prefix)
// and DeleteObject, holding objects in memory.
type fakeB2 struct {
	mu      sync.Mutex
	objects map[string]fakeObject
}

func newFakeB2(t *testing.T) (*fakeB2, string) {
	f := &fakeB2{objects: map[string]fakeObject{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv.URL
}

func (f *fakeB2) put(key string, size int64, modified time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.objects[key] = fakeObject{size: size, modified: modified}
}

func (f *fakeB2) has(key string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.objects[key]
	return ok
}

func (f *fakeB2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/test-bucket" && r.URL.Query().Get("list-type") == "2":
		prefix := r.URL.Query().Get("prefix")
		var keys []string
		for k := range f.objects {
			if strings.HasPrefix(k, prefix) {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)

		var b strings.Builder
		b.WriteString(`<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">`)
		fmt.Fprintf(&b, `<Name>test-bucket</Name><KeyCount>%d</KeyCount><IsTruncated>false</IsTruncated>`, len(keys))
		for _, k := range keys {
			o := f.objects[k]
			fmt.Fprintf(&b, `<Contents><Key>%s</Key><LastModified>%s</LastModified><Size>%d</Size></Contents>`,
				k, o.modified.UTC().Format("2006-01-02T15:04:05.000Z"), o.size)
		}
		b.WriteString(`</ListBucketResult>`)
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(b.String()))

	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/test-bucket/"):
		key, _ := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/test-bucket/"))
		delete(f.objects, key)
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotImplemented)
	}
}

func userID(t *testing.T, s *server, username string) int64 {
	t.Helper()
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username = ?`, username).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

/* ---------- Files ---------- */

func TestUploadURL(t *testing.T) {
	_, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	prefix := userPrefix(userID(t, s, "alice"))

	rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"my..file.txt","size":1234}`, withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	resp := decode[uploadResponse](t, rec)
	if !validKey(resp.Key) || !strings.HasPrefix(resp.Key, prefix) || !strings.HasSuffix(resp.Key, "-my..file.txt") {
		t.Errorf("key = %q, want %s<id>-my..file.txt", resp.Key, prefix)
	}

	u, err := url.Parse(resp.URL)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(u.Path, "/test-bucket/") {
		t.Errorf("URL is not path-style: %s", resp.URL)
	}
	q := u.Query()
	if q.Get("X-Amz-Expires") != "600" {
		t.Errorf("X-Amz-Expires = %q, want 600", q.Get("X-Amz-Expires"))
	}
	// The size limit only binds if the length is part of the signature.
	if signed := q.Get("X-Amz-SignedHeaders"); !strings.Contains(signed, "content-length") {
		t.Errorf("X-Amz-SignedHeaders = %q, want content-length signed", signed)
	}

	// The reservation is in the ledger straight away.
	if used, _ := s.usedBytes(context.Background(), s.db, userID(t, s, "alice")); used != 1234 {
		t.Errorf("used after signing = %d, want 1234", used)
	}
}

func TestUploadURLRejects(t *testing.T) {
	_, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	tests := []struct {
		name, body string
		want       int
	}{
		{"malformed", `{`, http.StatusBadRequest},
		{"negative", `{"filename":"a","size":-1}`, http.StatusBadRequest},
		{"too large", `{"filename":"a","size":52428801}`, http.StatusRequestEntityTooLarge},
		{"no name", `{"filename":"../","size":1}`, http.StatusBadRequest},
	}
	for _, tt := range tests {
		if rec := do(t, h, http.MethodPost, "/upload-url", tt.body, withCookie(c)); rec.Code != tt.want {
			t.Errorf("%s: status %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
	if rec := do(t, h, http.MethodGet, "/upload-url", "", withCookie(c)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /upload-url: status %d, want 405", rec.Code)
	}
}

func TestQuota(t *testing.T) {
	_, endpoint := newFakeB2(t)
	cfg := testConfig(endpoint)
	cfg.quotaBytes = 1 << 20
	_, h := newTestServer(t, cfg)
	c := signup(t, h, "alice")

	if rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"a","size":600000}`, withCookie(c)); rec.Code != http.StatusOK {
		t.Fatalf("first upload: status %d, body %s", rec.Code, rec.Body)
	}
	// The first upload hasn't reached the bucket, but its reservation still
	// counts, so asking for many links at once can't exceed the quota.
	rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"b","size":600000}`, withCookie(c))
	if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "storage") {
		t.Errorf("second upload: status %d, body %s; want 413 about storage", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"c","size":400000}`, withCookie(c)); rec.Code != http.StatusOK {
		t.Errorf("upload that fits: status %d, body %s", rec.Code, rec.Body)
	}
}

func TestListReconcilesLedger(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	id := userID(t, s, "alice")
	p := userPrefix(id)

	b2.put(p+"0000000000000000-old.txt", 1, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	b2.put(p+"ffffffffffffffff-new.txt", 2048, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC))
	b2.put(p+"8888888888888888-mid.txt", 3, time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC))

	// One upload that was signed long ago and never arrived, and one signed
	// just now that is still in flight.
	now := time.Now()
	s.db.Exec(`INSERT INTO files (key, user_id, size, created_at) VALUES (?, ?, ?, ?)`,
		p+"1111111111111111-abandoned.bin", id, 9000, now.Add(-time.Hour).Unix())
	s.db.Exec(`INSERT INTO files (key, user_id, size, created_at) VALUES (?, ?, ?, ?)`,
		p+"2222222222222222-inflight.bin", id, 500, now.Unix())

	rec := do(t, h, http.MethodGet, "/files", "", withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	files := decode[[]fileInfo](t, rec)
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "new.txt,mid.txt,old.txt" {
		t.Errorf("order = %s, want new.txt,mid.txt,old.txt", got)
	}
	if files[0].Size != 2048 || files[0].LastModified != "2026-10-01T00:00:00Z" {
		t.Errorf("first file = %+v", files[0])
	}

	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if want := int64(1 + 2048 + 3 + 500); me.UsedBytes != want {
		t.Errorf("used = %d, want %d (bucket objects plus the in-flight reservation)", me.UsedBytes, want)
	}
}

func TestFilesArePrivate(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	alice := signup(t, h, "alice")
	bob := signup(t, h, "bob")
	aliceKey := userPrefix(userID(t, s, "alice")) + "0123456789abcdef-secret.txt"
	b2.put(aliceKey, 10, time.Now())

	if files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(bob))); len(files) != 0 {
		t.Errorf("bob sees %d files, want 0", len(files))
	}
	if files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(alice))); len(files) != 1 {
		t.Errorf("alice sees %d files, want 1", len(files))
	}

	q := "?key=" + url.QueryEscape(aliceKey)
	if rec := do(t, h, http.MethodGet, "/download-url"+q, "", withCookie(bob)); rec.Code != http.StatusNotFound {
		t.Errorf("bob downloads alice's file: status %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodDelete, "/files"+q, "", withCookie(bob)); rec.Code != http.StatusNotFound {
		t.Errorf("bob deletes alice's file: status %d, want 404", rec.Code)
	}
	if !b2.has(aliceKey) {
		t.Error("alice's file was deleted by bob")
	}
}

func TestDeleteFile(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	key := userPrefix(userID(t, s, "alice")) + "0123456789abcdef-a.txt"
	b2.put(key, 10, time.Now())
	do(t, h, http.MethodGet, "/files", "", withCookie(c)) // puts the object in the ledger

	if rec := do(t, h, http.MethodDelete, "/files?key="+url.QueryEscape(key), "", withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	if b2.has(key) {
		t.Error("object still in the bucket")
	}
	if me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c))); me.UsedBytes != 0 {
		t.Errorf("used after delete = %d, want 0", me.UsedBytes)
	}
	if rec := do(t, h, http.MethodDelete, "/files?key=not-a-key", "", withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid key: status %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPut, "/files", "", withCookie(c)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /files: status %d, want 405", rec.Code)
	}
}

func TestDownloadURL(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")
	key := userPrefix(userID(t, s, "alice")) + "0123456789abcdef-my..file.txt"

	rec := do(t, h, http.MethodGet, "/download-url?key="+url.QueryEscape(key), "", withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d, body %s", rec.Code, rec.Body)
	}
	u, err := url.Parse(decode[map[string]string](t, rec)["url"])
	if err != nil {
		t.Fatal(err)
	}
	want := `attachment; filename="my..file.txt"`
	if got := u.Query().Get("response-content-disposition"); got != want {
		t.Errorf("response-content-disposition = %q, want %q", got, want)
	}

	for _, key := range []string{"", "..%2Fsecret", "report.pdf"} {
		if rec := do(t, h, http.MethodGet, "/download-url?key="+key, "", withCookie(c)); rec.Code != http.StatusBadRequest {
			t.Errorf("key %q: status %d, want 400", key, rec.Code)
		}
	}
}

/* ---------- Page and health ---------- */

func TestPageServed(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))

	rec := do(t, h, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "<title>SHORTENED.</title>") {
		t.Fatalf("GET /: status %d", rec.Code)
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'self'", "connect-src 'self' " + testEndpoint, "frame-ancestors 'none'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q lacks %q", csp, want)
		}
	}
	if rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("missing X-Content-Type-Options: nosniff")
	}

	for path, ctype := range map[string]string{"/app.js": "javascript", "/style.css": "text/css"} {
		rec := do(t, h, http.MethodGet, path, "")
		if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), ctype) {
			t.Errorf("GET %s: status %d, Content-Type %q", path, rec.Code, rec.Header().Get("Content-Type"))
		}
	}
	// Only the embedded page files are served, not the Go source next to them.
	if rec := do(t, h, http.MethodGet, "/embed.go", ""); rec.Code != http.StatusNotFound {
		t.Errorf("GET /embed.go: status %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /: status %d, want 405", rec.Code)
	}
}

func TestHealth(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	if rec := do(t, h, http.MethodGet, "/health", ""); rec.Code != http.StatusOK {
		t.Errorf("/health: status %d, want 200", rec.Code)
	}
}

func TestLoadConfig(t *testing.T) {
	set := func(env map[string]string) {
		for _, k := range []string{"B2_KEY_ID", "B2_APP_KEY", "B2_ENDPOINT", "B2_REGION", "B2_BUCKET",
			"PORT", "DB_PATH", "QUOTA_MB", "MAX_USERS", "COOKIE_SECURE", "TRUST_PROXY"} {
			t.Setenv(k, env[k])
		}
	}
	base := map[string]string{
		"B2_KEY_ID": "id", "B2_APP_KEY": "key", "B2_ENDPOINT": testEndpoint,
		"B2_REGION": "us-west-004", "B2_BUCKET": "b",
	}

	set(base)
	cfg, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.port != "8080" || cfg.dbPath != "shortened.db" || cfg.quotaBytes != 500<<20 ||
		cfg.maxUsers != 0 || !cfg.cookieSecure || cfg.trustProxy {
		t.Errorf("defaults = %+v", cfg)
	}

	for name, override := range map[string][2]string{
		"missing bucket": {"B2_BUCKET", ""},
		"zero quota":     {"QUOTA_MB", "0"},
		"text quota":     {"QUOTA_MB", "lots"},
		"negative users": {"MAX_USERS", "-1"},
	} {
		env := map[string]string{}
		for k, v := range base {
			env[k] = v
		}
		env[override[0]] = override[1]
		set(env)
		if _, err := loadConfig(); err == nil {
			t.Errorf("%s: loadConfig succeeded, want an error", name)
		}
	}
}
