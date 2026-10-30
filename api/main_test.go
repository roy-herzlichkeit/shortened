package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
)

const testAPIKey = "test-api-key"

// newTestServer builds the real handler stack against endpoint. Presigning is
// done locally, so tests that only sign URLs never contact it.
func newTestServer(t *testing.T, endpoint string) http.Handler {
	t.Helper()
	s, err := newServer(context.Background(), config{
		keyID:    "0000000000000000000000001",
		appKey:   "K0000000000000000000000000000000",
		endpoint: endpoint,
		region:   "us-west-004",
		bucket:   "test-bucket",
		apiKey:   testAPIKey,
		origin:   "http://localhost:8000",
	})
	if err != nil {
		t.Fatalf("newServer: %v", err)
	}
	return s.routes()
}

func do(t *testing.T, h http.Handler, method, target, body string, withKey bool) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if withKey {
		req.Header.Set("X-API-Key", testAPIKey)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

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

// Every key the upload handler can issue must be accepted by the download and
// delete handlers; the old ".." check broke this for names like "my..file.txt".
func TestIssuedKeysAreValid(t *testing.T) {
	for _, in := range []string{"my..file.txt", "a.b.c", "x", strings.Repeat("z", 300) + ".gz", "a-_.b"} {
		id, err := newID()
		if err != nil {
			t.Fatal(err)
		}
		key := id + "-" + cleanFilename(in)
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
		"", "report.pdf", "/0123456789abcdef-a", "0123456789abcdef-", "0123456789ABCDEF-a",
		"0123456789abcdef-a/b", "0123456789abcdef-a b", "0123456789abcdef-" + strings.Repeat("a", 121),
	} {
		if validKey(key) {
			t.Errorf("validKey(%q) = true, want false", key)
		}
	}
}

func TestAuthAndCORS(t *testing.T) {
	h := newTestServer(t, "http://127.0.0.1:1")

	if rec := do(t, h, http.MethodGet, "/health", "", false); rec.Code != http.StatusOK {
		t.Errorf("/health = %d, want 200", rec.Code)
	}
	for _, path := range []string{"/upload-url", "/files", "/download-url"} {
		rec := do(t, h, http.MethodGet, path, "", false)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s without key = %d, want 401", path, rec.Code)
		}
		if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:8000" {
			t.Errorf("%s 401 Allow-Origin = %q", path, got)
		}

		rec = do(t, h, http.MethodOptions, path, "", false)
		if rec.Code != http.StatusNoContent {
			t.Errorf("%s preflight = %d, want 204", path, rec.Code)
		}
		if !strings.Contains(rec.Header().Get("Access-Control-Allow-Methods"), "DELETE") {
			t.Errorf("%s preflight does not allow DELETE", path)
		}
	}
}

func TestUploadURL(t *testing.T) {
	h := newTestServer(t, "https://s3.us-west-004.backblazeb2.com")

	rec := do(t, h, http.MethodPost, "/upload-url", `{"filename":"my..file.txt","size":1234}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var resp uploadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if !validKey(resp.Key) || !strings.HasSuffix(resp.Key, "-my..file.txt") {
		t.Errorf("key = %q", resp.Key)
	}

	u, err := url.Parse(resp.URL)
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "s3.us-west-004.backblazeb2.com" || !strings.HasPrefix(u.Path, "/test-bucket/") {
		t.Errorf("URL is not path-style on the endpoint: %s", resp.URL)
	}
	q := u.Query()
	if q.Get("X-Amz-Expires") != "600" {
		t.Errorf("X-Amz-Expires = %q, want 600", q.Get("X-Amz-Expires"))
	}
	// The size limit only binds if the length is part of the signature.
	if signed := q.Get("X-Amz-SignedHeaders"); !strings.Contains(signed, "content-length") {
		t.Errorf("X-Amz-SignedHeaders = %q, want content-length signed", signed)
	}
}

func TestUploadURLRejects(t *testing.T) {
	h := newTestServer(t, "https://s3.us-west-004.backblazeb2.com")
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
		if rec := do(t, h, http.MethodPost, "/upload-url", tt.body, true); rec.Code != tt.want {
			t.Errorf("%s: status = %d, want %d", tt.name, rec.Code, tt.want)
		}
	}
	if rec := do(t, h, http.MethodGet, "/upload-url", "", true); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET /upload-url = %d, want 405", rec.Code)
	}
}

func TestDownloadURL(t *testing.T) {
	h := newTestServer(t, "https://s3.us-west-004.backblazeb2.com")

	rec := do(t, h, http.MethodGet, "/download-url?key=0123456789abcdef-my..file.txt", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var resp map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(resp["url"])
	if err != nil {
		t.Fatal(err)
	}
	want := `attachment; filename="my..file.txt"`
	if got := u.Query().Get("response-content-disposition"); got != want {
		t.Errorf("response-content-disposition = %q, want %q", got, want)
	}

	for _, key := range []string{"", "..%2Fsecret", "report.pdf"} {
		if rec := do(t, h, http.MethodGet, "/download-url?key="+key, "", true); rec.Code != http.StatusBadRequest {
			t.Errorf("key %q: status = %d, want 400", key, rec.Code)
		}
	}
}

// fakeB2 answers just enough of the S3 API for ListObjectsV2 and DeleteObject.
type fakeB2 struct {
	mu      sync.Mutex
	deleted []string
}

func (f *fakeB2) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/test-bucket" && r.URL.Query().Get("list-type") == "2":
		w.Header().Set("Content-Type", "application/xml")
		w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>test-bucket</Name><KeyCount>3</KeyCount><IsTruncated>false</IsTruncated>
  <Contents><Key>0000000000000000-old.txt</Key><LastModified>2026-01-01T00:00:00.000Z</LastModified><Size>1</Size></Contents>
  <Contents><Key>ffffffffffffffff-new.txt</Key><LastModified>2026-10-01T00:00:00.000Z</LastModified><Size>2048</Size></Contents>
  <Contents><Key>8888888888888888-mid.txt</Key><LastModified>2026-05-01T00:00:00.000Z</LastModified><Size>3</Size></Contents>
</ListBucketResult>`))
	case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/test-bucket/"):
		f.mu.Lock()
		f.deleted = append(f.deleted, strings.TrimPrefix(r.URL.Path, "/test-bucket/"))
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "unexpected "+r.Method+" "+r.URL.String(), http.StatusNotImplemented)
	}
}

func TestListFilesNewestFirst(t *testing.T) {
	b2 := httptest.NewServer(&fakeB2{})
	defer b2.Close()
	h := newTestServer(t, b2.URL)

	rec := do(t, h, http.MethodGet, "/files", "", true)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	var files []fileInfo
	if err := json.Unmarshal(rec.Body.Bytes(), &files); err != nil {
		t.Fatal(err)
	}
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
}

func TestDeleteFile(t *testing.T) {
	fake := &fakeB2{}
	b2 := httptest.NewServer(fake)
	defer b2.Close()
	h := newTestServer(t, b2.URL)

	if rec := do(t, h, http.MethodDelete, "/files?key=0123456789abcdef-a.txt", "", true); rec.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body %s", rec.Code, rec.Body)
	}
	if len(fake.deleted) != 1 || fake.deleted[0] != "0123456789abcdef-a.txt" {
		t.Errorf("deleted = %v", fake.deleted)
	}
	if rec := do(t, h, http.MethodDelete, "/files?key=not-a-key", "", true); rec.Code != http.StatusBadRequest {
		t.Errorf("invalid key: status = %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPut, "/files", "", true); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT /files = %d, want 405", rec.Code)
	}
}
