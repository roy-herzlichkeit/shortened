package main

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func shareBody(key string, seconds int64) string {
	return fmt.Sprintf(`{"key":%q,"seconds":%d}`, key, seconds)
}

// mustShare makes a link to key lasting seconds and returns it.
func mustShare(t *testing.T, h http.Handler, c *http.Cookie, key string, seconds int64) shareInfo {
	t.Helper()
	rec := do(t, h, http.MethodPost, "/shares", shareBody(key, seconds), withCookie(c))
	if rec.Code != http.StatusCreated {
		t.Fatalf("share %s: status %d, body %s", key, rec.Code, rec.Body)
	}
	return decode[shareInfo](t, rec)
}

func liveLinks(t *testing.T, h http.Handler, c *http.Cookie) sharesResponse {
	t.Helper()
	rec := do(t, h, http.MethodGet, "/shares", "", withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /shares: status %d, body %s", rec.Code, rec.Body)
	}
	return decode[sharesResponse](t, rec)
}

// visit opens a share URL as a stranger: no cookie, its own IP.
func visit(t *testing.T, h http.Handler, path string) *http.Response {
	t.Helper()
	return do(t, h, http.MethodGet, path, "", withRemoteAddr("198.51.100.7:1")).Result()
}

func TestShareLink(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	key := stores(t, h, b2, c, "report.pdf", 2048)

	l := mustShare(t, h, c, key, 3600)
	if len(l.Code) != shareCodeLen || !shareCodePattern.MatchString(l.Code) || l.Path != "/s/"+l.Code {
		t.Errorf("code %q, path %q", l.Code, l.Path)
	}
	if got := l.ExpiresAt - l.CreatedAt; got != 3600 {
		t.Errorf("lifetime %d s, want 3600", got)
	}
	list := liveLinks(t, h, c)
	if len(list.Links) != 1 || list.Links[0].Code != l.Code || list.Links[0].Name != "report.pdf" {
		t.Errorf("live links = %+v", list.Links)
	}
	if list.MinSeconds != 600 || list.MaxSeconds != 7*24*3600 {
		t.Errorf("limits %d..%d, want 600..604800", list.MinSeconds, list.MaxSeconds)
	}

	// The recipient's page: name, size, a download link; never cached or indexed.
	res := visit(t, h, l.Path)
	body := readBody(t, res)
	if res.StatusCode != http.StatusOK || !strings.Contains(body, "report.pdf") || !strings.Contains(body, "2 KB") ||
		!strings.Contains(body, `href="/s/`+l.Code+`/download"`) {
		t.Fatalf("page: status %d, body %s", res.StatusCode, body)
	}
	for k, want := range map[string]string{"Cache-Control": "no-store", "X-Robots-Tag": "noindex", "Referrer-Policy": "no-referrer"} {
		if !strings.Contains(res.Header.Get(k), want) {
			t.Errorf("%s = %q, want %q", k, res.Header.Get(k), want)
		}
	}
	if !strings.Contains(body, `<meta name="robots" content="noindex`) {
		t.Error("page lacks the robots noindex meta tag")
	}
	if csp := res.Header.Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") || strings.Contains(csp, "script-src") {
		t.Errorf("CSP %q: want no scripts at all", csp)
	}

	// Each click signs a fresh 10-minute attachment link.
	first := visit(t, h, l.Path+"/download")
	if first.StatusCode != http.StatusFound {
		t.Fatalf("download: status %d", first.StatusCode)
	}
	u, err := url.Parse(first.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if !strings.HasSuffix(u.Path, key) || q.Get("X-Amz-Expires") != "600" ||
		q.Get("response-content-disposition") != `attachment; filename="report.pdf"` {
		t.Errorf("signed link %s", u)
	}
	if first.Header.Get("Cache-Control") != "no-store" {
		t.Error("the redirect may be cached")
	}
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	b, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestShareLifetimeLimits(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	key := stores(t, h, b2, c, "a.txt", 10)
	for _, secs := range []int64{0, 599, 7*24*3600 + 1, -5} {
		if rec := do(t, h, http.MethodPost, "/shares", shareBody(key, secs), withCookie(c)); rec.Code != http.StatusBadRequest {
			t.Errorf("%d s: status %d, want 400", secs, rec.Code)
		}
	}
	mustShare(t, h, c, key, 600)
	mustShare(t, h, c, key, 7*24*3600)

	// An upload that was never confirmed can't be shared.
	up := mustUpload(t, h, c, "pending.txt", 10, "")
	if rec := do(t, h, http.MethodPost, "/shares", shareBody(up.Key, 600), withCookie(c)); rec.Code != http.StatusNotFound {
		t.Errorf("unconfirmed upload: status %d, want 404", rec.Code)
	}
}

func TestShareExpiry(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	l := mustShare(t, h, c, stores(t, h, b2, c, "a.txt", 10), 600)
	if _, err := s.db.Exec(`UPDATE shares SET expires_at = ? WHERE code = ?`, time.Now().Unix()-1, l.Code); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{l.Path, l.Path + "/download"} {
		res := visit(t, h, p)
		if body := readBody(t, res); res.StatusCode != http.StatusGone || !strings.Contains(body, "expired") {
			t.Errorf("GET %s: status %d, body %s; want 410 expired", p, res.StatusCode, body)
		}
	}
	if n := len(liveLinks(t, h, c).Links); n != 0 {
		t.Errorf("%d live links listed, want 0", n)
	}
}

func TestShareRevoke(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	key := stores(t, h, b2, c, "a.txt", 10)
	l := mustShare(t, h, c, key, 3600)
	keep := mustShare(t, h, c, key, 3600)

	if rec := do(t, h, http.MethodDelete, "/shares?code="+l.Code, "", withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("revoke: status %d, body %s", rec.Code, rec.Body)
	}
	for _, p := range []string{l.Path, l.Path + "/download"} {
		res := visit(t, h, p)
		if body := readBody(t, res); res.StatusCode != http.StatusGone || !strings.Contains(body, "turned this link off") {
			t.Errorf("GET %s: status %d; want 410 revoked", p, res.StatusCode)
		}
	}
	if res := visit(t, h, keep.Path); res.StatusCode != http.StatusOK {
		t.Errorf("the other link: status %d, want 200", res.StatusCode)
	}
	if links := liveLinks(t, h, c).Links; len(links) != 1 || links[0].Code != keep.Code {
		t.Errorf("live links = %+v, want only the kept one", links)
	}
}

// Someone else's code or key behaves like one that doesn't exist.
func TestShareOthersCode(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	alice := signup(t, h, "alice")
	bob := signup(t, h, "bob")
	key := stores(t, h, b2, alice, "a.txt", 10)
	l := mustShare(t, h, alice, key, 3600)

	if rec := do(t, h, http.MethodDelete, "/shares?code="+l.Code, "", withCookie(bob)); rec.Code != http.StatusNotFound {
		t.Errorf("bob revoking alice's link: status %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/shares", shareBody(key, 600), withCookie(bob)); rec.Code != http.StatusNotFound {
		t.Errorf("bob sharing alice's file: status %d, want 404", rec.Code)
	}
	if n := len(liveLinks(t, h, bob).Links); n != 0 {
		t.Errorf("bob sees %d links, want 0", n)
	}
	if res := visit(t, h, l.Path); res.StatusCode != http.StatusOK {
		t.Errorf("alice's link after bob's tries: status %d, want 200", res.StatusCode)
	}
	for _, p := range []string{"/s/" + strings.Repeat("a", shareCodeLen), "/s/short", "/s/" + l.Code + "x", "/s/%3Cscript%3E"} {
		if res := visit(t, h, p); res.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: status %d, want 404", p, res.StatusCode)
		}
	}
	if rec := do(t, h, http.MethodGet, "/shares", ""); rec.Code != http.StatusUnauthorized {
		t.Errorf("GET /shares without a session: status %d, want 401", rec.Code)
	}
}

// Deleting a file kills its links, whether through the app or in the bucket.
func TestShareDeletedFile(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	key := stores(t, h, b2, c, "a.txt", 10)
	l := mustShare(t, h, c, key, 3600)
	if rec := do(t, h, http.MethodDelete, "/files?key="+url.QueryEscape(key), "", withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d", rec.Code)
	}
	for _, p := range []string{l.Path, l.Path + "/download"} {
		res := visit(t, h, p)
		if body := readBody(t, res); res.StatusCode != http.StatusGone || !strings.Contains(body, "has been deleted") {
			t.Errorf("GET %s after delete: status %d, body %s; want 410 file deleted", p, res.StatusCode, body)
		}
	}

	// Gone from the bucket by other means: the download finds out and the
	// link dies for good.
	key2 := stores(t, h, b2, c, "b.txt", 10)
	l2 := mustShare(t, h, c, key2, 3600)
	b2.drop(key2)
	res := visit(t, h, l2.Path+"/download")
	if body := readBody(t, res); res.StatusCode != http.StatusGone || !strings.Contains(body, "deleted") {
		t.Errorf("download of a file gone from the bucket: status %d, body %s", res.StatusCode, body)
	}
	if res := visit(t, h, l2.Path); res.StatusCode != http.StatusGone {
		t.Errorf("page afterwards: status %d, want 410", res.StatusCode)
	}
}

// Replace is a new version: the links follow it.
func TestShareSurvivesReplace(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	l := mustShare(t, h, c, stores(t, h, b2, c, "a.txt", 10), 3600)
	up := mustUpload(t, h, c, "a.txt", 20, "replace")
	b2.put(up.Key, 20, time.Now())
	if rec := post(t, h, c, "/files/confirm", up.Key); rec.Code != http.StatusOK {
		t.Fatalf("confirm: status %d", rec.Code)
	}
	res := visit(t, h, l.Path+"/download")
	if res.StatusCode != http.StatusFound || !strings.Contains(res.Header.Get("Location"), url.PathEscape(up.Key[strings.LastIndexByte(up.Key, '/')+1:])) {
		t.Errorf("after replace: status %d, location %s; want the new file", res.StatusCode, res.Header.Get("Location"))
	}
}

func TestShareRateLimited(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.shareLimiter = newIPLimiter(time.Hour, 5) // never refills during the test
	path := "/s/" + strings.Repeat("a", shareCodeLen)
	for i := 0; i < 5; i++ {
		do(t, h, http.MethodGet, path, "", withRemoteAddr("192.0.2.40:1"))
	}
	rec := do(t, h, http.MethodGet, path+"/download", "", withRemoteAddr("192.0.2.40:1"))
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") == "" {
		t.Errorf("6th request from one IP: status %d, want 429 with Retry-After", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, path, "", withRemoteAddr("192.0.2.41:1")); rec.Code != http.StatusNotFound {
		t.Errorf("another IP: status %d, want 404 (not limited)", rec.Code)
	}
}

func TestShareCodes(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 500; i++ {
		c, err := newShareCode()
		if err != nil {
			t.Fatal(err)
		}
		if !shareCodePattern.MatchString(c) || seen[c] {
			t.Fatalf("code %q bad or repeated", c)
		}
		seen[c] = true
	}
	for in, want := range map[int64]string{40: "40 B", 2048: "2 KB", 1536: "1.5 KB", 500 << 20: "500 MB"} {
		if got := humanSize(in); got != want {
			t.Errorf("humanSize(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[time.Duration]string{10 * time.Minute: "10 minutes", time.Hour: "1 hour", 7 * 24 * time.Hour: "7 days"} {
		if got := humanDuration(in); got != want {
			t.Errorf("humanDuration(%v) = %q, want %q", in, got, want)
		}
	}
}
