package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testPromo = "Corpo-Test-Code"

func couponBody(code string) string { return fmt.Sprintf(`{"code":%q}`, code) }

func me(t *testing.T, h http.Handler, c *http.Cookie) meResponse {
	t.Helper()
	return decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
}

func promoConfig(endpoint string) config {
	cfg := testConfig(endpoint)
	cfg.promoCode = testPromo
	return cfg
}

// A wrong code changes nothing; the right one in other letter cases sets corpo
// for life, and the limits change at once; a second use is refused.
func TestCoupon(t *testing.T) {
	s, h := newTestServer(t, promoConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)
	c := signup(t, h, "alice")
	if m := me(t, h, c); m.Plan != planFree || m.QuotaBytes != s.cfg.quotaBytes || m.CouponUsed || m.ShareMaxSecs != 7*24*3600 {
		t.Fatalf("new account: %+v", m)
	}
	for _, wrong := range []string{"", "  ", "corpo-test-cod", "Corpo-Test-Code-", "CORPO"} {
		if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(wrong), withCookie(c)); rec.Code != http.StatusBadRequest {
			t.Errorf("code %q: status %d, want 400", wrong, rec.Code)
		}
	}
	if m := me(t, h, c); m.Plan != planFree {
		t.Fatalf("wrong codes changed the plan to %q", m.Plan)
	}

	rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody("  cORPO-tEST-cODE "), withCookie(c))
	if rec.Code != http.StatusOK {
		t.Fatalf("right code: status %d, body %s", rec.Code, rec.Body)
	}
	m := me(t, h, c)
	if m.Plan != planCorpo || m.QuotaBytes != 5<<30 || !m.CouponUsed || m.ShareMaxSecs != 30*24*3600 {
		t.Errorf("after the coupon: %+v; want corpo, 5 GB, 30 days", m)
	}
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo), withCookie(c)); rec.Code != http.StatusConflict {
		t.Errorf("second use: status %d, want 409", rec.Code)
	}

	// Unlimited uses: another account can use it too.
	bob := signup(t, h, "bob")
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody("CORPO-TEST-CODE"), withCookie(bob)); rec.Code != http.StatusOK {
		t.Errorf("another account: status %d, want 200", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo)); rec.Code != http.StatusUnauthorized {
		t.Errorf("no session: status %d, want 401", rec.Code)
	}
}

// The quota follows the plan from the next request on.
func TestCouponRaisesQuotaAtOnce(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	cfg := promoConfig(endpoint)
	cfg.quotaBytes = 100
	_, h := newTestServer(t, cfg)
	c := signup(t, h, "alice")
	stores(t, h, b2, c, "a.txt", 80)
	if rec := requestUpload(t, h, c, "b.txt", 50, ""); rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "of 0.0 MB") {
		t.Fatalf("over the free quota: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo), withCookie(c)); rec.Code != http.StatusOK {
		t.Fatalf("coupon: status %d", rec.Code)
	}
	if rec := requestUpload(t, h, c, "b.txt", 50, ""); rec.Code != http.StatusOK {
		t.Errorf("after the coupon: status %d, body %s; want 200", rec.Code, rec.Body)
	}
	up := decode[usageResponse](t, post(t, h, c, "/files/release", mustUpload(t, h, c, "c.txt", 10, "").Key))
	if up.QuotaBytes != 5<<30 {
		t.Errorf("usage answers quota %d, want 5 GB", up.QuotaBytes)
	}
}

// Share links: 7 days at most on free, 30 on corpo.
func TestPlanShareMaximum(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, promoConfig(endpoint))
	c := signup(t, h, "alice")
	key := stores(t, h, b2, c, "a.txt", 10)
	if rec := do(t, h, http.MethodPost, "/shares", shareBody(key, 8*24*3600), withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("free, 8 days: status %d, want 400", rec.Code)
	}
	if _, err := s.db.Exec(`UPDATE users SET plan = 'corpo' WHERE username = 'alice'`); err != nil {
		t.Fatal(err)
	}
	if m := me(t, h, c); m.Plan != planCorpo || m.QuotaBytes != 5<<30 {
		t.Errorf("corpo: %+v", m)
	}
	mustShare(t, h, c, key, 30*24*3600)
	if rec := do(t, h, http.MethodPost, "/shares", shareBody(key, 30*24*3600+1), withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("corpo, 30 days and a second: status %d, want 400", rec.Code)
	}
	if got := liveLinks(t, h, c).MaxSeconds; got != 30*24*3600 {
		t.Errorf("listed maximum %d, want 30 days", got)
	}
}

func TestCouponAtSignup(t *testing.T) {
	s, h := newTestServer(t, promoConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)

	// Wrong: refused before any mail, nothing kept.
	body := `{"username":"carol","password":"correct horse battery","email":"carol@example.test","coupon":"nope"}`
	if rec := do(t, h, http.MethodPost, "/auth/signup", body); rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong coupon at sign-up: status %d, want 400", rec.Code)
	}
	if n := len(s.mails(t, "carol@example.test")); n != 0 {
		t.Errorf("%d mails sent for a refused sign-up", n)
	}

	// Right, in lower case: the account starts on corpo, and can't use it again.
	body = `{"username":"carol","password":"correct horse battery","email":"carol@example.test","coupon":"corpo-test-code"}`
	rec := do(t, h, http.MethodPost, "/auth/signup", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("sign-up with coupon: status %d, body %s", rec.Code, rec.Body)
	}
	if n := countUsers(t, s); n != 0 {
		t.Fatalf("%d accounts before the code, want 0", n)
	}
	rec = do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(s.lastCode(t, "carol@example.test")), withCookie(signupCookieFrom(t, rec)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("verify: status %d, body %s", rec.Code, rec.Body)
	}
	c := sessionFrom(t, rec)
	if m := me(t, h, c); m.Plan != planCorpo || !m.CouponUsed || m.QuotaBytes != 5<<30 {
		t.Errorf("signed up with the coupon: %+v", m)
	}
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo), withCookie(c)); rec.Code != http.StatusConflict {
		t.Errorf("coupon again after sign-up: status %d, want 409", rec.Code)
	}

	// No coupon: free, as before.
	if m := me(t, h, signup(t, h, "dave")); m.Plan != planFree || m.CouponUsed {
		t.Errorf("signed up without a coupon: %+v", m)
	}
}

// Without PROMO_CODE there is no coupon: no code works, the empty one included.
func TestCouponOff(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)
	c := signup(t, h, "alice")
	for _, code := range []string{"", testPromo} {
		if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(code), withCookie(c)); rec.Code != http.StatusNotFound {
			t.Errorf("coupon off, code %q: status %d, want 404", code, rec.Code)
		}
	}
	body := `{"username":"bob","password":"correct horse battery","email":"bob@example.test","coupon":"anything"}`
	if rec := do(t, h, http.MethodPost, "/auth/signup", body); rec.Code != http.StatusBadRequest {
		t.Errorf("coupon off, at sign-up: status %d, want 400", rec.Code)
	}
	if s.couponMatches("") {
		t.Error("the empty code matched with the coupon off")
	}
}

func TestCouponRateLimited(t *testing.T) {
	s, h := newTestServer(t, promoConfig(testEndpoint))
	c := signup(t, h, "alice")
	s.limiter = newIPLimiter(time.Hour, 5) // never refills during the test
	for i := 0; i < 5; i++ {
		do(t, h, http.MethodPost, "/auth/coupon", couponBody("guess"), withCookie(c), withRemoteAddr("192.0.2.50:1"))
	}
	if rec := do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo), withCookie(c), withRemoteAddr("192.0.2.50:1")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("6th try from one IP: status %d, want 429", rec.Code)
	}
	if m := me(t, h, c); m.Plan != planFree {
		t.Errorf("a refused try changed the plan to %q", m.Plan)
	}
}

func TestPlanCounts(t *testing.T) {
	s, h := newTestServer(t, promoConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)
	signup(t, h, "aaa")
	signup(t, h, "bbb")
	c := signup(t, h, "ccc")
	signup(t, h, "ddd")
	do(t, h, http.MethodPost, "/auth/coupon", couponBody(testPromo), withCookie(c))
	if _, err := s.db.Exec(`UPDATE users SET plan = 'corpo' WHERE username = 'ddd'`); err != nil {
		t.Fatal(err)
	}
	users, corpo, err := s.planCounts(t.Context())
	if err != nil || users != 4 || corpo != 2 {
		t.Errorf("counts %d users, %d corpo (%v); want 4, 2", users, corpo, err)
	}
}

// A database from before plans: every account starts on free, a pending
// sign-up keeps working, and reopening changes nothing.
func TestMigratePlans(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL, created_at INTEGER NOT NULL, email TEXT, pending_email TEXT)`,
		`CREATE TABLE signups (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, password_hash TEXT NOT NULL,
			email TEXT NOT NULL, code_hash TEXT NOT NULL, expires_at INTEGER NOT NULL, tries INTEGER NOT NULL DEFAULT 0,
			created_at INTEGER NOT NULL)`,
		`INSERT INTO users (username, password_hash, created_at, email) VALUES ('one', 'x', 0, 'one@example.test'), ('two', 'x', 0, NULL)`,
		`INSERT INTO signups VALUES ('t', 'three', 'x', 'three@example.test', 'h', 0, 0, 0)`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	for i := 0; i < 2; i++ { // the second open must be a no-op
		db, err := openDB(path)
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		var free, couponless int
		if err := db.QueryRow(`SELECT COUNT(*) FROM users WHERE plan = 'free' AND coupon_at = 0`).Scan(&free); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM signups WHERE coupon = 0`).Scan(&couponless); err != nil {
			t.Fatal(err)
		}
		if free != 2 || couponless != 1 {
			t.Errorf("open %d: %d free users (want 2), %d sign-ups without coupon (want 1)", i, free, couponless)
		}
		db.Close()
	}
}
