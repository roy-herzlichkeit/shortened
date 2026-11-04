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

func verifyBody(code string) string { return fmt.Sprintf(`{"code":%q}`, code) }

// wrongCode is a 6-digit code that is not code.
func wrongCode(code string) string {
	if code == "000000" {
		return "111111"
	}
	return "000000"
}

func countUsers(t *testing.T, s *server) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// No account exists until the mailed code is entered.
func TestSignupCreatesAccountOnlyAfterCode(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	rec := do(t, h, http.MethodPost, "/auth/signup", creds("alice", "correct horse battery"))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("signup: status %d, body %s", rec.Code, rec.Body)
	}
	for _, c := range rec.Result().Cookies() {
		if c.Name == sessionCookie {
			t.Errorf("sign-up set a session before the code")
		}
	}
	sc := signupCookieFrom(t, rec)
	if n := countUsers(t, s); n != 0 {
		t.Errorf("%d users before the code, want 0", n)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery")); rec.Code != http.StatusUnauthorized {
		t.Errorf("login before the code: status %d, want 401", rec.Code)
	}
	pending := do(t, h, http.MethodGet, "/auth/signup/pending", "", withCookie(sc))
	if pending.Code != http.StatusOK || !strings.Contains(pending.Body.String(), `"pendingEmail":"alice@example.test"`) {
		t.Errorf("pending: status %d, body %s", pending.Code, pending.Body)
	}
	if rec := do(t, h, http.MethodGet, "/auth/signup/pending", ""); rec.Code != http.StatusNotFound {
		t.Errorf("pending without the cookie: status %d, want 404", rec.Code)
	}

	code := s.lastCode(t, "alice@example.test")
	if code == "" {
		t.Fatal("no code mailed at sign-up")
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(wrongCode(code)), withCookie(sc)); rec.Code != http.StatusBadRequest {
		t.Errorf("wrong code: status %d, want 400", rec.Code)
	}
	if n := countUsers(t, s); n != 0 {
		t.Errorf("%d users after a wrong code, want 0", n)
	}
	rec = do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(code), withCookie(sc))
	if rec.Code != http.StatusCreated {
		t.Fatalf("right code: status %d, body %s", rec.Code, rec.Body)
	}
	c := sessionFrom(t, rec)
	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if !me.Verified || me.Email != "alice@example.test" || me.Username != "alice" {
		t.Errorf("me after the code = %+v", me)
	}
	if rec := do(t, h, http.MethodGet, "/download-url?key=x", "", withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("files after the code: status %d, want 400 (bad key)", rec.Code)
	}
	// The request is used up.
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(code), withCookie(sc)); rec.Code != http.StatusGone {
		t.Errorf("code reused: status %d, want 410", rec.Code)
	}
	var left int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM signups`).Scan(&left); err != nil || left != 0 {
		t.Errorf("%d pending sign-ups left (err %v), want 0", left, err)
	}
}

func TestSignupRequiresValidEmail(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	for _, email := range []string{"", "alice", "alice@", "@example.com", "alice@localhost", "Alice <a@example.com>", "a b@example.com"} {
		body := fmt.Sprintf(`{"username":"alice","password":"correct horse battery","email":%q}`, email)
		if rec := do(t, h, http.MethodPost, "/auth/signup", body); rec.Code != http.StatusBadRequest {
			t.Errorf("email %q: status %d, want 400", email, rec.Code)
		}
	}
}

// When the mail service refuses the address, the person is told and nothing
// is kept.
func TestSignupMailRefused(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.mailer.(*fakeMailer).fail = true
	rec := do(t, h, http.MethodPost, "/auth/signup", creds("alice", "correct horse battery"))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "could not send") {
		t.Errorf("refused mail: status %d, body %s; want 502", rec.Code, rec.Body)
	}
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM signups`).Scan(&n); err != nil || n != 0 {
		t.Errorf("%d pending sign-ups (err %v), want 0", n, err)
	}
	if n := countUsers(t, s); n != 0 {
		t.Errorf("%d users, want 0", n)
	}
}

func TestCodeStoredOnlyAsHash(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	startSignup(t, h, "alice")
	code := s.lastCode(t, "alice@example.test")
	var codeHash, pwHash string
	if err := s.db.QueryRow(`SELECT code_hash, password_hash FROM signups`).Scan(&codeHash, &pwHash); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(codeHash, code) || !strings.HasPrefix(codeHash, "$2") {
		t.Errorf("stored code %q is not a bcrypt hash of the code", codeHash)
	}
	if strings.Contains(pwHash, "correct horse") || !strings.HasPrefix(pwHash, "$2") {
		t.Errorf("stored password %q is not a bcrypt hash", pwHash)
	}

	// The same for a code that verifies an address on an existing account.
	c := legacyUser(t, h, "bob")
	do(t, h, http.MethodPost, "/auth/email", `{"email":"bob@example.test"}`, withCookie(c))
	if err := s.db.QueryRow(`SELECT code_hash FROM otps`).Scan(&codeHash); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(codeHash, s.lastCode(t, "bob@example.test")) || !strings.HasPrefix(codeHash, "$2") {
		t.Errorf("stored code %q is not a bcrypt hash of the code", codeHash)
	}
}

func TestCodeDiesAfterFiveTries(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100) // more calls than the real limit allows
	sc := startSignup(t, h, "alice")
	code := s.lastCode(t, "alice@example.test")
	for i := 0; i < codeTries; i++ {
		if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(wrongCode(code)), withCookie(sc)); rec.Code != http.StatusBadRequest {
			t.Fatalf("try %d: status %d", i+1, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(code), withCookie(sc)); rec.Code != http.StatusBadRequest {
		t.Errorf("right code after %d wrong tries: status %d, want 400", codeTries, rec.Code)
	}
	// A new code starts over.
	if rec := do(t, h, http.MethodPost, "/auth/signup/resend", "", withCookie(sc)); rec.Code != http.StatusAccepted {
		t.Fatalf("resend: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(s.lastCode(t, "alice@example.test")), withCookie(sc)); rec.Code != http.StatusCreated {
		t.Errorf("new code: status %d, body %s; want 201", rec.Code, rec.Body)
	}

	// The address code of an existing account dies the same way.
	c := legacyUser(t, h, "bob")
	do(t, h, http.MethodPost, "/auth/email", `{"email":"bob@example.test"}`, withCookie(c))
	code = s.lastCode(t, "bob@example.test")
	for i := 0; i < codeTries; i++ {
		do(t, h, http.MethodPost, "/auth/email/verify", verifyBody(wrongCode(code)), withCookie(c))
	}
	if rec := do(t, h, http.MethodPost, "/auth/email/verify", verifyBody(code), withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("address code after %d wrong tries: status %d, want 400", codeTries, rec.Code)
	}
}

func TestCodeExpires(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	sc := startSignup(t, h, "alice")
	code := s.lastCode(t, "alice@example.test")
	if _, err := s.db.Exec(`UPDATE signups SET expires_at = ?`, time.Now().Add(-time.Second).Unix()); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(code), withCookie(sc)); rec.Code != http.StatusBadRequest {
		t.Errorf("expired code: status %d, want 400", rec.Code)
	}
	// Past signupTTL the whole request is gone.
	if _, err := s.db.Exec(`UPDATE signups SET created_at = ?`, time.Now().Add(-signupTTL).Unix()); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/resend", "", withCookie(sc)); rec.Code != http.StatusGone {
		t.Errorf("resend for an old sign-up: status %d, want 410", rec.Code)
	}
}

func TestThreeMailsPerHour(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100) // more calls than the real limit allows
	// mail 1
	sc := startSignup(t, h, "alice")
	for i := 2; i <= mailsPerHour; i++ {
		if rec := do(t, h, http.MethodPost, "/auth/signup/resend", "", withCookie(sc)); rec.Code != http.StatusAccepted {
			t.Fatalf("resend %d: status %d, body %s", i, rec.Code, rec.Body)
		}
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/resend", "", withCookie(sc)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th mail in an hour: status %d, want 429", rec.Code)
	}
	// A fresh sign-up to the same address doesn't get around it.
	if rec := do(t, h, http.MethodPost, "/auth/signup", `{"username":"other","password":"correct horse battery","email":"alice@example.test"}`); rec.Code != http.StatusTooManyRequests {
		t.Errorf("new sign-up past the limit: status %d, want 429", rec.Code)
	}
	if n := len(s.mails(t, "alice@example.test")); n != mailsPerHour {
		t.Errorf("%d mails sent, want %d", n, mailsPerHour)
	}
	// An hour later the limit has room again.
	if _, err := s.db.Exec(`UPDATE signup_mail SET sent_at = sent_at - 3601`); err != nil {
		t.Fatal(err)
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup/resend", "", withCookie(sc)); rec.Code != http.StatusAccepted {
		t.Errorf("after an hour: status %d, want 202", rec.Code)
	}

	// Accounts adding an address have their own limit of 3 an hour.
	c := legacyUser(t, h, "bob")
	for i := 1; i <= mailsPerHour; i++ {
		if rec := do(t, h, http.MethodPost, "/auth/email", `{"email":"bob@example.test"}`, withCookie(c)); rec.Code != http.StatusAccepted {
			t.Fatalf("address code %d: status %d, body %s", i, rec.Code, rec.Body)
		}
	}
	if rec := do(t, h, http.MethodPost, "/auth/email", `{"email":"bob@example.test"}`, withCookie(c)); rec.Code != http.StatusTooManyRequests {
		t.Errorf("4th address code in an hour: status %d, want 429", rec.Code)
	}
}

// A verified address can't be taken by another account, and the sign-up
// answer doesn't reveal that it is in use: the owner gets a notice instead.
func TestEmailOnePerAccount(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	signup(t, h, "alice")
	before := len(s.mails(t, "alice@example.test"))

	body := `{"username":"bob","password":"correct horse battery","email":"ALICE@Example.TEST"}`
	rec := do(t, h, http.MethodPost, "/auth/signup", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("sign-up with a taken address: status %d, want the usual 202", rec.Code)
	}
	bob := signupCookieFrom(t, rec)
	ms := s.mails(t, "alice@example.test")
	if len(ms) != before+1 || codeInText.MatchString(ms[len(ms)-1].text) || !strings.Contains(ms[len(ms)-1].text, "already belongs") {
		t.Errorf("owner should get a notice without a code; got %d new mails", len(ms)-before)
	}
	// Bob has no code to enter, and a guess doesn't take the address.
	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody("123456"), withCookie(bob)); rec.Code != http.StatusBadRequest {
		t.Errorf("verify without a code: status %d, want 400", rec.Code)
	}
	if n := countUsers(t, s); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
}

// The username is only taken when a code is entered: of two people waiting
// for the same name, the first to confirm gets it.
func TestUsernameTakenWhileWaiting(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	first := startSignup(t, h, "carol")
	body := `{"username":"carol","password":"correct horse battery","email":"carol2@example.test"}`
	second := signupCookieFrom(t, do(t, h, http.MethodPost, "/auth/signup", body))

	if rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(s.lastCode(t, "carol2@example.test")), withCookie(second)); rec.Code != http.StatusCreated {
		t.Fatalf("second confirms first: status %d, body %s", rec.Code, rec.Body)
	}
	rec := do(t, h, http.MethodPost, "/auth/signup/verify", verifyBody(s.lastCode(t, "carol@example.test")), withCookie(first))
	if rec.Code != http.StatusConflict {
		t.Errorf("first confirms after: status %d, want 409", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/signup", creds("carol", "correct horse battery")); rec.Code != http.StatusConflict {
		t.Errorf("new sign-up for a taken name: status %d, want 409", rec.Code)
	}
	if n := countUsers(t, s); n != 1 {
		t.Errorf("%d users, want 1", n)
	}
}

func TestLoginWithEmail(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	signup(t, h, "alice")
	startSignup(t, h, "bob") // waiting for its code

	if rec := do(t, h, http.MethodPost, "/auth/login", `{"username":"Alice@Example.test","password":"correct horse battery"}`); rec.Code != http.StatusOK ||
		!strings.Contains(rec.Body.String(), `"username":"alice"`) {
		t.Errorf("login by email: status %d, body %s", rec.Code, rec.Body)
	}
	// A pending address is not a login.
	if rec := do(t, h, http.MethodPost, "/auth/login", `{"username":"bob@example.test","password":"correct horse battery"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("login by unverified email: status %d, want 401", rec.Code)
	}
	wrong := do(t, h, http.MethodPost, "/auth/login", `{"username":"alice@example.test","password":"wrong password"}`).Body.String()
	unknown := do(t, h, http.MethodPost, "/auth/login", `{"username":"nobody@example.test","password":"wrong password"}`).Body.String()
	if wrong != unknown {
		t.Errorf("unknown-email and wrong-password answers differ: %q vs %q", unknown, wrong)
	}
}

func TestForgotAndReset(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100) // more calls than the real limit allows
	first := signup(t, h, "alice")
	second := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery"))
	other := sessionFrom(t, second)
	legacyUser(t, h, "bob") // no verified address

	answers := map[string]string{}
	for _, login := range []string{"alice", "ALICE@example.test", "nobody", "nobody@example.test", "bob"} {
		rec := do(t, h, http.MethodPost, "/auth/forgot", fmt.Sprintf(`{"login":%q}`, login))
		if rec.Code != http.StatusAccepted {
			t.Errorf("forgot %q: status %d", login, rec.Code)
		}
		answers[rec.Body.String()] = login
	}
	if len(answers) != 1 {
		t.Errorf("forgot answers differ by account: %v", answers)
	}
	if n := len(s.mails(t, "bob@example.test")); n != 1 { // only the sign-up code
		t.Errorf("bob (unverified) got %d mails, want 1", n)
	}

	code := s.lastCode(t, "alice@example.test")
	reset := func(login, code, pass string) int {
		return do(t, h, http.MethodPost, "/auth/reset",
			fmt.Sprintf(`{"login":%q,"code":%q,"password":%q}`, login, code, pass)).Code
	}
	if got := reset("nobody", code, "brand new password"); got != http.StatusBadRequest {
		t.Errorf("reset of an unknown account: status %d, want 400", got)
	}
	if got := reset("alice", wrongCode(code), "brand new password"); got != http.StatusBadRequest {
		t.Errorf("reset with a wrong code: status %d, want 400", got)
	}
	rec := do(t, h, http.MethodPost, "/auth/reset", fmt.Sprintf(`{"login":"alice","code":%q,"password":"brand new password"}`, code))
	if rec.Code != http.StatusOK {
		t.Fatalf("reset: status %d, body %s", rec.Code, rec.Body)
	}
	fresh := sessionFrom(t, rec)

	for name, c := range map[string]*http.Cookie{"first": first, "second": other} {
		if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s session after reset: status %d, want 401", name, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(fresh)); rec.Code != http.StatusOK {
		t.Errorf("session from the reset: status %d, want 200", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery")); rec.Code != http.StatusUnauthorized {
		t.Errorf("old password after reset: status %d, want 401", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "brand new password")); rec.Code != http.StatusOK {
		t.Errorf("new password: status %d, want 200", rec.Code)
	}
	if got := reset("alice", code, "another password"); got != http.StatusBadRequest {
		t.Errorf("reset code reused: status %d, want 400", got)
	}
}

func TestChangeEmail(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")

	if rec := do(t, h, http.MethodPost, "/auth/email", `{"email":"new@example.test","password":"wrong password"}`, withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("change without the password: status %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/email", `{"email":"new@example.test","password":"correct horse battery"}`, withCookie(c)); rec.Code != http.StatusAccepted {
		t.Fatalf("change: status %d, body %s", rec.Code, rec.Body)
	}
	// Until the code is entered, the old address is still the one.
	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if me.Email != "alice@example.test" || me.PendingEmail != "new@example.test" || !me.Verified {
		t.Errorf("me while pending = %+v", me)
	}
	code := s.lastCode(t, "new@example.test")
	if rec := do(t, h, http.MethodPost, "/auth/email/verify", verifyBody(code), withCookie(c)); rec.Code != http.StatusOK {
		t.Fatalf("verify new address: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", `{"username":"new@example.test","password":"correct horse battery"}`); rec.Code != http.StatusOK {
		t.Errorf("login with the new address: status %d", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", `{"username":"alice@example.test","password":"correct horse battery"}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("login with the old address: status %d, want 401", rec.Code)
	}
}

// A reset code mailed to an address the account no longer has is void.
func TestResetCodeVoidAfterEmailChange(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")
	do(t, h, http.MethodPost, "/auth/forgot", `{"login":"alice"}`)
	resetCode := s.lastCode(t, "alice@example.test")

	do(t, h, http.MethodPost, "/auth/email", `{"email":"new@example.test","password":"correct horse battery"}`, withCookie(c))
	do(t, h, http.MethodPost, "/auth/email/verify", verifyBody(s.lastCode(t, "new@example.test")), withCookie(c))

	rec := do(t, h, http.MethodPost, "/auth/reset", fmt.Sprintf(`{"login":"alice","code":%q,"password":"brand new password"}`, resetCode))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("old reset code after an address change: status %d, want 400", rec.Code)
	}
}

func TestChangePassword(t *testing.T) {
	_, h := newTestServer(t, testConfig(testEndpoint))
	c := signup(t, h, "alice")
	other := sessionFrom(t, do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery")))

	if rec := do(t, h, http.MethodPost, "/auth/password", `{"current":"wrong password","password":"brand new password"}`, withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("wrong current password: status %d, want 403", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/password", `{"current":"correct horse battery","password":"short"}`, withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("short new password: status %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/password", `{"current":"correct horse battery","password":"brand new password"}`, withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("change: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)); rec.Code != http.StatusOK {
		t.Errorf("this session after the change: status %d, want 200", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(other)); rec.Code != http.StatusUnauthorized {
		t.Errorf("other session after the change: status %d, want 401", rec.Code)
	}
}

func TestCodeEndpointsRateLimited(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Hour, 10) // never refills during the test
	for i := 0; i < 10; i++ {
		do(t, h, http.MethodPost, "/auth/reset", `{"login":"alice","code":"123456","password":"long enough pass"}`, withRemoteAddr("192.0.2.9:1"))
	}
	for _, path := range []string{"/auth/reset", "/auth/forgot", "/auth/email/verify", "/auth/login", "/auth/signup", "/auth/signup/verify", "/auth/signup/resend"} {
		if rec := do(t, h, http.MethodPost, path, `{}`, withRemoteAddr("192.0.2.9:1")); rec.Code != http.StatusTooManyRequests {
			t.Errorf("%s after 10 tries from one IP: status %d, want 429", path, rec.Code)
		}
	}
}

func TestMailBodies(t *testing.T) {
	m := verifyMessage("a@example.test", "alice", "042517")
	for name, body := range map[string]string{"text": m.text, "html": m.html} {
		if !strings.Contains(body, "042517") || !strings.Contains(body, "10 minutes") {
			t.Errorf("%s body lacks the code or its lifetime:\n%s", name, body)
		}
	}
	for _, m := range []message{m, resetMessage("a@example.test", "alice", "042517"), inUseMessage("a@example.test")} {
		if strings.Contains(m.html, "<img") || strings.Contains(m.html, "http") || strings.Contains(m.text, "http") {
			t.Errorf("%q has an image or a link; mails carry no tracking:\n%s", m.subject, m.html)
		}
	}
}

// Accounts from before email keep working: they sign in and are asked for an
// address, and their files wait until it is verified.
func TestMigrationKeepsUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	old, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
			password_hash TEXT NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE TABLE sessions (token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL)`,
		`CREATE TABLE files (key TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
			size INTEGER NOT NULL, created_at INTEGER NOT NULL, confirmed_at INTEGER NOT NULL DEFAULT 0, replaces TEXT NOT NULL DEFAULT '')`,
	} {
		if _, err := old.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for i, name := range []string{"one", "two", "three", "four"} {
		if _, err := old.Exec(`INSERT INTO users (id, username, password_hash, created_at) VALUES (?, ?, 'x', 0)`, i+1, name); err != nil {
			t.Fatal(err)
		}
	}
	old.Close()

	db, err := openDB(path)
	if err != nil {
		t.Fatalf("open old database: %v", err)
	}
	have, err := columnsOf(db, "users")
	if err != nil || !have["email"] || !have["pending_email"] {
		t.Fatalf("columns after migration: %v, %v", have, err)
	}
	var n, maxID int
	if err := db.QueryRow(`SELECT COUNT(*), MAX(id) FROM users WHERE email IS NULL`).Scan(&n, &maxID); err != nil || n != 4 || maxID != 4 {
		t.Errorf("users after migration: %d (max id %d), err %v; want the 4 kept", n, maxID, err)
	}
	db.Close()
	// Reopening an already-migrated database is a no-op.
	db, err = openDB(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	db.Close()

	// Now the same through the app: an account with no address.
	s, h := newTestServer(t, testConfig(testEndpoint))
	c := legacyUser(t, h, "alice")
	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if me.Verified || me.Email != "" {
		t.Errorf("me for an account without an address = %+v", me)
	}
	if rec := do(t, h, http.MethodGet, "/download-url?key=x", "", withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("files without an address: status %d, want 403", rec.Code)
	}
	// Adding the first address needs no password (the session is fresh).
	if rec := do(t, h, http.MethodPost, "/auth/email", `{"email":"alice2@example.test"}`, withCookie(c)); rec.Code != http.StatusAccepted {
		t.Fatalf("add address: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodPost, "/auth/email/verify", verifyBody(s.lastCode(t, "alice2@example.test")), withCookie(c)); rec.Code != http.StatusOK {
		t.Fatalf("verify added address: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := do(t, h, http.MethodGet, "/download-url?key=x", "", withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("files after verifying: status %d, want 400 (bad key)", rec.Code)
	}
}
