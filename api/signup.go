package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Sign-up happens in two steps. POST /auth/signup only stores a pending
// request (username, password hash, address, code hash) and mails the code;
// no account exists yet. POST /auth/signup/verify with the right code creates
// the account, already verified, and signs it in. A pending request is found
// through its own HttpOnly cookie, scoped to /auth/signup, holding a random
// token whose hash is the row's key. Until the code is entered the username
// is not reserved: whoever confirms first gets it.
const (
	signupCookieName = "signup"
	signupTTL        = time.Hour // a pending request lives this long; each code codeTTL
	mailSendTimeout  = 30 * time.Second
)

var errNoSignup = errors.New("no pending sign-up")

type pendingSignup struct {
	tokenHash    string
	username     string
	passwordHash string
	email        string
	codeHash     string // "" when the address belongs to an account: no code was sent
	expiresAt    int64
	tries        int
	coupon       bool // came with the right coupon: the account starts on corpo
}

func (s *server) signupCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{ // #nosec G124 -- Secure is configurable on purpose, see sessionCookie
		Name:     signupCookieName,
		Value:    value,
		Path:     "/auth/signup",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

// sendMailNow sends m and waits for the answer, so a refused address can be
// reported to the person who typed it. Only used where the answer doesn't
// depend on whether an account exists.
func (s *server) sendMailNow(ctx context.Context, m message) error {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), mailSendTimeout)
	defer cancel()
	err := s.mailer.send(ctx, m)
	if err != nil {
		log.Printf("send mail (%s): %v", m.subject, err)
	}
	return err
}

// reserveSignupMail counts a sign-up mail against the address's hourly limit,
// or returns errMailLimit when the last hour already holds mailsPerHour.
func (s *server) reserveSignupMail(ctx context.Context, email string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM signup_mail WHERE sent_at <= ?`, now-3600); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM signup_mail WHERE email = ?`, email).Scan(&n); err != nil {
		return err
	}
	if n >= mailsPerHour {
		return errMailLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO signup_mail (email, sent_at) VALUES (?, ?)`, email, now); err != nil {
		return err
	}
	return tx.Commit()
}

// signupMail builds the mail for a sign-up to email, and the hash of the code
// in it. If a verified account already owns the address, the mail is a
// notice with no code and the hash is "": the caller answers the same either
// way, so sign-up doesn't reveal which addresses are in use.
func (s *server) signupMail(ctx context.Context, username, email string) (string, message, error) {
	var taken bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? COLLATE NOCASE)`, email).Scan(&taken); err != nil {
		return "", message{}, err
	}
	if taken {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(email)) // as long as hashing a code
		return "", inUseMessage(email), nil
	}
	code, err := newCode()
	if err != nil {
		return "", message{}, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
	if err != nil {
		return "", message{}, err
	}
	return string(hash), verifyMessage(email, username, code), nil
}

// loadSignup returns the live pending sign-up named by the request's signup
// cookie, or errNoSignup.
func (s *server) loadSignup(r *http.Request) (pendingSignup, error) {
	c, err := r.Cookie(signupCookieName)
	if err != nil || c.Value == "" {
		return pendingSignup{}, errNoSignup
	}
	p := pendingSignup{tokenHash: hashToken(c.Value)}
	err = s.db.QueryRowContext(r.Context(), `
		SELECT username, password_hash, email, code_hash, expires_at, tries, coupon FROM signups
		WHERE token_hash = ? AND created_at > ?`, p.tokenHash, time.Now().Add(-signupTTL).Unix()).
		Scan(&p.username, &p.passwordHash, &p.email, &p.codeHash, &p.expiresAt, &p.tries, &p.coupon)
	if errors.Is(err, sql.ErrNoRows) {
		return pendingSignup{}, errNoSignup
	}
	return p, err
}

// handleSignup: POST /auth/signup {"username","password","email"}. Stores a
// pending sign-up and mails its code; the account is created by
// handleSignupVerify. Answers 202 {"username","pendingEmail"}.
func (s *server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	c, ok := readCredentials(w, r, false)
	if !ok {
		return
	}
	email, err := normalizeEmail(c.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// A coupon is optional; a wrong one is refused before any mail goes out.
	coupon := strings.TrimSpace(c.Coupon) != ""
	if coupon && !s.couponMatches(c.Coupon) {
		writeError(w, http.StatusBadRequest, "that coupon code isn't valid; check it, or leave it empty")
		return
	}
	ctx := r.Context()
	fail := func(err error) {
		log.Printf("sign-up %q: %v", c.Username, err)
		writeError(w, http.StatusInternalServerError, "could not start the sign-up")
	}

	// Checked again when the code is entered; this only saves a mail.
	if status, msg, err := s.canCreate(ctx, s.db, c.Username); err != nil {
		fail(err)
		return
	} else if status != 0 {
		writeError(w, status, msg)
		return
	}
	switch err := s.reserveSignupMail(ctx, email); {
	case errors.Is(err, errMailLimit):
		writeError(w, http.StatusTooManyRequests, "that address has had 3 codes in the last hour; wait a while and try again")
		return
	case err != nil:
		fail(err)
		return
	}

	pwHash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcryptCost)
	if err != nil {
		fail(err)
		return
	}
	codeHash, msg, err := s.signupMail(ctx, c.Username, email)
	if err != nil {
		fail(err)
		return
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		fail(err)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now()

	// Drop requests past their life, and this browser's earlier one.
	if _, err := s.db.ExecContext(ctx, `DELETE FROM signups WHERE created_at <= ?`, now.Add(-signupTTL).Unix()); err != nil {
		log.Printf("expire sign-ups: %v", err)
	}
	if old, err := r.Cookie(signupCookieName); err == nil {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM signups WHERE token_hash = ?`, hashToken(old.Value)); err != nil {
			log.Printf("drop earlier sign-up: %v", err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `
		INSERT INTO signups (token_hash, username, password_hash, email, code_hash, expires_at, tries, created_at, coupon)
		VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		hashToken(token), c.Username, string(pwHash), email, codeHash, now.Add(codeTTL).Unix(), now.Unix(), coupon); err != nil {
		fail(err)
		return
	}

	if err := s.sendMailNow(ctx, msg); err != nil {
		if _, err := s.db.ExecContext(ctx, `DELETE FROM signups WHERE token_hash = ?`, hashToken(token)); err != nil {
			log.Printf("drop unsent sign-up: %v", err)
		}
		writeError(w, http.StatusBadGateway, "could not send the code to that address; check it and try again")
		return
	}
	http.SetCookie(w, s.signupCookie(token, int(signupTTL/time.Second)))
	writeJSON(w, http.StatusAccepted, map[string]string{"username": c.Username, "pendingEmail": email})
}

// handleSignupPending: GET /auth/signup/pending. Lets the page pick up a
// sign-up waiting for its code after a reload: 200 {"username","pendingEmail"}
// or 404.
func (s *server) handleSignupPending(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	p, err := s.loadSignup(r)
	switch {
	case errors.Is(err, errNoSignup):
		writeError(w, http.StatusNotFound, "no sign-up is waiting for a code")
		return
	case err != nil:
		log.Printf("load sign-up: %v", err)
		writeError(w, http.StatusInternalServerError, "could not read the sign-up")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": p.username, "pendingEmail": p.email})
}

// handleSignupVerify: POST /auth/signup/verify {"code"}. The right code
// creates the account with its address already verified, signs it in and
// answers 201 {"username"}. 410 means there is no pending sign-up (any more).
func (s *server) handleSignupVerify(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body, `{"code":"123456"}`) {
		return
	}
	code := strings.TrimSpace(body.Code)
	if !codePattern.MatchString(code) {
		writeError(w, http.StatusBadRequest, "the code is 6 digits")
		return
	}
	ctx := r.Context()
	p, err := s.loadSignup(r)
	switch {
	case errors.Is(err, errNoSignup):
		writeError(w, http.StatusGone, "this sign-up has expired; please sign up again")
		return
	case err != nil:
		log.Printf("load sign-up: %v", err)
		writeError(w, http.StatusInternalServerError, "could not check the code")
		return
	}
	if time.Now().Unix() >= p.expiresAt || p.tries >= codeTries {
		writeError(w, http.StatusBadRequest, genericCodeFail)
		return
	}
	// The try is counted before comparing, so parallel guesses can't share one.
	if _, err := s.db.ExecContext(ctx, `UPDATE signups SET tries = tries + 1 WHERE token_hash = ?`, p.tokenHash); err != nil {
		log.Printf("count code try: %v", err)
		writeError(w, http.StatusInternalServerError, "could not check the code")
		return
	}
	hash := []byte(p.codeHash)
	if p.codeHash == "" {
		hash = dummyHash() // no code was sent; nothing can match
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(code)) != nil || p.codeHash == "" {
		writeError(w, http.StatusBadRequest, genericCodeFail)
		return
	}

	id, status, msg := s.createUser(ctx, p.username, p.passwordHash, p.email, p.coupon)
	if status != 0 {
		// Someone confirmed the same username or address first, or sign-up
		// closed meanwhile. This request can't succeed, so it goes.
		if status != http.StatusInternalServerError {
			s.dropSignup(ctx, w, p.tokenHash)
		}
		writeError(w, status, msg)
		return
	}
	s.dropSignup(ctx, w, p.tokenHash)
	if !s.startSession(w, r, id) {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": p.username})
}

// handleSignupResend: POST /auth/signup/resend. Mails a new code for the
// pending sign-up, replacing the old one. Answers 202 {"pendingEmail"}.
func (s *server) handleSignupResend(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	ctx := r.Context()
	p, err := s.loadSignup(r)
	switch {
	case errors.Is(err, errNoSignup):
		writeError(w, http.StatusGone, "this sign-up has expired; please sign up again")
		return
	case err != nil:
		log.Printf("load sign-up: %v", err)
		writeError(w, http.StatusInternalServerError, "could not send a new code")
		return
	}
	switch err := s.reserveSignupMail(ctx, p.email); {
	case errors.Is(err, errMailLimit):
		writeError(w, http.StatusTooManyRequests, "that address has had 3 codes in the last hour; wait a while and try again")
		return
	case err != nil:
		log.Printf("resend sign-up code: %v", err)
		writeError(w, http.StatusInternalServerError, "could not send a new code")
		return
	}
	codeHash, msg, err := s.signupMail(ctx, p.username, p.email)
	if err != nil {
		log.Printf("resend sign-up code: %v", err)
		writeError(w, http.StatusInternalServerError, "could not send a new code")
		return
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE signups SET code_hash = ?, expires_at = ?, tries = 0 WHERE token_hash = ?`,
		codeHash, time.Now().Add(codeTTL).Unix(), p.tokenHash); err != nil {
		log.Printf("resend sign-up code: %v", err)
		writeError(w, http.StatusInternalServerError, "could not send a new code")
		return
	}
	if err := s.sendMailNow(ctx, msg); err != nil {
		writeError(w, http.StatusBadGateway, "could not send the code to that address; sign up again with another")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"pendingEmail": p.email})
}

// dropSignup deletes a pending sign-up and clears its cookie.
func (s *server) dropSignup(ctx context.Context, w http.ResponseWriter, tokenHash string) {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM signups WHERE token_hash = ?`, tokenHash); err != nil {
		log.Printf("drop sign-up: %v", err)
	}
	http.SetCookie(w, s.signupCookie("", -1))
}

// canCreate says whether an account named username could be created now: 0,
// or an HTTP status and message saying why not.
func (s *server) canCreate(ctx context.Context, q rowQuerier, username string) (int, string, error) {
	if s.cfg.maxUsers > 0 {
		var n int
		if err := q.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return 0, "", err
		}
		if n >= s.cfg.maxUsers {
			return http.StatusForbidden, "sign-up is closed: the user limit has been reached", nil
		}
	}
	var taken bool
	if err := q.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`, username).Scan(&taken); err != nil {
		return 0, "", err
	}
	if taken {
		return http.StatusConflict, "that username is taken", nil
	}
	return 0, "", nil
}

// createUser inserts a verified account, or returns an HTTP status and
// message saying why it can't. The checks and the insert share one
// transaction, which the single DB connection makes atomic.
func (s *server) createUser(ctx context.Context, username, pwHash, email string, coupon bool) (int64, int, string) {
	fail := func(err error) (int64, int, string) {
		log.Printf("create user %q: %v", username, err)
		return 0, http.StatusInternalServerError, "could not create the account"
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()

	status, msg, err := s.canCreate(ctx, tx, username)
	if err != nil {
		return fail(err)
	}
	if status != 0 {
		return 0, status, msg
	}
	var taken bool
	if err := tx.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? COLLATE NOCASE)`, email).Scan(&taken); err != nil {
		return fail(err)
	}
	if taken {
		// Only reachable by someone who just proved they own the address.
		return 0, http.StatusConflict, "that address already belongs to another account; sign in to that one or use another address"
	}
	plan, couponAt := planFree, int64(0)
	if coupon {
		plan, couponAt = planCorpo, time.Now().Unix()
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at, email, plan, coupon_at) VALUES (?, ?, ?, ?, ?, ?)`,
		username, pwHash, time.Now().Unix(), email, plan, couponAt)
	if err != nil {
		return fail(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return fail(err)
	}
	if err := tx.Commit(); err != nil {
		return fail(err)
	}
	return id, 0, ""
}
