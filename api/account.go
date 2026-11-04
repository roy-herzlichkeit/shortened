package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	codeTTL         = 10 * time.Minute
	codeTries       = 5
	mailsPerHour    = 3
	purposeVerify   = "verify" // confirms pending_email
	purposeReset    = "reset"  // password reset, sent to the verified email
	genericCodeFail = "that code is wrong or has expired; ask for a new one"
)

var (
	codePattern  = regexp.MustCompile(`^[0-9]{6}$`)
	errMailLimit = errors.New("mail limit reached")
)

// readJSON decodes a small JSON body into v, writing a 400 on failure.
func readJSON(w http.ResponseWriter, r *http.Request, v any, example string) bool {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON like "+example)
		return false
	}
	return true
}

func validPassword(p string) bool {
	return len(p) >= minPasswordLen && len(p) <= maxPasswordLen
}

// newCode returns six random digits, uniform over 000000-999999.
func newCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

// reserveMail counts a mail against the account's hourly limit, or returns
// errMailLimit when the last hour already holds mailsPerHour of them.
func (s *server) reserveMail(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM mail_log WHERE sent_at <= ?`, now-3600); err != nil {
		return err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM mail_log WHERE user_id = ?`, userID).Scan(&n); err != nil {
		return err
	}
	if n >= mailsPerHour {
		return errMailLimit
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO mail_log (user_id, sent_at) VALUES (?, ?)`, userID, now); err != nil {
		return err
	}
	return tx.Commit()
}

// issueCode stores a fresh code for (user, purpose), replacing any earlier
// one, and returns it. Only its bcrypt hash is kept.
func (s *server) issueCode(ctx context.Context, userID int64, purpose, target string) (string, error) {
	code, err := newCode()
	if err != nil {
		return "", err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcryptCost)
	if err != nil {
		return "", err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO otps (user_id, purpose, target, code_hash, expires_at, tries) VALUES (?, ?, ?, ?, ?, 0)
		ON CONFLICT (user_id, purpose) DO UPDATE SET
			target = excluded.target, code_hash = excluded.code_hash,
			expires_at = excluded.expires_at, tries = 0`,
		userID, purpose, target, string(hash), time.Now().Add(codeTTL).Unix())
	return code, err
}

// checkCode spends one try on the user's code for purpose. It returns the
// address the code was sent to when the code is right; a right code is used
// up. After codeTries wrong tries, or once expired, the code is gone.
func (s *server) checkCode(ctx context.Context, userID int64, purpose, code string) (string, bool, error) {
	var (
		target, hash string
		expires      int64
		tries        int
	)
	err := s.db.QueryRowContext(ctx,
		`SELECT target, code_hash, expires_at, tries FROM otps WHERE user_id = ? AND purpose = ?`,
		userID, purpose).Scan(&target, &hash, &expires, &tries)
	if errors.Is(err, sql.ErrNoRows) {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(code)) // same timing as a real check
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if time.Now().Unix() >= expires || tries >= codeTries {
		_, err := s.db.ExecContext(ctx, `DELETE FROM otps WHERE user_id = ? AND purpose = ?`, userID, purpose)
		return "", false, err
	}
	// The try is counted before comparing, so parallel guesses can't share one.
	if _, err := s.db.ExecContext(ctx,
		`UPDATE otps SET tries = tries + 1 WHERE user_id = ? AND purpose = ?`, userID, purpose); err != nil {
		return "", false, err
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(code)) != nil {
		return "", false, nil
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM otps WHERE user_id = ? AND purpose = ?`, userID, purpose)
	return target, err == nil, err
}

// sendVerifyCode starts verification of email for u: it records email as
// pending and mails a code to it. If a verified account already owns the
// address, that address gets a notice instead of a code; the caller answers
// the same either way. It returns errMailLimit past the hourly limit.
func (s *server) sendVerifyCode(ctx context.Context, u user, email string) error {
	var taken bool
	if err := s.db.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?)`, email, u.id).Scan(&taken); err != nil {
		return err
	}
	if err := s.reserveMail(ctx, u.id); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE users SET pending_email = ? WHERE id = ?`, email, u.id); err != nil {
		return err
	}
	if taken {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(email)) // as long as hashing a code
		s.sendMail(inUseMessage(email))
		return nil
	}
	code, err := s.issueCode(ctx, u.id, purposeVerify, email)
	if err != nil {
		return err
	}
	s.sendMail(verifyMessage(email, u.username, code))
	return nil
}

// handleSetEmail: POST /auth/email {"email","password"}. Adds an address (an
// account without one), sends a new code (the pending one), or changes the
// verified address, which needs the password too. The new address counts
// only once its code is entered.
func (s *server) handleSetEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body, `{"email":"...","password":"..."}`) {
		return
	}
	u := userFrom(r)
	email, err := normalizeEmail(body.Email)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if u.email != "" {
		if email == u.email {
			writeError(w, http.StatusBadRequest, "that is already your address")
			return
		}
		if !s.passwordMatches(r.Context(), u.id, body.Password) {
			writeError(w, http.StatusForbidden, "enter your current password to change the address")
			return
		}
	}
	switch err := s.sendVerifyCode(r.Context(), u, email); {
	case errors.Is(err, errMailLimit):
		writeError(w, http.StatusTooManyRequests, "you have asked for 3 codes in the last hour; wait a while and try again")
		return
	case err != nil:
		log.Printf("set email for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not send the code")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"pendingEmail": email})
}

// handleVerifyEmail: POST /auth/email/verify {"code"}. A right code makes the
// pending address the account's verified one.
func (s *server) handleVerifyEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body, `{"code":"123456"}`) {
		return
	}
	u := userFrom(r)
	code := strings.TrimSpace(body.Code)
	if u.pendingEmail == "" {
		writeError(w, http.StatusBadRequest, "no address is waiting for a code; enter your address first")
		return
	}
	if !codePattern.MatchString(code) {
		writeError(w, http.StatusBadRequest, "the code is 6 digits")
		return
	}
	target, ok, err := s.checkCode(r.Context(), u.id, purposeVerify, code)
	if err != nil {
		log.Printf("check code for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not check the code")
		return
	}
	if !ok || target != u.pendingEmail {
		writeError(w, http.StatusBadRequest, genericCodeFail)
		return
	}

	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		log.Printf("verify email: %v", err)
		writeError(w, http.StatusInternalServerError, "could not save the address")
		return
	}
	defer tx.Rollback()
	var taken bool
	if err := tx.QueryRowContext(r.Context(),
		`SELECT EXISTS(SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id != ?)`, target, u.id).Scan(&taken); err != nil {
		log.Printf("verify email: %v", err)
		writeError(w, http.StatusInternalServerError, "could not save the address")
		return
	}
	if taken {
		// Only reachable by someone who just proved they own the address.
		writeError(w, http.StatusConflict, "that address already belongs to another account; sign in to that one or use another address")
		return
	}
	if _, err := tx.ExecContext(r.Context(),
		`UPDATE users SET email = ?, pending_email = NULL WHERE id = ?`, target, u.id); err != nil {
		log.Printf("verify email: %v", err)
		writeError(w, http.StatusInternalServerError, "could not save the address")
		return
	}
	if err := tx.Commit(); err != nil {
		log.Printf("verify email: %v", err)
		writeError(w, http.StatusInternalServerError, "could not save the address")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": target})
}

// accountByLogin finds an account by username or, if login holds an "@", by
// its verified address. found is false when there is none.
func (s *server) accountByLogin(ctx context.Context, login string) (u user, hash string, found bool, err error) {
	login = strings.ToLower(strings.TrimSpace(login))
	var email sql.NullString
	q := `SELECT id, username, password_hash, email FROM users WHERE username = ?`
	if strings.Contains(login, "@") {
		q = `SELECT id, username, password_hash, email FROM users WHERE email = ? COLLATE NOCASE`
	}
	err = s.db.QueryRowContext(ctx, q, login).Scan(&u.id, &u.username, &hash, &email)
	if errors.Is(err, sql.ErrNoRows) {
		return user{}, "", false, nil
	}
	if err != nil {
		return user{}, "", false, err
	}
	u.email = email.String
	return u, hash, true, nil
}

func (s *server) passwordMatches(ctx context.Context, userID int64, password string) bool {
	var hash string
	if err := s.db.QueryRowContext(ctx, `SELECT password_hash FROM users WHERE id = ?`, userID).Scan(&hash); err != nil {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) == nil
}

const forgotAnswer = "If an account with a verified address matches, a code is on its way. It works for 10 minutes."

// handleForgot: POST /auth/forgot {"login"}. Mails a reset code to the
// account's verified address. The answer is the same whether or not the
// account exists, has an address, or is over its mail limit, and the mail is
// sent in the background, so neither the text nor the timing tells.
func (s *server) handleForgot(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Login string `json:"login"`
	}
	if !readJSON(w, r, &body, `{"login":"username or email"}`) {
		return
	}
	if strings.TrimSpace(body.Login) == "" {
		writeError(w, http.StatusBadRequest, "enter your username or email address")
		return
	}
	u, _, found, err := s.accountByLogin(r.Context(), body.Login)
	if err != nil {
		log.Printf("forgot: %v", err)
	}
	if !found || u.email == "" || err != nil {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(body.Login)) // as long as hashing a code
		writeJSON(w, http.StatusAccepted, map[string]string{"message": forgotAnswer})
		return
	}
	switch err := s.reserveMail(r.Context(), u.id); {
	case errors.Is(err, errMailLimit):
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(body.Login))
	case err != nil:
		log.Printf("forgot for user %d: %v", u.id, err)
	default:
		code, err := s.issueCode(r.Context(), u.id, purposeReset, u.email)
		if err != nil {
			log.Printf("forgot for user %d: %v", u.id, err)
			break
		}
		s.sendMail(resetMessage(u.email, u.username, code))
	}
	writeJSON(w, http.StatusAccepted, map[string]string{"message": forgotAnswer})
}

// handleReset: POST /auth/reset {"login","code","password"}. A right code
// sets the new password, ends every session of the account, and signs this
// browser in.
func (s *server) handleReset(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Login    string `json:"login"`
		Code     string `json:"code"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body, `{"login":"...","code":"123456","password":"..."}`) {
		return
	}
	code := strings.TrimSpace(body.Code)
	if !codePattern.MatchString(code) {
		writeError(w, http.StatusBadRequest, "the code is 6 digits")
		return
	}
	if !validPassword(body.Password) {
		writeError(w, http.StatusBadRequest, "password must be 8-72 characters")
		return
	}
	u, _, found, err := s.accountByLogin(r.Context(), body.Login)
	if err != nil {
		log.Printf("reset: %v", err)
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	if !found {
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(code))
		writeError(w, http.StatusBadRequest, genericCodeFail)
		return
	}
	target, ok, err := s.checkCode(r.Context(), u.id, purposeReset, code)
	if err != nil {
		log.Printf("reset for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	// A code mailed to an address the account no longer has is void.
	if !ok || u.email == "" || target != u.email {
		writeError(w, http.StatusBadRequest, genericCodeFail)
		return
	}
	if err := s.setPassword(r.Context(), u.id, body.Password, ""); err != nil {
		log.Printf("reset for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not reset the password")
		return
	}
	if !s.startSession(w, r, u.id) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": u.username})
}

// handleChangePassword: POST /auth/password {"current","password"}. Ends every
// other session; this one stays signed in.
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !readJSON(w, r, &body, `{"current":"...","password":"..."}`) {
		return
	}
	u := userFrom(r)
	if !validPassword(body.Password) {
		writeError(w, http.StatusBadRequest, "the new password must be 8-72 characters")
		return
	}
	// 403, not 401: the session is fine, and 401 would sign the page out.
	if !s.passwordMatches(r.Context(), u.id, body.Current) {
		writeError(w, http.StatusForbidden, "your current password is wrong")
		return
	}
	keep := ""
	if c, err := r.Cookie(sessionCookie); err == nil {
		keep = hashToken(c.Value)
	}
	if err := s.setPassword(r.Context(), u.id, body.Password, keep); err != nil {
		log.Printf("change password for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not change the password")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// setPassword stores a new password and ends every session of the account
// except keep (a token hash, or "" for none). Any reset code goes too.
func (s *server) setPassword(ctx context.Context, userID int64, password, keep string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE users SET password_hash = ? WHERE id = ?`, []any{string(hash), userID}},
		{`DELETE FROM sessions WHERE user_id = ? AND token_hash != ?`, []any{userID, keep}},
		{`DELETE FROM otps WHERE user_id = ? AND purpose = ?`, []any{userID, purposeReset}},
	} {
		if _, err := tx.ExecContext(ctx, q.sql, q.args...); err != nil {
			return err
		}
	}
	return tx.Commit()
}
