package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
)

const (
	sessionCookie  = "session"
	sessionTTL     = 30 * 24 * time.Hour
	minPasswordLen = 8
	maxPasswordLen = 72 // bcrypt ignores everything past 72 bytes, so refuse it
	bcryptCost     = 12
)

var usernamePattern = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

// dummyHash is compared against when a login names an unknown user, so that a
// wrong username takes as long as a wrong password and the response time does
// not reveal which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcryptCost)

type user struct {
	id       int64
	username string
}

type userKey struct{}

func userFrom(r *http.Request) user {
	return r.Context().Value(userKey{}).(user)
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// readCredentials decodes and validates a sign-up or sign-in body, writing a
// 400 and returning false when it is unusable.
func readCredentials(w http.ResponseWriter, r *http.Request) (loginRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var c loginRequest
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, `body must be JSON like {"username":"...","password":"..."}`)
		return c, false
	}
	c.Username = strings.ToLower(strings.TrimSpace(c.Username))
	if !usernamePattern.MatchString(c.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-32 characters: letters, digits, _ or -")
		return c, false
	}
	if len(c.Password) < minPasswordLen || len(c.Password) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be 8-72 characters")
		return c, false
	}
	return c, true
}

func (s *server) handleSignup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	c, ok := readCredentials(w, r)
	if !ok {
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(c.Password), bcryptCost)
	if err != nil {
		log.Printf("hash password: %v", err)
		writeError(w, http.StatusInternalServerError, "could not create the account")
		return
	}

	id, status, msg := s.createUser(r.Context(), c.Username, string(hash))
	if status != 0 {
		writeError(w, status, msg)
		return
	}
	if !s.startSession(w, r, id) {
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"username": c.Username})
}

// createUser inserts the account, or returns an HTTP status and message saying
// why it can't. The checks and the insert share one transaction, which the
// single DB connection makes atomic.
func (s *server) createUser(ctx context.Context, username, hash string) (int64, int, string) {
	fail := func(err error) (int64, int, string) {
		log.Printf("create user %q: %v", username, err)
		return 0, http.StatusInternalServerError, "could not create the account"
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fail(err)
	}
	defer tx.Rollback()

	if s.cfg.maxUsers > 0 {
		var n int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users`).Scan(&n); err != nil {
			return fail(err)
		}
		if n >= s.cfg.maxUsers {
			return 0, http.StatusForbidden, "sign-up is closed: the user limit has been reached"
		}
	}

	var taken bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE username = ?)`, username).Scan(&taken); err != nil {
		return fail(err)
	}
	if taken {
		return 0, http.StatusConflict, "that username is taken"
	}

	res, err := tx.ExecContext(ctx,
		`INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)`,
		username, hash, time.Now().Unix())
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

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	c, ok := readCredentials(w, r)
	if !ok {
		// A malformed body says nothing about whether the account exists, so
		// the specific validation message is fine here.
		return
	}

	var (
		id   int64
		hash string
	)
	err := s.db.QueryRowContext(r.Context(),
		`SELECT id, password_hash FROM users WHERE username = ?`, c.Username).Scan(&id, &hash)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(c.Password)) // only spent for its timing
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	case err != nil:
		log.Printf("look up user %q: %v", c.Username, err)
		writeError(w, http.StatusInternalServerError, "could not sign in")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(c.Password)) != nil {
		writeError(w, http.StatusUnauthorized, "wrong username or password")
		return
	}

	if !s.startSession(w, r, id) {
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"username": c.Username})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM sessions WHERE token_hash = ?`, hashToken(c.Value)); err != nil {
			log.Printf("delete session: %v", err)
		}
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

type meResponse struct {
	Username   string `json:"username"`
	UsedBytes  int64  `json:"usedBytes"`
	QuotaBytes int64  `json:"quotaBytes"`
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	u := userFrom(r)
	used, err := s.usedBytes(r.Context(), s.db, u.id)
	if err != nil {
		log.Printf("usage for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not read storage usage")
		return
	}
	writeJSON(w, http.StatusOK, meResponse{Username: u.username, UsedBytes: used, QuotaBytes: s.cfg.quotaBytes})
}

// startSession stores a new session for userID and sets its cookie. Only a
// hash of the token is stored, so a leaked database cannot be replayed as
// cookies. It writes a 500 and returns false on failure.
func (s *server) startSession(w http.ResponseWriter, r *http.Request, userID int64) bool {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		log.Printf("session token: %v", err)
		writeError(w, http.StatusInternalServerError, "could not start a session")
		return false
	}
	token := base64.RawURLEncoding.EncodeToString(buf)
	now := time.Now()

	ctx := r.Context()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, now.Unix()); err != nil {
		log.Printf("expire sessions: %v", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)`,
		hashToken(token), userID, now.Add(sessionTTL).Unix()); err != nil {
		log.Printf("insert session: %v", err)
		writeError(w, http.StatusInternalServerError, "could not start a session")
		return false
	}

	http.SetCookie(w, s.sessionCookie(token, int(sessionTTL/time.Second)))
	return true
}

func (s *server) sessionCookie(value string, maxAge int) *http.Cookie {
	// Secure is on unless COOKIE_SECURE=false, which exists only so the app
	// can be tried over plain HTTP in browsers that refuse Secure cookies on
	// localhost. HttpOnly and SameSite are fixed.
	return &http.Cookie{ // #nosec G124 -- Secure is configurable on purpose, see above
		Name:     sessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.cfg.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	}
}

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// requireUser rejects requests without a live session and puts the signed-in
// user in the request context for next.
func (s *server) requireUser(next http.HandlerFunc) http.Handler {
	return s.sameOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(sessionCookie)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		var u user
		err = s.db.QueryRowContext(r.Context(), `
			SELECT u.id, u.username FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = ? AND s.expires_at > ?`,
			hashToken(c.Value), time.Now().Unix()).Scan(&u.id, &u.username)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			http.SetCookie(w, s.sessionCookie("", -1))
			writeError(w, http.StatusUnauthorized, "your session has expired; sign in again")
			return
		case err != nil:
			log.Printf("look up session: %v", err)
			writeError(w, http.StatusInternalServerError, "could not check the session")
			return
		}
		next(w, r.WithContext(context.WithValue(r.Context(), userKey{}, u)))
	}))
}

// sameOrigin blocks cross-site requests that change state. SameSite=Lax
// already keeps the cookie off cross-site POSTs; checking Origin as well covers
// older browsers and same-site subdomains. Requests without an Origin header
// (curl, scripts) carry no ambient cookie and are let through.
func (s *server) sameOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host {
					writeError(w, http.StatusForbidden, "cross-origin request refused")
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ipLimiter is a per-client-IP token bucket for the sign-in and sign-up
// endpoints, which are the ones worth guessing passwords against.
type ipLimiter struct {
	mu        sync.Mutex
	every     time.Duration
	burst     int
	clients   map[string]*limiterEntry
	lastSweep time.Time
}

type limiterEntry struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newIPLimiter(every time.Duration, burst int) *ipLimiter {
	return &ipLimiter{every: every, burst: burst, clients: map[string]*limiterEntry{}}
}

func (l *ipLimiter) allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	// An idle entry has refilled completely, so forgetting it changes nothing.
	if now.Sub(l.lastSweep) > time.Minute {
		full := l.every * time.Duration(l.burst)
		for k, e := range l.clients {
			if now.Sub(e.seen) > full {
				delete(l.clients, k)
			}
		}
		l.lastSweep = now
	}

	e, ok := l.clients[ip]
	if !ok {
		e = &limiterEntry{limiter: rate.NewLimiter(rate.Every(l.every), l.burst)}
		l.clients[ip] = e
	}
	e.seen = now
	return e.limiter.Allow()
}

func (s *server) rateLimited(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.limiter.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(s.limiter.every/time.Second)))
			writeError(w, http.StatusTooManyRequests, "too many attempts; wait a moment and try again")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// clientIP is the peer address, or, behind a reverse proxy that is trusted via
// TRUST_PROXY, the address that proxy appended to X-Forwarded-For. Only the
// last entry is used: earlier ones are whatever the client chose to send.
func (s *server) clientIP(r *http.Request) string {
	if s.cfg.trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
