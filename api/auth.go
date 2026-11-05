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
)

// bcryptCost is a variable only so tests can drop it to bcrypt.MinCost; under
// the race detector cost 12 makes each hash take seconds.
var bcryptCost = 12

var usernamePattern = regexp.MustCompile(`^[a-z0-9_-]{3,32}$`)

// dummyHash is compared against when a login names an unknown user, so that a
// wrong username takes as long as a wrong password and the response time does
// not reveal which usernames exist. It is built on first use so it picks up
// the cost in effect then.
var dummyHash = sync.OnceValue(func() []byte {
	h, err := bcrypt.GenerateFromPassword([]byte("not-a-real-password"), bcryptCost)
	if err != nil {
		panic(err) // only fails for an invalid cost, which is a programming error
	}
	return h
})

type user struct {
	id           int64
	username     string
	email        string // verified address, "" if none yet
	pendingEmail string // address waiting for its code
	plan         string // free or corpo
	couponAt     int64  // when the coupon was used, 0 if never
}

type userKey struct{}

func userFrom(r *http.Request) user {
	return r.Context().Value(userKey{}).(user)
}

type loginRequest struct {
	Username string `json:"username"` // sign-in also takes the verified email here
	Password string `json:"password"`
	Email    string `json:"email"`  // sign-up only
	Coupon   string `json:"coupon"` // sign-up only, optional
}

// readCredentials decodes and validates a sign-up or sign-in body, writing a
// 400 and returning false when it is unusable. Sign-in accepts an email
// address in place of the username.
func readCredentials(w http.ResponseWriter, r *http.Request, signin bool) (loginRequest, bool) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var c loginRequest
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		writeError(w, http.StatusBadRequest, `body must be JSON like {"username":"...","password":"..."}`)
		return c, false
	}
	c.Username = strings.ToLower(strings.TrimSpace(c.Username))
	if signin && strings.Contains(c.Username, "@") {
		if _, err := normalizeEmail(c.Username); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return c, false
		}
	} else if !usernamePattern.MatchString(c.Username) {
		writeError(w, http.StatusBadRequest, "username must be 3-32 characters: letters, digits, _ or -")
		return c, false
	}
	if len(c.Password) < minPasswordLen || len(c.Password) > maxPasswordLen {
		writeError(w, http.StatusBadRequest, "password must be 8-72 characters")
		return c, false
	}
	return c, true
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	c, ok := readCredentials(w, r, true)
	if !ok {
		// A malformed body says nothing about whether the account exists, so
		// the specific validation message is fine here.
		return
	}

	u, hash, found, err := s.accountByLogin(r.Context(), c.Username)
	id := u.id
	switch {
	case err == nil && !found:
		_ = bcrypt.CompareHashAndPassword(dummyHash(), []byte(c.Password)) // only spent for its timing
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
	writeJSON(w, http.StatusOK, map[string]string{"username": u.username})
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
	Username      string `json:"username"`
	Email         string `json:"email"`         // verified, "" if none
	PendingEmail  string `json:"pendingEmail"`  // waiting for its code
	Verified      bool   `json:"verified"`      // files need this
	UsedBytes     int64  `json:"usedBytes"`     // stored + reserved, what the quota counts
	StoredBytes   int64  `json:"storedBytes"`   // confirmed in the bucket
	ReservedBytes int64  `json:"reservedBytes"` // upload links not yet confirmed
	QuotaBytes    int64  `json:"quotaBytes"`    // from the plan
	Plan          string `json:"plan"`          // free or corpo
	CouponUsed    bool   `json:"couponUsed"`    // the coupon can't be used again
	ShareMaxSecs  int64  `json:"shareMaxSeconds"`
	MaxFileBytes  int64  `json:"maxFileBytes"` // the largest single upload
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	u := userFrom(r)
	// The meter should match the bucket: check the ledger against it first
	// (at most every syncEvery), so a file removed outside the app or an
	// upload that never arrived doesn't keep counting.
	if s.meSync && u.email != "" {
		s.syncIfStale(r.Context(), u.id)
	}
	stored, reserved, err := s.storageUsage(r.Context(), u.id)
	if err != nil {
		log.Printf("usage for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not read storage usage")
		return
	}
	writeJSON(w, http.StatusOK, meResponse{
		Username: u.username, Email: u.email, PendingEmail: u.pendingEmail, Verified: u.email != "",
		UsedBytes: stored + reserved, StoredBytes: stored, ReservedBytes: reserved, QuotaBytes: s.quotaFor(u),
		Plan: u.plan, CouponUsed: u.couponAt > 0, ShareMaxSecs: int64(s.maxShareTTL(u) / time.Second),
		MaxFileBytes: s.maxFileFor(u),
	})
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
		var (
			u              user
			email, pending sql.NullString
		)
		err = s.db.QueryRowContext(r.Context(), `
			SELECT u.id, u.username, u.email, u.pending_email, u.plan, u.coupon_at FROM sessions s JOIN users u ON u.id = s.user_id
			WHERE s.token_hash = ? AND s.expires_at > ?`,
			hashToken(c.Value), time.Now().Unix()).Scan(&u.id, &u.username, &email, &pending, &u.plan, &u.couponAt)
		u.email, u.pendingEmail = email.String, pending.String
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

// requireVerified is requireUser for routes that need a verified address: an
// account from before email, or one whose sign-up code hasn't been entered
// yet, gets 403 with needsEmail set, and the page asks for the address.
func (s *server) requireVerified(next http.HandlerFunc) http.Handler {
	return s.requireUser(func(w http.ResponseWriter, r *http.Request) {
		if userFrom(r).email == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{
				"error":      "confirm your email address first",
				"needsEmail": true,
			})
			return
		}
		next(w, r)
	})
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
