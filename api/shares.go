package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Share links: https://<host>/s/<code>. Anyone with the link can download the
// file until the link expires or its owner revokes it; no account is needed.
//
//   - The code is shareCodeLen random base62 characters (about 143 bits), so
//     links can't be guessed or enumerated.
//   - The page shows the name and size; each Download click signs a fresh
//     10-minute B2 link (attachment), so a copied B2 URL dies quickly while the
//     share link keeps working.
//   - A link is live while it isn't revoked, hasn't expired, and its file is
//     still a stored file of the owner. Deleting the file therefore kills its
//     links, however the file went. Replace moves them to the new file.
//   - Rows stay after a link dies, so the page can say why (expired, revoked,
//     file deleted), and are purged shareKeepDead later.

const (
	shareCodeLen  = 24
	minShareTTL   = 10 * time.Minute
	freeShareTTL  = 7 * 24 * time.Hour
	maxLiveShares = 100 // per account, a guard against runaway scripts
	shareKeepDead = 30 * 24 * time.Hour
)

const base62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

var shareCodePattern = regexp.MustCompile(`^[0-9A-Za-z]{24}$`)

// newShareCode draws shareCodeLen base62 characters from crypto/rand. Bytes of
// 248 and above are dropped, so each character is uniform (248 = 4 * 62).
func newShareCode() (string, error) {
	var b strings.Builder
	buf := make([]byte, 32)
	for b.Len() < shareCodeLen {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		for _, c := range buf {
			if c < 248 && b.Len() < shareCodeLen {
				b.WriteByte(base62[c%62])
			}
		}
	}
	return b.String(), nil
}

type shareInfo struct {
	Code      string `json:"code"`
	Path      string `json:"path"` // "/s/<code>"; the page adds its own origin
	Key       string `json:"key"`
	Name      string `json:"name"`
	CreatedAt int64  `json:"createdAt"` // Unix seconds
	ExpiresAt int64  `json:"expiresAt"`
}

type sharesResponse struct {
	MinSeconds int64       `json:"minSeconds"`
	MaxSeconds int64       `json:"maxSeconds"`
	Links      []shareInfo `json:"links"`
}

// handleShares: GET lists the live links, POST {"key","seconds"} makes one,
// DELETE ?code= revokes one.
func (s *server) handleShares(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listShares(w, r)
	case http.MethodPost:
		s.createShare(w, r)
	case http.MethodDelete:
		s.revokeShare(w, r)
	default:
		w.Header().Set("Allow", "GET, POST, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "use GET, POST or DELETE")
	}
}

func (s *server) listShares(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	rows, err := s.db.QueryContext(r.Context(), `
		SELECT s.code, s.key, s.created_at, s.expires_at FROM shares s
		JOIN files f ON f.key = s.key AND f.user_id = s.user_id AND f.confirmed_at > 0
		WHERE s.user_id = ? AND s.revoked_at = 0 AND s.expires_at > ?
		ORDER BY s.expires_at`, u.id, time.Now().Unix())
	if err != nil {
		log.Printf("list shares for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not list your links")
		return
	}
	defer func() { _ = rows.Close() }()
	links := []shareInfo{}
	for rows.Next() {
		var l shareInfo
		if err := rows.Scan(&l.Code, &l.Key, &l.CreatedAt, &l.ExpiresAt); err != nil {
			log.Printf("list shares for user %d: %v", u.id, err)
			writeError(w, http.StatusInternalServerError, "could not list your links")
			return
		}
		l.Path, l.Name = "/s/"+l.Code, displayName(l.Key)
		links = append(links, l)
	}
	if err := rows.Err(); err != nil {
		log.Printf("list shares for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not list your links")
		return
	}
	writeJSON(w, http.StatusOK, sharesResponse{
		MinSeconds: int64(minShareTTL / time.Second),
		MaxSeconds: int64(s.maxShareTTL(u) / time.Second),
		Links:      links,
	})
}

func (s *server) createShare(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	var body struct {
		Key     string `json:"key"`
		Seconds int64  `json:"seconds"`
	}
	if !readJSON(w, r, &body, `{"key":"u/...","seconds":3600}`) {
		return
	}
	maxTTL := s.maxShareTTL(u)
	ttl := time.Duration(body.Seconds) * time.Second
	if body.Seconds < int64(minShareTTL/time.Second) || body.Seconds > int64(maxTTL/time.Second) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("a link lasts from %s to %s", humanDuration(minShareTTL), humanDuration(maxTTL)))
		return
	}
	if !validKey(body.Key) {
		writeError(w, http.StatusBadRequest, "invalid key")
		return
	}
	ctx := r.Context()
	// Only a stored file of the caller's: someone else's key gets the same 404
	// as a missing one.
	var stored int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM files WHERE key = ? AND user_id = ? AND confirmed_at > 0`,
		body.Key, u.id).Scan(&stored); err != nil {
		log.Printf("share %q: %v", body.Key, err)
		writeError(w, http.StatusInternalServerError, "could not make the link")
		return
	}
	if stored == 0 {
		writeError(w, http.StatusNotFound, "file not found")
		return
	}

	now := time.Now()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM shares WHERE user_id = ? AND (expires_at < ? OR (revoked_at > 0 AND revoked_at < ?))`,
		u.id, now.Add(-shareKeepDead).Unix(), now.Add(-shareKeepDead).Unix()); err != nil {
		log.Printf("purge dead shares for user %d: %v", u.id, err)
	}
	var live int
	if err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM shares WHERE user_id = ? AND revoked_at = 0 AND expires_at > ?`,
		u.id, now.Unix()).Scan(&live); err != nil {
		log.Printf("share %q: %v", body.Key, err)
		writeError(w, http.StatusInternalServerError, "could not make the link")
		return
	}
	if live >= maxLiveShares {
		writeError(w, http.StatusConflict, fmt.Sprintf("you have %d active links; revoke some first", live))
		return
	}

	code, err := newShareCode()
	if err != nil {
		log.Printf("share code: %v", err)
		writeError(w, http.StatusInternalServerError, "could not make the link")
		return
	}
	l := shareInfo{Code: code, Path: "/s/" + code, Key: body.Key, Name: displayName(body.Key),
		CreatedAt: now.Unix(), ExpiresAt: now.Add(ttl).Unix()}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO shares (code, key, user_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
		l.Code, l.Key, u.id, l.CreatedAt, l.ExpiresAt); err != nil {
		log.Printf("share %q: %v", body.Key, err)
		writeError(w, http.StatusInternalServerError, "could not make the link")
		return
	}
	writeJSON(w, http.StatusCreated, l)
}

func (s *server) revokeShare(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	code := r.URL.Query().Get("code")
	if !shareCodePattern.MatchString(code) {
		writeError(w, http.StatusNotFound, "link not found")
		return
	}
	res, err := s.db.ExecContext(r.Context(),
		`UPDATE shares SET revoked_at = CASE WHEN revoked_at = 0 THEN ? ELSE revoked_at END WHERE code = ? AND user_id = ?`,
		time.Now().Unix(), code, u.id)
	if err != nil {
		log.Printf("revoke share for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not revoke the link")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusNotFound, "link not found") // someone else's, or none
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// revokeSharesOf kills every link to key, for a file being deleted.
func (s *server) revokeSharesOf(ctx context.Context, key string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE shares SET revoked_at = ? WHERE key = ? AND revoked_at = 0`, time.Now().Unix(), key)
	return err
}

/* ---------- The recipient's side ---------- */

// shareState is why a link works or doesn't.
type shareState int

const (
	shareLive shareState = iota
	shareUnknown
	shareExpired
	shareRevoked
	shareFileGone
)

type liveShare struct {
	key       string
	size      int64
	expiresAt time.Time
}

// lookupShare reads the link and its file's ledger row.
func (s *server) lookupShare(ctx context.Context, code string) (liveShare, shareState, error) {
	if !shareCodePattern.MatchString(code) {
		return liveShare{}, shareUnknown, nil
	}
	var (
		l                  liveShare
		expiresAt, revoked int64
		size, confirmed    sql.NullInt64
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT s.key, s.expires_at, s.revoked_at, f.size, f.confirmed_at FROM shares s
		LEFT JOIN files f ON f.key = s.key AND f.user_id = s.user_id
		WHERE s.code = ?`, code).Scan(&l.key, &expiresAt, &revoked, &size, &confirmed)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return liveShare{}, shareUnknown, nil
	case err != nil:
		return liveShare{}, shareUnknown, err
	}
	l.size, l.expiresAt = size.Int64, time.Unix(expiresAt, 0)
	// A deleted file is the reason that matters most to the recipient, so it
	// comes first (deleting a file also revokes its links).
	switch {
	case !size.Valid || confirmed.Int64 == 0:
		return l, shareFileGone, nil
	case revoked > 0:
		return l, shareRevoked, nil
	case !l.expiresAt.After(time.Now()):
		return l, shareExpired, nil
	}
	return l, shareLive, nil
}

// handleSharePage: GET /s/{code}, the page a recipient opens.
func (s *server) handleSharePage(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	l, state, err := s.lookupShare(r.Context(), code)
	if err != nil {
		log.Printf("share page: %v", err)
		s.writeSharePage(w, http.StatusInternalServerError, sharePage{Title: "Something went wrong", Text: "Try again in a moment."})
		return
	}
	if state != shareLive {
		s.writeDeadShare(w, state)
		return
	}
	s.writeSharePage(w, http.StatusOK, sharePage{
		Title:    displayName(l.key),
		Name:     displayName(l.key),
		Size:     humanSize(l.size),
		Expires:  l.expiresAt.UTC().Format("2 Jan 2006, 15:04 UTC"),
		Download: "/s/" + code + "/download",
	})
}

// handleShareDownload: GET /s/{code}/download signs a fresh 10-minute link and
// redirects to it.
func (s *server) handleShareDownload(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	l, state, err := s.lookupShare(r.Context(), code)
	if err != nil {
		log.Printf("share download: %v", err)
		s.writeSharePage(w, http.StatusInternalServerError, sharePage{Title: "Something went wrong", Text: "Try again in a moment."})
		return
	}
	if state != shareLive {
		s.writeDeadShare(w, state)
		return
	}
	switch _, err := s.headObject(r.Context(), l.key); {
	case errors.Is(err, errNotInBucket):
		// Gone from the bucket by other means: the ledger row goes, and with it
		// the link.
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ?`, l.key); err != nil {
			log.Printf("drop missing %q: %v", l.key, err)
		}
		s.writeDeadShare(w, shareFileGone)
		return
	case err != nil:
		log.Printf("share download head %q: %v", l.key, err)
		s.writeSharePage(w, http.StatusBadGateway, sharePage{Title: "Storage unreachable", Text: "The file couldn't be reached just now. Try again in a moment."})
		return
	}
	signed, err := s.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{
		Bucket:                     aws.String(s.cfg.bucket),
		Key:                        aws.String(l.key),
		ResponseContentDisposition: aws.String(`attachment; filename="` + displayName(l.key) + `"`),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("share presign %q: %v", l.key, err)
		s.writeSharePage(w, http.StatusBadGateway, sharePage{Title: "Storage unreachable", Text: "The download couldn't be signed. Try again in a moment."})
		return
	}
	shareHeaders(w)
	http.Redirect(w, r, signed.URL, http.StatusFound)
}

func (s *server) writeDeadShare(w http.ResponseWriter, state shareState) {
	switch state {
	case shareExpired:
		s.writeSharePage(w, http.StatusGone, sharePage{Title: "Link expired", Text: "This link has expired. Ask the person who sent it for a new one."})
	case shareRevoked:
		s.writeSharePage(w, http.StatusGone, sharePage{Title: "Link revoked", Text: "The owner has turned this link off. Ask them for a new one."})
	case shareFileGone:
		s.writeSharePage(w, http.StatusGone, sharePage{Title: "File deleted", Text: "The file behind this link has been deleted."})
	default:
		s.writeSharePage(w, http.StatusNotFound, sharePage{Title: "No such link", Text: "This link doesn't exist. Check that it was copied whole."})
	}
}

// shareLimited is the per-viewer-IP limit on /s/: enough for a person, not for
// a script trying codes or hammering one link.
func (s *server) shareLimited(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.shareLimiter.allow(s.clientIP(r)) {
			w.Header().Set("Retry-After", strconv.Itoa(int(s.shareLimiter.every/time.Second)))
			s.writeSharePage(w, http.StatusTooManyRequests, sharePage{Title: "Slow down", Text: "Too many requests from your network. Wait a moment and try again."})
			return
		}
		next(w, r)
	})
}

type sharePage struct {
	Title    string
	Text     string // for a dead link or an error
	Name     string // for a live link
	Size     string
	Expires  string
	Download string
}

var sharePageTmpl = template.Must(template.New("share").Parse(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>{{.Title}} · SHORTENED.</title>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Rajdhani:wght@500;600;700&amp;family=Share+Tech+Mono&amp;display=swap">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<header class="topbar">
  <div class="brand">
    <span class="brand-mark" aria-hidden="true">//</span>
    <a class="brand-name brand-link" href="/">Shortened<span class="brand-dot">.</span></a>
  </div>
</header>
<main>
  <section class="frame share-frame">
    <div class="frame-inner">
{{- if .Name}}
      <h1 class="frame-title"><span class="tag">&gt;&gt;</span> Shared file</h1>
      <p class="share-name mono">{{.Name}}</p>
      <p class="hint">{{.Size}} · this link works until {{.Expires}}</p>
      <a class="btn btn-primary" href="{{.Download}}" rel="nofollow">Download</a>
      <p class="hint">Each click makes a fresh download link that lasts 10 minutes.</p>
{{- else}}
      <h1 class="frame-title"><span class="tag">!!</span> {{.Title}}</h1>
      <p class="dialog-text">{{.Text}}</p>
{{- end}}
    </div>
  </section>
</main>
<footer class="footer mono">
  <span>// SHORTENED. file sharing</span>
</footer>
</body>
</html>
`))

// shareHeaders: never cached, never indexed, no referrer (the code is in the
// URL), and the same strict CSP as the app page, with no script at all.
func shareHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Robots-Tag", "noindex, nofollow")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", strings.Join([]string{
		"default-src 'none'",
		"style-src 'self' https://fonts.googleapis.com",
		"font-src https://fonts.gstatic.com",
		"img-src 'self' data:",
		"base-uri 'none'",
		"form-action 'none'",
		"frame-ancestors 'none'",
	}, "; "))
}

func (s *server) writeSharePage(w http.ResponseWriter, status int, p sharePage) {
	shareHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := sharePageTmpl.Execute(w, p); err != nil {
		log.Printf("share page: %v", err)
	}
}

// humanSize is formatSize from the page: "12.3 MB", "500 MB", "40 B".
func humanSize(n int64) string {
	if n < 1024 {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := [...]string{"KB", "MB", "GB", "TB"}
	v, i := float64(n)/1024, 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	return strings.TrimSuffix(strconv.FormatFloat(v, 'f', 1, 64), ".0") + " " + units[i]
}

// humanDuration: "10 minutes", "7 days".
func humanDuration(d time.Duration) string {
	unit, n := "minute", int64(d/time.Minute)
	switch {
	case d%(24*time.Hour) == 0:
		unit, n = "day", int64(d/(24*time.Hour))
	case d%time.Hour == 0:
		unit, n = "hour", int64(d/time.Hour)
	}
	if n != 1 {
		unit += "s"
	}
	return strconv.FormatInt(n, 10) + " " + unit
}
