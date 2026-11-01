package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ledgerGrace is how long a signed-but-unseen upload keeps its quota
// reservation: the link's lifetime plus time for a slow upload that started
// just before the link expired.
const ledgerGrace = linkTTL + 15*time.Minute

type uploadRequest struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type uploadResponse struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

func (s *server) handleUploadURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	u := userFrom(r)

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req uploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON like {\"filename\":\"...\",\"size\":12345}")
		return
	}
	if req.Size < 0 {
		writeError(w, http.StatusBadRequest, "size must not be negative")
		return
	}
	if req.Size > maxUploadSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file is larger than the 50 MB limit")
		return
	}

	name := cleanFilename(req.Filename)
	if name == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}

	id, err := newID()
	if err != nil {
		log.Printf("random id: %v", err)
		writeError(w, http.StatusInternalServerError, "could not build an object key")
		return
	}
	key := userPrefix(u.id) + id + "-" + name

	// Bring the ledger up to date first, so abandoned reservations stop
	// counting, then reserve this upload's size.
	if _, err := s.syncFiles(r.Context(), u.id); err != nil {
		log.Printf("sync files for user %d: %v", u.id, err)
		writeError(w, http.StatusBadGateway, "could not check your storage usage")
		return
	}
	used, ok, err := s.reserve(r.Context(), u.id, key, req.Size)
	if err != nil {
		log.Printf("reserve %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not check your storage usage")
		return
	}
	if !ok {
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"not enough storage left: %s of %s used", formatMB(used), formatMB(s.cfg.quotaBytes)))
		return
	}

	// The PUT signature covers the key and the declared Content-Length and
	// expires in 10 minutes, so the browser can upload exactly one object of
	// exactly the size it reserved, and only until the link goes stale.
	signed, err := s.presign.PresignPutObject(r.Context(), &s3.PutObjectInput{
		Bucket:        aws.String(s.cfg.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(req.Size),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign put %q: %v", key, err)
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ?`, key); err != nil {
			log.Printf("release reservation %q: %v", key, err)
		}
		writeError(w, http.StatusBadGateway, "could not sign the upload URL")
		return
	}

	writeJSON(w, http.StatusOK, uploadResponse{Key: key, URL: signed.URL})
}

// reserve records an upload of size bytes against the user's quota, or
// reports false with the current usage when it would not fit.
func (s *server) reserve(ctx context.Context, userID int64, key string, size int64) (int64, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, false, err
	}
	defer tx.Rollback()

	used, err := s.usedBytes(ctx, tx, userID)
	if err != nil {
		return 0, false, err
	}
	if used+size > s.cfg.quotaBytes {
		return used, false, nil
	}
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO files (key, user_id, size, created_at) VALUES (?, ?, ?, ?)`,
		key, userID, size, time.Now().Unix()); err != nil {
		return 0, false, err
	}
	return used, true, tx.Commit()
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *server) usedBytes(ctx context.Context, q rowQuerier, userID int64) (int64, error) {
	var used int64
	err := q.QueryRowContext(ctx, `SELECT COALESCE(SUM(size), 0) FROM files WHERE user_id = ?`, userID).Scan(&used)
	return used, err
}

type fileInfo struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
}

type bucketObject struct {
	key      string
	size     int64
	modified time.Time
}

// syncFiles lists the user's objects in the bucket and makes the ledger agree:
// objects get a row with their real size, and rows whose upload never arrived
// are dropped once their reservation has lapsed.
func (s *server) syncFiles(ctx context.Context, userID int64) ([]bucketObject, error) {
	var objects []bucketObject
	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.bucket),
		Prefix: aws.String(userPrefix(userID)),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, obj := range page.Contents {
			o := bucketObject{key: aws.ToString(obj.Key), size: aws.ToInt64(obj.Size)}
			if obj.LastModified != nil {
				o.modified = obj.LastModified.UTC()
			}
			objects = append(objects, o)
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	present := make(map[string]bool, len(objects))
	now := time.Now().Unix()
	for _, o := range objects {
		present[o.key] = true
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO files (key, user_id, size, created_at) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET size = excluded.size`,
			o.key, userID, o.size, now); err != nil {
			return nil, err
		}
	}

	stale, err := staleKeys(ctx, tx, userID, present)
	if err != nil {
		return nil, err
	}
	for _, key := range stale {
		if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE key = ?`, key); err != nil {
			return nil, err
		}
	}

	return objects, tx.Commit()
}

// staleKeys returns the user's ledger rows that are past their reservation
// window and have no object in the bucket.
func staleKeys(ctx context.Context, tx *sql.Tx, userID int64, present map[string]bool) ([]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key FROM files WHERE user_id = ? AND created_at < ?`,
		userID, time.Now().Add(-ledgerGrace).Unix())
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }() // read-only; rows.Err below reports failures

	var stale []string
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		if !present[key] {
			stale = append(stale, key)
		}
	}
	return stale, rows.Err()
}

func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listFiles(w, r)
	case http.MethodDelete:
		s.deleteFile(w, r)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		writeError(w, http.StatusMethodNotAllowed, "use GET or DELETE")
	}
}

// listFiles returns the signed-in user's files, newest first.
func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	objects, err := s.syncFiles(r.Context(), u.id)
	if err != nil {
		log.Printf("list files for user %d: %v", u.id, err)
		writeError(w, http.StatusBadGateway, "could not list your files")
		return
	}

	slices.SortStableFunc(objects, func(a, b bucketObject) int {
		return b.modified.Compare(a.modified)
	})
	files := make([]fileInfo, 0, len(objects))
	for _, o := range objects {
		info := fileInfo{Key: o.key, Name: displayName(o.key), Size: o.size}
		if !o.modified.IsZero() {
			info.LastModified = o.modified.Format(time.RFC3339)
		}
		files = append(files, info)
	}

	writeJSON(w, http.StatusOK, files)
}

func (s *server) deleteFile(w http.ResponseWriter, r *http.Request) {
	key, ok := ownKeyParam(w, r)
	if !ok {
		return
	}

	if err := s.deleteAllVersions(r.Context(), key); err != nil {
		log.Printf("delete %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not delete the file")
		return
	}
	if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ?`, key); err != nil {
		// The next listing reconciles the ledger, so this only delays the
		// freed space showing up.
		log.Printf("delete ledger row %q: %v", key, err)
	}

	w.WriteHeader(http.StatusNoContent)
}

// deleteAllVersions removes every stored version of key, and any hide markers.
// A plain DeleteObject on B2 only adds a hide marker on top of the file, which
// stays stored and billed, so deleting means deleting each version by ID. The
// bucket's lifecycle rule (daysFromHidingToDeleting: 1 on u/) is the backstop
// for anything this misses.
func (s *server) deleteAllVersions(ctx context.Context, key string) error {
	var versionIDs []string
	input := &s3.ListObjectVersionsInput{
		Bucket: aws.String(s.cfg.bucket),
		Prefix: aws.String(key),
	}
	for {
		page, err := s.client.ListObjectVersions(ctx, input)
		if err != nil {
			return fmt.Errorf("list versions: %w", err)
		}
		// Prefix matching could also return longer keys, so match exactly.
		for _, v := range page.Versions {
			if aws.ToString(v.Key) == key {
				versionIDs = append(versionIDs, aws.ToString(v.VersionId))
			}
		}
		for _, m := range page.DeleteMarkers {
			if aws.ToString(m.Key) == key {
				versionIDs = append(versionIDs, aws.ToString(m.VersionId))
			}
		}
		if !aws.ToBool(page.IsTruncated) {
			break
		}
		input.KeyMarker = page.NextKeyMarker
		input.VersionIdMarker = page.NextVersionIdMarker
	}

	// One DeleteObject per version: DeleteObjects needs a request checksum,
	// which the client deliberately doesn't send to B2. A file has one or two
	// versions, so the extra round trips don't matter.
	for _, id := range versionIDs {
		if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
			Bucket:    aws.String(s.cfg.bucket),
			Key:       aws.String(key),
			VersionId: aws.String(id),
		}); err != nil {
			return fmt.Errorf("delete version %s: %w", id, err)
		}
	}
	return nil
}

func (s *server) handleDownloadURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	key, ok := ownKeyParam(w, r)
	if !ok {
		return
	}

	// Forcing an attachment keeps an uploaded HTML or SVG file from rendering
	// in the browser on the bucket's origin. The name is already restricted to
	// [A-Za-z0-9._-], so it needs no quoting beyond the surrounding quotes.
	signed, err := s.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{
		Bucket:                     aws.String(s.cfg.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(`attachment; filename="` + displayName(key) + `"`),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign get %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not sign the download URL")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"url": signed.URL})
}

// ownKeyParam reads the "key" query parameter and writes an error unless it is
// a well-formed key inside the signed-in user's folder. Someone else's key gets
// the same 404 as a missing one, so keys can't be probed.
func ownKeyParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key query parameter")
		return "", false
	}
	if !validKey(key) {
		writeError(w, http.StatusBadRequest, "invalid key")
		return "", false
	}
	if !strings.HasPrefix(key, userPrefix(userFrom(r).id)) {
		writeError(w, http.StatusNotFound, "file not found")
		return "", false
	}
	return key, true
}

var (
	unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	keyPattern      = regexp.MustCompile(`^u/[1-9][0-9]{0,18}/[0-9a-f]{16}-[A-Za-z0-9._-]{1,120}$`)
)

// userPrefix is the folder in the bucket that holds one user's files.
func userPrefix(userID int64) string {
	return "u/" + strconv.FormatInt(userID, 10) + "/"
}

// validKey reports whether key looks like one this API issued: a user folder,
// a random hex prefix and a name that cleanFilename could have produced.
func validKey(key string) bool {
	return keyPattern.MatchString(key)
}

// displayName strips the folder and random prefix from a key, giving back the
// cleaned filename the uploader chose. Keys of any other shape are returned
// unchanged.
func displayName(key string) string {
	if !validKey(key) {
		return key
	}
	base := key[strings.LastIndexByte(key, '/')+1:]
	return base[idLen+1:]
}

// cleanFilename turns a client-supplied name into a flat, harmless object-key
// suffix: no directories, no control characters, no characters that would need
// escaping in a URL, and a bounded length that keeps the extension.
func cleanFilename(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = path.Base(name)
	name = unsafeNameChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-._")

	if len(name) > maxNameLen {
		ext := path.Ext(name)
		if len(ext) > 16 {
			ext = ""
		}
		base := strings.TrimSuffix(name, ext)
		if room := maxNameLen - len(ext); len(base) > room {
			base = base[:room]
		}
		name = strings.Trim(base, "-._") + ext
	}
	return name
}

func newID() (string, error) {
	buf := make([]byte, idLen/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func formatMB(bytes int64) string {
	return strconv.FormatFloat(float64(bytes)/(1<<20), 'f', 1, 64) + " MB"
}
