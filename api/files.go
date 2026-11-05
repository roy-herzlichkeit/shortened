package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// ledgerGrace is how long a signed-but-unseen upload keeps its quota
// reservation: the link's lifetime plus time for a slow upload that started
// just before the link expired. uploadGrace adds time for the file's size at
// a slow connection's pace (slowUploadRate), so a large CORPO upload still in
// progress isn't dropped.
const (
	ledgerGrace    = linkTTL + 15*time.Minute
	slowUploadRate = 256 << 10 // bytes a second: about 2 Mbit/s
)

func uploadGrace(size int64) time.Duration {
	return ledgerGrace + time.Duration(size/slowUploadRate)*time.Second
}

// syncEvery is how stale the ledger may be when /auth/me reports usage.
const syncEvery = 30 * time.Second

type uploadRequest struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
	// OnConflict says what to do when a file of the same name exists: ""
	// (ask: answer 409), "replace" or "keepboth".
	OnConflict string `json:"onConflict"`
}

type uploadResponse struct {
	Key  string `json:"key"`
	URL  string `json:"url"`
	Name string `json:"name"` // the stored name; "Keep both" picks a new one
}

// conflictResponse is the 409 for a name that is already in use.
type conflictResponse struct {
	Error      string `json:"error"`
	Conflict   bool   `json:"conflict"`
	Name       string `json:"name"`
	Suggestion string `json:"suggestion"` // what "Keep both" would store
}

const (
	onConflictAsk      = ""
	onConflictReplace  = "replace"
	onConflictKeepBoth = "keepboth"
)

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
	if limit := s.maxFileFor(u); req.Size > limit {
		msg := "file is larger than the 50 MB limit"
		if paidPlan(u.plan) {
			msg = "file is larger than " + humanSize(limit) + ", the most a single upload can be"
		}
		writeError(w, http.StatusRequestEntityTooLarge, msg)
		return
	}
	switch req.OnConflict {
	case onConflictAsk, onConflictReplace, onConflictKeepBoth:
	default:
		writeError(w, http.StatusBadRequest, `onConflict must be "", "replace" or "keepboth"`)
		return
	}

	name, err := checkFilename(req.Filename)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Bring the ledger up to date first, so abandoned reservations stop
	// counting and the name check sees what is really stored.
	if _, err := s.syncFiles(r.Context(), u.id); err != nil {
		log.Printf("sync files for user %d: %v", u.id, err)
		writeError(w, http.StatusBadGateway, "could not check your storage usage")
		return
	}
	res, err := s.reserve(r.Context(), u.id, s.quotaFor(u), name, req.Size, req.OnConflict)
	if err != nil {
		log.Printf("reserve %q for user %d: %v", name, u.id, err)
		writeError(w, http.StatusInternalServerError, "could not check your storage usage")
		return
	}
	switch res.outcome {
	case reserveNoRoom:
		writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf(
			"not enough storage left: %s of %s used", formatMB(res.used), formatMB(s.quotaFor(u))))
		return
	case reserveConflict:
		writeJSON(w, http.StatusConflict, conflictResponse{
			Error:      fmt.Sprintf("you already have a file named %s", name),
			Conflict:   true,
			Name:       name,
			Suggestion: res.name,
		})
		return
	case reserveBusy:
		writeError(w, http.StatusConflict, fmt.Sprintf(
			"another upload of %s is still in progress; wait for it to finish", name))
		return
	}

	// The PUT signature covers the key and the declared Content-Length and
	// expires in 10 minutes, so the browser can upload exactly one object of
	// exactly the size it reserved, and only until the link goes stale.
	signed, err := s.presign.PresignPutObject(r.Context(), &s3.PutObjectInput{
		Bucket:        aws.String(s.cfg.bucket),
		Key:           aws.String(res.key),
		ContentLength: aws.Int64(req.Size),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign put %q: %v", res.key, err)
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ?`, res.key); err != nil {
			log.Printf("release reservation %q: %v", res.key, err)
		}
		writeError(w, http.StatusBadGateway, "could not sign the upload URL")
		return
	}

	writeJSON(w, http.StatusOK, uploadResponse{Key: res.key, URL: signed.URL, Name: res.name})
}

type reserveOutcome int

const (
	reserveOK       reserveOutcome = iota
	reserveNoRoom                  // over quota
	reserveConflict                // the name is taken and the caller hasn't chosen
	reserveBusy                    // an unfinished upload already uses the name
)

type reservation struct {
	outcome reserveOutcome
	key     string // the new object's key (reserveOK)
	name    string // the stored name (reserveOK), or the "Keep both" name (reserveConflict)
	used    int64  // usage before this upload (reserveNoRoom)
}

// reserve records an upload of size bytes against the user's quota. The name
// check runs in the same transaction, so two tabs can't both claim a name:
// the single database connection serializes them.
//
//   - A name in use by a stored file: with onConflict "" it reports
//     reserveConflict and the "Keep both" name; "keepboth" stores under that
//     name; "replace" records the stored file in the new row's replaces column,
//     and its size doesn't count against the quota for this check, since it
//     goes once the new upload is confirmed.
//   - A name in use by an upload that hasn't been confirmed: "keepboth" picks
//     a free name, anything else reports reserveBusy.
func (s *server) reserve(ctx context.Context, userID, quota int64, name string, size int64, onConflict string) (reservation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return reservation{}, err
	}
	defer tx.Rollback()

	type row struct {
		key       string
		size      int64
		confirmed bool
	}
	rows, err := tx.QueryContext(ctx, `SELECT key, size, confirmed_at FROM files WHERE user_id = ?`, userID)
	if err != nil {
		return reservation{}, err
	}
	taken := map[string]bool{}
	var stored, pending *row
	var used int64
	for rows.Next() {
		var rw row
		var confirmedAt int64
		if err := rows.Scan(&rw.key, &rw.size, &confirmedAt); err != nil {
			_ = rows.Close()
			return reservation{}, err
		}
		rw.confirmed = confirmedAt > 0
		used += rw.size
		n := displayName(rw.key)
		taken[n] = true
		if n == name {
			if rw.confirmed {
				stored = &rw
			} else {
				pending = &rw
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return reservation{}, err
	}
	if err := rows.Close(); err != nil {
		return reservation{}, err
	}

	var replaces string
	var credit int64
	if stored != nil || pending != nil {
		switch {
		case onConflict == onConflictKeepBoth:
			name = freeName(name, taken)
		case pending != nil:
			return reservation{outcome: reserveBusy}, nil
		case onConflict == onConflictReplace:
			replaces, credit = stored.key, stored.size
		default:
			return reservation{outcome: reserveConflict, name: freeName(name, taken)}, nil
		}
	}

	if used-credit+size > quota {
		return reservation{outcome: reserveNoRoom, used: used}, nil
	}

	id, err := newID()
	if err != nil {
		return reservation{}, fmt.Errorf("random id: %w", err)
	}
	key := userPrefix(userID) + id + "-" + name
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO files (key, user_id, size, created_at, replaces) VALUES (?, ?, ?, ?, ?)`,
		key, userID, size, time.Now().Unix(), replaces); err != nil {
		return reservation{}, err
	}
	return reservation{outcome: reserveOK, key: key, name: name}, tx.Commit()
}

// freeName returns "<base>-<n><ext>" for the smallest n >= 1 not in taken,
// shortening the base if the result would pass maxNameLen.
func freeName(name string, taken map[string]bool) string {
	ext := path.Ext(name)
	base := strings.TrimSuffix(name, ext)
	// ".env" has no base, and a very long "extension" isn't one: number the
	// whole name instead.
	if base == "" || len(ext) > 16 {
		base, ext = name, ""
	}
	for n := 1; ; n++ {
		suffix := "-" + strconv.Itoa(n) + ext
		b := base
		if len(b)+len(suffix) > maxNameLen {
			b = b[:maxNameLen-len(suffix)]
		}
		if candidate := b + suffix; !taken[candidate] {
			return candidate
		}
	}
}

type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// storageUsage splits the ledger into bytes stored (confirmed in the bucket)
// and bytes reserved by upload links not yet confirmed. The quota counts both.
func (s *server) storageUsage(ctx context.Context, userID int64) (stored, reserved int64, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(CASE WHEN confirmed_at > 0 THEN size ELSE 0 END), 0),
		       COALESCE(SUM(CASE WHEN confirmed_at = 0 THEN size ELSE 0 END), 0)
		FROM files WHERE user_id = ?`, userID).Scan(&stored, &reserved)
	return stored, reserved, err
}

// syncIfStale runs syncFiles unless the ledger was checked against the bucket
// in the last syncEvery. A failure is logged and the ledger is used as it is.
func (s *server) syncIfStale(ctx context.Context, userID int64) {
	if t, ok := s.syncedAt.Load(userID); ok && time.Since(t.(time.Time)) < syncEvery {
		return
	}
	if _, err := s.syncFiles(ctx, userID); err != nil {
		log.Printf("sync files for user %d: %v", userID, err)
	}
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
//   - every object gets a row with its real size, marked confirmed;
//   - a confirmed row with no object (deleted in the bucket by other means)
//     goes at once, unless it was confirmed after this listing started;
//   - an unconfirmed row with no object goes once its reservation has lapsed;
//   - a "Replace" upload that has landed removes the file it replaces, in
//     case the browser never got to confirm it.
func (s *server) syncFiles(ctx context.Context, userID int64) ([]bucketObject, error) {
	// A row confirmed while this listing ran may be missing from it; only rows
	// confirmed before the listing started are judged by it.
	started := time.Now()
	listStart := started.Unix()
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
			INSERT INTO files (key, user_id, size, created_at, confirmed_at) VALUES (?, ?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET size = excluded.size,
				confirmed_at = CASE WHEN files.confirmed_at = 0 THEN excluded.confirmed_at ELSE files.confirmed_at END`,
			o.key, userID, o.size, now, now); err != nil {
			return nil, err
		}
	}

	stale, replaced, err := ledgerChanges(ctx, tx, userID, present, listStart)
	if err != nil {
		return nil, err
	}
	for _, key := range stale {
		if _, err := tx.ExecContext(ctx, `DELETE FROM files WHERE key = ?`, key); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	s.syncedAt.Store(userID, started)

	// Finish "Replace" uploads whose new object is in the bucket. Outside the
	// transaction: it talks to the bucket, and it uses s.db itself.
	gone := map[string]bool{}
	for newKey, oldKey := range replaced {
		if err := s.finishReplace(ctx, userID, newKey, oldKey); err != nil {
			log.Printf("finish replace %q -> %q: %v", oldKey, newKey, err)
			continue
		}
		gone[oldKey] = true
	}
	if len(gone) > 0 {
		objects = slices.DeleteFunc(objects, func(o bucketObject) bool { return gone[o.key] })
	}
	return objects, nil
}

// ledgerChanges reads the user's ledger rows against the bucket listing. It
// returns the rows to drop (see syncFiles), and the "Replace" uploads whose new
// object is present, as new key -> key being replaced.
func ledgerChanges(ctx context.Context, tx *sql.Tx, userID int64, present map[string]bool, listStart int64) ([]string, map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `SELECT key, size, created_at, confirmed_at, replaces FROM files WHERE user_id = ?`, userID)
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rows.Close() }() // read-only; rows.Err below reports failures

	now := time.Now()
	var stale []string
	replaced := map[string]string{}
	for rows.Next() {
		var key, replaces string
		var size, createdAt, confirmedAt int64
		if err := rows.Scan(&key, &size, &createdAt, &confirmedAt, &replaces); err != nil {
			return nil, nil, err
		}
		switch {
		case present[key]:
			if replaces != "" {
				replaced[key] = replaces
			}
		case confirmedAt > 0 && confirmedAt < listStart:
			stale = append(stale, key) // was stored, isn't any more
		case confirmedAt == 0 && createdAt < now.Add(-uploadGrace(size)).Unix():
			stale = append(stale, key) // the upload never arrived
		}
	}
	return stale, replaced, rows.Err()
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

	// Links die first: a file that is half deleted must not stay shared.
	if err := s.revokeSharesOf(r.Context(), key); err != nil {
		log.Printf("revoke links to %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not delete the file")
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

// usageResponse is what confirm and release answer, so the page can redraw the
// usage bar without another request. usedBytes = storedBytes + reservedBytes,
// which is what the quota checks.
type usageResponse struct {
	UsedBytes     int64 `json:"usedBytes"`
	StoredBytes   int64 `json:"storedBytes"`
	ReservedBytes int64 `json:"reservedBytes"`
	QuotaBytes    int64 `json:"quotaBytes"`
}

func (s *server) writeUsage(w http.ResponseWriter, r *http.Request, u user) {
	stored, reserved, err := s.storageUsage(r.Context(), u.id)
	if err != nil {
		log.Printf("usage for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not read your storage usage")
		return
	}
	writeJSON(w, http.StatusOK, usageResponse{
		UsedBytes: stored + reserved, StoredBytes: stored, ReservedBytes: reserved, QuotaBytes: s.quotaFor(u),
	})
}

// pendingRow reads the caller's ledger row for key. ok is false when there is
// none, which a stranger's key also gets.
func (s *server) pendingRow(ctx context.Context, userID int64, key string) (size, confirmedAt int64, replaces string, ok bool, err error) {
	err = s.db.QueryRowContext(ctx, `SELECT size, confirmed_at, replaces FROM files WHERE key = ? AND user_id = ?`,
		key, userID).Scan(&size, &confirmedAt, &replaces)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, 0, "", false, nil
	}
	return size, confirmedAt, replaces, err == nil, err
}

// handleConfirm is called by the browser after its PUT to the bucket
// succeeded: POST /files/confirm?key=. The object must be in the bucket; its
// real size goes into the ledger and the row counts as stored from now on. For
// a "Replace" upload, the old file is deleted.
func (s *server) handleConfirm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	u := userFrom(r)
	key, ok := ownKeyParam(w, r)
	if !ok {
		return
	}
	if _, _, _, found, err := s.pendingRow(r.Context(), u.id, key); err != nil {
		log.Printf("confirm %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not read your storage usage")
		return
	} else if !found {
		writeError(w, http.StatusNotFound, "no upload is waiting for this file")
		return
	}

	size, err := s.headObject(r.Context(), key)
	switch {
	case errors.Is(err, errNotInBucket):
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ? AND confirmed_at = 0`, key); err != nil {
			log.Printf("drop unconfirmed %q: %v", key, err)
		}
		writeError(w, http.StatusNotFound, "the upload didn't reach storage; try again")
		return
	case err != nil:
		log.Printf("confirm head %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not reach storage to check the upload")
		return
	}

	if err := s.markConfirmed(r.Context(), u.id, key, size); err != nil {
		log.Printf("confirm %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not record the upload")
		return
	}
	s.writeUsage(w, r, u)
}

// markConfirmed records the object's real size, marks the row stored, and
// finishes a "Replace" upload. A replace that fails here is retried by the
// next listing.
func (s *server) markConfirmed(ctx context.Context, userID int64, key string, size int64) error {
	reserved, _, replaces, found, err := s.pendingRow(ctx, userID, key)
	if err != nil || !found {
		return err
	}
	if size != reserved {
		// The signed Content-Length makes this impossible through the app.
		log.Printf("confirm %q: stored %d bytes, reserved %d", key, size, reserved)
	}
	if _, err := s.db.ExecContext(ctx, `
		UPDATE files SET size = ?,
			confirmed_at = CASE WHEN confirmed_at = 0 THEN ? ELSE confirmed_at END
		WHERE key = ?`, size, time.Now().Unix(), key); err != nil {
		return err
	}
	if replaces != "" {
		if err := s.finishReplace(ctx, userID, key, replaces); err != nil {
			log.Printf("finish replace %q -> %q: %v", replaces, key, err)
		}
	}
	return nil
}

// finishReplace deletes the file a "Replace" upload swapped out, every
// version, and its ledger row, then clears the new row's replaces column. Its
// share links move to the new file: Replace is a new version, not a deletion.
func (s *server) finishReplace(ctx context.Context, userID int64, newKey, oldKey string) error {
	if !validKey(oldKey) || !strings.HasPrefix(oldKey, userPrefix(userID)) {
		return fmt.Errorf("refusing to replace %q: not one of this user's keys", oldKey)
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE shares SET key = ? WHERE key = ? AND user_id = ?`, newKey, oldKey, userID); err != nil {
		return err
	}
	if err := s.deleteAllVersions(ctx, oldKey); err != nil {
		return err
	}
	if _, err := s.db.ExecContext(ctx, `DELETE FROM files WHERE key = ?`, oldKey); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE files SET replaces = '' WHERE key = ?`, newKey)
	return err
}

// handleRelease is called by the browser when its PUT failed or was cancelled:
// POST /files/release?key=. The reservation goes at once, unless the object
// did reach the bucket after all, in which case the upload is confirmed so the
// ledger still matches the bucket.
func (s *server) handleRelease(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	u := userFrom(r)
	key, ok := ownKeyParam(w, r)
	if !ok {
		return
	}
	_, confirmedAt, _, found, err := s.pendingRow(r.Context(), u.id, key)
	if err != nil {
		log.Printf("release %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not read your storage usage")
		return
	}
	if !found || confirmedAt > 0 {
		// Nothing reserved, or already a stored file: releasing must never
		// drop a real file from the ledger.
		s.writeUsage(w, r, u)
		return
	}

	size, err := s.headObject(r.Context(), key)
	switch {
	case err == nil:
		err = s.markConfirmed(r.Context(), u.id, key, size)
	default:
		// Not in the bucket, or the bucket can't be asked: drop the
		// reservation. If the object does exist, the next listing adds it back.
		if !errors.Is(err, errNotInBucket) {
			log.Printf("release head %q: %v", key, err)
		}
		_, err = s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ? AND confirmed_at = 0`, key)
	}
	if err != nil {
		log.Printf("release %q: %v", key, err)
		writeError(w, http.StatusInternalServerError, "could not update your storage usage")
		return
	}
	s.writeUsage(w, r, u)
}

var errNotInBucket = errors.New("object not in bucket")

// headObject returns the object's size, or errNotInBucket if there is no
// visible object (B2 answers 404 for a hidden file too).
func (s *server) headObject(ctx context.Context, key string) (int64, error) {
	out, err := s.client.HeadObject(ctx, &s3.HeadObjectInput{
		Bucket: aws.String(s.cfg.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		var re *awshttp.ResponseError
		if errors.As(err, &re) && re.HTTPStatusCode() == http.StatusNotFound {
			return 0, errNotInBucket
		}
		return 0, err
	}
	return aws.ToInt64(out.ContentLength), nil
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

	// A signed link to a missing object would only show B2's error page, so
	// check first. A file that is gone also leaves the ledger at once.
	switch _, err := s.headObject(r.Context(), key); {
	case errors.Is(err, errNotInBucket):
		if _, err := s.db.ExecContext(r.Context(), `DELETE FROM files WHERE key = ?`, key); err != nil {
			log.Printf("drop missing %q: %v", key, err)
		}
		writeError(w, http.StatusNotFound, "this file is no longer in storage")
		return
	case err != nil:
		log.Printf("download head %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not reach storage to check the file; try again")
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
	keyPattern = regexp.MustCompile(`^u/[1-9][0-9]{0,18}/[0-9a-f]{16}-[A-Za-z0-9._-]{1,120}$`)
)

// userPrefix is the folder in the bucket that holds one user's files.
func userPrefix(userID int64) string {
	return "u/" + strconv.FormatInt(userID, 10) + "/"
}

// validKey reports whether key looks like one this API issued: a user folder,
// a random hex prefix and a name of the allowed characters.
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

// checkFilename cleans a name the browser sent for a new upload. Spaces become
// "-" and every character other than A-Z a-z 0-9 . _ - is dropped (the page
// does the same first and tells the user); what is left needs at least one
// letter or digit. Names stored before this rule keep their old form.
func checkFilename(name string) (string, error) {
	if name == "" {
		return "", errors.New("the file needs a name")
	}
	name = cleanName(name)
	if len(name) > maxNameLen {
		return "", fmt.Errorf("file name is longer than %d characters", maxNameLen)
	}
	if !strings.ContainsFunc(name, func(r rune) bool { return nameAlnum(r) }) {
		return "", errors.New("file name needs at least one letter or digit once characters that aren't allowed are dropped")
	}
	return name, nil
}

// cleanName turns spaces into "-" and drops every other character outside
// A-Z a-z 0-9 . _ -.
func cleanName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case nameAlnum(r) || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func nameAlnum(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9'
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
