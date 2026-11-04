package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Account deletion is immediate and retry-safe. The order:
//
//  1. Check the password and the word DELETE, and refuse while an upload link
//     is still out (its bytes could land after the folder was emptied).
//  2. Delete every object version and hide marker under u/<id>/ in B2, then
//     list again to be sure the folder is empty.
//  3. In one transaction, delete the account's rows: sessions, codes, mail
//     log, ledger, then the user row.
//  4. Clear the cookie and mail a confirmation to the verified address.
//
// If step 2 fails halfway, nothing in the database has changed: the account
// still signs in, and asking again deletes whatever is left. Step 3 is all or
// nothing. The username can then be taken again; the id never is
// (AUTOINCREMENT), so a new account never sees the old folder.
//
// Share links (Prompt 13) must be added to step 3 when they exist.

const deleteWord = "DELETE"

var errFolderNotEmpty = errors.New("objects left in the folder after deleting")

// handleDeleteAccount: POST /auth/account/delete {"password","confirm"}.
// Answers 204 and clears the session cookie.
func (s *server) handleDeleteAccount(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Password string `json:"password"`
		Confirm  string `json:"confirm"`
	}
	if !readJSON(w, r, &body, `{"password":"...","confirm":"DELETE"}`) {
		return
	}
	u := userFrom(r)
	ctx := r.Context()
	if strings.TrimSpace(body.Confirm) != deleteWord {
		writeError(w, http.StatusBadRequest, `type DELETE (in capitals) to confirm`)
		return
	}
	// 403, not 401: the session is fine, and 401 would sign the page out.
	if !s.passwordMatches(ctx, u.id, body.Password) {
		writeError(w, http.StatusForbidden, "your password is wrong")
		return
	}

	var inFlight int
	if err := s.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM files WHERE user_id = ? AND confirmed_at = 0 AND created_at > ?`,
		u.id, time.Now().Add(-ledgerGrace).Unix()).Scan(&inFlight); err != nil {
		log.Printf("delete account %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not delete the account")
		return
	}
	if inFlight > 0 {
		writeError(w, http.StatusConflict, "an upload is still in progress; let it finish or cancel it, then try again")
		return
	}

	if err := s.emptyUserFolder(ctx, u.id); err != nil {
		log.Printf("delete account %d: empty folder: %v", u.id, err)
		writeError(w, http.StatusBadGateway, "could not delete all your files; nothing else was changed, so try again")
		return
	}
	if err := s.deleteAccountRows(ctx, u.id); err != nil {
		log.Printf("delete account %d: rows: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "your files are deleted, but the account could not be; try again")
		return
	}
	s.syncedAt.Delete(u.id)
	log.Printf("account %d deleted", u.id)

	if u.email != "" {
		s.sendMail(deletedMessage(u.email, u.username))
	}
	http.SetCookie(w, s.sessionCookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}

// emptyUserFolder deletes every version and hide marker under u/<id>/, then
// checks that nothing is left.
func (s *server) emptyUserFolder(ctx context.Context, userID int64) error {
	prefix := userPrefix(userID)
	for pass := 0; pass < 2; pass++ {
		type ver struct{ key, id string }
		var all []ver
		input := &s3.ListObjectVersionsInput{Bucket: aws.String(s.cfg.bucket), Prefix: aws.String(prefix)}
		for {
			page, err := s.client.ListObjectVersions(ctx, input)
			if err != nil {
				return fmt.Errorf("list versions: %w", err)
			}
			for _, v := range page.Versions {
				all = append(all, ver{aws.ToString(v.Key), aws.ToString(v.VersionId)})
			}
			for _, m := range page.DeleteMarkers {
				all = append(all, ver{aws.ToString(m.Key), aws.ToString(m.VersionId)})
			}
			if !aws.ToBool(page.IsTruncated) {
				break
			}
			input.KeyMarker = page.NextKeyMarker
			input.VersionIdMarker = page.NextVersionIdMarker
		}
		if len(all) == 0 {
			return nil
		}
		if pass == 1 {
			return fmt.Errorf("%w: %d versions", errFolderNotEmpty, len(all))
		}
		// One DeleteObject per version, as in deleteAllVersions.
		for _, v := range all {
			if _, err := s.client.DeleteObject(ctx, &s3.DeleteObjectInput{
				Bucket:    aws.String(s.cfg.bucket),
				Key:       aws.String(v.key),
				VersionId: aws.String(v.id),
			}); err != nil {
				return fmt.Errorf("delete %q version %s: %w", v.key, v.id, err)
			}
		}
	}
	return nil
}

// deleteAccountRows removes the account and everything that points at it, in
// one transaction. The foreign keys would cascade, but each table is named so
// a table added later without ON DELETE CASCADE can't be missed silently.
func (s *server) deleteAccountRows(ctx context.Context, userID int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, q := range []string{
		`DELETE FROM sessions WHERE user_id = ?`,
		`DELETE FROM otps WHERE user_id = ?`,
		`DELETE FROM mail_log WHERE user_id = ?`,
		`DELETE FROM files WHERE user_id = ?`,
		`DELETE FROM users WHERE id = ?`,
	} {
		if _, err := tx.ExecContext(ctx, q, userID); err != nil {
			return err
		}
	}
	return tx.Commit()
}
