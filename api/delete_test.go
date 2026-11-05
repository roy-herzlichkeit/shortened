package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

func deleteBody(password, word string) string {
	return fmt.Sprintf(`{"password":%q,"confirm":%q}`, password, word)
}

// rowsFor counts the rows that still point at user id, per table.
func rowsFor(t *testing.T, s *server, id int64) map[string]int {
	t.Helper()
	out := map[string]int{}
	for _, q := range []struct{ table, query string }{
		{"users", `SELECT COUNT(*) FROM users WHERE id = ?`},
		{"shares", `SELECT COUNT(*) FROM shares WHERE user_id = ?`},
		{"sessions", `SELECT COUNT(*) FROM sessions WHERE user_id = ?`},
		{"files", `SELECT COUNT(*) FROM files WHERE user_id = ?`},
		{"otps", `SELECT COUNT(*) FROM otps WHERE user_id = ?`},
		{"mail_log", `SELECT COUNT(*) FROM mail_log WHERE user_id = ?`},
	} {
		var n int
		if err := s.db.QueryRow(q.query, id).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			out[q.table] = n
		}
	}
	return out
}

// Deleting an account removes every version in B2 and every row, ends the
// sessions and mails a confirmation; the username is free again afterwards and
// the new account gets a new id and an empty folder.
func TestDeleteAccount(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)
	c := signup(t, h, "alice")
	other := sessionFrom(t, do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery")))
	id := userID(t, s, "alice")
	prefix := userPrefix(id)

	k1 := stores(t, h, b2, c, "one.txt", 100)
	stores(t, h, b2, c, "two.txt", 200)
	b2.put(k1, 150, time.Now()) // an older version under the newest
	b2.put(prefix+"0000000000000000-hidden.txt", 5, time.Now())
	b2.hide(prefix + "0000000000000000-hidden.txt")
	do(t, h, http.MethodPost, "/auth/forgot", `{"login":"alice"}`) // leaves an otp and a mail_log row
	link := mustShare(t, h, c, k1, 3600)
	bob := signup(t, h, "bob")
	bobKey := stores(t, h, b2, bob, "bobs.txt", 10)

	if rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "delete"), withCookie(c)); rec.Code != http.StatusBadRequest {
		t.Errorf("lower-case word: status %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("wrong password", "DELETE"), withCookie(c)); rec.Code != http.StatusForbidden {
		t.Errorf("wrong password: status %d, want 403", rec.Code)
	}
	if n := b2.count(prefix); n != 3 {
		t.Fatalf("refused deletes touched the bucket: %d keys left, want 3", n)
	}

	rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "DELETE"), withCookie(c))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("delete: status %d, body %s", rec.Code, rec.Body)
	}
	if n := b2.count(prefix); n != 0 {
		t.Errorf("%d keys left under %s, want 0", n, prefix)
	}
	if !b2.has(bobKey) {
		t.Error("another user's file was deleted")
	}
	if res := visit(t, h, link.Path); res.StatusCode != http.StatusNotFound {
		t.Errorf("share link after the account was deleted: status %d, want 404", res.StatusCode)
	}
	if left := rowsFor(t, s, id); len(left) != 0 {
		t.Errorf("rows left for the deleted account: %v", left)
	}
	for name, ck := range map[string]*http.Cookie{"this": c, "other": other} {
		if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(ck)); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s session after delete: status %d, want 401", name, rec.Code)
		}
	}
	if rec := do(t, h, http.MethodPost, "/auth/login", creds("alice", "correct horse battery")); rec.Code != http.StatusUnauthorized {
		t.Errorf("login after delete: status %d, want 401", rec.Code)
	}
	ms := s.mails(t, "alice@example.test")
	if len(ms) == 0 || !strings.Contains(ms[len(ms)-1].subject, "deleted") {
		t.Errorf("no confirmation mail (%d mails to alice)", len(ms))
	}

	// The same username and address sign up again: a new id, an empty folder.
	c2 := signup(t, h, "alice")
	id2 := userID(t, s, "alice")
	if id2 == id {
		t.Errorf("new account reused id %d", id)
	}
	files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(c2)))
	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c2)))
	if me.UsedBytes != 0 || len(files) != 0 {
		t.Errorf("new account sees used %d and %d files, want an empty folder", me.UsedBytes, len(files))
	}
}

// B2 failing partway: nothing in the database changes, the account still
// works, and asking again finishes the job.
func TestDeleteAccountRetryAfterB2Failure(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	s.limiter = newIPLimiter(time.Millisecond, 100)
	c := signup(t, h, "alice")
	id := userID(t, s, "alice")
	for i := 0; i < 4; i++ {
		stores(t, h, b2, c, fmt.Sprintf("f%d.txt", i), 10)
	}

	b2.failDeletesAfter(2)
	rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "DELETE"), withCookie(c))
	if rec.Code != http.StatusBadGateway || !strings.Contains(rec.Body.String(), "try again") {
		t.Fatalf("delete with B2 failing: status %d, body %s; want 502", rec.Code, rec.Body)
	}
	if n := b2.count(userPrefix(id)); n != 2 {
		t.Errorf("%d keys left after the partial delete, want 2", n)
	}
	if left := rowsFor(t, s, id); left["users"] != 1 || left["sessions"] != 1 || left["files"] != 4 {
		t.Errorf("rows after the failed delete: %v; want the account untouched", left)
	}
	if rec := do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)); rec.Code != http.StatusOK {
		t.Errorf("session after the failed delete: status %d, want 200", rec.Code)
	}

	b2.failDeletesAfter(-1)
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "DELETE"), withCookie(c)); rec.Code != http.StatusNoContent {
		t.Fatalf("retry: status %d, body %s", rec.Code, rec.Body)
	}
	if n := b2.count(userPrefix(id)); n != 0 {
		t.Errorf("%d keys left after the retry, want 0", n)
	}
	if left := rowsFor(t, s, id); len(left) != 0 {
		t.Errorf("rows left after the retry: %v", left)
	}
}

// While an upload link is out, its bytes could land after the folder was
// emptied, so deletion waits for it.
func TestDeleteAccountWaitsForUpload(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	id := userID(t, s, "alice")
	up := mustUpload(t, h, c, "pending.bin", 10, "")
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "DELETE"), withCookie(c)); rec.Code != http.StatusConflict {
		t.Errorf("delete during an upload: status %d, want 409", rec.Code)
	}
	b2.put(up.Key, 10, time.Now())
	post(t, h, c, "/files/confirm", up.Key)
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", deleteBody("correct horse battery", "DELETE"), withCookie(c)); rec.Code != http.StatusNoContent {
		t.Errorf("delete after the upload finished: status %d, body %s", rec.Code, rec.Body)
	}
	if n := b2.count(userPrefix(id)); n != 0 {
		t.Errorf("%d keys left, want 0", n)
	}
}

func TestDeleteAccountRateLimited(t *testing.T) {
	s, h := newTestServer(t, testConfig(testEndpoint))
	s.limiter = newIPLimiter(time.Hour, 10) // never refills during the test
	for i := 0; i < 10; i++ {
		do(t, h, http.MethodPost, "/auth/account/delete", `{}`, withRemoteAddr("192.0.2.11:1"))
	}
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", `{}`, withRemoteAddr("192.0.2.11:1")); rec.Code != http.StatusTooManyRequests {
		t.Errorf("11th delete from one IP: status %d, want 429", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/auth/account/delete", `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("delete without a session: status %d, want 401", rec.Code)
	}
}

func TestDeletedMailBody(t *testing.T) {
	m := deletedMessage("a@example.test", "alice")
	if !strings.Contains(m.text, "alice") || strings.Contains(m.html, "http") || strings.Contains(m.text, "http") {
		t.Errorf("deleted mail should name the account and carry no links:\n%s", m.text)
	}
}
