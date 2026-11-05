package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Tests for keeping the quota ledger equal to what is really in the bucket:
// confirm, release, deletions made outside the app, and name clashes.

func requestUpload(t *testing.T, h http.Handler, c *http.Cookie, name string, size int64, onConflict string) *httptest.ResponseRecorder {
	t.Helper()
	body := fmt.Sprintf(`{"filename":%q,"size":%d,"onConflict":%q}`, name, size, onConflict)
	return do(t, h, http.MethodPost, "/upload-url", body, withCookie(c))
}

func mustUpload(t *testing.T, h http.Handler, c *http.Cookie, name string, size int64, onConflict string) uploadResponse {
	t.Helper()
	rec := requestUpload(t, h, c, name, size, onConflict)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload-url %s: status %d, body %s", name, rec.Code, rec.Body)
	}
	return decode[uploadResponse](t, rec)
}

func post(t *testing.T, h http.Handler, c *http.Cookie, path, key string) *httptest.ResponseRecorder {
	t.Helper()
	return do(t, h, http.MethodPost, path+"?key="+url.QueryEscape(key), "", withCookie(c))
}

func usedNow(t *testing.T, h http.Handler, c *http.Cookie) int64 {
	t.Helper()
	return decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c))).UsedBytes
}

// stores runs the whole happy path: reserve, PUT, confirm.
func stores(t *testing.T, h http.Handler, b2 *fakeB2, c *http.Cookie, name string, size int64) string {
	t.Helper()
	up := mustUpload(t, h, c, name, size, "")
	b2.put(up.Key, size, time.Now())
	if rec := post(t, h, c, "/files/confirm", up.Key); rec.Code != http.StatusOK {
		t.Fatalf("confirm %s: status %d, body %s", name, rec.Code, rec.Body)
	}
	return up.Key
}

// agoLedger moves every confirmation two seconds into the past. A row
// confirmed in the same second a listing starts is kept by that listing on
// purpose (see syncFiles), and tests run faster than a person reloads a page.
func agoLedger(t *testing.T, s *server) {
	t.Helper()
	if _, err := s.db.Exec(`UPDATE files SET confirmed_at = confirmed_at - 2 WHERE confirmed_at > 0`); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmUpload(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	up := mustUpload(t, h, c, "a.txt", 1000, "")
	b2.put(up.Key, 1000, time.Now())
	rec := post(t, h, c, "/files/confirm", up.Key)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm: status %d, body %s", rec.Code, rec.Body)
	}
	if u := decode[usageResponse](t, rec); u.UsedBytes != 1000 || u.QuotaBytes != 500<<20 {
		t.Errorf("confirm answered %+v, want 1000 of 500 MB", u)
	}
	var confirmedAt int64
	s.db.QueryRow(`SELECT confirmed_at FROM files WHERE key = ?`, up.Key).Scan(&confirmedAt)
	if confirmedAt == 0 {
		t.Error("row not marked confirmed")
	}

	// Confirming an upload that never reached the bucket drops it at once.
	lost := mustUpload(t, h, c, "lost.txt", 4000, "")
	if rec := post(t, h, c, "/files/confirm", lost.Key); rec.Code != http.StatusNotFound {
		t.Errorf("confirm without object: status %d, want 404", rec.Code)
	}
	if used := usedNow(t, h, c); used != 1000 {
		t.Errorf("used = %d, want 1000", used)
	}

	// Storage that can't be reached: the reservation stays for a retry.
	busy := mustUpload(t, h, c, "later.txt", 50, "")
	b2.setHeadFail(true)
	if rec := post(t, h, c, "/files/confirm", busy.Key); rec.Code != http.StatusBadGateway {
		t.Errorf("confirm with storage down: status %d, want 502", rec.Code)
	}
	b2.setHeadFail(false)
	if used := usedNow(t, h, c); used != 1050 {
		t.Errorf("used = %d, want 1050 (reservation kept)", used)
	}

	bob := signup(t, h, "bob")
	if rec := post(t, h, bob, "/files/confirm", up.Key); rec.Code != http.StatusNotFound {
		t.Errorf("bob confirms alice's key: status %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/files/confirm?key="+url.QueryEscape(up.Key), "", withCookie(c)); rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET confirm: status %d, want 405", rec.Code)
	}
}

// A PUT that failed: the browser calls release and the space is free at once,
// not after the reservation window.
func TestReleaseFailedPut(t *testing.T) {
	_, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	up := mustUpload(t, h, c, "big.bin", 40<<20, "")
	if used := usedNow(t, h, c); used != 40<<20 {
		t.Fatalf("used after reserve = %d", used)
	}
	rec := post(t, h, c, "/files/release", up.Key)
	if rec.Code != http.StatusOK {
		t.Fatalf("release: status %d, body %s", rec.Code, rec.Body)
	}
	if u := decode[usageResponse](t, rec); u.UsedBytes != 0 {
		t.Errorf("release answered used = %d, want 0", u.UsedBytes)
	}
	// The name is free again too.
	mustUpload(t, h, c, "big.bin", 1, "")
}

// A cancelled PUT whose bytes still landed: release must not lose the file.
func TestReleaseCancelledButStored(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	up := mustUpload(t, h, c, "a.txt", 700, "")
	b2.put(up.Key, 700, time.Now())
	if rec := post(t, h, c, "/files/release", up.Key); rec.Code != http.StatusOK {
		t.Fatalf("release: status %d", rec.Code)
	}
	if used := usedNow(t, h, c); used != 700 {
		t.Errorf("used = %d, want 700: the object is in the bucket", used)
	}

	// Releasing a confirmed file is a no-op.
	key := stores(t, h, b2, c, "b.txt", 300)
	post(t, h, c, "/files/release", key)
	if used := usedNow(t, h, c); used != 1000 {
		t.Errorf("used = %d, want 1000 after releasing a stored file", used)
	}
}

// A file deleted in B2 behind the app's back stops counting on the next page
// load, and a download of it gets a clear 404.
func TestObjectDeletedInBucket(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	gone := stores(t, h, b2, c, "gone.txt", 2000)
	stores(t, h, b2, c, "kept.txt", 10)
	b2.drop(gone)

	rec := do(t, h, http.MethodGet, "/download-url?key="+url.QueryEscape(gone), "", withCookie(c))
	if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "no longer in storage") {
		t.Errorf("download: status %d, body %s; want 404 no longer in storage", rec.Code, rec.Body)
	}
	if used := usedNow(t, h, c); used != 10 {
		t.Errorf("used after the download check = %d, want 10", used)
	}

	// The same through the listing, which the page does on load.
	other := stores(t, h, b2, c, "other.txt", 500)
	b2.drop(other)
	agoLedger(t, s) // the page loads later, not in the second of the confirm
	files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(c)))
	if len(files) != 1 || files[0].Name != "kept.txt" {
		t.Errorf("files = %+v, want only kept.txt", files)
	}
	if used := usedNow(t, h, c); used != 10 {
		t.Errorf("used after listing = %d, want 10", used)
	}

	// A HEAD that fails for another reason doesn't touch the ledger.
	b2.setHeadFail(true)
	if rec := do(t, h, http.MethodGet, "/download-url?key="+url.QueryEscape(files[0].Key), "", withCookie(c)); rec.Code != http.StatusBadGateway {
		t.Errorf("download with storage down: status %d, want 502", rec.Code)
	}
	b2.setHeadFail(false)
	if used := usedNow(t, h, c); used != 10 {
		t.Errorf("used = %d, want 10", used)
	}
}

// Ten reservations at once can't overrun the quota.
func TestParallelReservations(t *testing.T) {
	_, endpoint := newFakeB2(t)
	cfg := testConfig(endpoint)
	cfg.quotaBytes = 1 << 20
	_, h := newTestServer(t, cfg)
	c := signup(t, h, "alice")

	codes := make([]int, 10)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = requestUpload(t, h, c, fmt.Sprintf("f%d.bin", i), 200_000, "").Code
		}(i)
	}
	wg.Wait()
	ok := 0
	for _, code := range codes {
		switch code {
		case http.StatusOK:
			ok++
		case http.StatusRequestEntityTooLarge:
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if ok != 5 {
		t.Errorf("%d reservations granted, want 5 (5 x 200000 fits in 1 MiB, 6 doesn't)", ok)
	}
	if used := usedNow(t, h, c); used > cfg.quotaBytes {
		t.Errorf("used %d is over the quota %d", used, cfg.quotaBytes)
	}

	// Ten tabs uploading the same name at once: one wins, the rest are told
	// another upload is in progress.
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			codes[i] = requestUpload(t, h, c, "same.txt", 1, "").Code
		}(i)
	}
	wg.Wait()
	ok = 0
	for _, code := range codes {
		if code == http.StatusOK {
			ok++
		} else if code != http.StatusConflict {
			t.Errorf("same name: unexpected status %d", code)
		}
	}
	if ok != 1 {
		t.Errorf("same name: %d reservations granted, want 1", ok)
	}
}

func TestSameName(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	cfg := testConfig(endpoint)
	cfg.quotaBytes = 1 << 20
	s, h := newTestServer(t, cfg)
	c := signup(t, h, "alice")

	old := stores(t, h, b2, c, "a.txt", 800_000)

	// Asking: 409 with what "Keep both" would store.
	rec := requestUpload(t, h, c, "a.txt", 10, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("same name: status %d, want 409", rec.Code)
	}
	if cr := decode[conflictResponse](t, rec); !cr.Conflict || cr.Name != "a.txt" || cr.Suggestion != "a-1.txt" {
		t.Errorf("conflict = %+v", cr)
	}

	// Keep both: stored under the next free name.
	kb := mustUpload(t, h, c, "a.txt", 10, onConflictKeepBoth)
	if kb.Name != "a-1.txt" || displayName(kb.Key) != "a-1.txt" {
		t.Errorf("keep both stored %q", kb.Name)
	}
	post(t, h, c, "/files/release", kb.Key)
	b2.put(userPrefix(userID(t, s, "alice"))+"1111111111111111-a-1.txt", 1, time.Now())
	if kb2 := mustUpload(t, h, c, "a.txt", 10, onConflictKeepBoth); kb2.Name != "a-2.txt" {
		t.Errorf("keep both with a-1.txt taken stored %q, want a-2.txt", kb2.Name)
	} else {
		post(t, h, c, "/files/release", kb2.Key)
	}

	// While a Replace is in flight, a second tab can't take the name.
	rp := mustUpload(t, h, c, "a.txt", 900_000, onConflictReplace) // fits: a.txt's 800000 is credited
	for _, mode := range []string{"", onConflictReplace} {
		rec := requestUpload(t, h, c, "a.txt", 1, mode)
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "in progress") {
			t.Errorf("second tab (%q): status %d, body %s; want 409 in progress", mode, rec.Code, rec.Body)
		}
	}

	b2.put(rp.Key, 900_000, time.Now())
	rec = post(t, h, c, "/files/confirm", rp.Key)
	if rec.Code != http.StatusOK {
		t.Fatalf("confirm replace: status %d", rec.Code)
	}
	if b2.stored(old) != 0 {
		t.Error("the replaced file is still in the bucket")
	}
	if u := decode[usageResponse](t, rec); u.UsedBytes != 900_000+1 {
		t.Errorf("used after replace = %d, want 900001 (new a.txt + a-1.txt)", u.UsedBytes)
	}
	files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(c)))
	n := 0
	for _, f := range files {
		if f.Name == "a.txt" {
			n++
			if f.Key != rp.Key {
				t.Errorf("a.txt is %s, want the new upload", f.Key)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d files named a.txt, want 1", n)
	}
}

// If the browser never confirms a Replace, the next listing finishes it.
func TestReplaceFinishedByListing(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	old := stores(t, h, b2, c, "a.txt", 100)
	rp := mustUpload(t, h, c, "a.txt", 200, onConflictReplace)
	b2.put(rp.Key, 200, time.Now())

	files := decode[[]fileInfo](t, do(t, h, http.MethodGet, "/files", "", withCookie(c)))
	if len(files) != 1 || files[0].Key != rp.Key {
		t.Errorf("files = %+v, want only the new a.txt", files)
	}
	if b2.stored(old) != 0 {
		t.Error("the replaced file is still in the bucket")
	}
	if used := usedNow(t, h, c); used != 200 {
		t.Errorf("used = %d, want 200", used)
	}
}

func TestUploadNameRules(t *testing.T) {
	_, endpoint := newFakeB2(t)
	_, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")

	if up := mustUpload(t, h, c, "my holiday photo.jpg", 1, ""); up.Name != "my-holiday-photo.jpg" {
		t.Errorf("spaces: stored %q", up.Name)
	}
	if up := mustUpload(t, h, c, "photo (1)!.jpg", 1, ""); up.Name != "photo-1.jpg" {
		t.Errorf("bad characters: stored %q, want them dropped", up.Name)
	}
	rec := requestUpload(t, h, c, "(!)", 1, "")
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "letter or digit") {
		t.Errorf("nothing left after cleaning: status %d, body %s", rec.Code, rec.Body)
	}
	if rec := requestUpload(t, h, c, "a.txt", 1, "overwrite"); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown onConflict: status %d, want 400", rec.Code)
	}
}

// /auth/me checks the ledger against the bucket before reporting usage, so
// the meter shows what B2 really holds, and it reports stored and reserved
// bytes apart.
func TestMeMatchesBucket(t *testing.T) {
	b2, endpoint := newFakeB2(t)
	s, h := newTestServer(t, testConfig(endpoint))
	c := signup(t, h, "alice")
	var id int64
	if err := s.db.QueryRow(`SELECT id FROM users WHERE username = 'alice'`).Scan(&id); err != nil {
		t.Fatal(err)
	}

	stores(t, h, b2, c, "kept.txt", 100)
	gone := stores(t, h, b2, c, "gone.txt", 2000)
	mustUpload(t, h, c, "pending.txt", 300, "") // a link signed, nothing uploaded yet
	b2.drop(gone)
	agoLedger(t, s)

	// Within syncEvery of the last check the ledger is used as it is.
	me := decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if me.StoredBytes != 2100 || me.ReservedBytes != 300 || me.UsedBytes != 2400 {
		t.Errorf("me before the check is due = %+v, want stored 2100, reserved 300, used 2400", me)
	}

	// Once the check is due, /auth/me alone drops the file B2 no longer has.
	s.syncedAt.Delete(id)
	me = decode[meResponse](t, do(t, h, http.MethodGet, "/auth/me", "", withCookie(c)))
	if me.StoredBytes != 100 || me.ReservedBytes != 300 || me.UsedBytes != 400 {
		t.Errorf("me after the check = %+v, want stored 100, reserved 300, used 400", me)
	}

	// Confirm and release answer the same split.
	u := decode[usageResponse](t, post(t, h, c, "/files/release", mustUpload(t, h, c, "x.txt", 50, "").Key))
	if u.StoredBytes != 100 || u.ReservedBytes != 300 || u.UsedBytes != 400 {
		t.Errorf("release answered %+v, want stored 100, reserved 300, used 400", u)
	}
}
