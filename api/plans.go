package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"
	"strings"
	"time"
)

// Plans. Every account is on one of two, for life:
//
//   - free: the QUOTA_MB quota (500 MB), files up to 50 MB each and share
//     links up to 7 days;
//   - corpo: 5 GB, files of any size within it (up to the 5,000,000,000
//     bytes B2 takes in one upload), links up to 30 days, a CORPO badge and
//     a red theme.
//     The coupon is the only way to it (buying was dropped).
//
// The plan is read with the session on every request, so a change applies at
// once. The coupon code comes from PROMO_CODE (SSM /<Env>/PROMO_CODE) and is
// never in the repo; without it the coupon is off.

const (
	planFree  = "free"
	planCorpo = "corpo"

	corpoQuota    = 5 << 30 // 5 GB
	corpoShareTTL = 30 * 24 * time.Hour
	corpoMaxFile  = 5_000_000_000 // the most B2 accepts in a single PUT
)

func paidPlan(plan string) bool { return plan == planCorpo }

// quotaFor is the account's storage limit in bytes.
func (s *server) quotaFor(u user) int64 {
	if paidPlan(u.plan) {
		return corpoQuota
	}
	return s.cfg.quotaBytes
}

// maxFileFor is the largest single file the account may upload.
func (s *server) maxFileFor(u user) int64 {
	if paidPlan(u.plan) {
		return corpoMaxFile
	}
	return maxUploadSize
}

// maxShareTTL is the longest share link the account may make.
func (s *server) maxShareTTL(u user) time.Duration {
	if paidPlan(u.plan) {
		return corpoShareTTL
	}
	return freeShareTTL
}

// couponMatches compares code with PROMO_CODE ignoring case and surrounding
// spaces. Both sides are hashed first, so the comparison takes the same time
// whatever the input's length or how much of it matches.
func (s *server) couponMatches(code string) bool {
	if s.cfg.promoCode == "" {
		return false
	}
	got := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(code))))
	want := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s.cfg.promoCode))))
	return subtle.ConstantTimeCompare(got[:], want[:]) == 1
}

// handleCoupon: POST /auth/coupon {"code"} → 200 {"plan","quotaBytes",
// "shareMaxSeconds"}. Once per account; wrong → 400, used → 409, no coupon
// configured → 404.
func (s *server) handleCoupon(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
	}
	if !readJSON(w, r, &body, `{"code":"..."}`) {
		return
	}
	u := userFrom(r)
	if s.cfg.promoCode == "" {
		writeError(w, http.StatusNotFound, "there is no coupon to redeem right now")
		return
	}
	if u.couponAt > 0 {
		writeError(w, http.StatusConflict, "this account has already used the coupon")
		return
	}
	if strings.TrimSpace(body.Code) == "" || !s.couponMatches(body.Code) {
		writeError(w, http.StatusBadRequest, "that coupon code isn't valid")
		return
	}
	// coupon_at = 0 in the WHERE makes a second, parallel try a no-op.
	res, err := s.db.ExecContext(r.Context(),
		`UPDATE users SET plan = ?, coupon_at = ? WHERE id = ? AND coupon_at = 0`, planCorpo, time.Now().Unix(), u.id)
	if err != nil {
		log.Printf("coupon for user %d: %v", u.id, err)
		writeError(w, http.StatusInternalServerError, "could not apply the coupon")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		writeError(w, http.StatusConflict, "this account has already used the coupon")
		return
	}
	log.Printf("account %d redeemed the coupon", u.id)
	u.plan = planCorpo
	writeJSON(w, http.StatusOK, map[string]any{
		"plan":            u.plan,
		"quotaBytes":      s.quotaFor(u),
		"shareMaxSeconds": int64(s.maxShareTTL(u) / time.Second),
	})
}

// planCounts returns how many accounts there are, and how many are corpo.
func (s *server) planCounts(ctx context.Context) (users, corpo int, err error) {
	err = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN plan = 'corpo' THEN 1 ELSE 0 END), 0)
		FROM users`).Scan(&users, &corpo)
	return users, corpo, err
}

// logDailyCounts writes the counts at start and then once a day, until ctx
// ends. There is no admin page; this line is the report.
func (s *server) logDailyCounts(ctx context.Context) {
	report := func() {
		users, corpo, err := s.planCounts(ctx)
		if err != nil {
			log.Printf("daily counts: %v", err)
			return
		}
		log.Printf("daily: %d users, %d corpo", users, corpo)
	}
	report()
	t := time.NewTicker(24 * time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			report()
		}
	}
}
