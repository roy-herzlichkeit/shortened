# CODE_NOTES

SHORTENED. is a file-sharing app with user accounts. A Go server serves the
page, manages accounts, and only ever *signs* URLs. A Backblaze B2 bucket holds
the bytes, and a SQLite file holds accounts, sessions and storage usage.

## Files

| Path | What it is |
| --- | --- |
| [api/main.go](api/main.go) | Config, B2 client, routes, the page handler with its CSP, and graceful shutdown. |
| [api/signup.go](api/signup.go) | Two-step sign-up: a pending request and its code, then the account. |
| [api/auth.go](api/auth.go) | Sign-in and sign-out, sessions, the `requireUser` and `sameOrigin` middleware, and the per-IP rate limiter. |
| [api/files.go](api/files.go) | Upload/download signing, listing, delete, the quota ledger, and key and filename rules. |
| [api/store.go](api/store.go) | Opens SQLite and creates the schema. |
| [api/main_test.go](api/main_test.go) | Tests against a real SQLite file and an in-process fake S3 endpoint. |
| [web/](web/) | `index.html`, `style.css` and `app.js`, embedded into the binary by `embed.go`. No build step. |
| [Dockerfile](Dockerfile) | Multi-stage build (`golang:1.27-alpine` → `alpine:3.20`), `CGO_ENABLED=0`, non-root, `/data` volume for the database, `HEALTHCHECK`. |
| [.env.example](.env.example) | Every environment variable, with fake values and an explanation of each. |
| [.github/workflows/ci.yml](.github/workflows/ci.yml) | Runs on every push to `main` and every PR. Five jobs: **Go** (tidy and `mod verify`, gofmt, vet, staticcheck, gosec, `go test -race` with coverage, static linux build); **vulns** (govulncheck); **docker** (hadolint, image build, healthy HEALTHCHECK, non-root user, end-to-end smoke test of sign-up, sessions, CSRF and signing, accounts surviving a restart, clean exit on SIGTERM); **web** (html-validate, the script parses, no inline scripts, no HTML built from strings, no auth in browser storage); **secrets** (gitleaks, no committed `.env`). |
| [.github/workflows/codeql.yml](.github/workflows/codeql.yml) | CodeQL `security-and-quality` for Go and JavaScript, on push, PR and weekly. |
| [.github/dependabot.yml](.github/dependabot.yml) | Weekly update PRs for Go modules, Docker base images and Actions. |
| [.htmlvalidate.json](.htmlvalidate.json) / [.gitleaks.toml](.gitleaks.toml) | Linter configs. Each turns off one false positive, with the reason in the file. |

## Endpoints

| Method and path | Auth | Does |
| --- | --- | --- |
| `GET /`, `/app.js`, `/style.css` | none | The page, with a strict CSP. |
| `GET /health` | none | `{"status":"ok"}` once the database answers. |
| `POST /auth/signup` | none, rate-limited | `{"username","password","email"}` → `202 {"username","pendingEmail"}`. Stores a pending sign-up (no account yet), mails its code and sets the `signup` cookie (HttpOnly, path `/auth/signup`, 1 hour). Name taken → `409`; over 3 mails an hour to the address → `429`; mail refused → `502` and nothing is kept. |
| `POST /auth/signup/verify` | `signup` cookie, rate-limited | `{"code"}` → `201 {"username"}`: creates the account with its address verified and sets the session cookie. Wrong or expired code → `400`; name or address taken meanwhile → `409`; no pending sign-up → `410`. |
| `POST /auth/signup/resend` | `signup` cookie, rate-limited | Mails a new code → `202 {"pendingEmail"}`. Same `429`, `502` and `410` as above. |
| `GET /auth/signup/pending` | `signup` cookie | `200 {"username","pendingEmail"}` or `404`; lets the page pick a sign-up back up after a reload. |
| `POST /auth/login` | none, rate-limited | `{"username","password"}`, where `username` may also be the verified email → `200`, sets the session cookie. |
| `POST /auth/logout` | cookie | Ends this session → `204`. |
| `GET /auth/me` | cookie | `{"username","email","pendingEmail","verified","usedBytes","storedBytes","reservedBytes","quotaBytes"}`. First checks the ledger against the bucket (at most every 30 s per user), so `storedBytes` is what B2 holds; `reservedBytes` is held by upload links not yet confirmed; `usedBytes` is their sum, which the quota counts. |
| `POST /auth/email` | cookie, rate-limited | `{"email","password"}` → `202 {"pendingEmail"}`: mails a code to the address (first address, a new code, or a change; a change needs the password, else `403`). Over 3 mails an hour → `429`. |
| `POST /auth/email/verify` | cookie, rate-limited | `{"code"}` → `200 {"email"}`: the pending address becomes the account's. Wrong or expired → `400`. |
| `POST /auth/forgot` | none, rate-limited | `{"login"}` (username or email) → always `202` with the same message; a code goes to the verified address if there is one. |
| `POST /auth/reset` | none, rate-limited | `{"login","code","password"}` → `200`, sets the password, ends every session, starts a new one. Any failure → `400` "that code is wrong or has expired". |
| `POST /auth/password` | cookie, rate-limited | `{"current","password"}` → `204`, ends every other session. Wrong current password → `403`. |
| `POST /upload-url` | cookie | `{"filename","size","onConflict"}` → `{"key","url","name"}`, a presigned PUT. `onConflict` is `""` (ask), `"replace"` or `"keepboth"`. A name in use with `""` gets `409 {"error","conflict":true,"name","suggestion"}`; a name with an upload still in flight gets `409 {"error"}`; a refused name gets `400`; no room gets `413`. |
| `POST /files/confirm?key=` | cookie | After a successful PUT. HEADs the object, records its real size, finishes a Replace → `{"usedBytes","quotaBytes"}`. No object → `404`, and the reservation is dropped. |
| `POST /files/release?key=` | cookie | After a failed or cancelled PUT. Drops the reservation at once (or confirms it, if the object did land) → `{"usedBytes","quotaBytes"}`. Never drops a confirmed file. |
| `GET /files` | cookie | The user's own files, newest first: `[{"key","name","size","lastModified"}]`. Reconciles the ledger with the bucket. |
| `DELETE /files?key=` | cookie | Deletes one of the user's own files → `204`. |
| `GET /download-url?key=` | cookie | HEADs the object first. Present → `{"url"}`, a presigned GET that downloads as an attachment. Missing → `404 "this file is no longer in storage"`, and its ledger row goes. Storage unreachable → `502`. |

Errors are always `{"error": "..."}`. A missing or expired session gets `401`.
Someone else's key gets `404`, the same as a missing file.

## Request flow

```
browser --POST /auth/login {username,password}--> server: bcrypt check, new session
server  --Set-Cookie: session=<random>; HttpOnly; Secure; SameSite=Lax--> browser

browser --POST /upload-url {filename,size,onConflict} + cookie--> server
server: session -> user; size <= 50 MB; check the name;
        list u/<id>/ in B2 and reconcile the ledger;
        name in use? -> 409 (ask), or Keep both / Replace;
        used (- the replaced file) + size <= quota?
        reserve the size in the ledger; key = u/<user id>/<16 hex>-<name>;
        sign a PUT for that key and exact Content-Length, valid 10 minutes
server --{"key","url","name"}--> browser --PUT bytes--> B2 (never through the server)
browser --POST /files/confirm (PUT ok) or /files/release (PUT failed/cancelled)--> server
server: HEAD the object; confirm the row with its real size, or drop it;
        a confirmed Replace deletes the old file -> {"usedBytes","quotaBytes"}
```

## Why these choices

**Open sign-up, with limits.** Anyone can register, so each user has a quota
(`QUOTA_MB`, 500 by default) and `MAX_USERS` can cap the number of accounts.
Sign-in and sign-up allow 10 attempts per client IP, then one every 6 seconds,
which slows password guessing. Without these, strangers could fill the bucket
at the owner's expense.

**Accounts in SQLite, through a pure-Go driver.** `modernc.org/sqlite` needs
no C toolchain, so the build is still one static `CGO_ENABLED=0` binary. The
pool holds a single connection: that serializes every statement, so "check
the quota, then reserve" and "check the username, then insert" are atomic
inside ordinary transactions. Never use `s.db` while a transaction is open on
it, or the single connection deadlocks. In Docker the file is
`/data/shortened.db`, and without a volume on `/data` every restart deletes
all accounts.

**Passwords are hashed with bcrypt (cost 12).** Passwords must be 8-72 bytes,
because bcrypt silently ignores anything past 72. A login for an unknown user
still runs a bcrypt comparison against a dummy hash, and it gets the same
message as a wrong password. That way neither the timing nor the text reveals
which usernames exist. Usernames are 3-32 characters of `[a-z0-9_-]`,
lowercased and unique regardless of case.

**Sessions are random tokens in an HttpOnly cookie.** The token has 32 random
bytes. The database stores only its SHA-256, so a leaked database can't be
replayed as cookies. The cookie is `HttpOnly` (scripts can't read it),
`SameSite=Lax`, `Secure` unless `COOKIE_SECURE=false`, and lasts 30 days.
Sign-out deletes the row, and expired rows are swept at each sign-in.

**The server serves the page.** Page and API share one origin, so the cookie
needs no CORS and the old `API_KEY`/`ALLOWED_ORIGIN` settings are gone. The
page gets a strict CSP: scripts and styles from `'self'` only (plus Google
Fonts), `connect-src` limited to `'self'` and the B2 endpoint's origin, and no
framing. That's why the script lives in `app.js` rather than inline.

**CSRF protection.** `SameSite=Lax` keeps the cookie off cross-site POSTs and
DELETEs. `sameOrigin` also refuses any non-GET request whose `Origin` header
names another host. Requests without `Origin`, such as curl or scripts, carry
no ambient cookie, so they're allowed through.

**Each user's files are private.** Keys are `u/<user id>/<16 hex>-<name>`.
Listing asks B2 only for the user's prefix. Download and delete accept only
keys of exactly that shape inside the caller's own prefix, and anything else
gets `404`.

**The quota ledger.** The `files` table records the declared size as soon as
an upload URL is signed, so ten links requested at once can't exceed the quota
(the single connection serializes them). A row is a reservation until
`confirmed_at` is set, and then a stored file:

- after a successful PUT the page calls `/files/confirm`; the server HEADs the
  object and records its real size;
- after a failed or cancelled PUT the page calls `/files/release`, and the
  reservation goes at once; if the bytes landed anyway, it is confirmed;
- a reservation nobody confirms or releases (tab closed) is dropped once it is
  older than the link lifetime plus 15 minutes, as before;
- every listing (the page lists on load) and every upload request reconciles
  the table with the bucket: objects get a confirmed row with their real
  size, and a confirmed row whose object is gone (deleted in B2 by other means)
  goes at once. A row confirmed in the same second the listing started is
  left for the next listing, since the listing may have begun before its PUT;
- a download HEADs the object, and a missing one leaves the ledger then.

Databases from before this gain `confirmed_at` and `replaces` on open
(`migrateFilesColumns`, logged as `migration: files table gained ...`). Old
rows start unconfirmed and are confirmed by the first listing that sees them.

**File names.** New uploads may use only `A-Z a-z 0-9 . _ -`, up to 120
bytes, with at least one letter or digit. Spaces become `-`; anything else is
refused with a message naming the characters, by the page before asking and
by the server with `400` (`checkFilename`). Names stored under the old rule
stay as they are; they already fit the key pattern.

**Same name.** A name is in use if one of the user's stored files has it. The
server answers `409` with what Keep both would store (`<name>-<n>.<ext>`, the
smallest free `n`, `freeName`), and the page asks Replace / Keep both / Cancel.
The check runs in the reserving transaction, so two tabs can't both claim a
name: while one upload of a name is in flight, another gets `409` "still in
progress". Replace reserves under a new key with `replaces` naming the old
one, and the old file's size doesn't count for the quota check. When the new
upload is confirmed (or a listing sees it), the old file is deleted, every
version, and its row goes. Until then the old file is untouched, so a failed
Replace loses nothing.

**The upload size is signed.** The declared size goes into the presigned PUT
as `Content-Length`, so B2 refuses a body of any other size. That makes both
the 50 MB limit and the quota binding. The browser sets `Content-Length`
itself from the file.

**Downloads are attachments.** Presigned GETs carry
`response-content-disposition=attachment; filename="<name>"`. An uploaded HTML
or SVG file is therefore saved, not rendered on the bucket's origin.

**Delete removes every version.** B2 keeps old versions: a plain
`DeleteObject` only adds a hide marker, and the file stays stored and billed.
`deleteAllVersions` lists the key's versions and hide markers, following the
listing's markers across pages. It keeps only entries whose key matches
exactly, because listing works by prefix. It then deletes each one by
`VersionId`. Single `DeleteObject` calls are used because `DeleteObjects`
needs a request checksum, which this client deliberately doesn't send to B2.
As a backstop, the bucket has a lifecycle rule (`daysFromHidingToDeleting: 1`
on `u/`) that purges anything hidden by other means within about a day.

**B2 specifics.** `UsePathStyle` plus `B2_ENDPOINT` makes the SDK address
`endpoint/bucket/key`. `RequestChecksumCalculation = WhenRequired` stops the
SDK adding CRC32 headers, which B2 rejects with a 400.

**Rate limiting behind a proxy.** By default the limiter keys on the TCP peer
address. Behind a reverse proxy, every client would then share the proxy's
address, so `TRUST_PROXY=true` switches to the last `X-Forwarded-For` entry,
the one the proxy appended. Earlier entries are client-controlled and ignored.

**API responses are never cached.** Every API route sends
`Cache-Control: no-store`, errors included, because the answers are per user:
file lists, signed links, the session cookie. A CDN in front must still use a
no-caching policy (CloudFront: `CachingDisabled`), since a policy with a
minimum TTL above zero overrides the header. The page itself keeps
`no-cache`, as it holds nothing per user.

**Optional HTTPS on the server.** With `TLS_CERT_FILE` and `TLS_KEY_FILE`
set, the server speaks HTTPS on `PORT`, TLS 1.2 or newer. That lets a CDN
reach the origin encrypted without a separate proxy. A proxy in front would
append its own address to `X-Forwarded-For` and break the `TRUST_PROXY`
rule above. The files are read once at start-up, so restart the server after
renewing the certificate. With neither set, it's plain HTTP, as for local use.

**The look.** The design is a neon-noir theme: hard yellow `#fcee0a` on
near-black, cyan and red accents, cut-corner panels and buttons, Rajdhani and
Share Tech Mono from Google Fonts, scanlines and a glitch title. It's inspired
by the Cyberpunk 2077 site's style but uses none of its logos, artwork, fonts
or name. Animations stop under `prefers-reduced-motion`.

**User IDs are never reused.** `users.id` is `AUTOINCREMENT`, because
without it SQLite hands out the highest deleted ID again, and a new account
would see whatever was left in the old account's `u/<id>/` folder. Databases
created before this are rebuilt on open by `migrateUsersAutoincrement`: it
copies users into a new table with the same IDs, swaps it in with foreign keys
off, and runs `PRAGMA foreign_key_check` before committing. Opening an
already-migrated database does nothing.

**Email and codes (v2).** Mail goes through Amazon SES as
`no-reply@shortened.herzlichkeit-zero.click` (`api/mail.go`). The domain is
signed with Easy DKIM, and DMARC is `p=none` (`deploy/email.yaml`). Bodies are
plain text plus simple HTML, with no images, links or tracking. Locally and in
CI, `MAIL_LOG=true` writes each mail to the log instead.

- **The account is created only when the code is right.** `POST /auth/signup`
  stores a row in `signups` (username, password hash, address, code hash) and
  mails the code; there is no `users` row and no session yet.
  `POST /auth/signup/verify` with the right code creates the account, already
  verified, and signs it in. The username is not reserved while waiting: if
  someone else confirms the same name first, the later one gets `409` and
  signs up again. A pending sign-up lives 1 hour (each code 10 minutes).
  The sign-up mail is sent before answering, so an address SES refuses gets
  `502` "could not send the code" instead of a silent wait.
- `users.email` is the **verified** address only: unique, case-insensitive
  (`users_email` index), NULL until verified. `pending_email` holds an address
  waiting for its code. Keeping them apart means an address nobody has proved
  they own can't block the real owner. Files and links need a verified address
  (`requireVerified` → `403 {"needsEmail":true}`, and the page asks for it).
- Accounts from before email (migrated by `migrateUsersEmail`, logged as
  `migration: users table gained email, pending_email`) sign in as before, are
  asked for an address, and get their files back once it is verified.
- Codes are 6 random digits, stored only as a bcrypt hash in `otps`, one per
  account and purpose (`verify`, `reset`). A new code replaces the old one.
  Each lasts 10 minutes and allows 5 tries; the try is counted before the
  comparison. A reset code is void if the account's address has changed since.
- At most 3 mails an hour per account (`mail_log`), and 3 sign-up mails an
  hour per address (`signup_mail`). Every code and password
  endpoint shares the sign-in limiter (10 per IP, then one every 6 s).
- Nothing reveals whether an address or a username has an account. Forgot always
  gives the same `202` text. Signing up with an address another account has
  verified gives the usual `202`, and the owner gets a notice instead of a code
  (sent the same way, so it takes as long). Forgot and the address codes of
  existing accounts are sent in the background, so the response time doesn't
  depend on whether a mail went out, and an unknown login still spends one
  bcrypt.
- A reset sets the new password and ends **every** session; changing the
  password ends every **other** session.

## Known limits

- **SES sandbox.** Until AWS grants production access, SES only delivers to
  verified addresses (200 a day). The boundary then also names the test
  address, because the sandbox authorises the recipient identity too.
- **No account deletion.** Users can't delete their own accounts. The `files`
  rows cascade, but the objects in B2 would have to be removed separately.
- **Single process only.** The rate limiter is in memory and SQLite is a local
  file. Running several copies needs a shared limiter and a server database.
- **Coarse limits.** The rate limit is per IP, not per account, so a botnet
  could still spread password guesses across many addresses.

## Environment variables

Required: `B2_KEY_ID`, `B2_APP_KEY`, `B2_ENDPOINT`, `B2_REGION`, `B2_BUCKET`.
Optional, with defaults:

- `PORT` = `8080`
- `DB_PATH` = `shortened.db`
- `QUOTA_MB` = `500`
- `MAX_USERS` = `0`, meaning no limit
- `COOKIE_SECURE` = `true`
- `TRUST_PROXY` = `false`
- `TLS_CERT_FILE`, `TLS_KEY_FILE` = empty, meaning plain HTTP. Set both to
  serve HTTPS; setting only one stops the server at start-up.
- `MAIL_FROM` = empty. When set, mail goes through SES as this address.
- `SES_REGION` = `us-east-1`
- `MAIL_LOG` = `false`. `true` logs mail instead (local and CI only). One of
  `MAIL_FROM` or `MAIL_LOG=true` is required.

See `.env.example` for what each one does.

## Running it

```
docker build -t shortened .
docker run --rm -p 8080:8080 -v shortened-data:/data --env-file .env shortened
```

or directly:

```
CGO_ENABLED=0 GOOS=linux go build -o server ./api
```

Then open `http://localhost:8080`. Use `localhost`, not `127.0.0.1`: the CORS
rule names the exact origin.

### B2 setup (once per bucket)

1. Create a **private** bucket. Turn on default encryption (SSE-B2) and leave
   Object Lock **off**, because Object Lock would block deletes.
2. Create an application key limited to that bucket, with read and write
   access.
3. Add a CORS rule. Uploads and downloads go straight from the browser to B2,
   so the bucket must allow the site's origin. Use the `b2` CLI (`pip install
   b2`, then `b2 account authorize`). The web UI only accepts HTTPS origins.
   From Git Bash, not PowerShell 5.1, which strips the inner quotes:

   ```
   b2 bucket update --cors-rules '[{"corsRuleName":"shortened-local","allowedOrigins":["http://localhost:8080"],"allowedOperations":["s3_put","s3_get"],"allowedHeaders":["content-type"],"exposeHeaders":["ETag"],"maxAgeSeconds":3600}]' <bucket> allPrivate
   ```

   For a deployment, add the real `https://` origin to `allowedOrigins`.
4. Add the lifecycle rule that purges hidden file versions after a day. It is
   the backstop for the app's delete, which already removes every version:

   ```
   b2 bucket update --lifecycle-rule '{"daysFromHidingToDeleting":1,"daysFromUploadingToHiding":null,"fileNamePrefix":"u/"}' <bucket> allPrivate
   ```

   `bucket update` replaces all lifecycle rules at once. Check
   `b2 bucket get <bucket>` first, and include any rules you want to keep.

### Running on Windows without Docker

The server reads environment variables, not `.env` itself. In PowerShell:

```
Get-Content .env | Where-Object { $_ -match '^\s*[^#].*=' } | ForEach-Object { $k,$v = $_ -split '=',2; Set-Item "env:$($k.Trim())" ($v -replace '\s+#.*$','').Trim() }
go run ./api
```

## Checks run, and what was not

On 2026-10-30, on Go 1.27.3/windows, these were all clean:

- `gofmt`, `go vet`, staticcheck, gosec and govulncheck;
- the full test suite. Mutation checks confirmed that the privacy and quota
  tests fail when the ownership check or the reservation is removed;
- the linux build;
- html-validate and `node --check web/app.js`;
- actionlint.

The built server was also run locally against fake B2 credentials. These
worked: the page loaded in Chrome with no console errors, sign-up, sign-in and
`/auth/me`, and the error message when listing failed.

**End to end against a real B2 bucket**, on 2026-10-30, with curl:

- sign-up worked, and the upload URL was signed inside `u/<id>/`;
- the PUT to B2 returned `200`;
- **a PUT with a different body size got `403` from B2**, which confirms the
  signed `Content-Length` binds;
- the listing showed the file, and usage matched;
- the download returned `200` with `Content-Disposition: attachment` and
  byte-identical content;
- the CORS preflight from `http://localhost:8080` was allowed;
- delete returned `204`, and both the listing and the usage went back to
  zero.

The user also uploaded a file through the page in Chrome successfully. That run
showed the old delete only hid files; the fix was then verified on the real
bucket on the same day. A file with two stored versions had no versions left
after one app delete (checked with `b2 ls --versions`).

**Tests are fast and timing-free.** `TestMain` drops bcrypt to `MinCost`, so
the suite runs in about 2 s locally; CI's `-race` run had taken 105 s. The
rate-limit test uses a limiter that never refills; with the real one, slow
`-race` runs earned back a token and the test failed. Mutation checks confirm
the delete test fails if any of these is removed: deleting by version, the
exact-key filter, or following pagination. The fake B2 keeps versions and
rejects foreign version IDs, as B2 does.

**Phone layout**, checked with headless Chrome at 390 and 320 px wide, and with
a 120-character file name:

- no horizontal overflow;
- long names end in an ellipsis;
- every button is at least 40 px tall.

This check found and fixed a real bug. The panel column was a CSS grid item
with the default `min-width: auto`, so one long file name widened the page
past the screen. It is now `grid-template-columns: minmax(0, 1fr)`.

**Usage and uploads (v2 Prompt 9)**, on 2026-11-04, local server against the
dev bucket, test users in `u/9001/` and up (an id sequence seeded past the
folders already in use), all files removed afterwards:

- `go test ./...`, `go vet`, gofmt, staticcheck, gosec, html-validate clean.
  The new tests in `api/ledger_test.go` cover confirm, release after a failed
  PUT, release after a cancelled PUT whose bytes landed, an object deleted in
  B2 behind the app (listing and download), ten parallel reservations against
  the quota, ten tabs on one name, conflict / Keep both / Replace, and a
  Replace finished by the listing;
- the same flows over HTTP with real B2 (29 checks), including a PUT of the
  wrong size refused with `403` and released at once, and an object removed
  with `b2 rm` giving `404 "this file is no longer in storage"`;
- the page in headless Chrome at 1000 and 390 px (28 checks): usage text
  ("127 KB of 500 MB") after every upload, delete and failure, the
  Replace / Keep both / Cancel dialog, the name message in the browser, the
  missing-file message with the page staying put, a PUT blocked by CORS, and
  Cancel during a throttled upload releasing the reservation. Screenshots are
  in `.agent/shots/after/`. For the flows that need the PUT to reach B2, that
  Chrome ran with web security off in a throwaway profile, because the dev
  bucket's CORS rule doesn't list `http://localhost:8092`, where the test ran.

**Email, codes and reset (v2 Prompt 11)**, on 2026-11-04:

- `go test ./...`, `go vet`, gofmt, html-validate and `node --check` are clean.
  The tests in `api/account_test.go` use a fake mailer. They cover the code
  before files, the hash-only storage, 5 tries, expiry, 3 mails an hour, one
  account per address with no leak at sign-up, sign-in by email, forgot (the
  same answer for every kind of login) and reset (sessions ended), an email
  change (the old address holds until the code; a reset code mailed to the old
  address goes void), a password change (other sessions ended), the rate limit
  on the code endpoints, mail bodies without links or images, and the
  migration of an old database with its 4 users kept.
- The page in headless Chrome against a local server with `MAIL_LOG=true`,
  codes read from the log (19 checks): sign-up → code (a wrong one first) →
  app, sign-in by email in any case, an email change, a password change,
  forgot → reset → signed in, no overflow at 390 and 320 px, and no script
  errors. That run found two bugs, both fixed: the form stayed in sign-up mode
  after signing out, and a long button label widened the page at 320 px.

Not run:

- The Docker image has not been rebuilt locally (Docker Desktop was not
  running). CI builds it and runs the smoke test.
- Nothing has been deployed anywhere other than localhost.

**Usage that matches the bucket**, on 2026-11-04:

- Before, the meter was the ledger total as last reconciled, reservations
  included, and `/auth/me` never looked at B2. So a file removed outside the
  app, or an upload cut off when the tab closed, could show as used for up to
  25 minutes. Now `/auth/me` reconciles first (throttled to once per 30 s per
  user), the meter shows stored bytes with reserved ones apart ("· 3 MB
  uploading"), and the page releases its reservation with `sendBeacon` when
  the tab is closed mid-upload.
- `TestMeMatchesBucket`: a file dropped from the fake bucket stops counting
  through `/auth/me` alone once the check is due; stored and reserved are
  reported apart by `/auth/me`, confirm and release. Unit tests that use the
  real B2 host with fake keys keep `/auth/me` from listing, so they stay
  offline.
- Headless Chrome, local server: a signed link with nothing uploaded shows
  "0 B of 500 MB · 3 MB uploading"; leaving the page with it active brings
  the meter back to "0 B of 500 MB"; no script errors.

**Account created only after the code, Account as a pop-up**, on 2026-11-04:

- `go test ./...`, `go vet`, gofmt, html-validate and `node --check` are clean.
  New tests: no account or session before the code, `pending` after a reload,
  a refused mail keeping nothing, 5 tries then a resend, expiry of the code and
  of the whole request, 3 sign-up mails an hour per address (a fresh sign-up
  doesn't get around it), the in-use notice, and two people waiting for one
  name (the first to confirm gets it, the other `409`). The address flow of
  accounts from before email keeps its own tests.
- Headless Chrome against a local server: sign-up → code view (no account, `me`
  401) → reload keeps it → new code → wrong code → right code → app; Account
  opens as a dialog, its errors show inside it, Esc and Close shut it; at 320 px
  neither the page nor the dialog scrolls sideways (the top bar now wraps its
  user row; the new Account button had made it 385 px wide); a taken name is
  refused at sign-up.
