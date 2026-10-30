# CODE_NOTES

SHORTENED. is a file-sharing app with user accounts. A Go server serves the
page, manages accounts, and only ever *signs* URLs. A Backblaze B2 bucket holds
the bytes, and a SQLite file holds accounts, sessions and storage usage.

## Files

| Path | What it is |
| --- | --- |
| [api/main.go](api/main.go) | Config, B2 client, routes, the page handler with its CSP, and graceful shutdown. |
| [api/auth.go](api/auth.go) | Sign-up, sign-in and sign-out, sessions, the `requireUser` and `sameOrigin` middleware, and the per-IP rate limiter. |
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
| `POST /auth/signup` | none, rate-limited | `{"username","password"}` → `201`, sets the session cookie. |
| `POST /auth/login` | none, rate-limited | Same body → `200`, sets the session cookie. |
| `POST /auth/logout` | cookie | Ends this session → `204`. |
| `GET /auth/me` | cookie | `{"username","usedBytes","quotaBytes"}`. |
| `POST /upload-url` | cookie | `{"filename","size"}` → `{"key","url"}`, a presigned PUT. |
| `GET /files` | cookie | The user's own files, newest first: `[{"key","name","size","lastModified"}]`. |
| `DELETE /files?key=` | cookie | Deletes one of the user's own files → `204`. |
| `GET /download-url?key=` | cookie | `{"url"}`, a presigned GET that downloads as an attachment. |

Errors are always `{"error": "..."}`. A missing or expired session gets `401`.
Someone else's key gets `404`, the same as a missing file.

## Request flow

```
browser --POST /auth/login {username,password}--> server: bcrypt check, new session
server  --Set-Cookie: session=<random>; HttpOnly; Secure; SameSite=Lax--> browser

browser --POST /upload-url {filename,size} + cookie--> server
server: session -> user; size <= 50 MB; clean name;
        key = u/<user id>/<16 hex>-<name>
        list u/<id>/ in B2 and reconcile the ledger; used + size <= quota?
        reserve the size in the ledger; sign a PUT for that key and exact
        Content-Length, valid 10 minutes
server --{"key","url"}--> browser --PUT bytes--> B2 (never through the server)
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
an upload URL is signed, so ten links requested at once can't exceed the quota.
Every listing, and every new upload request, reconciles the table with the
bucket. Real objects get their real size. Reservations whose upload never
arrived are dropped once they are older than the link lifetime plus 15
minutes.

**The upload size is signed.** The declared size goes into the presigned PUT
as `Content-Length`, so B2 refuses a body of any other size. That makes both
the 50 MB limit and the quota binding. The browser sets `Content-Length`
itself from the file.

**Downloads are attachments.** Presigned GETs carry
`response-content-disposition=attachment; filename="<name>"`. An uploaded HTML
or SVG file is therefore saved, not rendered on the bucket's origin.

**B2 specifics.** `UsePathStyle` plus `B2_ENDPOINT` makes the SDK address
`endpoint/bucket/key`. `RequestChecksumCalculation = WhenRequired` stops the
SDK adding CRC32 headers, which B2 rejects with a 400.

**Rate limiting behind a proxy.** By default the limiter keys on the TCP peer
address. Behind a reverse proxy, every client would then share the proxy's
address, so `TRUST_PROXY=true` switches to the last `X-Forwarded-For` entry,
the one the proxy appended. Earlier entries are client-controlled and ignored.

**The look.** The design is a neon-noir theme: hard yellow `#fcee0a` on
near-black, cyan and red accents, cut-corner panels and buttons, Rajdhani and
Share Tech Mono from Google Fonts, scanlines and a glitch title. It's inspired
by the Cyberpunk 2077 site's style but uses none of its logos, artwork, fonts
or name. Animations stop under `prefers-reduced-motion`.

## Known limits

- **No email.** Accounts have no email address, so a forgotten password can't
  be recovered and there is no verification. An admin can only delete the row.
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

Then open `http://localhost:8080`. The bucket needs a CORS rule allowing `PUT`
(with the `Content-Type` header) and `GET` from the site's origin, because
uploads and downloads go straight to B2.

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

Not run:

- A real bucket has never been used, so no actual upload, download, listing or
  delete has happened.
- The Docker image has not been rebuilt, `go test -race` has not been run, and
  the CI smoke test has not run (Docker was unavailable locally).
- The phone-width layout has not been checked in a browser.
