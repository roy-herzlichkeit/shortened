# CODE_NOTES

A file-sharing app in three pieces: a Go API that only ever *signs* URLs, a
bucket that holds the bytes, and one HTML page that talks to both.

## Files

| Path | What it is |
| --- | --- |
| [api/main.go](api/main.go) | The whole API: config loading, B2 client, four handlers, CORS/API-key middleware. |
| [web/index.html](web/index.html) | The whole UI: API key field, file picker, Upload button, file list with Download links. Plain HTML + JS, no build step. |
| [Dockerfile](Dockerfile) | Multi-stage build (`golang:1.27-alpine` → `alpine:3.20`), `CGO_ENABLED=0`, binary only in the final image. |
| [.env.example](.env.example) | Every environment variable with fake values. |
| [go.mod](go.mod) / [go.sum](go.sum) | Module `github.com/roy-herzlichkeit/shortened`, Go 1.24, with the four AWS SDK modules and their transitive versions pinned and hashed. Only the SDK plus the standard library is used. |

## Request flow

Upload: the browser asks the API for permission to upload

```
browser  --POST /upload-url {filename,size} + X-API-Key-->  API
API: size <= 50 MB? -> clean filename -> key = <16 hex>-<name>
     sign PutObject for that key, 10 minute expiry
API  --{"key","url"}-->  browser
browser  --PUT file bytes------>  B2 (presigned URL, no key, no API in the path)
browser  --GET /files---------->  API --> ListObjectsV2 --> bucket listing
```

Download: the browser asks for a link, then leaves for the bucket

```
browser  --GET /download-url?key=...  + X-API-Key-->  API
API  --{"url"}-->  browser
browser  --GET url--------------->  B2 (presigned URL)
```

`GET /health` answers `{"status":"ok"}` with no API key, so a container
healthcheck or load balancer can poll it. Nothing else is reachable without the
key, and no endpoint ever proxies file bytes.

## Why these choices

**Presigned URLs, no proxy.** B2 does the storage work and the API stays a
signature service. Uploads and downloads never pass through the Go process, so
its memory and bandwidth stay flat no matter how large the files or how many
clients are transferring at once.

**AWS SDK for Go v2 with a custom endpoint and path-style addressing.** B2
exposes the S3 API, so `s3` plus `s3.PresignClient` is enough. `B2_ENDPOINT`
plus `UsePathStyle = true` makes the SDK address `endpoint/bucket/key`; without
path style it would guess a `bucket.endpoint` hostname that B2 does not serve.

**`RequestChecksumCalculation = WhenRequired` (and `ResponseChecksumValidation`
on the same principle).** Recent SDK versions attach CRC32 checksum headers to
every request by default. B2 rejects them on operations that do not ask for a
checksum, so requests fail with a 400 unless the SDK is told to add checksums
only where the operation requires them. The reason is repeated as a comment at
the setting in `api/main.go`.

**Static credentials from the environment.** The container gets a bucket-scoped
B2 application key, not an account-wide master key. `loadConfig` fails at
startup if any required variable is missing, so a misconfigured deployment
crashes immediately instead of serving 502s later.

**Random ID prefix on every key.** `key = <16 hex chars>-<cleaned name>` keeps
uploads from overwriting each other and stops a client from choosing a key such
as a directory traversal or a name that breaks URL escaping. `cleanFilename`
strips directory parts, collapses anything outside `[A-Za-z0-9._-]`, trims
leading dots and separators, and caps the length while keeping the extension.

**`path-style` signer for both directions, 10 minute expiry.** The expiry is
short because the link is the credential: it is the only thing an attacker could
reuse, and both the PUT and the GET expire on their own.

**API key in a custom header.** `X-API-Key` compared with
`crypto/subtle.ConstantTimeCompare`, so the check does not leak the key through
timing, and the key never appears in a URL or a log line. Bad or missing keys
give `401` and a JSON `{"error": ...}`.

**CORS applied by one middleware.** The three key-protected routes share
`server.protect`, which sets `Access-Control-Allow-Origin` from
`ALLOWED_ORIGIN`, allows `Content-Type` and `X-API-Key`, and answers `OPTIONS`
with `204` before any key check (preflights never carry the key). `/health` is
deliberately outside it.

**Bare JSON array for `/files`.** The contract spells out the wrapper object
for `/upload-url` and `/download-url` but describes `/files` only as "a list of
`{"key","size","lastModified"}`", so the response is that list itself, with
`lastModified` in RFC 3339 and `size` in bytes.

**Standard library only besides the SDK.** `net/http` with a `ServeMux`,
`encoding/json`, `crypto/rand`. No framework, no database, no background
workers. File state lives entirely in the bucket.

## Environment variables

`B2_KEY_ID`, `B2_APP_KEY`, `B2_ENDPOINT`, `B2_REGION`, `B2_BUCKET`, `API_KEY`,
`ALLOWED_ORIGIN` are required. `PORT` defaults to `8080`. See `.env.example`.

## Running it

```
docker build -t shortened-api .
docker run --rm -p 8080:8080 --env-file .env shortened-api
```

or directly with the contract's build command:

```
CGO_ENABLED=0 GOOS=linux go build -o server ./api
```

The page is static, so it is served separately — `python -m http.server` in
`web/` is enough for local use. Two things must line up with it: set `API_URL`
at the top of the page's script to the API address, and put the page's exact
origin in `ALLOWED_ORIGIN`. The bucket also needs a CORS rule allowing `PUT`
and `GET` from that origin, because the upload and download requests go straight
to B2 and not through the API.

## Checks run, and what was not

Checks that were run, on Go 1.27.3: `CGO_ENABLED=0 GOOS=linux go build -o
server ./api` succeeds and produces a statically linked linux/amd64 binary,
`go vet ./api` is clean, `gofmt -l api` reports nothing, and the page's script
passes `node --check`. A local windows build was also started against fake B2
credentials to drive the HTTP layer: `/health` returns `200
{"status":"ok"}`; a missing and a wrong `X-API-Key` both return `401`; an
`OPTIONS` preflight returns `204` with the `ALLOWED_ORIGIN` header; oversize
`size` returns `413`; malformed JSON returns `400`; a wrong method returns `405`;
missing and traversal `key` values return `400`; and a valid `/upload-url` call
returns a path-style presigned PUT on the configured endpoint with
`X-Amz-Expires=600` and only `host` signed.

Not run: nothing has ever spoken to a real bucket — no upload, download,
listing or signed link was exercised, and the page was never opened in a
browser. So B2's acceptance of the presigned URLs and checksum handling, the
required bucket CORS rules, and the key's permissions are all unconfirmed.
There are also no automated tests.
