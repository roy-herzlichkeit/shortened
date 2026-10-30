# syntax=docker/dockerfile:1

# Build stage: compiles the API with the same CGO-free settings as the project's
# build command.
FROM golang:1.27-alpine AS build
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY api/ ./api/
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/server ./api

# Final stage: no Go toolchain and no package tooling, just the binary and the
# CA bundle it needs to reach B2 over TLS.
FROM alpine:3.24
# Unpinned on purpose: the newest CA bundle is the one we want, and pinned apk
# versions break whenever Alpine drops the old package from its index.
# hadolint ignore=DL3018
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 app
COPY --from=build /out/server /server

USER app
EXPOSE 8080
# busybox wget ships with alpine; /health needs no API key.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget -q -O /dev/null "http://127.0.0.1:${PORT:-8080}/health" || exit 1
ENTRYPOINT ["/server"]
