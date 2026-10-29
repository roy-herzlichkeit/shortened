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
FROM alpine:3.20
RUN apk add --no-cache ca-certificates \
    && adduser -D -H -u 10001 app
COPY --from=build /out/server /server

USER app
EXPOSE 8080
ENTRYPOINT ["/server"]
