// Command server is the file-sharing app: it serves the web page, manages user
// accounts, and signs Backblaze B2 URLs.
//
// It never carries file bytes: it only hands out short-lived, presigned URLs
// so the browser can PUT an upload straight to the bucket and GET a download
// straight from it. Each user's files live under their own prefix in the
// bucket, and a SQLite database holds accounts, sessions and the quota ledger.
package main

import (
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/roy-herzlichkeit/shortened/web"
)

const (
	maxUploadSize = 50 << 20 // 50 MB, the documented per-file limit
	linkTTL       = 10 * time.Minute
	maxNameLen    = 120
	maxBodyBytes  = 8 << 10
	idLen         = 16 // hex characters in the random key prefix
)

type config struct {
	keyID        string
	appKey       string
	endpoint     string
	region       string
	bucket       string
	port         string
	dbPath       string
	quotaBytes   int64
	maxUsers     int
	cookieSecure bool
	trustProxy   bool
	tlsCert      string // PEM file; with tlsKey, the server speaks HTTPS
	tlsKey       string
}

func loadConfig() (config, error) {
	cfg := config{
		keyID:        os.Getenv("B2_KEY_ID"),
		appKey:       os.Getenv("B2_APP_KEY"),
		endpoint:     os.Getenv("B2_ENDPOINT"),
		region:       os.Getenv("B2_REGION"),
		bucket:       os.Getenv("B2_BUCKET"),
		port:         envOr("PORT", "8080"),
		dbPath:       envOr("DB_PATH", "shortened.db"),
		cookieSecure: os.Getenv("COOKIE_SECURE") != "false",
		trustProxy:   os.Getenv("TRUST_PROXY") == "true",
		tlsCert:      os.Getenv("TLS_CERT_FILE"),
		tlsKey:       os.Getenv("TLS_KEY_FILE"),
	}

	// One without the other is a broken deploy, not a request for plain HTTP.
	if (cfg.tlsCert == "") != (cfg.tlsKey == "") {
		return config{}, errors.New("set both TLS_CERT_FILE and TLS_KEY_FILE for HTTPS, or neither for plain HTTP")
	}

	required := []struct{ name, value string }{
		{"B2_KEY_ID", cfg.keyID},
		{"B2_APP_KEY", cfg.appKey},
		{"B2_ENDPOINT", cfg.endpoint},
		{"B2_REGION", cfg.region},
		{"B2_BUCKET", cfg.bucket},
	}
	for _, v := range required {
		if v.value == "" {
			return config{}, errors.New("missing required environment variable " + v.name)
		}
	}

	quotaMB, err := strconv.ParseInt(envOr("QUOTA_MB", "500"), 10, 64)
	if err != nil || quotaMB <= 0 {
		return config{}, errors.New("QUOTA_MB must be a positive whole number of megabytes")
	}
	cfg.quotaBytes = quotaMB << 20

	cfg.maxUsers, err = strconv.Atoi(envOr("MAX_USERS", "0"))
	if err != nil || cfg.maxUsers < 0 {
		return config{}, errors.New("MAX_USERS must be 0 (no limit) or a positive whole number")
	}

	return cfg, nil
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

type server struct {
	cfg     config
	db      *sql.DB
	client  *s3.Client
	presign *s3.PresignClient
	limiter *ipLimiter
}

func newServer(ctx context.Context, cfg config, db *sql.DB) (*server, error) {
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.keyID, cfg.appKey, "")),
	)
	if err != nil {
		return nil, err
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		// B2 speaks the S3 API but is not a real S3 region, so we must point the
		// SDK at the bucket's own endpoint and let it address the bucket by
		// path (endpoint/bucket/key) instead of by host (bucket.endpoint/key).
		o.BaseEndpoint = aws.String(cfg.endpoint)
		o.UsePathStyle = true

		// B2 rejects the CRC32 checksum headers that recent SDK versions add to
		// every request by default ("when supported"); it only understands them
		// on operations that require a checksum. Restricting both directions to
		// "when required" keeps B2 from answering with a 400 InvalidRequest.
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
	})

	return &server{
		cfg:     cfg,
		db:      db,
		client:  client,
		presign: s3.NewPresignClient(client),
		// 10 attempts at once, then one every 6 seconds, per client IP.
		limiter: newIPLimiter(6*time.Second, 10),
	}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("/health", noStore(http.HandlerFunc(s.handleHealth)))

	mux.Handle("/auth/signup", noStore(s.rateLimited(s.sameOrigin(http.HandlerFunc(s.handleSignup)))))
	mux.Handle("/auth/login", noStore(s.rateLimited(s.sameOrigin(http.HandlerFunc(s.handleLogin)))))
	mux.Handle("/auth/logout", noStore(s.sameOrigin(http.HandlerFunc(s.handleLogout))))
	mux.Handle("/auth/me", noStore(s.requireUser(s.handleMe)))

	mux.Handle("/upload-url", noStore(s.requireUser(s.handleUploadURL)))
	mux.Handle("/files", noStore(s.requireUser(s.handleFiles)))
	mux.Handle("/files/confirm", noStore(s.requireUser(s.handleConfirm)))
	mux.Handle("/files/release", noStore(s.requireUser(s.handleRelease)))
	mux.Handle("/download-url", noStore(s.requireUser(s.handleDownloadURL)))

	mux.Handle("/", s.pageHandler())
	return mux
}

// noStore marks a response as never cacheable. API answers are per user (file
// lists, signed links, the session cookie), so a shared cache such as a CDN
// must never keep one and hand it to someone else. It is set before the
// handler runs, so error responses carry it too.
func noStore(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// pageHandler serves the embedded web page. The page and the API share an
// origin, so the session cookie needs no CORS, and the CSP can stay strict.
func (s *server) pageHandler() http.Handler {
	files := http.FileServerFS(web.FS)

	csp := strings.Join([]string{
		"default-src 'self'",
		// The upload PUT goes straight to the bucket's endpoint.
		"connect-src 'self' " + originOf(s.cfg.endpoint),
		"style-src 'self' https://fonts.googleapis.com",
		"font-src https://fonts.gstatic.com",
		"img-src 'self' data:",
		"object-src 'none'",
		"base-uri 'none'",
		"form-action 'self'",
		"frame-ancestors 'none'",
	}, "; ")

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			writeError(w, http.StatusMethodNotAllowed, "use GET")
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-cache")
		files.ServeHTTP(w, r)
	})
}

// originOf returns scheme://host of a URL, which is what CSP source lists take.
func originOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := openDB(cfg.dbPath)
	if err != nil {
		log.Fatalf("database %q: %v", cfg.dbPath, err)
	}
	defer db.Close()

	s, err := newServer(ctx, cfg, db)
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	srv := newHTTPServer(cfg, s.routes())
	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		scheme := "http"
		if cfg.tlsCert != "" {
			scheme = "https"
		}
		log.Printf("listening on :%s, %s (bucket %q, database %q, quota %d MB)",
			cfg.port, scheme, cfg.bucket, cfg.dbPath, cfg.quotaBytes>>20)
		serveErr <- serve(srv, ln, cfg)
	}()

	select {
	case err := <-serveErr:
		log.Fatalf("server: %v", err)
	case <-ctx.Done():
	}

	// Let in-flight requests finish before the container stops.
	log.Printf("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

func newHTTPServer(cfg config, h http.Handler) *http.Server {
	return &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Only used in HTTPS mode. TLS 1.0 and 1.1 are deprecated (RFC 8996).
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
}

// serve runs srv on ln: HTTPS when a certificate is configured, which lets a
// CDN reach the origin encrypted, and plain HTTP otherwise, as for local use.
func serve(srv *http.Server, ln net.Listener, cfg config) error {
	if cfg.tlsCert != "" {
		return srv.ServeTLS(ln, cfg.tlsCert, cfg.tlsKey)
	}
	return srv.Serve(ln)
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	if err := s.db.PingContext(r.Context()); err != nil {
		log.Printf("health: database: %v", err)
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
