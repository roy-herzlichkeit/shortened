// Command server is the signing API for the file-sharing app.
//
// It never carries file bytes: it only hands out short-lived, presigned
// Backblaze B2 URLs so the browser can PUT an upload straight to the bucket and
// GET a download straight from it.
package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

const (
	maxUploadSize = 50 << 20 // 50 MB, the documented per-file limit
	linkTTL       = 10 * time.Minute
	maxNameLen    = 120
	maxBodyBytes  = 8 << 10
	idLen         = 16 // hex characters in the random key prefix
)

type config struct {
	keyID    string
	appKey   string
	endpoint string
	region   string
	bucket   string
	apiKey   string
	origin   string
	port     string
}

func loadConfig() (config, error) {
	cfg := config{
		keyID:    os.Getenv("B2_KEY_ID"),
		appKey:   os.Getenv("B2_APP_KEY"),
		endpoint: os.Getenv("B2_ENDPOINT"),
		region:   os.Getenv("B2_REGION"),
		bucket:   os.Getenv("B2_BUCKET"),
		apiKey:   os.Getenv("API_KEY"),
		origin:   os.Getenv("ALLOWED_ORIGIN"),
		port:     os.Getenv("PORT"),
	}
	if cfg.port == "" {
		cfg.port = "8080"
	}

	required := []struct{ name, value string }{
		{"B2_KEY_ID", cfg.keyID},
		{"B2_APP_KEY", cfg.appKey},
		{"B2_ENDPOINT", cfg.endpoint},
		{"B2_REGION", cfg.region},
		{"B2_BUCKET", cfg.bucket},
		{"API_KEY", cfg.apiKey},
		{"ALLOWED_ORIGIN", cfg.origin},
	}
	for _, v := range required {
		if v.value == "" {
			return config{}, errors.New("missing required environment variable " + v.name)
		}
	}
	return cfg, nil
}

type server struct {
	cfg     config
	client  *s3.Client
	presign *s3.PresignClient
}

func newServer(ctx context.Context, cfg config) (*server, error) {
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

	return &server{cfg: cfg, client: client, presign: s3.NewPresignClient(client)}, nil
}

func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.Handle("/upload-url", s.protect(s.handleUploadURL))
	mux.Handle("/files", s.protect(s.handleFiles))
	mux.Handle("/download-url", s.protect(s.handleDownloadURL))
	return mux
}

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	s, err := newServer(ctx, cfg)
	if err != nil {
		log.Fatalf("aws config: %v", err)
	}

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           s.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serveErr := make(chan error, 1)
	go func() {
		log.Printf("listening on :%s (bucket %q, allowed origin %q)", cfg.port, cfg.bucket, cfg.origin)
		serveErr <- srv.ListenAndServe()
	}()

	select {
	case err := <-serveErr:
		log.Fatalf("server: %v", err)
	case <-ctx.Done():
	}

	// Let in-flight signing requests finish before the container stops.
	log.Printf("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// protect wraps the endpoints that need an API key: it answers CORS preflights,
// rejects requests without the shared key, and adds the CORS headers to every
// response the wrapped handler writes.
func (s *server) protect(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", s.cfg.origin)
		h.Set("Vary", "Origin")
		h.Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		h.Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		h.Set("Access-Control-Max-Age", "600")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		given := r.Header.Get("X-API-Key")
		if subtle.ConstantTimeCompare([]byte(given), []byte(s.cfg.apiKey)) != 1 {
			writeError(w, http.StatusUnauthorized, "missing or invalid X-API-Key")
			return
		}

		next(w, r)
	})
}

func (s *server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

type uploadRequest struct {
	Filename string `json:"filename"`
	Size     int64  `json:"size"`
}

type uploadResponse struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

func (s *server) handleUploadURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req uploadRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "body must be JSON like {\"filename\":\"...\",\"size\":12345}")
		return
	}
	if req.Size < 0 {
		writeError(w, http.StatusBadRequest, "size must not be negative")
		return
	}
	if req.Size > maxUploadSize {
		writeError(w, http.StatusRequestEntityTooLarge, "file is larger than the 50 MB limit")
		return
	}

	name := cleanFilename(req.Filename)
	if name == "" {
		writeError(w, http.StatusBadRequest, "filename is required")
		return
	}

	id, err := newID()
	if err != nil {
		log.Printf("random id: %v", err)
		writeError(w, http.StatusInternalServerError, "could not build an object key")
		return
	}
	key := id + "-" + name

	// The PUT signature covers the key and the declared Content-Length and
	// expires in 10 minutes, so the browser can upload exactly one object of
	// exactly the size it asked for, and only until the link goes stale. Signing
	// the length is what makes the 50 MB limit binding rather than advisory.
	signed, err := s.presign.PresignPutObject(r.Context(), &s3.PutObjectInput{
		Bucket:        aws.String(s.cfg.bucket),
		Key:           aws.String(key),
		ContentLength: aws.Int64(req.Size),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign put %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not sign the upload URL")
		return
	}

	writeJSON(w, http.StatusOK, uploadResponse{Key: key, URL: signed.URL})
}

type fileInfo struct {
	Key          string `json:"key"`
	Name         string `json:"name"`
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
}

func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.listFiles(w, r)
	case http.MethodDelete:
		s.deleteFile(w, r)
	default:
		w.Header().Set("Allow", "GET, DELETE, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "use GET or DELETE")
	}
}

// listFiles returns every object in the bucket, newest first. The listing is
// unbounded because the bucket is the only record of what exists; a bucket
// large enough to make that slow needs a real index, not a cap here.
func (s *server) listFiles(w http.ResponseWriter, r *http.Request) {
	type object struct {
		info     fileInfo
		modified time.Time
	}
	var objects []object

	pages := s3.NewListObjectsV2Paginator(s.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(s.cfg.bucket),
	})
	for pages.HasMorePages() {
		page, err := pages.NextPage(r.Context())
		if err != nil {
			log.Printf("list bucket %q: %v", s.cfg.bucket, err)
			writeError(w, http.StatusBadGateway, "could not list the bucket")
			return
		}
		for _, obj := range page.Contents {
			key := aws.ToString(obj.Key)
			o := object{info: fileInfo{Key: key, Name: displayName(key), Size: aws.ToInt64(obj.Size)}}
			if obj.LastModified != nil {
				o.modified = obj.LastModified.UTC()
				o.info.LastModified = o.modified.Format(time.RFC3339)
			}
			objects = append(objects, o)
		}
	}

	slices.SortStableFunc(objects, func(a, b object) int {
		return b.modified.Compare(a.modified)
	})
	files := make([]fileInfo, 0, len(objects))
	for _, o := range objects {
		files = append(files, o.info)
	}

	writeJSON(w, http.StatusOK, files)
}

func (s *server) deleteFile(w http.ResponseWriter, r *http.Request) {
	key, ok := keyParam(w, r)
	if !ok {
		return
	}

	_, err := s.client.DeleteObject(r.Context(), &s3.DeleteObjectInput{
		Bucket: aws.String(s.cfg.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		log.Printf("delete %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not delete the file")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *server) handleDownloadURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	key, ok := keyParam(w, r)
	if !ok {
		return
	}

	// Forcing an attachment keeps an uploaded HTML or SVG file from rendering
	// in the browser on the bucket's origin. The name is already restricted to
	// [A-Za-z0-9._-], so it needs no quoting beyond the surrounding quotes.
	signed, err := s.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{
		Bucket:                     aws.String(s.cfg.bucket),
		Key:                        aws.String(key),
		ResponseContentDisposition: aws.String(`attachment; filename="` + displayName(key) + `"`),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign get %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not sign the download URL")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"url": signed.URL})
}

// keyParam reads the "key" query parameter and writes a 400 unless it has the
// exact shape handleUploadURL produces.
func keyParam(w http.ResponseWriter, r *http.Request) (string, bool) {
	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key query parameter")
		return "", false
	}
	if !validKey(key) {
		writeError(w, http.StatusBadRequest, "invalid key")
		return "", false
	}
	return key, true
}

var (
	unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)
	keyPattern      = regexp.MustCompile(`^[0-9a-f]{16}-[A-Za-z0-9._-]{1,120}$`)
)

// validKey reports whether key looks like one this API issued: a random hex
// prefix and a name that cleanFilename could have produced.
func validKey(key string) bool {
	return keyPattern.MatchString(key)
}

// displayName strips the random prefix from a key, giving back the cleaned
// filename the uploader chose. Keys of any other shape are returned unchanged.
func displayName(key string) string {
	if validKey(key) {
		return key[idLen+1:]
	}
	return key
}

// cleanFilename turns a client-supplied name into a flat, harmless object-key
// suffix: no directories, no control characters, no characters that would need
// escaping in a URL, and a bounded length that keeps the extension.
func cleanFilename(name string) string {
	name = strings.ReplaceAll(name, `\`, "/")
	name = path.Base(name)
	name = unsafeNameChars.ReplaceAllString(name, "-")
	name = strings.Trim(name, "-._")

	if len(name) > maxNameLen {
		ext := path.Ext(name)
		if len(ext) > 16 {
			ext = ""
		}
		base := strings.TrimSuffix(name, ext)
		if room := maxNameLen - len(ext); len(base) > room {
			base = base[:room]
		}
		name = strings.Trim(base, "-._") + ext
	}
	return name
}

func newID() (string, error) {
	buf := make([]byte, idLen/2)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
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
