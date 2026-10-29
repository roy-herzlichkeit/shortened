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
	"path"
	"regexp"
	"strings"
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

func main() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	ctx := context.Background()
	awsCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion(cfg.region),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.keyID, cfg.appKey, "")),
	)
	if err != nil {
		log.Fatalf("aws config: %v", err)
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

	s := &server{cfg: cfg, client: client, presign: s3.NewPresignClient(client)}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealth)
	mux.Handle("/upload-url", s.protect(s.handleUploadURL))
	mux.Handle("/files", s.protect(s.handleFiles))
	mux.Handle("/download-url", s.protect(s.handleDownloadURL))

	srv := &http.Server{
		Addr:              ":" + cfg.port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("listening on :%s (bucket %q, allowed origin %q)", cfg.port, cfg.bucket, cfg.origin)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("server: %v", err)
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
		h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
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

	// The PUT policy is bound to the key and expires in 10 minutes, so the
	// browser can upload exactly one object and only until the link goes stale.
	signed, err := s.presign.PresignPutObject(r.Context(), &s3.PutObjectInput{
		Bucket: aws.String(s.cfg.bucket),
		Key:    aws.String(key),
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
	Size         int64  `json:"size"`
	LastModified string `json:"lastModified"`
}

func (s *server) handleFiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	files := []fileInfo{}
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
			info := fileInfo{Key: aws.ToString(obj.Key), Size: aws.ToInt64(obj.Size)}
			if obj.LastModified != nil {
				info.LastModified = obj.LastModified.UTC().Format(time.RFC3339)
			}
			files = append(files, info)
		}
	}

	writeJSON(w, http.StatusOK, files)
}

func (s *server) handleDownloadURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, OPTIONS")
		writeError(w, http.StatusMethodNotAllowed, "use GET")
		return
	}

	key := r.URL.Query().Get("key")
	if key == "" {
		writeError(w, http.StatusBadRequest, "missing key query parameter")
		return
	}
	if strings.HasPrefix(key, "/") || strings.Contains(key, "..") {
		writeError(w, http.StatusBadRequest, "invalid key")
		return
	}

	signed, err := s.presign.PresignGetObject(r.Context(), &s3.GetObjectInput{
		Bucket: aws.String(s.cfg.bucket),
		Key:    aws.String(key),
	}, s3.WithPresignExpires(linkTTL))
	if err != nil {
		log.Printf("presign get %q: %v", key, err)
		writeError(w, http.StatusBadGateway, "could not sign the download URL")
		return
	}

	writeJSON(w, http.StatusOK, map[string]string{"url": signed.URL})
}

var unsafeNameChars = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

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
	buf := make([]byte, 8)
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
