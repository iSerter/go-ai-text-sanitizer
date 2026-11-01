// Package httpapi serves the sanitizer over HTTP.
//
// It exposes two endpoints:
//
//	GET  /health    liveness probe; never requires authentication
//	POST /sanitize  sanitize (or, with detect_only, inspect) a text
//
// POST /sanitize accepts either a JSON body (Content-Type: application/json)
// described by SanitizeRequest, or any other body as the raw text, with
// options given as query parameters (preset, rule, no_rule, detect_only,
// positions, invalid_utf8). When Config.APIKey is set, /sanitize requires it
// as "Authorization: Bearer KEY" or "X-API-Key: KEY".
package httpapi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net/http"
	"strconv"
	"strings"

	"github.com/iSerter/go-ai-text-sanitizer/aisanitizer"
)

// DefaultMaxBodyBytes is the request body limit used when Config.MaxBodyBytes
// is zero.
const DefaultMaxBodyBytes = 10 << 20

// Config configures the handler returned by New.
type Config struct {
	// APIKey, when non-empty, is required on /sanitize.
	APIKey string
	// MaxBodyBytes limits request bodies; zero means DefaultMaxBodyBytes.
	MaxBodyBytes int64
	// Version is reported by /health.
	Version string
	// Logger receives internal errors; nil discards them.
	Logger *log.Logger
}

// SanitizeRequest is the JSON body accepted by POST /sanitize. Only Text is
// required.
type SanitizeRequest struct {
	Text         string   `json:"text"`
	Preset       string   `json:"preset,omitempty"`
	Rules        []string `json:"rules,omitempty"`
	DisableRules []string `json:"disable_rules,omitempty"`
	DetectOnly   bool     `json:"detect_only,omitempty"`
	Positions    int      `json:"positions,omitempty"`
	// InvalidUTF8 is "error" (the default), "replace" or "drop".
	InvalidUTF8 string `json:"invalid_utf8,omitempty"`
}

// SanitizeResponse is the body returned by POST /sanitize. Text is omitted
// for detect-only requests.
type SanitizeResponse struct {
	Text   *string             `json:"text,omitempty"`
	Report *aisanitizer.Report `json:"report"`
}

type server struct {
	keyHash [sha256.Size]byte
	auth    bool
	maxBody int64
	version string
	logger  *log.Logger
}

// New returns a handler serving /health and /sanitize.
func New(cfg Config) http.Handler {
	s := &server{
		auth:    cfg.APIKey != "",
		keyHash: sha256.Sum256([]byte(cfg.APIKey)),
		maxBody: cfg.MaxBodyBytes,
		version: cfg.Version,
		logger:  cfg.Logger,
	}
	if s.maxBody <= 0 {
		s.maxBody = DefaultMaxBodyBytes
	}
	if s.version == "" {
		s.version = "dev"
	}
	if s.logger == nil {
		s.logger = log.New(io.Discard, "", 0)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", s.health)
	mux.HandleFunc("POST /sanitize", s.requireKey(s.sanitize))
	return mux
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "ok",
		"version": s.version,
		"unicode": aisanitizer.UnicodeVersion,
	})
}

func (s *server) requireKey(next http.HandlerFunc) http.HandlerFunc {
	if !s.auth {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			if h := r.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "Bearer ") {
				key = strings.TrimSpace(h[7:])
			}
		}
		// Hashing makes the comparison constant-time regardless of length.
		got := sha256.Sum256([]byte(key))
		if key == "" || subtle.ConstantTimeCompare(got[:], s.keyHash[:]) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="ai-text-sanitizer"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next(w, r)
	}
}

func (s *server) sanitize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, s.maxBody)
	req, err := readRequest(r)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", tooBig.Limit))
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	opts, err := req.options()
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.InvalidUTF8 == "" || strings.EqualFold(req.InvalidUTF8, "error") {
		if err := aisanitizer.CheckUTF8(req.Text); err != nil {
			writeError(w, http.StatusBadRequest, err.Error()+` (set invalid_utf8 to "replace" or "drop")`)
			return
		}
	}

	var resp SanitizeResponse
	if req.DetectOnly {
		resp.Report, err = aisanitizer.Detect(req.Text, opts)
		if err != nil {
			// Only extra detectors fail, and the API registers none.
			s.logger.Printf("detect: %v", err)
		}
	} else {
		out, report := aisanitizer.Sanitize(req.Text, opts)
		resp.Text, resp.Report = &out, report
	}
	writeJSON(w, http.StatusOK, resp)
}

// readRequest decodes a JSON body, or treats any other body as raw text with
// options taken from the query string.
func readRequest(r *http.Request) (*SanitizeRequest, error) {
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if ct == "application/json" {
		var req SanitizeRequest
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				return nil, err
			}
			return nil, fmt.Errorf("invalid JSON body: %v", err)
		}
		return &req, nil
	}

	data, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	q := r.URL.Query()
	req := &SanitizeRequest{
		Text:         string(data),
		Preset:       q.Get("preset"),
		Rules:        q["rule"],
		DisableRules: q["no_rule"],
		InvalidUTF8:  q.Get("invalid_utf8"),
	}
	if v := q.Get("detect_only"); v != "" {
		if req.DetectOnly, err = strconv.ParseBool(v); err != nil {
			return nil, fmt.Errorf("invalid detect_only %q", v)
		}
	}
	if v := q.Get("positions"); v != "" {
		if req.Positions, err = strconv.Atoi(v); err != nil {
			return nil, fmt.Errorf("invalid positions %q", v)
		}
	}
	return req, nil
}

func (req *SanitizeRequest) options() (*aisanitizer.Options, error) {
	o, err := aisanitizer.Preset(req.Preset)
	if err != nil {
		return nil, err
	}
	set := func(ids []string, on bool) error {
		for _, v := range ids {
			// Accept both repeated values and comma-separated lists.
			for _, id := range strings.Split(v, ",") {
				if id = strings.TrimSpace(id); id == "" {
					continue
				}
				if err := o.SetRule(aisanitizer.RuleID(id), on); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := set(req.Rules, true); err != nil {
		return nil, err
	}
	if err := set(req.DisableRules, false); err != nil {
		return nil, err
	}
	switch strings.ToLower(req.InvalidUTF8) {
	case "", "error", "replace":
		o.InvalidUTF8 = aisanitizer.InvalidUTF8Replace
	case "drop":
		o.InvalidUTF8 = aisanitizer.InvalidUTF8Drop
	default:
		return nil, fmt.Errorf("invalid invalid_utf8 %q (want error, replace or drop)", req.InvalidUTF8)
	}
	if req.Positions < 0 {
		return nil, fmt.Errorf("invalid positions %d (want >= 0)", req.Positions)
	}
	o.MaxPositions = req.Positions
	return o, nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.Encode(v) //nolint:errcheck // the client went away; nothing to do
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
