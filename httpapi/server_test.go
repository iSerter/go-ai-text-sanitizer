package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type response struct {
	code   int
	header http.Header
	body   map[string]any
	raw    string
}

func do(t *testing.T, h http.Handler, method, target, contentType, body string, header ...string) response {
	t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := response{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &res.body); err != nil {
			t.Fatalf("decoding %q: %v", rec.Body.String(), err)
		}
	}
	return res
}

func TestHealth(t *testing.T) {
	h := New(Config{APIKey: "secret", Version: "1.2.3"})
	r := do(t, h, "GET", "/health", "", "")
	if r.code != 200 || r.body["status"] != "ok" || r.body["version"] != "1.2.3" || r.body["unicode"] == "" {
		t.Errorf("got %d %v", r.code, r.body)
	}
}

func TestSanitizeJSON(t *testing.T) {
	h := New(Config{})
	r := do(t, h, "POST", "/sanitize", "application/json", `{"text":"a\u200Bb <x> & (oaicite:0){index=0}"}`)
	if r.code != 200 {
		t.Fatalf("got %d %s", r.code, r.raw)
	}
	if r.body["text"] != "ab <x> &" {
		t.Errorf("text = %q", r.body["text"])
	}
	if strings.Contains(r.raw, "\\u003c") {
		t.Errorf("HTML was escaped: %s", r.raw)
	}
	rep, _ := r.body["report"].(map[string]any)
	if rep["modified"] != true {
		t.Errorf("report = %v", rep)
	}
}

func TestSanitizeRawText(t *testing.T) {
	h := New(Config{})
	r := do(t, h, "POST", "/sanitize?preset=plain", "text/plain", "\u201Chi\u201D\u200B")
	if r.code != 200 || r.body["text"] != `"hi"` {
		t.Errorf("got %d %s", r.code, r.raw)
	}
}

func TestSanitizeRules(t *testing.T) {
	h := New(Config{})
	r := do(t, h, "POST", "/sanitize", "application/json", `{"text":"a\u200Bb","disable_rules":["zero_width"]}`)
	if r.code != 200 {
		t.Fatalf("got %d %s", r.code, r.raw)
	}
	if r.body["text"] != "a\u200Bb" {
		t.Errorf("text = %q", r.body["text"])
	}
}

func TestDetectOnly(t *testing.T) {
	h := New(Config{})
	for _, r := range []response{
		do(t, h, "POST", "/sanitize", "application/json", `{"text":"a\u200Bb","detect_only":true}`),
		do(t, h, "POST", "/sanitize?detect_only=1", "", "a\u200Bb"),
	} {
		if r.code != 200 {
			t.Fatalf("got %d %s", r.code, r.raw)
		}
		if _, ok := r.body["text"]; ok {
			t.Errorf("detect-only response has text: %s", r.raw)
		}
		rep, _ := r.body["report"].(map[string]any)
		if fs, _ := rep["findings"].([]any); len(fs) == 0 {
			t.Errorf("no findings: %s", r.raw)
		}
	}
}

func TestBadRequests(t *testing.T) {
	h := New(Config{})
	for name, tc := range map[string]struct{ target, ct, body string }{
		"bad json":       {"/sanitize", "application/json", `{"text":`},
		"unknown field":  {"/sanitize", "application/json", `{"txt":"x"}`},
		"unknown preset": {"/sanitize", "application/json", `{"text":"x","preset":"nope"}`},
		"unknown rule":   {"/sanitize?rule=nope", "text/plain", "x"},
		"bad policy":     {"/sanitize?invalid_utf8=nope", "text/plain", "x"},
		"bad positions":  {"/sanitize?positions=x", "text/plain", "x"},
		"invalid utf8":   {"/sanitize", "text/plain", "a\xffb"},
	} {
		r := do(t, h, "POST", tc.target, tc.ct, tc.body)
		if r.code != 400 || r.body["error"] == "" {
			t.Errorf("%s: got %d %s", name, r.code, r.raw)
		}
	}
}

func TestInvalidUTF8Policies(t *testing.T) {
	h := New(Config{})
	for policy, want := range map[string]string{"replace": "a\uFFFDb", "drop": "ab"} {
		r := do(t, h, "POST", "/sanitize?invalid_utf8="+policy, "text/plain", "a\xffb")
		if r.code != 200 || r.body["text"] != want {
			t.Errorf("%s: got %d %s", policy, r.code, r.raw)
		}
	}
}

func TestAuth(t *testing.T) {
	h := New(Config{APIKey: "secret"})
	for name, tc := range map[string]struct {
		header []string
		want   int
	}{
		"missing":      {nil, 401},
		"wrong bearer": {[]string{"Authorization", "Bearer nope"}, 401},
		"wrong header": {[]string{"X-API-Key", "nope"}, 401},
		"basic scheme": {[]string{"Authorization", "Basic secret"}, 401},
		"bearer":       {[]string{"Authorization", "Bearer secret"}, 200},
		"bearer lower": {[]string{"Authorization", "bearer secret"}, 200},
		"x-api-key":    {[]string{"X-API-Key", "secret"}, 200},
	} {
		r := do(t, h, "POST", "/sanitize", "text/plain", "x", tc.header...)
		if r.code != tc.want {
			t.Errorf("%s: got %d %s", name, r.code, r.raw)
		}
		if r.code == 401 && r.header.Get("WWW-Authenticate") == "" {
			t.Errorf("%s: missing WWW-Authenticate", name)
		}
	}
	if r := do(t, New(Config{}), "POST", "/sanitize", "text/plain", "x"); r.code != 200 {
		t.Errorf("no key configured: got %d", r.code)
	}
}

func TestBodyTooLarge(t *testing.T) {
	h := New(Config{MaxBodyBytes: 10})
	for _, ct := range []string{"text/plain", "application/json"} {
		body := strings.Repeat("x", 11)
		if ct == "application/json" {
			body = `{"text":"` + body + `"}`
		}
		if r := do(t, h, "POST", "/sanitize", ct, body); r.code != 413 {
			t.Errorf("%s: got %d %s", ct, r.code, r.raw)
		}
	}
}

func TestMethodNotAllowed(t *testing.T) {
	h := New(Config{})
	if r := do(t, h, "GET", "/sanitize", "", ""); r.code != 405 {
		t.Errorf("GET /sanitize: got %d", r.code)
	}
	if r := do(t, h, "POST", "/health", "", ""); r.code != 405 {
		t.Errorf("POST /health: got %d", r.code)
	}
	if r := do(t, h, "GET", "/nope", "", ""); r.code != 404 {
		t.Errorf("GET /nope: got %d", r.code)
	}
}
