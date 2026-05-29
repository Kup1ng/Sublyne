package webassets

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const samplePlaceholder = PlaceholderWebPath

// httpResult is what tests assert against. The doGet helper drains and
// closes the response body before returning it, which keeps the
// bodyclose linter satisfied (it can't see "the body got closed
// inside the helper" if the helper returns *http.Response itself).
type httpResult struct {
	Status      int
	ContentType string
	Body        []byte
}

func buildTestFS() fstest.MapFS {
	return fstest.MapFS{
		"index.html": {Data: []byte(
			"<!DOCTYPE html><html><head><link rel=\"modulepreload\" href=\"" + samplePlaceholder + "_nuxt/entry.abc.js\"></head>" +
				"<body><div id=\"__nuxt\"></div></body></html>",
		)},
		"_nuxt/entry.abc.js": {Data: []byte(
			"const base = '" + samplePlaceholder + "';\nfetch(base + 'api/login');",
		)},
		"_nuxt/logo.png": {Data: []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}},
	}
}

func doGet(t *testing.T, h http.Handler, target string) httpResult {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	resp := rec.Result()
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return httpResult{
		Status:      resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
		Body:        body,
	}
}

func TestSPAHandler_ServesIndexAtRoot(t *testing.T) {
	h := SPAHandler(buildTestFS(), "x7Kp9aR2")
	r := doGet(t, h, "/")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if !strings.HasPrefix(r.ContentType, "text/html") {
		t.Errorf("content-type = %q, want text/html prefix", r.ContentType)
	}
	if !bytes.Contains(r.Body, []byte(`/x7Kp9aR2/_nuxt/entry.abc.js`)) {
		t.Errorf("placeholder not substituted; body=%s", string(r.Body))
	}
	if bytes.Contains(r.Body, []byte(PlaceholderWebPath)) {
		t.Errorf("placeholder still present after substitution; body=%s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`<meta name="sublyne-web-path" content="/x7Kp9aR2">`)) {
		t.Errorf("meta tag missing; body=%s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`<link rel="icon" href="data:,">`)) {
		t.Errorf("empty favicon link missing; body=%s", string(r.Body))
	}
}

// TestSPAHandler_PreservesRuntimeConfig pins the regression the
// initial Phase 5 deploy hit: the hand-written index.html omitted the
// `<script>window.__NUXT__={};window.__NUXT__.config=…</script>`
// block Nuxt's bundle reads on boot to find `app.baseURL`, and the
// SPA crashed with "Cannot read properties of undefined (reading
// 'baseURL')". The fix was to capture Nuxt's real SPA shell (via
// scripts/build-spa-index.mjs) and embed THAT. This test guards the
// other half of the contract — that the Go server's placeholder
// substitution doesn't trample the config block.
func TestSPAHandler_PreservesRuntimeConfigBlock(t *testing.T) {
	const shell = `<!DOCTYPE html><html><head></head><body>` +
		`<div id="__nuxt"></div>` +
		`<script>window.__NUXT__={};window.__NUXT__.config={app:{baseURL:"` + PlaceholderWebPath + `",buildAssetsDir:"/_nuxt/"}}</script>` +
		`<script type="application/json" id="__NUXT_DATA__">[]</script>` +
		`</body></html>`

	fsys := fstest.MapFS{"index.html": {Data: []byte(shell)}}
	h := SPAHandler(fsys, "abc123")
	r := doGet(t, h, "/")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if !bytes.Contains(r.Body, []byte(`window.__NUXT__.config=`)) {
		t.Errorf("runtime-config <script> block missing from served body: %s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`baseURL:"/abc123/"`)) {
		t.Errorf("baseURL placeholder not substituted inside runtime config: %s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`id="__NUXT_DATA__"`)) {
		t.Errorf("__NUXT_DATA__ payload script missing: %s", string(r.Body))
	}
}

func TestSPAHandler_RewritesJS(t *testing.T) {
	h := SPAHandler(buildTestFS(), "abc123")
	r := doGet(t, h, "/_nuxt/entry.abc.js")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if !strings.HasPrefix(r.ContentType, "application/javascript") {
		t.Errorf("content-type = %q, want application/javascript prefix", r.ContentType)
	}
	if !bytes.Contains(r.Body, []byte(`'/abc123/'`)) {
		t.Errorf("JS bundle did not get placeholder substitution; body=%s", string(r.Body))
	}
}

func TestSPAHandler_LeavesBinariesUntouched(t *testing.T) {
	h := SPAHandler(buildTestFS(), "abc123")
	r := doGet(t, h, "/_nuxt/logo.png")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if r.ContentType != "image/png" {
		t.Errorf("content-type = %q, want image/png", r.ContentType)
	}
	want := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
	if !bytes.Equal(r.Body, want) {
		t.Errorf("PNG bytes mutated; got=%x", r.Body)
	}
}

func TestSPAHandler_DeepRouteFallsBackToIndex(t *testing.T) {
	h := SPAHandler(buildTestFS(), "abc123")
	r := doGet(t, h, "/tunnels/new")
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SPA fallback)", r.Status)
	}
	if !bytes.Contains(r.Body, []byte("<div id=\"__nuxt\">")) {
		t.Errorf("fallback did not serve index.html; body=%s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`content="/abc123"`)) {
		t.Errorf("fallback HTML missing injected meta tag; body=%s", string(r.Body))
	}
}

func TestSPAHandler_NilFSReturns503(t *testing.T) {
	h := SPAHandler(nil, "abc123")
	r := doGet(t, h, "/")
	if r.Status != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503", r.Status)
	}
}
