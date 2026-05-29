package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
)

// These tests pin the Phase 5 web-path enforcement contract: every
// request that lands outside `/<webPath>/` is 404 with no body, while
// requests inside it reach the API and the SPA static handler. They
// are intentionally scoped to the router — auth_handlers_test.go
// already exercises the business logic behind the API endpoints.

func TestRouter_404OutsideWebPath(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)

	cases := []string{
		"/",
		"/api/login",
		"/healthz",
		"/dashboard",
		"/_nuxt/entry.js",
		"/" + testWebPath + "X",
	}
	for _, p := range cases {
		t.Run(p, func(t *testing.T) {
			r := getJSON(t, s.URL+p, nil)
			if r.Status != http.StatusNotFound {
				t.Errorf("status = %d, want 404", r.Status)
			}
			if len(bytes.TrimSpace(r.Body)) != 0 {
				t.Errorf("body should be empty, got %q", string(r.Body))
			}
		})
	}
}

func TestRouter_SPAServedAtPrefixRoot(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/"), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if !strings.HasPrefix(r.Headers.Get("Content-Type"), "text/html") {
		t.Errorf("content-type = %q, want text/html", r.Headers.Get("Content-Type"))
	}
	if !bytes.Contains(r.Body, []byte("__nuxt")) {
		t.Errorf("body did not contain the SPA root marker: %s", string(r.Body))
	}
	if !bytes.Contains(r.Body, []byte(`content="/`+testWebPath+`"`)) {
		t.Errorf("served HTML did not include the injected web-path meta tag: %s", string(r.Body))
	}
}

func TestRouter_BarePrefixRedirects(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	// Issue a request without following redirects so we can assert
	// the panel root specifically lands on the trailing-slash form.
	req, err := http.NewRequest(http.MethodGet, s.URL+"/"+testWebPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// chi.Mount registers the bare prefix as a stub; depending on chi
	// version it either redirects to `/<prefix>/` or serves the root
	// directly. Either outcome is acceptable as long as the bare path
	// stays usable (i.e. not a 404). Acceptance tests on the VM
	// always exercise the trailing-slash form.
	if resp.StatusCode == http.StatusNotFound {
		t.Errorf("bare prefix returned 404, want 200/301")
	}
}

func TestRouter_DeepSPARouteFallsBackToIndex(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/settings"), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (SPA fallback)", r.Status)
	}
	if !bytes.Contains(r.Body, []byte("__nuxt")) {
		t.Errorf("expected SPA index fallback, got %s", string(r.Body))
	}
}

func TestRouter_NuxtAssetServed(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/_nuxt/entry.js"), nil)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200", r.Status)
	}
	if !strings.HasPrefix(r.Headers.Get("Content-Type"), "application/javascript") {
		t.Errorf("content-type = %q, want application/javascript", r.Headers.Get("Content-Type"))
	}
}

func TestRouter_SettingsRequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	r := getJSON(t, panelURL(s, "/api/settings"), nil)
	if r.Status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", r.Status)
	}
}

func TestRouter_SettingsReturnsView(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	login := postJSON(t, panelURL(s, "/api/login"), `{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login: %d %s", login.Status, string(login.Body))
	}
	var creds struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &creds); err != nil {
		t.Fatal(err)
	}
	r := getJSON(t, panelURL(s, "/api/settings"), map[string]string{"Authorization": "Bearer " + creds.Token})
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d (%s), want 200", r.Status, string(r.Body))
	}
	var view SettingsView
	if err := json.Unmarshal(r.Body, &view); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(r.Body))
	}
	wantView := SettingsView{
		ServerRole: "client",
		PanelPort:  18080,
		WebPath:    testWebPath,
		LogLevel:   "info",
		Version:    "test",
	}
	if view != wantView {
		t.Errorf("view = %+v, want %+v", view, wantView)
	}
	// PSK and password hash never appear here. Sanity-check by
	// ensuring the JSON has only the documented keys.
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(r.Body, &keys); err != nil {
		t.Fatal(err)
	}
	wanted := map[string]bool{"server_role": true, "panel_port": true, "web_path": true, "log_level": true, "version": true}
	for k := range keys {
		if !wanted[k] {
			t.Errorf("unexpected key in /api/settings response: %q", k)
		}
	}
}

// TestRouter_WGConfigs_HiddenOnRemote pins the R6 contract: when the
// panel runs as Remote-role, /api/wg-configs and its sub-routes return
// 404 for the operator's authenticated session. The WG picker is a
// Client-only concept and a curious operator pasting the URL should
// not be able to see (or accidentally write to) a config that the
// upload path will never use.
func TestRouter_WGConfigs_HiddenOnRemote(t *testing.T) {
	f := newTestFixture(t)
	f.withRole(tunnels.RoleRemote)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	for _, p := range []string{
		"/api/wg-configs",
		"/api/wg-configs/1",
		"/api/wg-configs/1/handshake",
	} {
		t.Run("GET "+p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), hdr)
			if r.Status != http.StatusNotFound {
				t.Errorf("status = %d body=%q, want 404", r.Status, string(r.Body))
			}
		})
	}
	// A POST to /api/wg-configs must also 404 on Remote — defence in
	// depth against a curious operator with the REST endpoint memorised.
	t.Run("POST /api/wg-configs", func(t *testing.T) {
		r := postJSON(t, panelURL(s, "/api/wg-configs"), `{"name":"x","raw_text":"y"}`, hdr)
		if r.Status != http.StatusNotFound {
			t.Errorf("status = %d body=%q, want 404", r.Status, string(r.Body))
		}
	})
}

// TestRouter_WGConfigs_ListedOnClient is the no-regression companion
// to TestRouter_WGConfigs_HiddenOnRemote: on a Client-role server the
// route still answers 200 (with an empty list when no configs exist).
func TestRouter_WGConfigs_ListedOnClient(t *testing.T) {
	f := newTestFixture(t) // default role is client
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	r := getJSON(t, panelURL(s, "/api/wg-configs"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200", r.Status, string(r.Body))
	}
}

// TestRouter_SOCKS5Proxies_HiddenOnRemote pins the R10 contract: when
// the panel runs as Remote-role, /api/socks5-proxies and its sub-routes
// return 404. The SOCKS5 picker is a Client-only concept (the Client
// dials the proxy on upload; the Remote just receives UDP) and a
// curious operator pasting the URL should land on an honest 404 — same
// shape as the R6 WG-hide.
func TestRouter_SOCKS5Proxies_HiddenOnRemote(t *testing.T) {
	f := newTestFixture(t)
	f.withRole(tunnels.RoleRemote)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	for _, p := range []string{
		"/api/socks5-proxies",
		"/api/socks5-proxies/1",
	} {
		t.Run("GET "+p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), hdr)
			if r.Status != http.StatusNotFound {
				t.Errorf("status = %d body=%q, want 404", r.Status, string(r.Body))
			}
		})
	}
	// A POST to /api/socks5-proxies must also 404 on Remote — defence
	// in depth against a curious operator with the REST endpoint
	// memorised.
	t.Run("POST /api/socks5-proxies", func(t *testing.T) {
		r := postJSON(t, panelURL(s, "/api/socks5-proxies"),
			`{"name":"x","host":"127.0.0.1","port":1080}`, hdr)
		if r.Status != http.StatusNotFound {
			t.Errorf("status = %d body=%q, want 404", r.Status, string(r.Body))
		}
	})
}

// TestRouter_SOCKS5Proxies_ListedOnClient is the no-regression
// companion to TestRouter_SOCKS5Proxies_HiddenOnRemote: on a
// Client-role server the route still answers 200 (with an empty list
// when no proxies exist).
func TestRouter_SOCKS5Proxies_ListedOnClient(t *testing.T) {
	f := newTestFixture(t) // default role is client
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	r := getJSON(t, panelURL(s, "/api/socks5-proxies"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status = %d body=%q, want 200", r.Status, string(r.Body))
	}
}

// TestRouter_NewRouterPanicsWithoutWebPath documents the contract on
// the constructor's required field. main.go pulls WebPath from the
// validated config so this is purely a wiring guard.
func TestRouter_NewRouterPanicsWithoutWebPath(t *testing.T) {
	f := newTestFixture(t)
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("NewRouter with empty WebPath should panic")
		}
	}()
	deps := f.routerDeps()
	deps.WebPath = ""
	_ = httptest.NewServer(NewRouter(deps))
}
