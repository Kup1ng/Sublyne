package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// TestSOCKS5_RequiresAuth pins that every SOCKS5 endpoint is behind
// the same auth wall as the WireGuard endpoints.
func TestSOCKS5_RequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	for _, p := range []string{
		"/api/socks5-proxies",
		"/api/socks5-proxies/1",
	} {
		t.Run(p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), nil)
			if r.Status != http.StatusUnauthorized {
				t.Errorf("GET %s without auth = %d, want 401", p, r.Status)
			}
		})
	}
}

// TestSOCKS5_CreateRedactsPassword pins that the create response
// returns "***" for password, never the raw bytes.
func TestSOCKS5_CreateRedactsPassword(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	body, err := json.Marshal(map[string]any{
		"name":                 "starlink-lb",
		"host":                 "192.0.2.10",
		"port":                 1080,
		"username":             "alice",
		"password":             "super-secret-shouldnt-leak",
		"parallel_connections": 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	res := postJSON(t, panelURL(s, "/api/socks5-proxies"), string(body), hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("create = %d body=%s", res.Status, string(res.Body))
	}
	if strings.Contains(string(res.Body), "super-secret-shouldnt-leak") {
		t.Errorf("response leaked password: %s", string(res.Body))
	}
	if !strings.Contains(string(res.Body), `"password":"***"`) {
		t.Errorf("expected redacted password, got %s", string(res.Body))
	}
}

// TestSOCKS5_RevealReturnsPassword pins the explicit ?reveal=1
// opt-in for the get endpoint.
func TestSOCKS5_RevealReturnsPassword(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	body, _ := json.Marshal(map[string]any{
		"name":                 "reveal-test",
		"host":                 "192.0.2.11",
		"port":                 1080,
		"username":             "bob",
		"password":             "another-secret-byte",
		"parallel_connections": 4,
	})
	create := postJSON(t, panelURL(s, "/api/socks5-proxies"), string(body), hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Status, string(create.Body))
	}
	var resp struct {
		Proxy struct {
			ID int64 `json:"id"`
		} `json:"proxy"`
	}
	_ = json.Unmarshal(create.Body, &resp)

	plain := getJSON(t, panelURL(s, "/api/socks5-proxies/"+strconv.FormatInt(resp.Proxy.ID, 10)), hdr)
	if plain.Status != http.StatusOK {
		t.Fatalf("get plain: %d", plain.Status)
	}
	if strings.Contains(string(plain.Body), "another-secret-byte") {
		t.Errorf("default get leaked password: %s", string(plain.Body))
	}

	reveal := getJSON(t, panelURL(s, "/api/socks5-proxies/"+strconv.FormatInt(resp.Proxy.ID, 10)+"?reveal=1"), hdr)
	if reveal.Status != http.StatusOK {
		t.Fatalf("reveal get: %d", reveal.Status)
	}
	if !strings.Contains(string(reveal.Body), "another-secret-byte") {
		t.Errorf("reveal=1 should expose password, got %s", string(reveal.Body))
	}
}

// TestSOCKS5_RejectsInvalidPort verifies field-level validation
// flags an out-of-range port with the per-field error shape.
func TestSOCKS5_RejectsInvalidPort(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := `{"name":"bad-port","host":"10.0.0.1","port":99999,"parallel_connections":4}`
	res := postJSON(t, panelURL(s, "/api/socks5-proxies"), body, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", res.Status, string(res.Body))
	}
	var resp struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(res.Body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp.Fields["port"]; !ok {
		t.Errorf("expected fields.port, got %+v", resp.Fields)
	}
}

// TestSOCKS5_RejectsParallelConnectionsOverCap pins the safety cap.
// 65 should be rejected (cap is 64).
func TestSOCKS5_RejectsParallelConnectionsOverCap(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := `{"name":"overcap","host":"10.0.0.1","port":1080,"parallel_connections":65}`
	res := postJSON(t, panelURL(s, "/api/socks5-proxies"), body, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "parallel_connections") {
		t.Errorf("expected fields.parallel_connections, got %s", string(res.Body))
	}
}

// TestSOCKS5_DeleteRefusedWhileReferenced pins the "detach the
// link first" contract: deleting a proxy that any tunnel still
// references returns 409 and names the dependent tunnels.
func TestSOCKS5_DeleteRefusedWhileReferenced(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	create := postJSON(t, panelURL(s, "/api/socks5-proxies"),
		`{"name":"linked","host":"192.0.2.10","port":1080,"parallel_connections":4}`, hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Status, string(create.Body))
	}
	var crResp struct {
		Proxy struct {
			ID int64 `json:"id"`
		} `json:"proxy"`
	}
	_ = json.Unmarshal(create.Body, &crResp)

	// Create a tunnel that links via upload_mode=socks5 +
	// socks5_proxy_id. SOCKS5 upload pairs with the tcp_syn download
	// transport under the v2 matrix (socks5ClientBody handles both the
	// transport flip and dropping the legacy wireguard_config blob).
	socks5Body := socks5ClientBody(crResp.Proxy.ID, "")
	tunRes := postJSON(t, panelURL(s, "/api/tunnels"), socks5Body, hdr)
	if tunRes.Status != http.StatusCreated {
		t.Fatalf("seed tunnel: %d %s", tunRes.Status, string(tunRes.Body))
	}

	del := doDelete(t, panelURL(s, "/api/socks5-proxies/"+strconv.FormatInt(crResp.Proxy.ID, 10)), hdr)
	if del.Status != http.StatusConflict {
		t.Fatalf("delete-while-referenced = %d, want 409 body=%s", del.Status, string(del.Body))
	}
	if !strings.Contains(string(del.Body), "tunnel-1") {
		t.Errorf("conflict body should name the dependent tunnel, got %s", string(del.Body))
	}
}

// TestSOCKS5Tunnel_StartFlipsEnabled pins the R9a contract: a
// socks5-mode tunnel can now be saved AND started. The R8 contract
// (Start returns 400 NOT_IMPLEMENTED) is replaced now that the
// dataplane carries the single-connection SOCKS5 path. The test
// fixture's Dataplane is nil, so Start short-circuits past the IPC
// call and only flips the `enabled` flag in the DB; the goal here is
// to prove the handler no longer refuses SOCKS5 mode.
func TestSOCKS5Tunnel_StartFlipsEnabled(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	cr := postJSON(t, panelURL(s, "/api/socks5-proxies"),
		`{"name":"r9a-test","host":"192.0.2.10","port":1080,"parallel_connections":4}`, hdr)
	if cr.Status != http.StatusCreated {
		t.Fatalf("create proxy: %d %s", cr.Status, string(cr.Body))
	}
	var crResp struct {
		Proxy struct {
			ID int64 `json:"id"`
		} `json:"proxy"`
	}
	_ = json.Unmarshal(cr.Body, &crResp)

	socks5Body := socks5ClientBody(crResp.Proxy.ID, "")
	create := postJSON(t, panelURL(s, "/api/tunnels"), socks5Body, hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create tunnel: %d %s", create.Status, string(create.Body))
	}
	var dto tunnelDTO
	_ = json.Unmarshal(create.Body, &dto)
	if dto.UploadMode != "socks5" {
		t.Errorf("upload_mode = %q, want socks5", dto.UploadMode)
	}
	if dto.Socks5ProxyID == nil || *dto.Socks5ProxyID != crResp.Proxy.ID {
		t.Errorf("socks5_proxy_id not round-tripped: %+v", dto.Socks5ProxyID)
	}

	// R9a: Start must succeed (no more NOT_IMPLEMENTED gate).
	start := postJSON(t, panelURL(s, "/api/tunnels/"+strconv.FormatInt(dto.ID, 10)+"/start"), "", hdr)
	if start.Status != http.StatusOK {
		t.Fatalf("Start status = %d, want 200 body=%s", start.Status, string(start.Body))
	}
	if strings.Contains(string(start.Body), "NOT_IMPLEMENTED") {
		t.Errorf("R9a removed the NOT_IMPLEMENTED gate; Start body should not contain it: %s", string(start.Body))
	}
	var started tunnelDTO
	_ = json.Unmarshal(start.Body, &started)
	if !started.Enabled {
		t.Errorf("expected enabled=true after Start, got %+v", started)
	}
}

// TestSOCKS5Tunnel_StartMissingProxyIs400 pins the R9a recovery path:
// if the linked proxy has been deleted out from under the tunnel (or
// the FK is somehow missing), Start surfaces a per-form error instead
// of a generic 500.
func TestSOCKS5Tunnel_StartMissingProxyIs400(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	cr := postJSON(t, panelURL(s, "/api/socks5-proxies"),
		`{"name":"to-delete","host":"192.0.2.10","port":1080,"parallel_connections":4}`, hdr)
	var crResp struct {
		Proxy struct {
			ID int64 `json:"id"`
		} `json:"proxy"`
	}
	_ = json.Unmarshal(cr.Body, &crResp)

	socks5Body := socks5ClientBody(crResp.Proxy.ID, "")
	tunRes := postJSON(t, panelURL(s, "/api/tunnels"), socks5Body, hdr)
	if tunRes.Status != http.StatusCreated {
		t.Fatalf("create tunnel: %d %s", tunRes.Status, string(tunRes.Body))
	}
	var dto tunnelDTO
	_ = json.Unmarshal(tunRes.Body, &dto)

	// Force the dependent-row state: clear the FK in the DB directly so
	// the tunnel still claims socks5 mode without a proxy to back it.
	// Going through the panel would refuse (validation rejects "socks5
	// mode without a proxy"); this simulates "proxy deleted via a tool
	// that didn't go through the panel".
	if _, err := f.db.Exec(`UPDATE tunnels SET socks5_proxy_id = NULL WHERE id = ?`, dto.ID); err != nil {
		t.Fatalf("force-clear FK: %v", err)
	}

	start := postJSON(t, panelURL(s, "/api/tunnels/"+strconv.FormatInt(dto.ID, 10)+"/start"), "", hdr)
	if start.Status != http.StatusBadRequest {
		t.Fatalf("Start with missing proxy = %d, want 400 body=%s", start.Status, string(start.Body))
	}
}

// TestSOCKS5Tunnel_RejectsBothPickers covers the validator's mutual-
// exclusion rule: upload_mode=socks5 + a wg_config_id is a per-field
// error on wg_config_id.
func TestSOCKS5Tunnel_RejectsBothPickers(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	// Create a WG config and a SOCKS5 proxy so both ids are valid.
	wg := postJSON(t, panelURL(s, "/api/wg-configs"),
		`{"name":"r8-mut","raw_text":`+strconv.Quote(genWGConfig(t))+`}`, hdr)
	if wg.Status != http.StatusCreated {
		t.Fatalf("seed wg: %d %s", wg.Status, string(wg.Body))
	}
	var wgResp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(wg.Body, &wgResp)
	sx := postJSON(t, panelURL(s, "/api/socks5-proxies"),
		`{"name":"r8-mut","host":"192.0.2.10","port":1080,"parallel_connections":4}`, hdr)
	if sx.Status != http.StatusCreated {
		t.Fatalf("seed socks5: %d %s", sx.Status, string(sx.Body))
	}
	var sxResp struct {
		Proxy struct {
			ID int64 `json:"id"`
		} `json:"proxy"`
	}
	_ = json.Unmarshal(sx.Body, &sxResp)

	bothBody := socks5ClientBody(sxResp.Proxy.ID,
		`, "wg_config_id": `+strconv.FormatInt(wgResp.Config.ID, 10))
	res := postJSON(t, panelURL(s, "/api/tunnels"), bothBody, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "wg_config_id") {
		t.Errorf("expected wg_config_id mutual-exclusion error, got %s", string(res.Body))
	}
}
