package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// genWGConfig returns a freshly-generated wg-quick text. Each call
// derives new keys so concurrent tests can't see each other's bytes.
func genWGConfig(t *testing.T) string {
	t.Helper()
	priv := mustGenKey(t)
	peer := mustGenKey(t)
	psk := mustGenKey(t)
	return strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + priv.String(),
		"Address = 10.66.66.2/32",
		"MTU = 1280",
		"ListenPort = 51820",
		"",
		"[Peer]",
		"PublicKey = " + peer.PublicKey().String(),
		"PresharedKey = " + psk.String(),
		"AllowedIPs = 0.0.0.0/0",
		"Endpoint = 198.51.100.20:81",
		"PersistentKeepalive = 25",
	}, "\n")
}

func mustGenKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("GeneratePrivateKey: %v", err)
	}
	return k
}

func TestWGConfig_RequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	for _, p := range []string{
		"/api/wg-configs",
		"/api/wg-configs/1",
		"/api/wg-configs/1/handshake",
	} {
		t.Run(p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), nil)
			if r.Status != http.StatusUnauthorized {
				t.Errorf("GET %s without auth = %d, want 401", p, r.Status)
			}
		})
	}
}

func TestWGConfig_CreateMasksRawText(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	body, err := json.Marshal(map[string]any{
		"name":     "starlink-1",
		"raw_text": genWGConfig(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	res := postJSON(t, panelURL(s, "/api/wg-configs"), string(body), hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("create = %d body=%s", res.Status, string(res.Body))
	}
	var resp struct {
		Config struct {
			ID            int64  `json:"id"`
			Name          string `json:"name"`
			RawText       string `json:"raw_text"`
			PublicKeySelf string `json:"public_key_self"`
		} `json:"config"`
		Warnings []string `json:"warnings"`
	}
	if err := json.Unmarshal(res.Body, &resp); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(res.Body))
	}
	if resp.Config.RawText != RedactedRawText {
		t.Errorf("RawText not redacted: %q", resp.Config.RawText)
	}
	if resp.Config.PublicKeySelf == "" {
		t.Error("PublicKeySelf should be derived from PrivateKey")
	}
	if strings.Contains(string(res.Body), "PrivateKey =") {
		t.Errorf("response leaked raw config: %s", string(res.Body))
	}
}

func TestWGConfig_RejectsMalformed(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := `{"name":"bad","raw_text":"not even close to wg-quick"}`
	res := postJSON(t, panelURL(s, "/api/wg-configs"), body, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s", res.Status, string(res.Body))
	}
	var resp struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(res.Body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, ok := resp.Fields["raw_text"]; !ok {
		t.Errorf("expected fields.raw_text, got %+v", resp.Fields)
	}
}

func TestWGConfig_RevealReturnsRawText(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	wgText := genWGConfig(t)
	body, _ := json.Marshal(map[string]any{"name": "reveal-test", "raw_text": wgText})
	create := postJSON(t, panelURL(s, "/api/wg-configs"), string(body), hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Status, string(create.Body))
	}
	var resp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(create.Body, &resp)

	r := getJSON(t, panelURL(s, "/api/wg-configs/"+strconv.FormatInt(resp.Config.ID, 10)), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("get redacted: %d", r.Status)
	}
	if strings.Contains(string(r.Body), "PrivateKey =") {
		t.Errorf("default get leaked raw text: %s", string(r.Body))
	}

	reveal := getJSON(t, panelURL(s, "/api/wg-configs/"+strconv.FormatInt(resp.Config.ID, 10)+"?reveal=1"), hdr)
	if reveal.Status != http.StatusOK {
		t.Fatalf("reveal get: %d", reveal.Status)
	}
	if !strings.Contains(string(reveal.Body), "PrivateKey =") {
		t.Errorf("reveal=1 should expose raw text, got %s", string(reveal.Body))
	}
}

func TestWGConfig_DeleteRefusedWhileReferenced(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	create := postJSON(t, panelURL(s, "/api/wg-configs"),
		`{"name":"linked","raw_text":`+strconv.Quote(genWGConfig(t))+`}`, hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create wg: %d %s", create.Status, string(create.Body))
	}
	var crResp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(create.Body, &crResp)

	// Create a tunnel that links to this config.
	tunnelBody := strings.Replace(validClientBody, `"wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0"`,
		`"wg_config_id": `+strconv.FormatInt(crResp.Config.ID, 10), 1)
	tunRes := postJSON(t, panelURL(s, "/api/tunnels"), tunnelBody, hdr)
	if tunRes.Status != http.StatusCreated {
		t.Fatalf("seed tunnel: %d %s", tunRes.Status, string(tunRes.Body))
	}

	// Delete should now refuse and name the dependent tunnel.
	del := doDelete(t, panelURL(s, "/api/wg-configs/"+strconv.FormatInt(crResp.Config.ID, 10)), hdr)
	if del.Status != http.StatusConflict {
		t.Fatalf("delete-while-referenced = %d, want 409 body=%s", del.Status, string(del.Body))
	}
	if !strings.Contains(string(del.Body), "tunnel-1") {
		t.Errorf("conflict body should name the dependent tunnel, got %s", string(del.Body))
	}
}

func TestWGConfig_UpdateKeepRawPreservesSecret(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	wgText := genWGConfig(t)
	create := postJSON(t, panelURL(s, "/api/wg-configs"),
		`{"name":"keep","raw_text":`+strconv.Quote(wgText)+`}`, hdr)
	if create.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.Status, string(create.Body))
	}
	var crResp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(create.Body, &crResp)

	// Update with only the name → raw_text must survive untouched.
	upd := doPut(t,
		panelURL(s, "/api/wg-configs/"+strconv.FormatInt(crResp.Config.ID, 10)),
		`{"name":"keep-renamed"}`, hdr)
	if upd.Status != http.StatusOK {
		t.Fatalf("rename-only update: %d %s", upd.Status, string(upd.Body))
	}

	reveal := getJSON(t, panelURL(s, "/api/wg-configs/"+strconv.FormatInt(crResp.Config.ID, 10)+"?reveal=1"), hdr)
	if !strings.Contains(string(reveal.Body), "PrivateKey =") {
		t.Errorf("rename-only update lost raw_text: %s", string(reveal.Body))
	}
}

func TestWGConfig_ListRedactsRawText(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	for _, name := range []string{"a", "b"} {
		body := `{"name":"` + name + `","raw_text":` + strconv.Quote(genWGConfig(t)) + `}`
		if r := postJSON(t, panelURL(s, "/api/wg-configs"), body, hdr); r.Status != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, r.Status, string(r.Body))
		}
	}
	r := getJSON(t, panelURL(s, "/api/wg-configs"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("list: %d", r.Status)
	}
	if strings.Contains(string(r.Body), "PrivateKey =") {
		t.Errorf("list leaked raw text: %s", string(r.Body))
	}
	if !strings.Contains(string(r.Body), `"raw_text":"***"`) {
		t.Errorf("expected redacted raw_text in list response, got %s", string(r.Body))
	}
}

func TestWGConfig_TunnelLinkRoundTrip(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	cr := postJSON(t, panelURL(s, "/api/wg-configs"),
		`{"name":"link-rt","raw_text":`+strconv.Quote(genWGConfig(t))+`}`, hdr)
	if cr.Status != http.StatusCreated {
		t.Fatalf("create wg: %d %s", cr.Status, string(cr.Body))
	}
	var crResp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(cr.Body, &crResp)

	// Build a tunnel input that uses wg_config_id instead of the
	// legacy text path.
	tunnelBody := strings.Replace(validClientBody, `"wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0"`,
		`"wg_config_id": `+strconv.FormatInt(crResp.Config.ID, 10), 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), tunnelBody, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("create tunnel with wg_config_id: %d %s", res.Status, string(res.Body))
	}
	var dto tunnelDTO
	_ = json.Unmarshal(res.Body, &dto)
	if dto.WGConfigID == nil || *dto.WGConfigID != crResp.Config.ID {
		t.Errorf("wg_config_id not round-tripped: %+v", dto.WGConfigID)
	}
}

func TestWGConfig_TunnelLinkRejectsUnknownID(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	// Reference a wg_config_id that doesn't exist.
	tunnelBody := strings.Replace(validClientBody, `"wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0"`,
		`"wg_config_id": 9999`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), tunnelBody, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "wg_config_id") {
		t.Errorf("expected per-field wg_config_id error, got %s", string(res.Body))
	}
}

func TestWGConfig_HandshakeReportsNoInterface(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	cr := postJSON(t, panelURL(s, "/api/wg-configs"),
		`{"name":"hs","raw_text":`+strconv.Quote(genWGConfig(t))+`}`, hdr)
	if cr.Status != http.StatusCreated {
		t.Fatalf("create: %d %s", cr.Status, string(cr.Body))
	}
	var crResp struct {
		Config struct {
			ID int64 `json:"id"`
		} `json:"config"`
	}
	_ = json.Unmarshal(cr.Body, &crResp)

	// No Manager in the fixture → handshake returns the empty state
	// (interface name unknown, stale=true). The panel renders this as
	// "no interface up yet".
	r := getJSON(t, panelURL(s, "/api/wg-configs/"+strconv.FormatInt(crResp.Config.ID, 10)+"/handshake"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("handshake: %d %s", r.Status, string(r.Body))
	}
	var hs struct {
		Stale            bool `json:"stale"`
		HasEverConnected bool `json:"has_ever_connected"`
	}
	if err := json.Unmarshal(r.Body, &hs); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !hs.Stale {
		t.Error("with no manager, handshake should be stale=true")
	}
	if hs.HasEverConnected {
		t.Error("with no manager, has_ever_connected should be false")
	}
}
