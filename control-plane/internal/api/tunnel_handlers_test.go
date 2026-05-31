package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// loginAndTokenHeader returns an Authorization: Bearer header for a
// freshly-logged-in admin so the tunnel tests don't have to repeat the
// login boilerplate. baseURL is the *httptest.Server.URL value.
func loginAndTokenHeader(t *testing.T, baseURL string) map[string]string {
	t.Helper()
	login := postJSON(t, baseURL+"/"+testWebPath+"/api/login",
		`{"username":"admin","password":"correct horse"}`, nil)
	if login.Status != http.StatusOK {
		t.Fatalf("login status = %d body=%s", login.Status, string(login.Body))
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(login.Body, &body); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	return map[string]string{"Authorization": "Bearer " + body.Token}
}

// validClientBody returns a JSON body the panel would post for a
// fresh client-role tunnel. Tests mutate the returned string with
// strings.Replace as needed.
const validClientBody = `{
  "name": "tunnel-1",
  "psk": "shared-psk-32-chars-long-xxxxxxxx",
  "download_spoof_source_ip": "203.0.113.5",
  "download_spoof_source_port": 443,
  "download_transport": "udp",
  "mtu": 1400,
  "max_connections": 50000,
  "idle_timeout": 300,
  "local_listen_addr": "0.0.0.0",
  "ports": [44443],
  "download_receive_port": 8443,
  "upload_target_addr": "198.51.100.10:55555",
  "wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0",
  "ping_smoothing_enabled": false,
  "ping_smoothing_target_ms": 60,
  "pacing_enabled": false,
  "pacing_target_ms": 100,
  "enabled": false
}`

const validRemoteBody = `{
  "name": "tunnel-r-1",
  "psk": "shared-psk-32-chars-long-yyyyyyyy",
  "download_spoof_source_ip": "203.0.113.5",
  "download_spoof_source_port": 443,
  "download_transport": "udp",
  "mtu": 1400,
  "max_connections": 50000,
  "idle_timeout": 300,
  "upload_listen_addr": "0.0.0.0:55555",
  "forward_target": "127.0.0.1",
  "ports": [5201],
  "download_send_port": 8443,
  "client_real_ip": "198.51.100.20",
  "enabled": false
}`

// socks5ClientBody builds the JSON body for a SOCKS5-upload client
// tunnel that is VALID under the v2 upload×download matrix: SOCKS5
// upload pairs only with the tcp_syn (or icmp/icmpv6) download
// transport, never udp. It starts from validClientBody, flips the
// download transport to tcp_syn, and swaps the legacy wireguard_config
// blob for `upload_mode=socks5 + socks5_proxy_id`. Extra JSON fragments
// (e.g. a stray wg_config_id for the mutual-exclusion test) can be
// appended via `extra`.
func socks5ClientBody(proxyID int64, extra string) string {
	b := strings.Replace(validClientBody,
		`"download_transport": "udp"`,
		`"download_transport": "tcp_syn"`, 1)
	repl := `"upload_mode": "socks5", "socks5_proxy_id": ` +
		strconv.FormatInt(proxyID, 10) + extra
	return strings.Replace(b,
		`"wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0"`,
		repl, 1)
}

func TestTunnels_RequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	for _, p := range []string{
		"/api/tunnels",
		"/api/tunnels/1",
		"/api/tunnels/1/start",
		"/api/tunnels/1/stop",
		"/api/tunnels/1/export",
		"/api/tunnels/import",
	} {
		t.Run(p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), nil)
			if r.Status != http.StatusUnauthorized {
				t.Errorf("GET %s without auth = %d, want 401", p, r.Status)
			}
		})
	}
}

func TestCreateTunnel_HappyClient(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	res := postJSON(t, panelURL(s, "/api/tunnels"), validClientBody, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("create status = %d body=%s", res.Status, string(res.Body))
	}
	var out tunnelDTO
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.ID == 0 || out.Name != "tunnel-1" || out.Role != "client" {
		t.Errorf("unexpected created tunnel: %+v", out)
	}
	if out.PSK != RedactedPSK {
		t.Errorf("PSK should be redacted in create response, got %q", out.PSK)
	}
	if out.Enabled {
		t.Error("created tunnel should land stopped")
	}
}

func TestCreateTunnel_PortConflictReported(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	// First create the canonical fixture tunnel.
	first := postJSON(t, panelURL(s, "/api/tunnels"), validClientBody, hdr)
	if first.Status != http.StatusCreated {
		t.Fatalf("seed create: %d %s", first.Status, string(first.Body))
	}

	// Second tunnel reuses the first's application port (44443). Keep the
	// ports list the same; change the receive port so the conflict comes
	// from the unified ports list alone.
	second := strings.Replace(validClientBody, `"name": "tunnel-1"`, `"name": "tunnel-2"`, 1)
	second = strings.Replace(second, `"download_receive_port": 8443`, `"download_receive_port": 8444`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), second, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	var body struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(res.Body))
	}
	// v2.7.0: an application-port clash is reported on the unified `ports`
	// field, naming the colliding port and the owning tunnel.
	msg, ok := body.Fields["ports"]
	if !ok {
		t.Fatalf("expected fields.ports, got %+v", body.Fields)
	}
	if !strings.Contains(msg, "44443") || !strings.Contains(msg, "tunnel-1") {
		t.Errorf("conflict message should name the port and the owner; got %q", msg)
	}
}

func TestCreateTunnel_RejectsRemoteOnClientServer(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	res := postJSON(t, panelURL(s, "/api/tunnels"), validRemoteBody, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	// Server is a client; the validator should flag every field that
	// remote tunnels require *and* the matching client fields they
	// omit. The simplest cross-check is that the response is a fields
	// map.
	var body struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(res.Body))
	}
	if len(body.Fields) == 0 {
		t.Errorf("expected per-field errors, got: %+v", body)
	}
}

func TestCreateTunnel_RemoteServer_AcceptsRemoteBody(t *testing.T) {
	f := newTestFixture(t)
	f.withRole(tunnels.RoleRemote)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	res := postJSON(t, panelURL(s, "/api/tunnels"), validRemoteBody, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("status = %d body=%s", res.Status, string(res.Body))
	}
	var out tunnelDTO
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Role != "remote" {
		t.Errorf("role = %q, want remote", out.Role)
	}
	if out.PSK != RedactedPSK {
		t.Errorf("PSK should be redacted, got %q", out.PSK)
	}
	if out.UploadListenAddr == nil || *out.UploadListenAddr != "0.0.0.0:55555" {
		t.Errorf("upload_listen_addr round-trip = %v", out.UploadListenAddr)
	}
}

func TestListTunnels_RedactsPSK(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	mustCreate(t, s.URL, hdr, validClientBody)
	res := getJSON(t, panelURL(s, "/api/tunnels"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("list status = %d body=%s", res.Status, string(res.Body))
	}
	if strings.Contains(string(res.Body), "shared-psk-32-chars-long") {
		t.Errorf("list response leaked the PSK: %s", string(res.Body))
	}
	if !strings.Contains(string(res.Body), `"psk":"***"`) {
		t.Errorf("expected redacted PSK marker in response, got %s", string(res.Body))
	}
}

func TestStartStopFlipsEnabled(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	start := postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/start"), `{}`, hdr)
	if start.Status != http.StatusOK {
		t.Fatalf("start: %d %s", start.Status, string(start.Body))
	}
	var enabled tunnelDTO
	_ = json.Unmarshal(start.Body, &enabled)
	if !enabled.Enabled {
		t.Error("after start, enabled should be true")
	}

	stop := postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/stop"), `{}`, hdr)
	if stop.Status != http.StatusOK {
		t.Fatalf("stop: %d %s", stop.Status, string(stop.Body))
	}
	var disabled tunnelDTO
	_ = json.Unmarshal(stop.Body, &disabled)
	if disabled.Enabled {
		t.Error("after stop, enabled should be false")
	}
}

func TestDeleteTunnel_RefusedWhileEnabled(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	_ = postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/start"), `{}`, hdr)
	del := doDelete(t, panelURL(s, "/api/tunnels/"+strID(id)), hdr)
	if del.Status != http.StatusConflict {
		t.Fatalf("delete-while-enabled = %d, want 409 body=%s", del.Status, string(del.Body))
	}

	_ = postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/stop"), `{}`, hdr)
	del = doDelete(t, panelURL(s, "/api/tunnels/"+strID(id)), hdr)
	if del.Status != http.StatusOK {
		t.Fatalf("delete after stop = %d, want 200 body=%s", del.Status, string(del.Body))
	}
}

func TestUpdateTunnel_PSKOmittedKeepsExisting(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	// Send the same body but without the psk field; mtu changes.
	body := strings.Replace(validClientBody, `"mtu": 1400`, `"mtu": 1380`, 1)
	body = strings.Replace(body, `"psk": "shared-psk-32-chars-long-xxxxxxxx",`, "", 1)
	res := doPut(t, panelURL(s, "/api/tunnels/"+strID(id)), body, hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("update = %d body=%s", res.Status, string(res.Body))
	}

	// Export (with secrets) should still show the original PSK.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export?secrets=1"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	if !strings.Contains(string(exp.Body), "shared-psk-32-chars-long-xxxxxxxx") {
		t.Errorf("export should show the kept PSK, got %s", string(exp.Body))
	}
}

// TestMultiTunnel_DistinctPortsCoexist proves §3.7: many tunnels can be
// configured on a single server as long as their ports don't collide.
// Stopping or deleting one tunnel must not affect the others' rows.
func TestMultiTunnel_DistinctPortsCoexist(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	// Two client tunnels with different ports.
	idA := mustCreate(t, s.URL, hdr, validClientBody)
	b := strings.Replace(validClientBody, `"name": "tunnel-1"`, `"name": "tunnel-2"`, 1)
	b = strings.Replace(b, `"ports": [44443]`, `"ports": [44455]`, 1)
	b = strings.Replace(b, `"download_receive_port": 8443`, `"download_receive_port": 8455`, 1)
	idB := mustCreate(t, s.URL, hdr, b)

	if idA == idB {
		t.Fatalf("ids should differ: %d == %d", idA, idB)
	}

	// Delete tunnel A — tunnel B should still be listable.
	del := doDelete(t, panelURL(s, "/api/tunnels/"+strID(idA)), hdr)
	if del.Status != http.StatusOK {
		t.Fatalf("delete A = %d", del.Status)
	}
	res := getJSON(t, panelURL(s, "/api/tunnels"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("list = %d", res.Status)
	}
	var body struct {
		Tunnels []tunnelDTO `json:"tunnels"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(body.Tunnels) != 1 || body.Tunnels[0].ID != idB {
		t.Fatalf("expected exactly tunnel B alive, got %v", body.Tunnels)
	}
}

// TestMultiTunnel_PortConflictRejected proves §3.5: creating a second
// tunnel that reuses the first's application port must be refused.
func TestMultiTunnel_PortConflictRejected(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	_ = mustCreate(t, s.URL, hdr, validClientBody)

	// Second body collides on the application port (44443).
	dup := strings.Replace(validClientBody, `"name": "tunnel-1"`, `"name": "tunnel-2"`, 1)
	dup = strings.Replace(dup, `"download_receive_port": 8443`, `"download_receive_port": 8444`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), dup, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected 400 conflict, got %d body=%s", res.Status, string(res.Body))
	}
	// v2.7.0: the app-port clash surfaces on the unified `ports` field.
	if !strings.Contains(string(res.Body), "ports") {
		t.Fatalf("expected ports in error, got %s", string(res.Body))
	}
	if !strings.Contains(string(res.Body), "tunnel-1") {
		t.Fatalf("expected first tunnel name in error, got %s", string(res.Body))
	}
}

// TestUpdateTunnel_DisabledTunnelSkipsDataplane confirms the handler
// doesn't call into the dataplane when the tunnel isn't enabled — a
// disabled tunnel will pick up the new values on the next Start, so
// there's nothing for the dataplane to hot-reload yet. With a nil
// dataplane in the test fixture, this is also what saves us from
// needing a live IPC connection during the unit test.
func TestUpdateTunnel_DisabledTunnelSkipsDataplane(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	body := strings.Replace(validClientBody, `"mtu": 1400`, `"mtu": 1380`, 1)
	body = strings.Replace(body, `"psk": "shared-psk-32-chars-long-xxxxxxxx",`, "", 1)
	res := doPut(t, panelURL(s, "/api/tunnels/"+strID(id)), body, hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("update disabled tunnel = %d body=%s", res.Status, string(res.Body))
	}
	// No `restart_required` or `dataplane_*` fields should be set on
	// an update against a disabled tunnel (no dataplane interaction).
	if strings.Contains(string(res.Body), "restart_required") {
		t.Errorf("disabled tunnel update should not emit restart_required, body=%s", string(res.Body))
	}
	if strings.Contains(string(res.Body), "dataplane_applied") {
		t.Errorf("disabled tunnel update should not emit dataplane_applied, body=%s", string(res.Body))
	}
}

// TestUpdateTunnel_IPv6ListenAcceptedOnCreate covers PRD §8.3 at the
// API level: an operator can save a tunnel with an IPv6 listen host and
// the API accepts it (the dataplane bind respects whichever family
// parsed). v2.7.0: local_listen_addr is host-only, so the IPv6 form is a
// bare `::` and the port lives in the ports list.
func TestUpdateTunnel_IPv6ListenAcceptedOnCreate(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := strings.Replace(validClientBody, `"local_listen_addr": "0.0.0.0"`,
		`"local_listen_addr": "::"`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), body, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("create with v6 listen = %d body=%s", res.Status, string(res.Body))
	}
}

func TestExportTunnel_RevealsPSK(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)
	// Secrets are opt-in: ?secrets=1 reveals the PSK.
	res := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export?secrets=1"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("export: %d body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "shared-psk-32-chars-long-xxxxxxxx") {
		t.Errorf("export should reveal the PSK, got %s", string(res.Body))
	}
	if cd := res.Headers.Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("missing attachment Content-Disposition, got %q", cd)
	}
}

// seedWGConfig inserts a WireGuard config row directly via the repo
// (bypassing the parser) and returns its id and name. Tunnel import
// round-trips reference a WG config by NAME, so the import target panel
// must already have a config of that name; this seeds it.
func seedWGConfig(t *testing.T, f *testFixture, name string) (int64, string) {
	t.Helper()
	cfg, err := f.wgRepo.Create(context.Background(), wg.Config{
		Name:             name,
		RawText:          "[Interface]\nPrivateKey=seed\n[Peer]\nPublicKey=peer\nEndpoint=198.51.100.10:51820\nAllowedIPs=0.0.0.0/0",
		InterfaceAddress: "10.0.0.2/32",
		Endpoint:         "198.51.100.10:51820",
		PublicKeySelf:    "seedpub",
		PeerCount:        1,
	})
	if err != nil {
		t.Fatalf("seed wg config: %v", err)
	}
	return cfg.ID, cfg.Name
}

// clientBodyWithWG returns a client tunnel body that links a WireGuard
// config by id instead of the legacy inline text, so export resolves a
// wireguard_config_name and import can re-link it by name.
func clientBodyWithWG(wgID int64) string {
	b := strings.Replace(validClientBody,
		`"wireguard_config": "[Interface]\nPrivateKey=...\n[Peer]\nPublicKey=...\nEndpoint=198.51.100.20:81\nAllowedIPs=0.0.0.0/0"`,
		`"wg_config_id": `+strconv.FormatInt(wgID, 10), 1)
	return b
}

func TestExportImport_RoundTripIdentical(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	wgID, wgName := seedWGConfig(t, f, "seller-wg")
	id := mustCreate(t, s.URL, hdr, clientBodyWithWG(wgID))

	// Read the original DTO so we can compare resolved fields later.
	origRes := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)), hdr)
	if origRes.Status != http.StatusOK {
		t.Fatalf("get original: %d %s", origRes.Status, string(origRes.Body))
	}
	var orig tunnelDTO
	if err := json.Unmarshal(origRes.Body, &orig); err != nil {
		t.Fatalf("decode original: %v", err)
	}

	// Export WITH secrets and assert the envelope shape.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export?secrets=1"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	var env tunnelExportEnvelope
	if err := json.Unmarshal(exp.Body, &env); err != nil {
		t.Fatalf("decode envelope: %v body=%s", err, string(exp.Body))
	}
	if env.Type != ExportType || env.SchemaVersion != ExportSchemaVersion {
		t.Fatalf("envelope header = %q/%d, want %q/%d", env.Type, env.SchemaVersion, ExportType, ExportSchemaVersion)
	}
	if !env.SecretsIncluded {
		t.Errorf("secrets_included should be true with ?secrets=1")
	}
	if env.Tunnel.PSK == nil || *env.Tunnel.PSK != "shared-psk-32-chars-long-xxxxxxxx" {
		t.Errorf("export psk = %v, want the real PSK", env.Tunnel.PSK)
	}
	if env.Tunnel.WireguardConfigName == nil || *env.Tunnel.WireguardConfigName != wgName {
		t.Errorf("wireguard_config_name = %v, want %q", env.Tunnel.WireguardConfigName, wgName)
	}

	// Delete the original so its bind ports (a Client tunnel's ports are
	// exclusive across the panel) are free — this lets the import keep
	// IDENTICAL ports and prove a true byte-for-byte config round-trip on
	// the same panel. Stop is not needed: it was never started.
	if del := doDelete(t, panelURL(s, "/api/tunnels/"+strID(id)), hdr); del.Status != http.StatusOK {
		t.Fatalf("delete original: %d %s", del.Status, string(del.Body))
	}

	// Import the same envelope with a changed name only.
	imported := strings.Replace(string(exp.Body), `"name":"tunnel-1"`, `"name":"tunnel-imported"`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), imported, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("import: %d body=%s", res.Status, string(res.Body))
	}
	var got tunnelDTO
	if err := json.Unmarshal(res.Body, &got); err != nil {
		t.Fatalf("decode import response: %v", err)
	}

	if got.Enabled {
		t.Error("imported tunnel must land stopped")
	}
	if got.Name != "tunnel-imported" {
		t.Errorf("name = %q, want tunnel-imported", got.Name)
	}
	if got.ID == orig.ID {
		t.Errorf("imported tunnel should get a fresh id, got %d", got.ID)
	}
	// Config fields equal the original (modulo id/name/enabled). The WG
	// link must have been RESOLVED by name to this panel's id.
	if got.WGConfigID == nil || *got.WGConfigID != wgID {
		t.Errorf("resolved wg_config_id = %v, want %d", got.WGConfigID, wgID)
	}
	if got.Role != orig.Role {
		t.Errorf("role = %q, want %q", got.Role, orig.Role)
	}
	if got.DownloadTransport != orig.DownloadTransport {
		t.Errorf("download_transport = %q, want %q", got.DownloadTransport, orig.DownloadTransport)
	}
	if got.UploadMode != orig.UploadMode {
		t.Errorf("upload_mode = %q, want %q", got.UploadMode, orig.UploadMode)
	}
	if got.MTU != orig.MTU {
		t.Errorf("mtu = %d, want %d", got.MTU, orig.MTU)
	}
	if got.DownloadSpoofSourceIP != orig.DownloadSpoofSourceIP {
		t.Errorf("spoof ip = %q, want %q", got.DownloadSpoofSourceIP, orig.DownloadSpoofSourceIP)
	}
	if got.DownloadSpoofSourcePort != orig.DownloadSpoofSourcePort {
		t.Errorf("spoof port = %d, want %d", got.DownloadSpoofSourcePort, orig.DownloadSpoofSourcePort)
	}
	if len(got.Ports) != len(orig.Ports) || (len(got.Ports) == 1 && got.Ports[0] != orig.Ports[0]) {
		t.Errorf("ports = %v, want %v", got.Ports, orig.Ports)
	}
	if (got.LocalListenAddr == nil) != (orig.LocalListenAddr == nil) ||
		(got.LocalListenAddr != nil && *got.LocalListenAddr != *orig.LocalListenAddr) {
		t.Errorf("local_listen_addr = %v, want %v", got.LocalListenAddr, orig.LocalListenAddr)
	}
	if (got.UploadTargetAddr == nil) != (orig.UploadTargetAddr == nil) ||
		(got.UploadTargetAddr != nil && *got.UploadTargetAddr != *orig.UploadTargetAddr) {
		t.Errorf("upload_target_addr = %v, want %v", got.UploadTargetAddr, orig.UploadTargetAddr)
	}
}

func TestExport_DefaultStripsSecrets(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	var env tunnelExportEnvelope
	if err := json.Unmarshal(exp.Body, &env); err != nil {
		t.Fatalf("decode envelope: %v body=%s", err, string(exp.Body))
	}
	if env.SecretsIncluded {
		t.Errorf("secrets_included should be false by default")
	}
	if env.Tunnel.PSK != nil {
		t.Errorf("psk should be null without ?secrets=1, got %v", *env.Tunnel.PSK)
	}
	if strings.Contains(string(exp.Body), "shared-psk-32-chars-long") {
		t.Errorf("default export leaked the PSK: %s", string(exp.Body))
	}
}

func TestImport_RejectsWrongType(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	// A pre-v2.7.0 bare {"tunnel": …} export has no `type`.
	body := `{"tunnel":{"name":"x","role":"client"}}`
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), body, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), `"file"`) ||
		!strings.Contains(string(res.Body), "isn't a Sublyne tunnel export") {
		t.Errorf("expected a `file` field error, got %s", string(res.Body))
	}
}

func TestImport_RejectsWrongSchemaVersion(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := `{"type":"sublyne-tunnel-export","schema_version":2,"secrets_included":false,"tunnel":{"name":"x","role":"client"}}`
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), body, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), `"file"`) ||
		!strings.Contains(string(res.Body), "schema 2") {
		t.Errorf("expected a `file` field error naming schema 2, got %s", string(res.Body))
	}
}

func TestImport_UnknownWGName(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	wgID, _ := seedWGConfig(t, f, "seller-wg")
	id := mustCreate(t, s.URL, hdr, clientBodyWithWG(wgID))
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export?secrets=1"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	// Point the reference at a config name that doesn't exist here, and
	// rename so the unique-name check doesn't trip first.
	imported := strings.Replace(string(exp.Body), `"wireguard_config_name":"seller-wg"`, `"wireguard_config_name":"nonesuch"`, 1)
	imported = strings.Replace(imported, `"name":"tunnel-1"`, `"name":"tunnel-x"`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), imported, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "wireguard_config_name") {
		t.Errorf("expected a wireguard_config_name field error, got %s", string(res.Body))
	}
}

func TestImport_MissingPSKRejected(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	wgID, _ := seedWGConfig(t, f, "seller-wg")
	id := mustCreate(t, s.URL, hdr, clientBodyWithWG(wgID))
	// Default export strips the PSK to null.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	imported := strings.Replace(string(exp.Body), `"name":"tunnel-1"`, `"name":"tunnel-nopsk"`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), imported, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), `"psk"`) {
		t.Errorf("expected a psk field error (min length), got %s", string(res.Body))
	}
}

func TestImport_NameClashConflict(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)
	// Export with secrets so the PSK is present; keep the name the same
	// (the unique-name check is the blocker we want) but move the bind
	// ports so the port-conflict validator doesn't fire FIRST with a 400
	// — the name clash must surface as the 409 from Repo.Create.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export?secrets=1"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	body := strings.Replace(string(exp.Body), `"ports":[44443]`, `"ports":[44456]`, 1)
	body = strings.Replace(body, `"download_receive_port":8443`, `"download_receive_port":8456`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), body, hdr)
	if res.Status != http.StatusConflict {
		t.Fatalf("status = %d, want 409 body=%s", res.Status, string(res.Body))
	}
}

func TestClone_CopiesAndStartsStopped(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	wgID, _ := seedWGConfig(t, f, "seller-wg")
	id := mustCreate(t, s.URL, hdr, clientBodyWithWG(wgID))

	res := postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/clone"), `{}`, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("clone: %d body=%s", res.Status, string(res.Body))
	}
	var clone tunnelDTO
	if err := json.Unmarshal(res.Body, &clone); err != nil {
		t.Fatalf("decode clone: %v", err)
	}
	if clone.ID == id {
		t.Errorf("clone should have a fresh id, got %d", clone.ID)
	}
	if clone.Name != "tunnel-1 (copy)" {
		t.Errorf("clone name = %q, want %q", clone.Name, "tunnel-1 (copy)")
	}
	if clone.Enabled {
		t.Error("clone must land stopped")
	}
	if clone.WGConfigID == nil || *clone.WGConfigID != wgID {
		t.Errorf("clone wg_config_id = %v, want %d", clone.WGConfigID, wgID)
	}
	if len(clone.Ports) != 1 || clone.Ports[0] != 44443 {
		t.Errorf("clone ports = %v, want [44443]", clone.Ports)
	}
	// PSK preserved: export the clone with secrets and check.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(clone.ID)+"/export?secrets=1"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export clone: %d %s", exp.Status, string(exp.Body))
	}
	if !strings.Contains(string(exp.Body), "shared-psk-32-chars-long-xxxxxxxx") {
		t.Errorf("clone should preserve the PSK, got %s", string(exp.Body))
	}
}

func TestClone_NameSuffixIncrements(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	first := postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/clone"), `{}`, hdr)
	if first.Status != http.StatusCreated {
		t.Fatalf("clone 1: %d body=%s", first.Status, string(first.Body))
	}
	var c1 tunnelDTO
	if err := json.Unmarshal(first.Body, &c1); err != nil {
		t.Fatalf("decode clone 1: %v", err)
	}
	if c1.Name != "tunnel-1 (copy)" {
		t.Errorf("first clone name = %q, want %q", c1.Name, "tunnel-1 (copy)")
	}

	second := postJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/clone"), `{}`, hdr)
	if second.Status != http.StatusCreated {
		t.Fatalf("clone 2: %d body=%s", second.Status, string(second.Body))
	}
	var c2 tunnelDTO
	if err := json.Unmarshal(second.Body, &c2); err != nil {
		t.Fatalf("decode clone 2: %v", err)
	}
	if c2.Name != "tunnel-1 (copy 2)" {
		t.Errorf("second clone name = %q, want %q", c2.Name, "tunnel-1 (copy 2)")
	}
}

func mustCreate(t *testing.T, baseURL string, hdr map[string]string, body string) int64 {
	t.Helper()
	res := postJSON(t, baseURL+"/"+testWebPath+"/api/tunnels", body, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("seed create = %d body=%s", res.Status, string(res.Body))
	}
	var out tunnelDTO
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("decode created: %v", err)
	}
	return out.ID
}

func doDelete(t *testing.T, url string, hdr map[string]string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return doRequest(t, req)
}

func doPut(t *testing.T, url, body string, hdr map[string]string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	return doRequest(t, req)
}

func strID(id int64) string {
	// Avoid strconv.FormatInt-import churn — a tunnel id is always
	// positive in tests, so a tiny conversion is enough.
	if id == 0 {
		return "0"
	}
	digits := []byte{}
	for id > 0 {
		digits = append([]byte{byte('0' + id%10)}, digits...)
		id /= 10
	}
	return string(digits)
}
