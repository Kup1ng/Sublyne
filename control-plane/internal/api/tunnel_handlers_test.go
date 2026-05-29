package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
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
  "local_listen_addr": "0.0.0.0:44443",
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
  "forward_target": "127.0.0.1:5201",
  "download_send_port": 8443,
  "client_real_ip": "198.51.100.20",
  "enabled": false
}`

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

	// Second tunnel reuses local_listen_addr's port.
	second := strings.Replace(validClientBody, `"name": "tunnel-1"`, `"name": "tunnel-2"`, 1)
	// keep local_listen_addr the same; change the receive port so the
	// conflict comes from local_listen_addr alone.
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
	msg, ok := body.Fields["local_listen_addr"]
	if !ok {
		t.Fatalf("expected fields.local_listen_addr, got %+v", body.Fields)
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

	// Export should still show the original PSK.
	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
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
	b = strings.Replace(b, `"local_listen_addr": "0.0.0.0:44443"`, `"local_listen_addr": "0.0.0.0:44455"`, 1)
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
// tunnel that reuses the first's local_listen port must be refused.
func TestMultiTunnel_PortConflictRejected(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	_ = mustCreate(t, s.URL, hdr, validClientBody)

	// Second body collides on local_listen_addr port.
	dup := strings.Replace(validClientBody, `"name": "tunnel-1"`, `"name": "tunnel-2"`, 1)
	dup = strings.Replace(dup, `"download_receive_port": 8443`, `"download_receive_port": 8444`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels"), dup, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected 400 conflict, got %d body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "local_listen_addr") {
		t.Fatalf("expected local_listen_addr in error, got %s", string(res.Body))
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
// API level: an operator can save a tunnel with `[::]:port` and the
// API accepts it (the dataplane bind respects whichever family parsed).
func TestUpdateTunnel_IPv6ListenAcceptedOnCreate(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	body := strings.Replace(validClientBody, `"local_listen_addr": "0.0.0.0:44443"`,
		`"local_listen_addr": "[::]:44443"`, 1)
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
	res := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
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

func TestImportTunnel_RoundTrip(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	// Tweak the name so it doesn't collide.
	imported := strings.Replace(string(exp.Body), `"name":"tunnel-1"`, `"name":"tunnel-clone"`, 1)
	// Change the receive port and listen so it doesn't collide.
	imported = strings.Replace(imported, `"local_listen_addr":"0.0.0.0:44443"`, `"local_listen_addr":"0.0.0.0:44444"`, 1)
	imported = strings.Replace(imported, `"download_receive_port":8443`, `"download_receive_port":8444`, 1)

	res := postJSON(t, panelURL(s, "/api/tunnels/import"), imported, hdr)
	if res.Status != http.StatusCreated {
		t.Fatalf("import: %d body=%s", res.Status, string(res.Body))
	}
}

func TestImportTunnel_RejectsPortConflict(t *testing.T) {
	// Phase 13 acceptance: importing a tunnel whose local_listen_addr
	// or download_receive_port already belongs to another tunnel on
	// this server must fail. The handler runs the same validator as
	// CRUD; this test pins that promise.
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	id := mustCreate(t, s.URL, hdr, validClientBody)

	exp := getJSON(t, panelURL(s, "/api/tunnels/"+strID(id)+"/export"), hdr)
	if exp.Status != http.StatusOK {
		t.Fatalf("export: %d %s", exp.Status, string(exp.Body))
	}
	// Rename so the unique-name check doesn't trip first, but leave
	// local_listen_addr + download_receive_port unchanged so the port
	// conflict is the only blocker.
	clashing := strings.Replace(string(exp.Body), `"name":"tunnel-1"`, `"name":"tunnel-clash"`, 1)
	res := postJSON(t, panelURL(s, "/api/tunnels/import"), clashing, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("import (port clash): got %d want 400; body=%s", res.Status, string(res.Body))
	}
	if !strings.Contains(string(res.Body), "local_listen_addr") &&
		!strings.Contains(string(res.Body), "download_receive_port") {
		t.Errorf("expected per-field validation error pointing at the conflicting port, got %s", string(res.Body))
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
