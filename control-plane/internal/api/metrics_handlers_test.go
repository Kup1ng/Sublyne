package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
	"github.com/Kup1ng/Sublyne/control-plane/internal/metrics"
	"github.com/Kup1ng/Sublyne/control-plane/internal/tunnels"
	"github.com/Kup1ng/Sublyne/control-plane/internal/wg"
)

// seedClientTunnel returns a tunnel struct suitable for inserting into
// the repo for handshake-related tests. It mirrors the shape used by
// the tunnels package's own repo tests so the fixture stays consistent.
func seedClientTunnel(wgConfigID int64) tunnels.Tunnel {
	return tunnels.Tunnel{
		Name:                    "metric-test",
		Role:                    tunnels.RoleClient,
		Enabled:                 true,
		PSK:                     "shared-psk-32-chars-long-aaaaaaaa",
		DownloadSpoofSourceIP:   "203.0.113.5",
		DownloadSpoofSourcePort: 443,
		DownloadTransport:       tunnels.TransportUDP,
		MTU:                     1400,
		MaxConnections:          50000,
		IdleTimeout:             300,
		LocalListenAddr:         sql.NullString{String: "0.0.0.0:44443", Valid: true},
		DownloadReceivePort:     sql.NullInt64{Int64: 8443, Valid: true},
		UploadTargetAddr:        sql.NullString{String: "198.51.100.10:55555", Valid: true},
		WGConfigID:              sql.NullInt64{Int64: wgConfigID, Valid: true},
		PingSmoothingTargetMS:   60,
		PacingTargetMS:          100,
	}
}

// fakeWGManager satisfies wg.Manager for the handshake bug-fix test.
// Only `Handshake` and `Supported` are exercised; the rest panic so a
// future test that accidentally relies on a bring-up call fails loudly.
type fakeWGManager struct {
	supported bool
	hs        map[int64]wg.HandshakeStatus
}

func (m *fakeWGManager) Up(_ context.Context, _ int64, _ *wg.ParsedConfig) (wg.BringUpResult, error) {
	panic("fakeWGManager.Up should not be called from these tests")
}
func (m *fakeWGManager) Down(_ context.Context, _ int64) error {
	panic("fakeWGManager.Down should not be called from these tests")
}
func (m *fakeWGManager) Handshake(_ context.Context, tunnelID int64) (wg.HandshakeStatus, error) {
	if !m.supported {
		return wg.HandshakeStatus{}, wg.ErrManagerUnsupported
	}
	if s, ok := m.hs[tunnelID]; ok {
		return s, nil
	}
	return wg.HandshakeStatus{InterfaceName: wg.InterfaceNameFor(tunnelID)}, nil
}
func (m *fakeWGManager) TearDownAll(_ context.Context) error { return nil }
func (m *fakeWGManager) Supported() bool                     { return m.supported }

func TestMetrics_RequiresAuth(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	for _, p := range []string{
		"/api/metrics/latest",
		"/api/metrics/history",
		"/api/metrics/wg-handshake",
	} {
		t.Run(p, func(t *testing.T) {
			r := getJSON(t, panelURL(s, p), nil)
			if r.Status != http.StatusUnauthorized {
				t.Errorf("GET %s without auth = %d, want 401", p, r.Status)
			}
		})
	}
}

func TestLatestMetricsHandlerEmptyBeforeReports(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	r := getJSON(t, panelURL(s, "/api/metrics/latest"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status %d body=%s", r.Status, string(r.Body))
	}
	var snap LiveSnapshot
	if err := json.Unmarshal(r.Body, &snap); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(r.Body))
	}
	if !snap.At.IsZero() {
		t.Errorf("At = %v, want zero", snap.At)
	}
}

func TestLatestMetricsHandlerReturnsRecordedSample(t *testing.T) {
	f := newTestFixture(t)
	f.recorder.Append(ipc.StatsReport{
		Samples: []ipc.PerTunnelStats{
			{
				TunnelID:                 7,
				Role:                     "client",
				Transport:                "udp",
				BytesIn:                  4000,
				BytesOut:                 5000,
				PacketsIn:                40,
				PacketsOut:               50,
				ActiveSessions:           3,
				UploadRTTMsEWMA:          42.0,
				DownloadRTTMsEWMA:        61.0,
				LastPacketReceivedAtUnix: uint64(time.Now().Unix()),
				LastPacketSentAtUnix:     uint64(time.Now().Unix()),
			},
		},
		System: ipc.SystemStats{
			CPUPercent: 17.5,
		},
	})
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	r := getJSON(t, panelURL(s, "/api/metrics/latest"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status %d body=%s", r.Status, string(r.Body))
	}
	var snap LiveSnapshot
	if err := json.Unmarshal(r.Body, &snap); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(r.Body))
	}
	if len(snap.Tunnels) != 1 {
		t.Fatalf("Tunnels = %d, want 1", len(snap.Tunnels))
	}
	if snap.Tunnels[0].HealthBadge != "healthy" {
		t.Errorf("HealthBadge = %q, want healthy", snap.Tunnels[0].HealthBadge)
	}
	if snap.System.CPUPercent != 17.5 {
		t.Errorf("CPU = %v, want 17.5", snap.System.CPUPercent)
	}
}

func TestHistoryMetricsHandlerReturnsRing(t *testing.T) {
	f := newTestFixture(t)
	f.recorder.Append(ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 100}}})
	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	r := getJSON(t, panelURL(s, "/api/metrics/history"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status %d body=%s", r.Status, string(r.Body))
	}
	var hist metrics.HistoryResponse
	if err := json.Unmarshal(r.Body, &hist); err != nil {
		t.Fatalf("decode: %v body=%s", err, string(r.Body))
	}
	if len(hist.Tunnels[1]) != 1 || hist.Tunnels[1][0].Stats.BytesIn != 100 {
		t.Errorf("history wrong: %+v", hist)
	}
}

func TestHealthBadgeBoundaries(t *testing.T) {
	now := time.Now().Unix()
	cases := []struct {
		name string
		rs   string
		recv uint64
		sent uint64
		want string
	}{
		// Recent activity beats a stale runtime cache — the dashboard
		// reflects what the wire actually shows.
		{"fresh-overrides-stopped-cache", "stopped", uint64(now), uint64(now), "healthy"},
		{"error-runtime-always-down", "error", uint64(now), 0, "down"},
		{"healthy-fresh", "running", uint64(now), 0, "healthy"},
		{"idle-after-60s", "running", uint64(now - 90), 0, "idle"},
		{"down-after-301s", "running", uint64(now - 301), 0, "down"},
		{"old-with-stopped-cache-is-stopped", "stopped", uint64(now - 600), 0, "stopped"},
		{"idle-when-no-recv-and-running", "running", 0, 0, "idle"},
		{"stopped-empty-runtime", "", 0, 0, "stopped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := healthBadgeFor(c.rs, c.recv, c.sent, now)
			if got != c.want {
				t.Errorf("healthBadgeFor(%v) = %q, want %q", c, got, c.want)
			}
		})
	}
}

// TestWGHandshakeFixUsesTunnelRepo proves the Phase 11 bug fix: with a
// linked tunnel and a kernel-fresh handshake the endpoint returns the
// real timestamp. Without the fix the response always reported "no
// handshake" because the Phase 7 implementation required a `tunnel_id`
// query parameter the panel never sent.
func TestWGHandshakeFixUsesTunnelRepo(t *testing.T) {
	f := newTestFixture(t)
	// Seed a WG config + a tunnel that links to it.
	cfg, err := f.wgRepo.Create(context.Background(), wg.Config{
		Name:      "test-cfg",
		RawText:   "fake",
		PeerCount: 1,
	})
	if err != nil {
		t.Fatalf("create wg: %v", err)
	}
	tn, err := f.tunnelRepo.Create(context.Background(), seedClientTunnel(cfg.ID))
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}

	last := time.Now().Add(-30 * time.Second)
	fakeMgr := &fakeWGManager{
		supported: true,
		hs: map[int64]wg.HandshakeStatus{
			tn.ID: {
				InterfaceName:    wg.InterfaceNameFor(tn.ID),
				LastHandshake:    last,
				HasEverConnected: true,
			},
		},
	}
	f.wgDeps.Manager = fakeMgr
	f.metricsDeps.WGManager = fakeMgr

	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)

	// Per-config endpoint (the old buggy one) must now resolve.
	r := getJSON(t, panelURL(s, "/api/wg-configs/"+itoa(cfg.ID)+"/handshake"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("handshake status %d body=%s", r.Status, string(r.Body))
	}
	if !strings.Contains(string(r.Body), `"has_ever_connected":true`) {
		t.Errorf("body did not report a fresh handshake: %s", string(r.Body))
	}

	// New dashboard endpoint.
	r = getJSON(t, panelURL(s, "/api/metrics/wg-handshake"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("wg-handshake status %d body=%s", r.Status, string(r.Body))
	}
	var resp struct {
		Configs []WGHandshakeStatus `json:"configs"`
	}
	if err := json.Unmarshal(r.Body, &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Configs) != 1 {
		t.Fatalf("got %d configs, want 1", len(resp.Configs))
	}
	row := resp.Configs[0]
	if !row.HasEverConnected {
		t.Errorf("HasEverConnected=false, want true")
	}
	if row.Stale {
		t.Errorf("Stale=true for a 30-second-old handshake, want false")
	}
	if row.InterfaceName != wg.InterfaceNameFor(tn.ID) {
		t.Errorf("InterfaceName = %q, want %q", row.InterfaceName, wg.InterfaceNameFor(tn.ID))
	}
}

func TestWGHandshakeMarksStaleOver3Min(t *testing.T) {
	f := newTestFixture(t)
	cfg, err := f.wgRepo.Create(context.Background(), wg.Config{Name: "stale", RawText: "fake", PeerCount: 1})
	if err != nil {
		t.Fatalf("create wg: %v", err)
	}
	tn, err := f.tunnelRepo.Create(context.Background(), seedClientTunnel(cfg.ID))
	if err != nil {
		t.Fatalf("create tunnel: %v", err)
	}
	fakeMgr := &fakeWGManager{
		supported: true,
		hs: map[int64]wg.HandshakeStatus{
			tn.ID: {
				InterfaceName:    wg.InterfaceNameFor(tn.ID),
				LastHandshake:    time.Now().Add(-5 * time.Minute),
				HasEverConnected: true,
			},
		},
	}
	f.wgDeps.Manager = fakeMgr
	f.metricsDeps.WGManager = fakeMgr

	s := httpServerForFixture(t, f)
	hdr := loginAndTokenHeader(t, s.URL)
	r := getJSON(t, panelURL(s, "/api/metrics/wg-handshake"), hdr)
	if r.Status != http.StatusOK {
		t.Fatalf("status %d body=%s", r.Status, string(r.Body))
	}
	var resp struct {
		Configs []WGHandshakeStatus `json:"configs"`
	}
	_ = json.Unmarshal(r.Body, &resp)
	if len(resp.Configs) == 0 || !resp.Configs[0].Stale {
		t.Errorf("expected Stale=true for 5-minute-old handshake, got %+v", resp.Configs)
	}
}

// TestWebSocketPushesSnapshot proves the /api/ws endpoint:
//   - upgrades cleanly with a JWT cookie;
//   - sends the latest known snapshot immediately on connect;
//   - sends a fresh snapshot when the broadcast bus publishes one.
func TestWebSocketPushesSnapshot(t *testing.T) {
	f := newTestFixture(t)
	// Pre-seed a snapshot so the immediate-on-connect frame has content.
	f.recorder.Append(ipc.StatsReport{
		Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 111}},
		System:  ipc.SystemStats{CPUPercent: 9.9},
	})

	s := httpServerForFixture(t, f)
	tok := loginAndCookie(t, s.URL)

	wsURL := strings.Replace(s.URL, "http://", "ws://", 1) + "/" + testWebPath + "/api/ws"
	hdr := http.Header{}
	hdr.Set("Cookie", SessionCookieName+"="+tok)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, resp, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		HTTPHeader: hdr,
	})
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	// coder/websocket returns the underlying *http.Response so the
	// caller can inspect headers; bodyclose insists we close it even
	// though Dial closes the body on success itself.
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	defer func() { _ = conn.Close(websocket.StatusNormalClosure, "") }()

	// First frame should be the pre-seeded snapshot.
	got := readWS(ctx, t, conn)
	if got["type"] != "snapshot" {
		t.Fatalf("first frame type = %v, want snapshot", got["type"])
	}
	body, _ := got["body"].(map[string]any)
	tns, _ := body["tunnels"].([]any)
	if len(tns) == 0 {
		t.Fatalf("snapshot has no tunnels: %+v", body)
	}

	// Publish a fresh report — the WS handler should forward it.
	f.statsBus.Publish(ipc.StatsReport{
		Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 22222}},
		System:  ipc.SystemStats{CPUPercent: 50.0},
	})
	got = readWS(ctx, t, conn)
	body, _ = got["body"].(map[string]any)
	sys, _ := body["system"].(map[string]any)
	if sys["cpu_percent"].(float64) != 50.0 {
		t.Errorf("expected new snapshot to have cpu_percent=50, got %v", sys["cpu_percent"])
	}
}

// loginAndCookie returns the raw sublyne_token JWT value (no cookie
// header wrapping) for tests that need to set the cookie themselves —
// e.g. WebSocket upgrades.
func loginAndCookie(t *testing.T, baseURL string) string {
	t.Helper()
	loginBody := `{"username":"admin","password":"correct horse"}`
	res := postJSON(t, baseURL+"/"+testWebPath+"/api/login", loginBody, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: %d body=%s", res.Status, string(res.Body))
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil || body.Token == "" {
		t.Fatalf("decode token: %v body=%s", err, string(res.Body))
	}
	return body.Token
}

func readWS(ctx context.Context, t *testing.T, conn *websocket.Conn) map[string]any {
	t.Helper()
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, data, err := conn.Read(rctx)
	if err != nil {
		t.Fatalf("ws read: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("decode frame: %v raw=%s", err, string(data))
	}
	return got
}

func itoa(i int64) string {
	return strconv.FormatInt(i, 10)
}
