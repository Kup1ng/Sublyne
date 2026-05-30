package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"
)

// tunableViewByKey pulls one tunable out of a decoded response body so
// each assertion reads a single named knob.
func tunableViewByKey(t *testing.T, body tunablesResponse, key string) tunableView {
	t.Helper()
	for _, v := range body.Tunables {
		if v.Key == key {
			return v
		}
	}
	t.Fatalf("tunable %q not found in response: %+v", key, body.Tunables)
	return tunableView{}
}

func TestGetTunablesHandler_DefaultsWithNullValues(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	res := getJSON(t, panelURL(s, "/api/settings/tunables"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("GET tunables status=%d body=%s", res.Status, res.Body)
	}
	var body tunablesResponse
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, res.Body)
	}
	if !body.AppliesOnRestart {
		t.Error("expected applies_on_restart=true")
	}
	if len(body.Tunables) != len(tunableRegistry) {
		t.Fatalf("expected %d tunables, got %d", len(tunableRegistry), len(body.Tunables))
	}

	// Nothing persisted yet → every value is null.
	for _, v := range body.Tunables {
		if v.Value != nil {
			t.Errorf("tunable %q: expected null value, got %d", v.Key, *v.Value)
		}
	}

	// socket_buf_bytes has a numeric default; per_core_sockets is "auto"
	// (default null).
	sock := tunableViewByKey(t, body, "socket_buf_bytes")
	if sock.Default == nil || *sock.Default != 4194304 {
		t.Errorf("socket_buf_bytes default: want 4194304, got %v", sock.Default)
	}
	if sock.Min != 262144 || sock.Max != 16777216 {
		t.Errorf("socket_buf_bytes bounds: got min=%d max=%d", sock.Min, sock.Max)
	}
	pcs := tunableViewByKey(t, body, "per_core_sockets")
	if pcs.Default != nil {
		t.Errorf("per_core_sockets default: want null, got %d", *pcs.Default)
	}
	if pcs.Min != 1 || pcs.Max != 64 {
		t.Errorf("per_core_sockets bounds: got min=%d max=%d", pcs.Min, pcs.Max)
	}
}

func TestSetTunablesHandler_PersistsAndGetReflects(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	res := putJSON(t, panelURL(s, "/api/settings/tunables"),
		`{"socket_buf_bytes":8388608,"per_core_sockets":4}`, hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("PUT tunables status=%d body=%s", res.Status, res.Body)
	}
	var put tunablesResponse
	if err := json.Unmarshal(res.Body, &put); err != nil {
		t.Fatalf("decode put: %v body=%s", err, res.Body)
	}
	if v := tunableViewByKey(t, put, "socket_buf_bytes"); v.Value == nil || *v.Value != 8388608 {
		t.Errorf("PUT echo socket_buf_bytes: want 8388608, got %v", v.Value)
	}
	if v := tunableViewByKey(t, put, "per_core_sockets"); v.Value == nil || *v.Value != 4 {
		t.Errorf("PUT echo per_core_sockets: want 4, got %v", v.Value)
	}

	// GET must reflect the persisted values.
	res2 := getJSON(t, panelURL(s, "/api/settings/tunables"), hdr)
	if res2.Status != http.StatusOK {
		t.Fatalf("GET after PUT status=%d body=%s", res2.Status, res2.Body)
	}
	var body tunablesResponse
	if err := json.Unmarshal(res2.Body, &body); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if v := tunableViewByKey(t, body, "socket_buf_bytes"); v.Value == nil || *v.Value != 8388608 {
		t.Errorf("GET socket_buf_bytes: want 8388608, got %v", v.Value)
	}
	// recv_batch was never set → still null.
	if v := tunableViewByKey(t, body, "recv_batch"); v.Value != nil {
		t.Errorf("recv_batch should be null (untouched), got %d", *v.Value)
	}
}

func TestSetTunablesHandler_OutOfRangeRejected(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	// recv_batch max is 64; 100 is out of range. The whole request must
	// be rejected and nothing persisted (socket_buf_bytes too).
	res := putJSON(t, panelURL(s, "/api/settings/tunables"),
		`{"socket_buf_bytes":8388608,"recv_batch":100}`, hdr)
	if res.Status != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", res.Status, res.Body)
	}
	var errBody struct {
		Error  string            `json:"error"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(res.Body, &errBody); err != nil {
		t.Fatalf("decode err body: %v body=%s", err, res.Body)
	}
	if errBody.Fields["recv_batch"] == "" {
		t.Errorf("expected a field error for recv_batch, got %+v", errBody.Fields)
	}

	// Confirm the valid sibling was NOT persisted (all-or-nothing).
	res2 := getJSON(t, panelURL(s, "/api/settings/tunables"), hdr)
	var body tunablesResponse
	if err := json.Unmarshal(res2.Body, &body); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if v := tunableViewByKey(t, body, "socket_buf_bytes"); v.Value != nil {
		t.Errorf("socket_buf_bytes should not persist on rejected request, got %d", *v.Value)
	}
}

func TestSetTunablesHandler_NullClears(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	// Set, then clear with null.
	if res := putJSON(t, panelURL(s, "/api/settings/tunables"),
		`{"send_batch":32}`, hdr); res.Status != http.StatusOK {
		t.Fatalf("PUT set status=%d body=%s", res.Status, res.Body)
	}
	if res := putJSON(t, panelURL(s, "/api/settings/tunables"),
		`{"send_batch":null}`, hdr); res.Status != http.StatusOK {
		t.Fatalf("PUT clear status=%d body=%s", res.Status, res.Body)
	}

	res := getJSON(t, panelURL(s, "/api/settings/tunables"), hdr)
	var body tunablesResponse
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if v := tunableViewByKey(t, body, "send_batch"); v.Value != nil {
		t.Errorf("send_batch should be null after clear, got %d", *v.Value)
	}
}

func TestApplyTunableEnv_SetsAndSkips(t *testing.T) {
	f := newTestFixture(t)
	ctx := context.Background()

	// t.Setenv records the prior value and restores it at cleanup; we
	// then Unsetenv to model "unset at start". Both vars are restored
	// automatically when the test ends.
	t.Setenv("SUBLYNE_SOCKET_BUF_BYTES", "")
	t.Setenv("SUBLYNE_RECV_BATCH", "")
	_ = os.Unsetenv("SUBLYNE_SOCKET_BUF_BYTES")
	_ = os.Unsetenv("SUBLYNE_RECV_BATCH")

	// Persist one tunable; leave recv_batch unset.
	if err := upsertSetting(ctx, f.db, "tunable_socket_buf_bytes", "8388608"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	ApplyTunableEnv(ctx, f.db, nil)

	if got := os.Getenv("SUBLYNE_SOCKET_BUF_BYTES"); got != "8388608" {
		t.Errorf("SUBLYNE_SOCKET_BUF_BYTES: want 8388608, got %q", got)
	}
	if _, ok := os.LookupEnv("SUBLYNE_RECV_BATCH"); ok {
		t.Errorf("SUBLYNE_RECV_BATCH should remain unset, but it is set")
	}
}

func TestApplyTunableEnv_OutOfRangeIgnored(t *testing.T) {
	f := newTestFixture(t)
	ctx := context.Background()

	t.Setenv("SUBLYNE_RECV_BATCH", "")
	_ = os.Unsetenv("SUBLYNE_RECV_BATCH")

	// A hand-edited DB row out of the registry bounds must not be exported.
	if err := upsertSetting(ctx, f.db, "tunable_recv_batch", "9999"); err != nil {
		t.Fatalf("seed setting: %v", err)
	}

	ApplyTunableEnv(ctx, f.db, nil)

	if _, ok := os.LookupEnv("SUBLYNE_RECV_BATCH"); ok {
		t.Errorf("out-of-range SUBLYNE_RECV_BATCH should not be exported")
	}
}
