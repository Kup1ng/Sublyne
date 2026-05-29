package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
)

// loginCookie performs a login against the test server and returns
// the session cookie value. The protected logs/audit/settings routes
// run behind RequireAuth, so every assertion below carries it.
func loginCookie(t *testing.T, s *httptest.Server) string {
	t.Helper()
	res := postJSON(t, panelURL(s, "/api/login"),
		`{"username":"admin","password":"correct horse"}`, nil)
	if res.Status != http.StatusOK {
		t.Fatalf("login: status=%d body=%s", res.Status, res.Body)
	}
	for _, c := range res.Cookies {
		if c.Name == SessionCookieName {
			return c.Value
		}
	}
	t.Fatal("login: no session cookie")
	return ""
}

func TestListLogsHandler_FiltersByLevelAndSince(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)

	// Seed the bus directly so we don't depend on slog's global state.
	f.logBus.Publish(logging.LogEntry{Ts: time.Now().Add(-2 * time.Minute).UTC().Format(time.RFC3339Nano), Level: "DEBUG", Msg: "old-debug"})
	f.logBus.Publish(logging.LogEntry{Ts: time.Now().Add(-1 * time.Minute).UTC().Format(time.RFC3339Nano), Level: "INFO", Msg: "info-message"})
	f.logBus.Publish(logging.LogEntry{Ts: time.Now().UTC().Format(time.RFC3339Nano), Level: "WARN", Msg: "warn-message"})

	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}
	res := getJSON(t, panelURL(s, "/api/logs?level=info&limit=10"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("GET /api/logs status=%d body=%s", res.Status, res.Body)
	}
	var body LogResponse
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, res.Body)
	}
	if body.Level != "info" {
		t.Errorf("expected current level info, got %q", body.Level)
	}
	if len(body.Entries) != 2 {
		t.Fatalf("expected 2 entries (info+warn), got %d: %+v", len(body.Entries), body.Entries)
	}

	// URL-encode the cutoff so any non-UTC offset's '+' survives the
	// query parser (raw '+' in a query value decodes to space).
	cutoff := time.Now().Add(-30 * time.Second).UTC().Format(time.RFC3339Nano)
	res2 := getJSON(t, panelURL(s, "/api/logs?since="+url.QueryEscape(cutoff)), hdr)
	var body2 LogResponse
	if err := json.Unmarshal(res2.Body, &body2); err != nil {
		t.Fatalf("decode since: %v", err)
	}
	if len(body2.Entries) != 1 || body2.Entries[0].Msg != "warn-message" {
		t.Errorf("since filter mismatch: %+v", body2.Entries)
	}
}

func TestSetLogLevelHandler_AppliesLiveAndPersists(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	if got := f.levelCtrl.Get(); got != slog.LevelInfo {
		t.Fatalf("expected initial level INFO, got %v", got)
	}

	// Use a small fired-callback flag to assert the OnChange hook runs.
	var fired slog.Level
	f.levelCtrl.OnChange(func(l slog.Level) { fired = l })

	res := putJSON(t, panelURL(s, "/api/settings/log-level"), `{"level":"debug"}`, hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("PUT log-level status=%d body=%s", res.Status, res.Body)
	}
	var out setLogLevelResponse
	if err := json.Unmarshal(res.Body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Level != "debug" {
		t.Errorf("expected level=debug echoed, got %q", out.Level)
	}
	if got := f.levelCtrl.Get(); got != slog.LevelDebug {
		t.Errorf("LevelControl not updated; got %v", got)
	}
	if fired != slog.LevelDebug {
		t.Errorf("OnChange did not fire with new level, got %v", fired)
	}
	if stored := ReadRuntimeLogLevel(context.Background(), f.db); stored != "debug" {
		t.Errorf("expected stored runtime level=debug, got %q", stored)
	}
	entries, err := f.auditRec.List(context.Background(), time.Time{}, 0)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	found := false
	for _, e := range entries {
		if e.Action == audit.ActionLogLevelChange {
			found = true
			if !strings.Contains(e.Details, "debug") {
				t.Errorf("audit details missing new level: %q", e.Details)
			}
		}
	}
	if !found {
		t.Errorf("audit row for log_level_change not found among %+v", entries)
	}
}

func TestSetLogLevelHandler_RejectsBadLevel(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	res := putJSON(t, panelURL(s, "/api/settings/log-level"), `{"level":"chatty"}`, hdr)
	if res.Status != http.StatusBadRequest {
		t.Errorf("expected 400, got %d body=%s", res.Status, res.Body)
	}
	if f.levelCtrl.Get() != slog.LevelInfo {
		t.Error("level changed despite invalid value")
	}
}

func TestCrashReportsRoundTrip(t *testing.T) {
	f := newTestFixture(t)
	dir := t.TempDir()
	f.logsDeps.CrashDir = dir
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	name, err := logging.WriteCrashReport(dir, "panic: boom\nstack trace")
	if err != nil {
		t.Fatalf("WriteCrashReport: %v", err)
	}

	res := getJSON(t, panelURL(s, "/api/crash-reports"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("list status=%d body=%s", res.Status, res.Body)
	}
	var list struct {
		Reports []logging.CrashReport `json:"reports"`
	}
	if err := json.Unmarshal(res.Body, &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Reports) != 1 || list.Reports[0].Filename != name {
		t.Fatalf("unexpected reports: %+v", list.Reports)
	}

	res2 := getJSON(t, panelURL(s, "/api/crash-reports/"+name), hdr)
	if res2.Status != http.StatusOK {
		t.Fatalf("get status=%d body=%s", res2.Status, res2.Body)
	}
	if !strings.Contains(string(res2.Body), "panic: boom") {
		t.Errorf("crash body missing panic line: %s", res2.Body)
	}

	res3 := getJSON(t, panelURL(s, "/api/crash-reports/etc-passwd"), hdr)
	if res3.Status != http.StatusNotFound {
		t.Errorf("expected 404 for bad filename, got %d", res3.Status)
	}
}

// putJSON mirrors postJSON from auth_handlers_test.go for PUT verbs.
func putJSON(t *testing.T, url, body string, headers map[string]string) httpResult {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return doRequest(t, req)
}
