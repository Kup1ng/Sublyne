package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
)

func TestListAuditHandler_NewestFirst(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	ctx := context.Background()
	// loginCookie above already recorded one login_success row. Add
	// two more so the test asserts ordering across multiple actions.
	f.auditRec.Record(ctx, audit.ActionTunnelStart, audit.ActorAdmin, "1.2.3.4", "t-A", map[string]any{"id": 1})

	res := getJSON(t, panelURL(s, "/api/audit?limit=10"), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("status=%d body=%s", res.Status, res.Body)
	}
	var body struct {
		Entries []struct {
			Action  string          `json:"action"`
			Actor   string          `json:"actor"`
			Target  string          `json:"target"`
			IP      string          `json:"ip"`
			Details json.RawMessage `json:"details"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(res.Body, &body); err != nil {
		t.Fatalf("decode: %v body=%s", err, res.Body)
	}
	// loginCookie's POST /api/login wrote one login_success row before
	// this test added another row. Expect 2 entries newest-first.
	if len(body.Entries) != 2 {
		t.Fatalf("expected 2 audit rows, got %d: %+v", len(body.Entries), body.Entries)
	}
	if body.Entries[0].Action != audit.ActionTunnelStart {
		t.Errorf("expected newest=tunnel_start, got %q", body.Entries[0].Action)
	}
	if body.Entries[0].Target != "t-A" {
		t.Errorf("expected target=t-A, got %q", body.Entries[0].Target)
	}
	if body.Entries[1].Action != audit.ActionLoginSuccess {
		t.Errorf("expected oldest=login_success (from loginCookie), got %q", body.Entries[1].Action)
	}
}

func TestListAuditHandler_RespectsSince(t *testing.T) {
	f := newTestFixture(t)
	s := httpServerForFixture(t, f)
	cookie := loginCookie(t, s)
	hdr := map[string]string{"Cookie": SessionCookieName + "=" + cookie}

	ctx := context.Background()
	// Record the older row "now". The audit table stores ts as unix
	// seconds (integer), so the cutoff used by ?since= must be at
	// least one second in the future to reliably exclude it via the
	// `ts >= cutoff` predicate.
	f.auditRec.Record(ctx, audit.ActionLogLevelChange, audit.ActorAdmin, "1.2.3.4", "log_level", nil)
	cutoff := time.Now().Add(time.Second)
	// Insert a row whose ts is well past the cutoff so the since
	// filter sees it as newer. Using direct SQL avoids real-time
	// waiting in tests.
	if _, err := f.db.ExecContext(ctx, `INSERT INTO audit_log (ts, action, actor, ip, target, details) VALUES (?, ?, ?, ?, ?, ?)`,
		time.Now().Add(5*time.Second).Unix(), audit.ActionLogout, audit.ActorAdmin, "1.2.3.4", "admin", "{}"); err != nil {
		t.Fatalf("insert future row: %v", err)
	}

	res := getJSON(t, panelURL(s, "/api/audit?since="+url.QueryEscape(cutoff.UTC().Format(time.RFC3339Nano))), hdr)
	if res.Status != http.StatusOK {
		t.Fatalf("status=%d", res.Status)
	}
	if !strings.Contains(string(res.Body), audit.ActionLogout) {
		t.Errorf("expected logout entry past cutoff: body=%s", res.Body)
	}
	if strings.Contains(string(res.Body), audit.ActionLogLevelChange) {
		t.Error("did not expect older log_level_change in since-filtered list")
	}
}
