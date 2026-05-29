package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
)

// AuditDeps bundles the audit recorder. The router mounts the /audit
// route only when Recorder is non-nil.
type AuditDeps struct {
	Recorder *audit.Recorder
	Logger   *slog.Logger
}

func (d AuditDeps) logger() *slog.Logger {
	if d.Logger != nil {
		return d.Logger
	}
	return slog.Default()
}

// auditEntryResponse is the JSON-shape returned per row. The panel
// renders ts as a localised time, action via a friendly-name map, and
// details as collapsible JSON.
type auditEntryResponse struct {
	ID      int64           `json:"id"`
	Ts      time.Time       `json:"ts"`
	Action  string          `json:"action"`
	Actor   string          `json:"actor"`
	IP      string          `json:"ip"`
	Target  string          `json:"target"`
	Details json.RawMessage `json:"details"`
}

// ListAuditHandler returns the most recent audit_log rows.
//
//	?limit=N      — default 200, max 1000
//	?since=RFC3339 — only rows after this timestamp
func ListAuditHandler(deps AuditDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.Recorder == nil {
			writeJSON(w, http.StatusOK, map[string]any{"entries": []any{}})
			return
		}
		limit := 200
		if raw := r.URL.Query().Get("limit"); raw != "" {
			if n, err := strconv.Atoi(raw); err == nil && n > 0 {
				limit = n
			}
		}
		var since time.Time
		if raw := r.URL.Query().Get("since"); raw != "" {
			if ts, err := time.Parse(time.RFC3339Nano, raw); err == nil {
				since = ts
			} else if ts, err := time.Parse(time.RFC3339, raw); err == nil {
				since = ts
			}
		}
		entries, err := deps.Recorder.List(r.Context(), since, limit)
		if err != nil {
			deps.logger().Warn("audit: list failed", "err", err)
			writeJSONError(w, http.StatusInternalServerError, "could not load audit log")
			return
		}
		out := make([]auditEntryResponse, 0, len(entries))
		for _, e := range entries {
			out = append(out, auditEntryResponse{
				ID:      e.ID,
				Ts:      e.Ts,
				Action:  e.Action,
				Actor:   e.Actor,
				IP:      e.IP,
				Target:  e.Target,
				Details: json.RawMessage(e.Details),
			})
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": out})
	}
}
