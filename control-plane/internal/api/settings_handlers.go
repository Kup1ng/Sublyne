package api

import "net/http"

// SettingsView is the read-only payload returned by GET /api/settings.
//
// Phase 5 ships this as a static snapshot of what /etc/sublyne/config.toml
// + the build-time version metadata says. Phase 12 will add an editable
// path (log level today, then panel port + web path with restart-required
// callouts) that mutates the in-memory view; until then the view is
// frozen for the lifetime of the process.
//
// Secrets are deliberately absent. The PRD pins three values that never
// leave the database — admin password hash, per-tunnel PSKs, the JWT
// signing key. None of those should appear here, ever.
type SettingsView struct {
	ServerRole string `json:"server_role"`
	PanelPort  int    `json:"panel_port"`
	WebPath    string `json:"web_path"`
	LogLevel   string `json:"log_level"`
	Version    string `json:"version"`
}

// SettingsHandler returns a handler that emits the supplied view as
// JSON. The view is captured by value so callers can build it once at
// router-construction time.
func SettingsHandler(view SettingsView) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, view)
	}
}
