package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// writeJSON writes value as JSON with the supplied status code. It
// logs (but does not surface) encoding errors — by the time we get
// here the response headers have been committed.
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		slog.Warn("api: encode response", "err", err)
	}
}

// writeJSONError writes a uniform {"error": "..."} body. Keep error
// strings short and user-facing — they appear in toast notifications
// in the frontend.
func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
