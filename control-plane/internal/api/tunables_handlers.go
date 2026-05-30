package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"

	"github.com/Kup1ng/Sublyne/control-plane/internal/audit"
)

// tunable describes one operator-tunable performance knob. Each knob is
// persisted in the existing `settings` KV table under the key
// "tunable_<name>" and exported to the Rust dataplane child as an
// environment variable just before the child is spawned. The dataplane
// reads these env vars at startup (data-plane/src/perf.rs), so changes
// take effect on the next service restart — never live.
//
// HasDefault distinguishes a knob with a numeric built-in default
// (serialized in the GET JSON) from an "auto" knob whose unset state
// means "let the dataplane decide" (serialized as default: null and,
// when unset, NOT exported as an env var at all). Today only
// per_core_sockets is an auto knob.
type tunable struct {
	Name       string
	Env        string
	Default    int
	HasDefault bool
	Min        int
	Max        int
	Unit       string
	Label      string
	Help       string
}

// settingsKey returns the `settings` table key this tunable persists
// under. Kept as a method so the key format lives in exactly one place.
func (t tunable) settingsKey() string {
	return "tunable_" + t.Name
}

// tunableRegistry is the authoritative list of operator-tunable
// performance knobs. The order here is the order the GET endpoint
// returns them, which the frontend renders top-to-bottom.
//
// Keep these env names in sync with data-plane/src/perf.rs.
var tunableRegistry = []tunable{
	{
		Name:       "socket_buf_bytes",
		Env:        "SUBLYNE_SOCKET_BUF_BYTES",
		Default:    4194304,
		HasDefault: true,
		Min:        262144,
		Max:        16777216,
		Unit:       "bytes",
		Label:      "Socket buffer size",
		Help:       "Per-socket send/receive buffer. Bigger absorbs more traffic bursts and prevents UDP drops at high speed, but uses more kernel memory per socket. Default 4 MiB. Raise toward 8-16 MiB only if you see receive drops above ~200 Mbit/s.",
	},
	{
		Name:       "recv_batch",
		Env:        "SUBLYNE_RECV_BATCH",
		Default:    16,
		HasDefault: true,
		Min:        1,
		Max:        64,
		Unit:       "packets",
		Label:      "Receive batch size",
		Help:       "How many packets the download path reads per system call. Higher uses less CPU per packet at high throughput, at a little more memory and latency. Default 16.",
	},
	{
		Name:       "send_batch",
		Env:        "SUBLYNE_SEND_BATCH",
		Default:    16,
		HasDefault: true,
		Min:        1,
		Max:        64,
		Unit:       "packets",
		Label:      "Send batch size",
		Help:       "How many packets the Remote sends per system call. Higher uses less CPU at high throughput. Default 16. Wire ordering is preserved regardless, so this does not affect the anti-replay window.",
	},
	{
		Name: "per_core_sockets",
		Env:  "SUBLYNE_PER_CORE_SOCKETS",
		// HasDefault false → "auto": default serializes as null and an
		// unset value is NOT exported (Rust auto-detects core count).
		HasDefault: false,
		Min:        1,
		Max:        64,
		Unit:       "workers",
		Label:      "Worker threads",
		Help:       "Number of parallel HMAC worker threads. Default: one per CPU core (leave blank for auto). The Remote's seal workers are internally capped to keep within the anti-replay window, so raising this past 4 mainly helps the Client's verify pool. Set below your core count to leave a core for the panel.",
	},
}

// tunableView is the per-knob JSON shape returned by GET/PUT. Value and
// Default are pointers so an unset value (and the per_core_sockets
// "auto" default) serialize as JSON null rather than 0.
type tunableView struct {
	Key     string `json:"key"`
	Env     string `json:"env"`
	Value   *int   `json:"value"`
	Default *int   `json:"default"`
	Min     int    `json:"min"`
	Max     int    `json:"max"`
	Unit    string `json:"unit"`
	Label   string `json:"label"`
	Help    string `json:"help"`
}

// tunablesResponse is the top-level shape for GET/PUT. applies_on_restart
// is always true: these knobs are read by the dataplane only at startup.
type tunablesResponse struct {
	AppliesOnRestart bool          `json:"applies_on_restart"`
	Tunables         []tunableView `json:"tunables"`
}

// readTunableValue returns the persisted override for one tunable, or
// nil if the row is absent / empty / non-integer. A non-integer stored
// value is treated as unset rather than surfaced as an error: the worst
// case is the operator re-enters it.
func readTunableValue(ctx context.Context, db *sql.DB, t tunable) *int {
	if db == nil {
		return nil
	}
	var v string
	err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key = ?`, t.settingsKey()).Scan(&v)
	if err != nil {
		return nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return nil
	}
	return &n
}

// buildTunablesResponse assembles the GET/PUT response body from the
// current settings rows.
func buildTunablesResponse(ctx context.Context, db *sql.DB) tunablesResponse {
	views := make([]tunableView, 0, len(tunableRegistry))
	for _, t := range tunableRegistry {
		var def *int
		if t.HasDefault {
			d := t.Default
			def = &d
		}
		views = append(views, tunableView{
			Key:     t.Name,
			Env:     t.Env,
			Value:   readTunableValue(ctx, db, t),
			Default: def,
			Min:     t.Min,
			Max:     t.Max,
			Unit:    t.Unit,
			Label:   t.Label,
			Help:    t.Help,
		})
	}
	return tunablesResponse{AppliesOnRestart: true, Tunables: views}
}

// GetTunablesHandler returns every tunable with its persisted override
// (or null when unset). The frontend renders one field per entry.
func GetTunablesHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.DB == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "settings store not configured")
			return
		}
		writeJSON(w, http.StatusOK, buildTunablesResponse(r.Context(), deps.DB))
	}
}

// SetTunablesHandler accepts a partial object {name: value} where value
// is an integer to set, or JSON null to clear (revert to default).
// Omitted names are left unchanged. Every provided value is validated
// against its min/max before anything is written; if any is out of range
// the whole request is rejected 400 and nothing is persisted.
func SetTunablesHandler(deps LogsDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if deps.DB == nil {
			writeJSONError(w, http.StatusServiceUnavailable, "settings store not configured")
			return
		}

		// Decode into json.RawMessage per field so we can tell "absent"
		// (omitted) from "present and null" (explicit clear) from an
		// integer set.
		var raw map[string]json.RawMessage
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&raw); err != nil {
			writeJSONError(w, http.StatusBadRequest, "invalid request body")
			return
		}

		byName := make(map[string]tunable, len(tunableRegistry))
		for _, t := range tunableRegistry {
			byName[t.Name] = t
		}

		// Validate the entire payload first. Two collections: sets
		// (name → value) and clears (name) so we only touch the DB once
		// the whole request is known good.
		sets := make(map[string]int)
		clears := make(map[string]bool)
		fieldErrs := make(map[string]string)
		for name, msg := range raw {
			t, ok := byName[name]
			if !ok {
				fieldErrs[name] = "unknown tunable"
				continue
			}
			// Explicit null → clear (revert to default).
			if string(msg) == "null" {
				clears[name] = true
				continue
			}
			var v int
			if err := json.Unmarshal(msg, &v); err != nil {
				fieldErrs[name] = "must be a whole number"
				continue
			}
			if v < t.Min || v > t.Max {
				fieldErrs[name] = fmt.Sprintf("must be between %d and %d", t.Min, t.Max)
				continue
			}
			sets[name] = v
		}
		if len(fieldErrs) > 0 {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":  "Some fields need attention.",
				"fields": fieldErrs,
			})
			return
		}

		// Apply: clears delete the row (so GET returns null), sets
		// upsert the integer string. Persistence failure surfaces as a
		// 500 — unlike the live log-level toggle, there's no live state
		// to fall back on, so the operator should know it didn't stick.
		for name := range clears {
			t := byName[name]
			if _, err := deps.DB.ExecContext(r.Context(),
				`DELETE FROM settings WHERE key = ?`, t.settingsKey()); err != nil {
				deps.logger().Warn("tunables: clear failed", "tunable", name, "err", err)
				writeJSONError(w, http.StatusInternalServerError, "could not save settings")
				return
			}
		}
		for name, v := range sets {
			t := byName[name]
			if err := upsertSetting(r.Context(), deps.DB, t.settingsKey(), strconv.Itoa(v)); err != nil {
				deps.logger().Warn("tunables: set failed", "tunable", name, "err", err)
				writeJSONError(w, http.StatusInternalServerError, "could not save settings")
				return
			}
		}

		// Audit once for the whole change. Values are not secret, so we
		// record the set names + values and the cleared names. Guard the
		// nil recorder.
		if deps.Audit != nil && (len(sets) > 0 || len(clears) > 0) {
			actor := audit.ActorAdmin
			if admin, ok := AdminFromContext(r.Context()); ok {
				actor = admin.Username
			}
			clearedNames := make([]string, 0, len(clears))
			for name := range clears {
				clearedNames = append(clearedNames, name)
			}
			deps.Audit.Record(r.Context(), audit.ActionLogLevelChange, actor, ClientIP(r), "perf_tunables", map[string]any{
				"set":     sets,
				"cleared": clearedNames,
			})
		}

		writeJSON(w, http.StatusOK, buildTunablesResponse(r.Context(), deps.DB))
	}
}

// ApplyTunableEnv reads operator-set performance tunables from the settings
// table and exports them as SUBLYNE_* environment variables so the dataplane
// child (which inherits this process's environment) picks them up at startup.
// Unset tunables are left to the dataplane's built-in defaults. Call BEFORE the
// dataplane supervisor spawns the child.
func ApplyTunableEnv(ctx context.Context, db *sql.DB, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	if db == nil {
		return
	}
	for _, t := range tunableRegistry {
		v := readTunableValue(ctx, db, t)
		if v == nil {
			// Unset → leave the env var alone so the dataplane uses its
			// built-in default (or, for the auto knob, auto-detects).
			continue
		}
		// Range-check against the registry bounds. Every tunable here has
		// a real min/max, but guard anyway so a hand-edited DB row can't
		// push an out-of-range value into the child.
		if *v < t.Min || *v > t.Max {
			logger.Warn("tunables: persisted value out of range, ignoring",
				"tunable", t.Name, "value", *v, "min", t.Min, "max", t.Max)
			continue
		}
		if err := os.Setenv(t.Env, strconv.Itoa(*v)); err != nil {
			logger.Warn("tunables: setenv failed", "env", t.Env, "err", err)
			continue
		}
		logger.Info("tunables: applied operator override", "env", t.Env, "value", *v)
	}
}
