// Package config loads the bootstrap configuration for the
// Sublyne control plane from /etc/sublyne/config.toml.
//
// Only six values live in the on-disk config: role, panel_port,
// web_path, db_path, log_path, log_level. Everything else (admin
// credentials, tunnels, WireGuard configs, JWT signing key, audit
// log) is stored in SQLite at db_path. See PROJECT_REQUIREMENTS.md
// §6 for the full split.
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

// Config holds the bootstrap configuration for the control plane.
//
// All fields are required at runtime; Load applies the defaults from
// Default() to any unset field, then runs Validate() before returning.
type Config struct {
	// Role selects the server's behavior: "client" runs the Iran-side
	// listener, "remote" runs the foreign exit. See PRD §2.1.
	Role string `toml:"role"`

	// PanelPort is the TCP port the HTTP admin panel binds.
	// setup.sh picks a random 5-digit port in 10000-65535.
	PanelPort int `toml:"panel_port"`

	// WebPath is the obfuscated URL prefix under which the panel and
	// API are mounted (e.g. "x7Kp9aR2"). All routes live at
	// "/<web_path>/". setup.sh generates a random 16-char URL-safe
	// string at install time.
	WebPath string `toml:"web_path"`

	// DBPath is the on-disk location of the SQLite database.
	// Defaults to /var/lib/sublyne/sublyne.db.
	DBPath string `toml:"db_path"`

	// LogPath is the rotating application log file.
	// Defaults to /var/lib/sublyne/logs/app.log. The rotating sink
	// itself is delivered in Phase 12; until then logs go to stdout.
	LogPath string `toml:"log_path"`

	// LogLevel is one of "trace", "debug", "info", "warn", "error".
	// Defaults to "info".
	LogLevel string `toml:"log_level"`
}

// Default returns a Config populated with the values applied when a
// field is absent from /etc/sublyne/config.toml.
//
// Role and panel_port have no useful default in production (setup.sh
// always writes both), but Default keeps them set so unit tests can
// construct a Config without owning the whole filesystem.
func Default() Config {
	return Config{
		Role:      "client",
		PanelPort: 18080,
		WebPath:   "panel",
		DBPath:    "/var/lib/sublyne/sublyne.db",
		LogPath:   "/var/lib/sublyne/logs/app.log",
		LogLevel:  "info",
	}
}

// Load reads path, decodes it as TOML on top of Default(), and runs
// Validate(). Any error returned has the config path attached.
func Load(path string) (Config, error) {
	cfg := Default()
	if _, err := os.Stat(path); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", path, err)
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, fmt.Errorf("config %q: %w", path, err)
	}
	return cfg, nil
}

// Validate returns nil when every field holds a usable value.
func (c Config) Validate() error {
	switch c.Role {
	case "client", "remote":
	default:
		return fmt.Errorf("invalid role %q (must be \"client\" or \"remote\")", c.Role)
	}
	if c.PanelPort < 1 || c.PanelPort > 65535 {
		return fmt.Errorf("panel_port %d out of range 1-65535", c.PanelPort)
	}
	if strings.TrimSpace(c.WebPath) == "" {
		return errors.New("web_path is required")
	}
	if strings.ContainsAny(c.WebPath, "/?#") {
		return fmt.Errorf("web_path %q must not contain '/', '?', or '#'", c.WebPath)
	}
	if c.DBPath == "" {
		return errors.New("db_path is required")
	}
	if c.LogPath == "" {
		return errors.New("log_path is required")
	}
	switch c.LogLevel {
	case "trace", "debug", "info", "warn", "error":
	default:
		return fmt.Errorf("invalid log_level %q (must be one of trace, debug, info, warn, error)", c.LogLevel)
	}
	return nil
}
