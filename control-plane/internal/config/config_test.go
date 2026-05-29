package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTempConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestLoad_AppliesDefaultsForUnsetFields(t *testing.T) {
	path := writeTempConfig(t, `
role        = "remote"
panel_port  = 12345
web_path    = "abc123"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Role != "remote" {
		t.Errorf("role = %q, want %q", cfg.Role, "remote")
	}
	if cfg.PanelPort != 12345 {
		t.Errorf("panel_port = %d, want 12345", cfg.PanelPort)
	}
	if cfg.WebPath != "abc123" {
		t.Errorf("web_path = %q", cfg.WebPath)
	}
	if cfg.DBPath != "/var/lib/sublyne/sublyne.db" {
		t.Errorf("db_path default not applied: %q", cfg.DBPath)
	}
	if cfg.LogPath != "/var/lib/sublyne/logs/app.log" {
		t.Errorf("log_path default not applied: %q", cfg.LogPath)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log_level default not applied: %q", cfg.LogLevel)
	}
}

func TestLoad_RoundTripsAllFields(t *testing.T) {
	path := writeTempConfig(t, `
role        = "client"
panel_port  = 55555
web_path    = "x7Kp9aR2tNvE3oQc"
db_path     = "/tmp/sublyne.db"
log_path    = "/tmp/sublyne.log"
log_level   = "debug"
`)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	want := Config{
		Role:      "client",
		PanelPort: 55555,
		WebPath:   "x7Kp9aR2tNvE3oQc",
		DBPath:    "/tmp/sublyne.db",
		LogPath:   "/tmp/sublyne.log",
		LogLevel:  "debug",
	}
	if cfg != want {
		t.Errorf("config mismatch:\n got %+v\nwant %+v", cfg, want)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	_, err := Load(filepath.Join(t.TempDir(), "absent.toml"))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestLoad_InvalidTOML(t *testing.T) {
	path := writeTempConfig(t, "this is not = valid = toml = at all\n")
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid TOML")
	}
}

func TestValidate(t *testing.T) {
	good := Default()
	good.WebPath = "abc"
	good.PanelPort = 20000
	if err := good.Validate(); err != nil {
		t.Fatalf("baseline valid config rejected: %v", err)
	}

	cases := []struct {
		name    string
		mutate  func(*Config)
		wantSub string
	}{
		{"empty role", func(c *Config) { c.Role = "" }, "role"},
		{"unknown role", func(c *Config) { c.Role = "middleman" }, "role"},
		{"port zero", func(c *Config) { c.PanelPort = 0 }, "panel_port"},
		{"port over max", func(c *Config) { c.PanelPort = 70000 }, "panel_port"},
		{"port negative", func(c *Config) { c.PanelPort = -1 }, "panel_port"},
		{"empty webpath", func(c *Config) { c.WebPath = "" }, "web_path"},
		{"whitespace webpath", func(c *Config) { c.WebPath = "   " }, "web_path"},
		{"slash in webpath", func(c *Config) { c.WebPath = "abc/def" }, "web_path"},
		{"empty db path", func(c *Config) { c.DBPath = "" }, "db_path"},
		{"empty log path", func(c *Config) { c.LogPath = "" }, "log_path"},
		{"unknown log level", func(c *Config) { c.LogLevel = "verbose" }, "log_level"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := Default()
			c.WebPath = "abc"
			c.PanelPort = 20000
			tc.mutate(&c)
			err := c.Validate()
			if err == nil {
				t.Fatalf("expected error containing %q", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q does not mention %q", err, tc.wantSub)
			}
		})
	}
}

func TestDefault_IsValid(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Fatalf("Default() should already be valid: %v", err)
	}
}
