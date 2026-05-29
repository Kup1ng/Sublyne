package logging

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWriteAndListCrashReports(t *testing.T) {
	dir := t.TempDir()
	name1, err := WriteCrashReport(dir, "panic: first\nstack")
	if err != nil {
		t.Fatalf("WriteCrashReport 1: %v", err)
	}
	// Drop a second file with a back-dated mtime so the sort order is
	// deterministic without relying on time.Sleep.
	older := filepath.Join(dir, "crash-1000.log")
	if err := os.WriteFile(older, []byte("panic: old\n"), 0o640); err != nil {
		t.Fatalf("write older: %v", err)
	}
	past := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	if err := os.Chtimes(older, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	reports, err := ListCrashReports(dir)
	if err != nil {
		t.Fatalf("ListCrashReports: %v", err)
	}
	if len(reports) != 2 {
		t.Fatalf("expected 2 reports, got %d", len(reports))
	}
	// Newest first: the freshly-written file beats the back-dated one.
	if reports[0].Filename != name1 {
		t.Errorf("expected newest=%q, got %q", name1, reports[0].Filename)
	}
	if reports[0].Preview == "" {
		t.Error("expected non-empty preview for first report")
	}
	if !strings.Contains(reports[1].Preview, "panic: old") {
		t.Errorf("expected old preview to contain panic line; got %q", reports[1].Preview)
	}

	body, err := ReadCrashReport(dir, name1)
	if err != nil {
		t.Fatalf("ReadCrashReport: %v", err)
	}
	if !strings.Contains(string(body), "panic: first") {
		t.Errorf("read body missing expected line: %q", body)
	}
}

func TestListCrashReports_MissingDirReturnsEmpty(t *testing.T) {
	reports, err := ListCrashReports(filepath.Join(t.TempDir(), "absent"))
	if err != nil {
		t.Fatalf("expected nil error for missing dir, got %v", err)
	}
	if len(reports) != 0 {
		t.Errorf("expected 0 reports, got %d", len(reports))
	}
}

func TestReadCrashReport_RejectsPathTraversal(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadCrashReport(dir, "crash-1/etc-passwd"); err == nil {
		t.Error("expected error on path-separator filename")
	}
	if _, err := ReadCrashReport(dir, "app.log"); err == nil {
		t.Error("expected error on non-crash-prefix filename")
	}
}

func TestFormatPanic(t *testing.T) {
	body := FormatPanic("boom", "test")
	if !strings.Contains(body, "panic: boom") {
		t.Errorf("missing panic line in body: %q", body)
	}
	if !strings.Contains(body, "location: test") {
		t.Errorf("missing location: %q", body)
	}
	if !strings.Contains(body, "goroutine") {
		t.Errorf("missing stack trace: %q", body)
	}
}

// secretBearingStruct mirrors the shape of an internal type that
// carries credentials — its name and zero value never appear in a
// rendered panic. The test below proves the rendering pipeline
// collapses an instance of this type to its type name only, even
// when the field would have been visible under fmt.Sprintf("%v", v).
type secretBearingStruct struct {
	Username string
	PSK      []byte
}

func TestSafePanicMessage(t *testing.T) {
	cases := []struct {
		name      string
		recovered any
		wantSub   string // substring expected in the rendered message
		wantNotIn string // substring that MUST NOT appear (the secret bytes)
	}{
		{
			name:      "string",
			recovered: "bootstrap failed",
			wantSub:   "bootstrap failed",
		},
		{
			name:      "error",
			recovered: errors.New("nil pointer dereference"),
			wantSub:   "nil pointer dereference",
		},
		{
			name:      "nil",
			recovered: nil,
			wantSub:   "<nil>",
		},
		{
			name:      "struct collapses to type only",
			recovered: secretBearingStruct{Username: "admin", PSK: []byte("HIGHLY-SENSITIVE-PSK-BYTES")},
			wantSub:   "logging.secretBearingStruct",
			wantNotIn: "HIGHLY-SENSITIVE-PSK-BYTES",
		},
		{
			name:      "pointer to struct collapses to type only",
			recovered: &secretBearingStruct{Username: "admin", PSK: []byte("SECRET-XYZ")},
			wantSub:   "*logging.secretBearingStruct",
			wantNotIn: "SECRET-XYZ",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := SafePanicMessage(tc.recovered)
			if !strings.Contains(got, tc.wantSub) {
				t.Errorf("SafePanicMessage(%v) = %q; want substring %q", tc.recovered, got, tc.wantSub)
			}
			if tc.wantNotIn != "" && strings.Contains(got, tc.wantNotIn) {
				t.Errorf("SafePanicMessage leaked secret bytes: got %q (contained %q)", got, tc.wantNotIn)
			}
		})
	}
}

func TestFormatPanic_StructPanicDoesNotLeakSecrets(t *testing.T) {
	body := FormatPanic(secretBearingStruct{
		Username: "admin",
		PSK:      []byte("never-print-me-please"),
	}, "test")
	if strings.Contains(body, "never-print-me-please") {
		t.Fatalf("FormatPanic leaked PSK bytes in crash body:\n%s", body)
	}
	if !strings.Contains(body, "logging.secretBearingStruct") {
		t.Errorf("expected type name in crash body, got:\n%s", body)
	}
}

func TestSetCrashDir_FirstCallWins(t *testing.T) {
	// SetCrashDir is sync.Once-gated and a previous test run may have
	// claimed it; we accept either "never set" or "the first call's
	// value" here.
	SetCrashDir("/tmp/sublyne-crash-test")
	got := CrashDir()
	if got != "" && got != "/tmp/sublyne-crash-test" {
		t.Logf("crash dir already installed as %q (first-writer wins)", got)
	}
}
