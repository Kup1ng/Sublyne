package api

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/Kup1ng/Sublyne/control-plane/internal/logging"
)

func TestCrashRecoverer_WritesFile(t *testing.T) {
	dir := t.TempDir()
	// SetCrashDir is sync.Once — guard the test in case another test
	// in this package has already claimed it.
	logging.SetCrashDir(dir)
	if got := logging.CrashDir(); got != dir {
		t.Skipf("crash dir already %q (sync.Once); cannot run this test in this order", got)
	}

	h := CrashRecoverer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic("boom from handler")
	}))

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/oops", nil)
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read crash dir: %v", err)
	}
	found := false
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), logging.CrashFilePrefix) {
			continue
		}
		found = true
		body, err := os.ReadFile(dir + string(os.PathSeparator) + e.Name())
		if err != nil {
			t.Fatalf("read crash file: %v", err)
		}
		if !strings.Contains(string(body), "boom from handler") {
			t.Errorf("crash file missing panic value: %q", body)
		}
		if !strings.Contains(string(body), "GET /oops") {
			t.Errorf("crash file missing request line: %q", body)
		}
	}
	if !found {
		t.Errorf("no crash-*.log file in %q (entries: %v)", dir, entries)
	}
}

func TestCrashRecoverer_PassesThroughErrAbortHandler(t *testing.T) {
	defer func() {
		if r := recover(); r != http.ErrAbortHandler {
			t.Errorf("expected ErrAbortHandler to propagate, got %v", r)
		}
	}()
	h := CrashRecoverer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	h.ServeHTTP(rec, req)
}
