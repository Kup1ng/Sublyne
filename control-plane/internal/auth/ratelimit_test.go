package auth

import (
	"context"
	"sync"
	"testing"
	"time"
)

// fakeClock advances only when its Advance method is called. The
// Limiter consults now() on every operation, so step-by-step tests
// can simulate the brute-force window deterministically.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock(start time.Time) *fakeClock {
	return &fakeClock{now: start}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestLimiter(t *testing.T, clock *fakeClock) *Limiter {
	t.Helper()
	db := newTestDB(t)
	cfg := DefaultLimiterConfig()
	cfg.PruneInterval = time.Hour // disable background pruning in tests
	cfg.PruneOlderThan = 24 * time.Hour
	return NewLimiter(db, cfg, clock.Now, nil)
}

func TestLimiter_AllowsBelowThreshold(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim := newTestLimiter(t, clock)

	for i := 0; i < DefaultLockoutThreshold-1; i++ {
		decision, err := lim.Check(context.Background(), "1.2.3.4")
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		if !decision.Allowed {
			t.Fatalf("attempt %d locked out prematurely: %+v", i, decision)
		}
		if err := lim.Record(context.Background(), "1.2.3.4", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	// 4 failures recorded; 5th should still be allowed.
	decision, err := lim.Check(context.Background(), "1.2.3.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed {
		t.Errorf("after %d failures the IP should still be allowed, got %+v", DefaultLockoutThreshold-1, decision)
	}
}

func TestLimiter_LocksOutAtThreshold(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim := newTestLimiter(t, clock)

	for i := 0; i < DefaultLockoutThreshold; i++ {
		if _, err := lim.Check(context.Background(), "9.9.9.9"); err != nil {
			t.Fatalf("Check pre-record: %v", err)
		}
		if err := lim.Record(context.Background(), "9.9.9.9", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	decision, err := lim.Check(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected lockout after %d failures, got Allowed=true", DefaultLockoutThreshold)
	}
	if decision.RetryAfter <= 0 || decision.RetryAfter > DefaultLockoutDuration+time.Second {
		t.Errorf("RetryAfter = %v, want >0 and <= %v", decision.RetryAfter, DefaultLockoutDuration)
	}
}

func TestLimiter_LockoutLastsFullDuration(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim := newTestLimiter(t, clock)

	// Trip the lockout (Threshold failures inside the window).
	for i := 0; i < DefaultLockoutThreshold; i++ {
		if err := lim.Record(context.Background(), "5.5.5.5", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if d, _ := lim.Check(context.Background(), "5.5.5.5"); d.Allowed {
		t.Fatal("expected lockout immediately after threshold")
	}

	// REGRESSION GUARD: after the COUNTING WINDOW elapses (the failing
	// rows age out of Window) the IP must STILL be locked. Previously the
	// gate counted only within Window, so an attacker who waited 5 min was
	// freed — making the real lockout 5 min, not the configured 15.
	clock.Advance(DefaultLockoutWindow + time.Second)
	if d, err := lim.Check(context.Background(), "5.5.5.5"); err != nil {
		t.Fatalf("Check: %v", err)
	} else if d.Allowed {
		t.Errorf("IP unlocked after only the %v counting window; lockout must last %v",
			DefaultLockoutWindow, DefaultLockoutDuration)
	}

	// After the full lockout duration past the last failure, the IP is
	// allowed again.
	clock.Advance(DefaultLockoutDuration)
	if d, err := lim.Check(context.Background(), "5.5.5.5"); err != nil {
		t.Fatalf("Check: %v", err)
	} else if !d.Allowed {
		t.Errorf("lockout should have expired after %v, got %+v", DefaultLockoutDuration, d)
	}
}

func TestLimiter_GlobalCapTriggersBeforeFailures(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim := newTestLimiter(t, clock)

	// Fire DefaultGlobalCap successful attempts; failures would
	// trip the per-window threshold first.
	for i := 0; i < DefaultGlobalCap; i++ {
		if err := lim.Record(context.Background(), "4.4.4.4", true); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	d, err := lim.Check(context.Background(), "4.4.4.4")
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if d.Allowed {
		t.Fatalf("expected global cap to trip after %d attempts", DefaultGlobalCap)
	}
	if d.RetryAfter <= 0 {
		t.Errorf("RetryAfter = %v, want >0", d.RetryAfter)
	}
}

func TestLimiter_DifferentIPsDoNotInterfere(t *testing.T) {
	clock := newFakeClock(time.Now())
	lim := newTestLimiter(t, clock)

	for i := 0; i < DefaultLockoutThreshold; i++ {
		if err := lim.Record(context.Background(), "10.10.10.10", false); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	// 10.10.10.10 locked; 11.11.11.11 unaffected.
	dLocked, _ := lim.Check(context.Background(), "10.10.10.10")
	if dLocked.Allowed {
		t.Fatalf("expected lockout on 10.10.10.10")
	}
	dFresh, _ := lim.Check(context.Background(), "11.11.11.11")
	if !dFresh.Allowed {
		t.Errorf("a clean IP must not inherit lockout from another IP: %+v", dFresh)
	}
}
