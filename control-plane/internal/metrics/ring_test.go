package metrics

import (
	"testing"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
)

// makeReport builds a synthetic StatsReport with one tunnel and one
// non-zero system row so the ring buffer has something to remember.
func makeReport(id int64, bytesIn, bytesOut uint64) ipc.StatsReport {
	return ipc.StatsReport{
		Samples: []ipc.PerTunnelStats{
			{
				TunnelID:                 id,
				Role:                     "client",
				Transport:                "udp",
				BytesIn:                  bytesIn,
				BytesOut:                 bytesOut,
				PacketsIn:                bytesIn / 100,
				PacketsOut:               bytesOut / 100,
				ActiveSessions:           5,
				LastPacketReceivedAtUnix: uint64(time.Now().Unix()),
				LastPacketSentAtUnix:     uint64(time.Now().Unix()),
				UploadRTTMsEWMA:          42.5,
				DownloadRTTMsEWMA:        60.1,
				PacketLossEstimate:       0.001,
			},
		},
		System: ipc.SystemStats{
			CPUPercent:     12.5,
			MemUsedBytes:   2 << 30,
			MemTotalBytes:  8 << 30,
			DiskUsedBytes:  10 << 30,
			DiskTotalBytes: 100 << 30,
			NetInterfaces: map[string]ipc.NetInterfaceStats{
				"eth0": {RxBytesPerSec: 1_000_000, TxBytesPerSec: 500_000},
			},
		},
	}
}

func TestRecorderAppendStoresLatest(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0)
	r := NewRecorder(func() time.Time { return clock })

	r.Append(makeReport(1, 1000, 2000))
	got := r.Latest()
	if got.At.IsZero() {
		t.Fatalf("Latest.At zero after Append")
	}
	if len(got.Samples) != 1 {
		t.Fatalf("want 1 sample, got %d", len(got.Samples))
	}
	if got.Samples[0].BytesIn != 1000 {
		t.Errorf("bytes_in=%d, want 1000", got.Samples[0].BytesIn)
	}
	if got.System.CPUPercent != 12.5 {
		t.Errorf("cpu_percent=%v, want 12.5", got.System.CPUPercent)
	}
}

func TestRecorderSameMinuteOverwrites(t *testing.T) {
	// Two reports inside the same minute bucket — the second overwrites
	// the first. The ring length stays at 1.
	clock := time.Unix(1_700_000_000, 0)
	r := NewRecorder(func() time.Time { return clock })
	r.Append(makeReport(1, 1000, 2000))
	clock = clock.Add(5 * time.Second)
	r.Append(makeReport(1, 3000, 4000))

	per, sys := r.Len(1)
	if per != 1 {
		t.Errorf("per-tunnel length=%d, want 1 (same-minute overwrite)", per)
	}
	if sys != 1 {
		t.Errorf("system length=%d, want 1 (same-minute overwrite)", sys)
	}
	h := r.History()
	if len(h.Tunnels[1]) != 1 || h.Tunnels[1][0].Stats.BytesIn != 3000 {
		t.Errorf("history last sample wrong: %+v", h.Tunnels[1])
	}
}

func TestRecorderDifferentMinuteAppends(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	r := NewRecorder(func() time.Time { return clock })
	r.Append(makeReport(1, 1000, 2000))
	clock = clock.Add(70 * time.Second)
	r.Append(makeReport(1, 3000, 4000))

	per, sys := r.Len(1)
	if per != 2 {
		t.Errorf("per-tunnel length=%d, want 2 (cross-minute)", per)
	}
	if sys != 2 {
		t.Errorf("system length=%d, want 2 (cross-minute)", sys)
	}
}

func TestRecorderRingEviction(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	r := NewRecorder(func() time.Time { return clock })
	// Push MaxSamples+5 minute buckets. Earliest 5 must evict.
	const overshoot = 5
	for i := 0; i < MaxSamples+overshoot; i++ {
		r.Append(makeReport(1, uint64(i*1000), uint64(i*2000)))
		clock = clock.Add(time.Minute)
	}
	per, sys := r.Len(1)
	if per != MaxSamples {
		t.Errorf("per-tunnel length=%d, want %d", per, MaxSamples)
	}
	if sys != MaxSamples {
		t.Errorf("system length=%d, want %d", sys, MaxSamples)
	}
	h := r.History()
	// First retained sample should correspond to iteration `overshoot`.
	first := h.Tunnels[1][0]
	if first.Stats.BytesIn != uint64(overshoot*1000) {
		t.Errorf("first sample BytesIn=%d, want %d (older entries should have evicted)",
			first.Stats.BytesIn, overshoot*1000)
	}
	last := h.Tunnels[1][len(h.Tunnels[1])-1]
	if last.Stats.BytesIn != uint64((MaxSamples+overshoot-1)*1000) {
		t.Errorf("last sample BytesIn=%d, want %d",
			last.Stats.BytesIn, (MaxSamples+overshoot-1)*1000)
	}
}

func TestRecorderTracksMultipleTunnels(t *testing.T) {
	clock := time.Unix(1_700_000_000, 0).Truncate(time.Minute)
	r := NewRecorder(func() time.Time { return clock })
	// Build a report with two distinct tunnel ids.
	rep := ipc.StatsReport{
		Samples: []ipc.PerTunnelStats{
			{TunnelID: 1, Role: "client", Transport: "udp", BytesIn: 100},
			{TunnelID: 2, Role: "remote", Transport: "tcp_syn", BytesIn: 200},
		},
	}
	r.Append(rep)
	clock = clock.Add(time.Minute + time.Second)
	r.Append(rep)
	if n, _ := r.Len(1); n != 2 {
		t.Errorf("tunnel 1 length=%d, want 2", n)
	}
	if n, _ := r.Len(2); n != 2 {
		t.Errorf("tunnel 2 length=%d, want 2", n)
	}
}

func TestRecorderLatestEmptyBeforeAppend(t *testing.T) {
	r := NewRecorder(nil)
	got := r.Latest()
	if !got.At.IsZero() {
		t.Errorf("Latest.At = %v, want zero", got.At)
	}
	if len(got.Samples) != 0 {
		t.Errorf("Latest.Samples = %v, want empty", got.Samples)
	}
}

func TestSubscribeIPCForwardsAndFansOut(t *testing.T) {
	r := NewRecorder(nil)
	src := make(chan ipc.StatsReport, 4)
	watcher := make(chan ipc.StatsReport, 4)
	stop := make(chan struct{})
	defer close(stop)

	SubscribeIPC(stop, src, r, watcher)

	src <- makeReport(7, 5000, 6000)
	src <- makeReport(7, 9000, 10000)

	// Drain the watcher to confirm fan-out happened.
	got := 0
	for i := 0; i < 2; i++ {
		select {
		case <-watcher:
			got++
		case <-time.After(2 * time.Second):
			t.Fatalf("watcher did not receive report %d in time", i+1)
		}
	}

	// Wait briefly for the recorder Append to land in the ring.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		latest := r.Latest()
		if len(latest.Samples) > 0 && latest.Samples[0].BytesIn == 9000 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("recorder did not pick up the latest sample within 2 s")
}
