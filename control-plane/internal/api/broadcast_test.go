package api

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Kup1ng/Sublyne/control-plane/internal/ipc"
)

// passthroughRenderer wires a tiny renderer that emits a predictable
// byte slice from a StatsReport so the bus tests can verify fan-out
// semantics without dragging in JSON or the metrics dependencies.
func passthroughRenderer() SnapshotRenderer {
	return func(r ipc.StatsReport) ([]byte, error) {
		if len(r.Samples) == 0 {
			return []byte(""), nil
		}
		return []byte(fmt.Sprintf("bytes_in=%d", r.Samples[0].BytesIn)), nil
	}
}

func TestBroadcastFanOutToAllSubscribers(t *testing.T) {
	b := NewBroadcast()
	b.SetRenderer(passthroughRenderer(), nil)
	a := b.Subscribe(2)
	b2 := b.Subscribe(2)

	report := ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 100}}}
	b.Publish(report)
	for label, ch := range map[string]<-chan []byte{"a": a, "b": b2} {
		select {
		case got := <-ch:
			if string(got) != "bytes_in=100" {
				t.Errorf("%s got wrong value: %q", label, string(got))
			}
		case <-time.After(time.Second):
			t.Fatalf("%s did not receive the published report", label)
		}
	}
}

func TestBroadcastUnsubscribeStopsDelivery(t *testing.T) {
	b := NewBroadcast()
	b.SetRenderer(passthroughRenderer(), nil)
	ch := b.Subscribe(1)
	b.Unsubscribe(ch)
	// Unsubscribed channels are closed; reading should return zero.
	select {
	case _, ok := <-ch:
		if ok {
			t.Errorf("read returned data after unsubscribe")
		}
	case <-time.After(100 * time.Millisecond):
		t.Errorf("read did not return after channel close")
	}
}

func TestBroadcastDropsOldOnSlowSubscriber(t *testing.T) {
	b := NewBroadcast()
	b.SetRenderer(passthroughRenderer(), nil)
	ch := b.Subscribe(1)

	// Publish two messages without reading — the first should be
	// dropped, the second should still land.
	b.Publish(ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 1}}})
	b.Publish(ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 2}}})

	select {
	case got := <-ch:
		if string(got) != "bytes_in=2" {
			t.Errorf("expected newest sample (BytesIn=2), got %q", string(got))
		}
	case <-time.After(time.Second):
		t.Fatalf("nothing arrived after dropping policy applied")
	}
}

func TestBroadcastPublishChanPumpsToSubscribers(t *testing.T) {
	b := NewBroadcast()
	b.SetRenderer(passthroughRenderer(), nil)
	ch := b.Subscribe(2)
	sink := b.PublishChan()
	defer close(sink)

	got := int32(0)
	go func() {
		for r := range ch {
			if string(r) == "bytes_in=42" {
				atomic.AddInt32(&got, 1)
			}
		}
	}()

	sink <- ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 42}}}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && atomic.LoadInt32(&got) == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	if atomic.LoadInt32(&got) == 0 {
		t.Fatalf("PublishChan did not deliver via Broadcast")
	}
}

// TestBroadcastPublishWithoutRendererIsNoop guards against accidentally
// emitting empty frames before main.go has wired the renderer.
func TestBroadcastPublishWithoutRendererIsNoop(t *testing.T) {
	b := NewBroadcast()
	ch := b.Subscribe(1)
	b.Publish(ipc.StatsReport{Samples: []ipc.PerTunnelStats{{TunnelID: 1, BytesIn: 5}}})
	select {
	case got := <-ch:
		t.Fatalf("expected no delivery without renderer, got %q", string(got))
	case <-time.After(50 * time.Millisecond):
		// success
	}
}
