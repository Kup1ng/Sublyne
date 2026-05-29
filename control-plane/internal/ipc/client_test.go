package ipc

import (
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// TestClient_PingReply spins up an in-memory net.Pipe pair, runs a
// scripted "Rust" peer on one side, and exercises Send via the Client
// on the other.
func TestClient_PingReply(t *testing.T) {
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close(); _ = serverEnd.Close() })

	client := NewClient(clientEnd, nil)
	t.Cleanup(func() { _ = client.Close() })

	// Scripted peer: send Ready, then mirror back a Reply{ok:true} for
	// every incoming Ping.
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, err := WriteFrame(serverEnd, Envelope{
			Type:    "Ready",
			ID:      "ready-1",
			Payload: json.RawMessage(`{"version":"test"}`),
		})
		if err != nil {
			t.Errorf("server write Ready: %v", err)
			return
		}
		// Read one frame, expect Ping, send Reply.
		env, err := ReadFrame(serverEnd)
		if err != nil {
			t.Errorf("server read: %v", err)
			return
		}
		if env.Type != "Ping" {
			t.Errorf("server: unexpected type %q", env.Type)
			return
		}
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "Reply",
			ID:      env.ID,
			Payload: json.RawMessage(`{"ok":true}`),
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	reply, err := client.Send(ctx, "Ping", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !reply.OK {
		t.Fatalf("expected reply.OK, got %+v", reply)
	}
	wg.Wait()
}

// TestClient_ErrorReply checks that an `ok:false` reply with a code
// surfaces as a typed IPCError on the Client side.
func TestClient_ErrorReply(t *testing.T) {
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close(); _ = serverEnd.Close() })

	client := NewClient(clientEnd, nil)
	t.Cleanup(func() { _ = client.Close() })

	go func() {
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "Ready",
			ID:      "r-1",
			Payload: json.RawMessage(`{"version":"t"}`),
		})
		env, err := ReadFrame(serverEnd)
		if err != nil {
			return
		}
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "Reply",
			ID:      env.ID,
			Payload: json.RawMessage(`{"ok":false,"error":{"code":"PORT_IN_USE","message":"already bound"}}`),
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	reply, err := client.Send(ctx, "StartTunnel", map[string]any{"id": 1})
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if reply.OK {
		t.Fatal("expected reply.OK to be false")
	}
	if reply.Error == nil || reply.Error.Code != CodePortInUse {
		t.Errorf("unexpected error: %+v", reply.Error)
	}
}

// TestClient_StatsReportFanout exercises the Phase 11 SubscribeStats
// channel. The IPC server pushes a `StatsReport` event every 5 s; the
// Go control plane fans it out to subscribers identical to how state-
// change events flow.
func TestClient_StatsReportFanout(t *testing.T) {
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close(); _ = serverEnd.Close() })

	client := NewClient(clientEnd, nil)
	t.Cleanup(func() { _ = client.Close() })

	ch := client.SubscribeStats(4)
	push := make(chan struct{})
	go func() {
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "Ready",
			ID:      "r-1",
			Payload: json.RawMessage(`{"version":"t"}`),
		})
		<-push
		// Body schema mirrors data-plane/src/metrics.rs.
		_, _ = WriteFrame(serverEnd, Envelope{
			Type: "StatsReport",
			ID:   "stats-1",
			Payload: json.RawMessage(`{
				"samples":[{
					"tunnel_id":42,"role":"client","transport":"udp",
					"bytes_in":1000,"bytes_out":2000,
					"packets_in":10,"packets_out":20,
					"active_sessions":5,
					"last_packet_received_at_unix":1700000000,
					"last_packet_sent_at_unix":1700000001,
					"upload_rtt_ms_ewma":42.0,
					"download_rtt_ms_ewma":61.0,
					"packet_loss_estimate":0.0,
					"auth_drops":0,
					"session_rejects":0,
					"transport_packets":{"udp":10,"tcp_syn":0,"icmp":0,"icmpv6":0}
				}],
				"system":{
					"cpu_percent":12.3,
					"mem_used_bytes":1000,"mem_total_bytes":2000,
					"disk_used_bytes":100,"disk_total_bytes":200,
					"net_interfaces":{},
					"load_avg_1min":0.5
				}
			}`),
		})
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	close(push)
	select {
	case rep := <-ch:
		if len(rep.Samples) != 1 || rep.Samples[0].TunnelID != 42 {
			t.Errorf("unexpected samples: %+v", rep.Samples)
		}
		if rep.System.CPUPercent != 12.3 {
			t.Errorf("unexpected cpu: %v", rep.System.CPUPercent)
		}
		if rep.Samples[0].TransportPackets.UDP != 10 {
			t.Errorf("transport_packets.udp = %d, want 10", rep.Samples[0].TransportPackets.UDP)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for stats report")
	}
}

// TestClient_StateChangeFanout exercises the SubscribeStateChanges
// channel.
//
// Subtle ordering: we MUST register the subscriber before the server
// writes the TunnelStateChanged frame. The client's readLoop dispatches
// events synchronously via the current c.stateSubs slice, so an event
// that arrives before any subscriber is registered is silently dropped
// (by design — events are fire-and-forget). The previous form of this
// test wrote both frames first and only subscribed after WaitReady
// returned, which races against the readLoop and intermittently lost
// the event. Subscribe before the server emits, then signal the
// server goroutine to push the frame.
func TestClient_StateChangeFanout(t *testing.T) {
	serverEnd, clientEnd := net.Pipe()
	t.Cleanup(func() { _ = clientEnd.Close(); _ = serverEnd.Close() })

	client := NewClient(clientEnd, nil)
	t.Cleanup(func() { _ = client.Close() })

	// Subscribe first. The channel is bounded; the dispatcher drops
	// the oldest sample on overflow, so a slow test consumer is fine.
	ch := client.SubscribeStateChanges(4)

	pushEvent := make(chan struct{})
	go func() {
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "Ready",
			ID:      "r-1",
			Payload: json.RawMessage(`{"version":"t"}`),
		})
		<-pushEvent // wait for the test to confirm subscribe + WaitReady
		_, _ = WriteFrame(serverEnd, Envelope{
			Type:    "TunnelStateChanged",
			ID:      "evt-1",
			Payload: json.RawMessage(`{"tunnel_id":7,"state":"running"}`),
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := client.WaitReady(ctx); err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	close(pushEvent) // now safe — subscriber is registered, Ready consumed
	select {
	case evt := <-ch:
		if evt.TunnelID != 7 || evt.State != StateRunning {
			t.Errorf("unexpected event: %+v", evt)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for state change")
	}
}
