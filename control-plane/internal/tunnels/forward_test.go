package tunnels

import (
	"context"
	"errors"
	"testing"
)

func TestResolveKcpTuning_PurePreset(t *testing.T) {
	got, err := ResolveKcpTuning(PresetBalanced, "")
	if err != nil {
		t.Fatalf("resolve balanced: %v", err)
	}
	want := kcpPresets[PresetBalanced]
	if got != want {
		t.Errorf("balanced preset = %+v, want %+v", got, want)
	}
}

func TestResolveKcpTuning_OverrideMergesAndKeepsOthers(t *testing.T) {
	// Override only snd_wnd; every other field stays at the interactive
	// preset's value.
	got, err := ResolveKcpTuning(PresetInteractive, `{"snd_wnd": 2048}`)
	if err != nil {
		t.Fatalf("resolve override: %v", err)
	}
	base := kcpPresets[PresetInteractive]
	if got.SndWnd != 2048 {
		t.Errorf("snd_wnd override not applied: got %d", got.SndWnd)
	}
	if got.RcvWnd != base.RcvWnd || got.Interval != base.Interval || got.NC != base.NC {
		t.Errorf("non-overridden fields drifted: %+v vs base %+v", got, base)
	}
}

func TestResolveKcpTuning_RejectsBadJSON(t *testing.T) {
	if _, err := ResolveKcpTuning(PresetBalanced, "{not json"); err == nil {
		t.Error("expected error for malformed JSON override")
	}
}

func TestResolveKcpTuning_RejectsOutOfRange(t *testing.T) {
	if _, err := ResolveKcpTuning(PresetBalanced, `{"snd_wnd": 99999}`); err == nil {
		t.Error("expected error for out-of-range snd_wnd")
	}
	if _, err := ResolveKcpTuning(PresetBalanced, `{"interval": 1}`); err == nil {
		t.Error("expected error for interval below floor")
	}
}

// v4-audit B6: a typo'd / unknown override key must be a loud error, not
// silently ignored (which would leave the preset value while the panel showed
// the operator's intended override).
func TestResolveKcpTuning_RejectsUnknownKey(t *testing.T) {
	if _, err := ResolveKcpTuning(PresetBalanced, `{"snd_win": 2048}`); err == nil {
		t.Error("expected error for unknown KCP override key 'snd_win'")
	}
}

func TestResolveQuicTuning_RejectsUnknownKey(t *testing.T) {
	if _, err := ResolveQuicTuning(PresetBalanced, `{"keepalive_ms": 5000}`); err == nil {
		t.Error("expected error for unknown QUIC override key 'keepalive_ms'")
	}
}

// v4-audit B7: a keepalive at or beyond the idle timeout never refreshes the
// connection in time, and a sub-1s keepalive floods PINGs.
func TestResolveQuicTuning_RejectsKeepAliveBeyondIdle(t *testing.T) {
	if _, err := ResolveQuicTuning(PresetBalanced, `{"keep_alive_ms": 70000, "max_idle_ms": 60000}`); err == nil {
		t.Error("expected error when keep_alive_ms >= max_idle_ms")
	}
	if _, err := ResolveQuicTuning(PresetBalanced, `{"keep_alive_ms": 0}`); err == nil {
		t.Error("expected error for keep_alive_ms below the 1000ms floor")
	}
}

func TestResolveQuicTuning_PurePreset(t *testing.T) {
	got, err := ResolveQuicTuning(PresetLossy, "")
	if err != nil {
		t.Fatalf("resolve lossy: %v", err)
	}
	if got.Congestion != "bbr" {
		t.Errorf("lossy preset congestion = %q, want bbr", got.Congestion)
	}
}

func TestResolveQuicTuning_RejectsBadCongestion(t *testing.T) {
	if _, err := ResolveQuicTuning(PresetBalanced, `{"congestion": "reno"}`); err == nil {
		t.Error("expected error for unknown congestion controller")
	}
}

func TestResolveQuicTuning_RejectsConnWindowBelowStream(t *testing.T) {
	// conn window must be >= stream window.
	if _, err := ResolveQuicTuning(PresetBalanced, `{"conn_recv_window": 131072, "stream_recv_window": 1048576}`); err == nil {
		t.Error("expected error when conn_recv_window < stream_recv_window")
	}
}

func TestValidate_ForwardDefaultsToUDP(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-default")
	t1.ForwardProtocol = ""
	t1.TCPReliabilityEngine = ""
	t1.ForwardEnginePreset = ""
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if t1.ForwardProtocol != ForwardProtocolUDP {
		t.Errorf("forward_protocol = %q, want udp", t1.ForwardProtocol)
	}
	if t1.TCPReliabilityEngine != TCPEngineKCP {
		t.Errorf("engine = %q, want kcp", t1.TCPReliabilityEngine)
	}
	if t1.ForwardEnginePreset != string(PresetBalanced) {
		t.Errorf("preset = %q, want balanced", t1.ForwardEnginePreset)
	}
}

func TestValidate_ForwardTCPKcpHappy(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-tcp-kcp")
	t1.ForwardProtocol = ForwardProtocolTCP
	t1.TCPReliabilityEngine = TCPEngineKCP
	t1.ForwardEnginePreset = string(PresetInteractive)
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("validate tcp+kcp: %v", err)
	}
}

func TestValidate_ForwardTCPQuicHappy(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleRemote("fwd-tcp-quic")
	t1.ForwardProtocol = ForwardProtocolTCP
	t1.TCPReliabilityEngine = TCPEngineQUIC
	t1.ForwardEnginePreset = string(PresetBalanced)
	if err := Validate(ctx, repo, RoleRemote, &t1, 0); err != nil {
		t.Fatalf("validate tcp+quic: %v", err)
	}
}

func TestValidate_ForwardQuicRejectsLowMtu(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-quic-lowmtu")
	t1.ForwardProtocol = ForwardProtocolTCP
	t1.TCPReliabilityEngine = TCPEngineQUIC
	t1.MTU = 1000 // below QuicMinMTU
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["mtu"]; !ok {
		t.Errorf("expected an mtu error for QUIC below the floor: %v", ve.Fields)
	}
}

func TestValidate_ForwardRejectsBadEngine(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-bad-engine")
	t1.ForwardProtocol = ForwardProtocolTCP
	t1.TCPReliabilityEngine = "wireguard"
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["tcp_reliability_engine"]; !ok {
		t.Errorf("missing tcp_reliability_engine error: %v", ve.Fields)
	}
}

func TestValidate_ForwardRejectsBadTuningOverride(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-bad-tuning")
	t1.ForwardProtocol = ForwardProtocolTCP
	t1.TCPReliabilityEngine = TCPEngineKCP
	t1.ForwardEnginePreset = string(PresetBalanced)
	t1.ForwardEngineTuning = `{"snd_wnd": 999999}`
	err := Validate(ctx, repo, RoleClient, &t1, 0)
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("err = %v, want ValidationError", err)
	}
	if _, ok := ve.Fields["forward_engine_tuning"]; !ok {
		t.Errorf("missing forward_engine_tuning error: %v", ve.Fields)
	}
}

// A UDP tunnel must ignore a malformed tuning blob entirely — the blob
// only matters when forward_protocol is tcp.
func TestValidate_ForwardUDPIgnoresTuning(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	t1 := sampleClient("fwd-udp-ignores")
	t1.ForwardProtocol = ForwardProtocolUDP
	t1.ForwardEngineTuning = `{not even json`
	if err := Validate(ctx, repo, RoleClient, &t1, 0); err != nil {
		t.Fatalf("udp tunnel should ignore tuning blob, got: %v", err)
	}
}

// A row created without any forward fields round-trips as udp/kcp/balanced
// (the repo applies the CHECK-satisfying defaults), so legacy rows and
// minimal API bodies stay valid.
func TestRepoForwardDefaultsRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	got, err := repo.Create(ctx, sampleClient("fwd-defaults"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ForwardProtocol != ForwardProtocolUDP {
		t.Errorf("forward_protocol = %q, want udp", got.ForwardProtocol)
	}
	if got.TCPReliabilityEngine != TCPEngineKCP {
		t.Errorf("engine = %q, want kcp", got.TCPReliabilityEngine)
	}
	if got.ForwardEnginePreset != string(PresetBalanced) {
		t.Errorf("preset = %q, want balanced", got.ForwardEnginePreset)
	}
}

func TestRepoForwardTCPRoundTrip(t *testing.T) {
	repo := NewRepo(newTestDB(t))
	ctx := context.Background()
	in := sampleClient("fwd-tcp")
	in.ForwardProtocol = ForwardProtocolTCP
	in.TCPReliabilityEngine = TCPEngineQUIC
	in.ForwardEnginePreset = string(PresetLossy)
	in.ForwardEngineTuning = `{"congestion":"cubic"}`
	got, err := repo.Create(ctx, in)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if got.ForwardProtocol != ForwardProtocolTCP ||
		got.TCPReliabilityEngine != TCPEngineQUIC ||
		got.ForwardEnginePreset != string(PresetLossy) ||
		got.ForwardEngineTuning != `{"congestion":"cubic"}` {
		t.Errorf("tcp forward fields did not round-trip: %+v", got)
	}
}
