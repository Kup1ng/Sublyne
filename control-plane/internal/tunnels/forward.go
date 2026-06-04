package tunnels

import (
	"encoding/json"
	"fmt"
	"strings"
)

// KcpTuning is the fully-resolved set of KCP knobs the control plane
// hands the dataplane for a tcp-forwarding tunnel. Every field is filled
// from a preset (optionally overridden) before it reaches the wire — the
// dataplane applies them verbatim and never falls back to its own
// defaults, so the panel is the single source of truth.
//
// The values are production-proven. Stream mode, ACK-no-delay, and
// write-delay are NOT operator-tunable (they are always on/on/off
// respectively) — only the knobs below are exposed.
type KcpTuning struct {
	NoDelay  int `json:"nodelay"`  // 0 = normal, 1 = fast (always 1 in every preset)
	Interval int `json:"interval"` // flush interval, ms
	Resend   int `json:"resend"`   // fast-retransmit threshold
	NC       int `json:"nc"`       // 1 = disable congestion control
	SndWnd   int `json:"snd_wnd"`  // send window, packets
	RcvWnd   int `json:"rcv_wnd"`  // recv window, packets
	MTU      int `json:"mtu"`      // KCP segment cap; 0 = derive from tunnel MTU (clamped ≤1280)
}

// kcpPresets are the named baselines. 'balanced' carries the
// production-proven defaults: full 2048-packet window with congestion
// control DISABLED (nc=1) — the combination the predecessor's slow build
// got wrong (it shipped nc=0 + a halved window and throttled throughput).
var kcpPresets = map[ForwardEnginePreset]KcpTuning{
	ForwardEnginePresetBalanced:    {NoDelay: 1, Interval: 20, Resend: 2, NC: 1, SndWnd: 2048, RcvWnd: 2048, MTU: 0},
	ForwardEnginePresetInteractive: {NoDelay: 1, Interval: 10, Resend: 2, NC: 1, SndWnd: 1024, RcvWnd: 1024, MTU: 0},
	ForwardEnginePresetLossy:       {NoDelay: 1, Interval: 20, Resend: 1, NC: 1, SndWnd: 4096, RcvWnd: 4096, MTU: 0},
}

// kcpOverride is the partial-override JSON shape stored in the
// forward_engine_tuning column. Every field is a pointer so an absent
// key keeps the preset value, distinct from an explicit zero.
type kcpOverride struct {
	NoDelay  *int `json:"nodelay,omitempty"`
	Interval *int `json:"interval,omitempty"`
	Resend   *int `json:"resend,omitempty"`
	NC       *int `json:"nc,omitempty"`
	SndWnd   *int `json:"snd_wnd,omitempty"`
	RcvWnd   *int `json:"rcv_wnd,omitempty"`
	MTU      *int `json:"mtu,omitempty"`
}

// ResolveKcpTuning returns the resolved KCP tuning for a preset plus an
// optional JSON override blob (the forward_engine_tuning column). It
// validates ranges and returns a user-facing error on a bad override so
// the API can surface it on the form. An empty / whitespace override
// returns the preset verbatim. An unknown preset falls back to balanced.
func ResolveKcpTuning(preset ForwardEnginePreset, overrideJSON string) (KcpTuning, error) {
	base, ok := kcpPresets[preset]
	if !ok {
		base = kcpPresets[DefaultForwardEnginePreset]
	}
	overrideJSON = strings.TrimSpace(overrideJSON)
	if overrideJSON != "" {
		var ov kcpOverride
		dec := json.NewDecoder(strings.NewReader(overrideJSON))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&ov); err != nil {
			return KcpTuning{}, fmt.Errorf("engine tuning is not a valid override object: %w", err)
		}
		if ov.NoDelay != nil {
			base.NoDelay = *ov.NoDelay
		}
		if ov.Interval != nil {
			base.Interval = *ov.Interval
		}
		if ov.Resend != nil {
			base.Resend = *ov.Resend
		}
		if ov.NC != nil {
			base.NC = *ov.NC
		}
		if ov.SndWnd != nil {
			base.SndWnd = *ov.SndWnd
		}
		if ov.RcvWnd != nil {
			base.RcvWnd = *ov.RcvWnd
		}
		if ov.MTU != nil {
			base.MTU = *ov.MTU
		}
	}
	if err := base.validate(); err != nil {
		return KcpTuning{}, err
	}
	return base, nil
}

// validate bounds every knob to a sane range so a hand-crafted override
// (or an import) can't drive the dataplane into a pathological config.
func (t KcpTuning) validate() error {
	if t.NoDelay < 0 || t.NoDelay > 1 {
		return fmt.Errorf("nodelay must be 0 or 1")
	}
	if t.Interval < 5 || t.Interval > 100 {
		return fmt.Errorf("interval must be between 5 and 100 ms")
	}
	if t.Resend < 0 || t.Resend > 10 {
		return fmt.Errorf("resend must be between 0 and 10")
	}
	if t.NC < 0 || t.NC > 1 {
		return fmt.Errorf("nc must be 0 or 1")
	}
	if t.SndWnd < 64 || t.SndWnd > 8192 {
		return fmt.Errorf("send window must be between 64 and 8192 packets")
	}
	if t.RcvWnd < 64 || t.RcvWnd > 8192 {
		return fmt.Errorf("receive window must be between 64 and 8192 packets")
	}
	// 0 means "derive from the tunnel MTU"; any explicit override must
	// leave room for the KCP header and stay under the safe 1280 ceiling.
	if t.MTU != 0 && (t.MTU < 200 || t.MTU > 1280) {
		return fmt.Errorf("KCP MTU override must be between 200 and 1280 bytes (or 0 to derive it)")
	}
	return nil
}
