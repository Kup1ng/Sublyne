package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"

	"github.com/google/uuid"
)

// Client is a typed wrapper over the dataplane IPC connection.
//
// Concurrency model (mirrors .claude/skills/rust-go-ipc/SKILL.md):
//   - one reader goroutine consumes every frame off the socket and
//     either fans it out to a per-id reply channel (Reply frames) or
//     to subscribers keyed by frame type (event frames);
//   - one writer goroutine drains a bounded command queue and writes
//     to the socket;
//   - public Send(ctx, type, payload) returns the matching Reply
//     after both sides of the round-trip complete, or fails when
//     the context is done.
//
// The Client is created by the supervisor after the dataplane child
// process has bound its socket. Reconnecting after a crash is the
// supervisor's job; the Client is rebuilt afresh each time.
type Client struct {
	conn   net.Conn
	logger *slog.Logger

	writeQ chan Envelope
	stopCh chan struct{}
	wg     sync.WaitGroup

	mu        sync.Mutex
	closed    bool
	closeErr  error
	pending   map[string]chan Envelope
	stateSubs []chan TunnelStateChanged
	statsSubs []chan StatsReport
	readyOnce sync.Once
	ready     chan ReadyPayload
}

// NewClient wraps conn into a typed Client. The caller is responsible
// for the conn lifecycle on failure (the Client closes it on Close()
// or on the read loop returning).
func NewClient(conn net.Conn, logger *slog.Logger) *Client {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Client{
		conn:    conn,
		logger:  logger,
		writeQ:  make(chan Envelope, 256),
		stopCh:  make(chan struct{}),
		pending: make(map[string]chan Envelope),
		ready:   make(chan ReadyPayload, 1),
	}
	c.wg.Add(2)
	go c.readLoop()
	go c.writeLoop()
	return c
}

// closeOnce performs idempotent teardown: record the first error, mark
// closed, close stopCh once, and close the conn so the peer loop and any
// blocked Send callers wake immediately. Safe to call repeatedly.
func (c *Client) closeOnce(err error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if c.closeErr == nil {
		c.closeErr = err
	}
	c.closed = true
	close(c.stopCh)
	c.mu.Unlock()
	_ = c.conn.Close()
}

// Closed returns a channel that is closed when the Client is torn down
// (socket EOF/error or Close()). Receivers unblock once the client is dead.
func (c *Client) Closed() <-chan struct{} {
	return c.stopCh
}

// Close shuts down both loops and closes the underlying connection.
// Pending Send callers receive context.Canceled (if the supplied ctx
// fires) or an "ipc: closed" error.
func (c *Client) Close() error {
	c.closeOnce(nil)
	c.wg.Wait()
	// Drain any still-pending replies with a synthetic error so
	// blocked Send callers wake up.
	c.mu.Lock()
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	for _, ch := range c.stateSubs {
		close(ch)
	}
	c.stateSubs = nil
	for _, ch := range c.statsSubs {
		close(ch)
	}
	c.statsSubs = nil
	c.mu.Unlock()
	return nil
}

// WaitReady blocks until the dataplane has sent its Ready frame or
// ctx fires. Returns the version reported by the dataplane on success.
func (c *Client) WaitReady(ctx context.Context) (ReadyPayload, error) {
	select {
	case r := <-c.ready:
		return r, nil
	case <-ctx.Done():
		return ReadyPayload{}, ctx.Err()
	case <-c.stopCh:
		return ReadyPayload{}, errors.New("ipc: closed before ready")
	}
}

// Send issues one command and returns its Reply. payload is
// JSON-marshalled; a nil payload becomes `{}` per protocol.
func (c *Client) Send(ctx context.Context, ty string, payload any) (ReplyPayload, error) {
	var body json.RawMessage
	if payload == nil {
		body = json.RawMessage("{}")
	} else {
		b, err := json.Marshal(payload)
		if err != nil {
			return ReplyPayload{}, fmt.Errorf("ipc: marshal payload: %w", err)
		}
		body = b
	}
	id := uuid.NewString()
	replyCh := make(chan Envelope, 1)

	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return ReplyPayload{}, errors.New("ipc: client closed")
	}
	c.pending[id] = replyCh
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.pending, id)
		c.mu.Unlock()
	}()

	env := Envelope{Type: ty, ID: id, Payload: body}
	select {
	case c.writeQ <- env:
	case <-ctx.Done():
		return ReplyPayload{}, ctx.Err()
	case <-c.stopCh:
		return ReplyPayload{}, errors.New("ipc: client closed")
	}

	select {
	case env := <-replyCh:
		if env.Type != "Reply" {
			return ReplyPayload{}, fmt.Errorf("ipc: unexpected frame type %q", env.Type)
		}
		var rp ReplyPayload
		if err := json.Unmarshal(env.Payload, &rp); err != nil {
			return ReplyPayload{}, fmt.Errorf("ipc: decode reply: %w", err)
		}
		return rp, nil
	case <-ctx.Done():
		return ReplyPayload{}, ctx.Err()
	case <-c.stopCh:
		return ReplyPayload{}, errors.New("ipc: client closed")
	}
}

// SubscribeStateChanges returns a channel that receives every
// TunnelStateChanged event emitted by the dataplane. The channel is
// closed when the Client closes. Callers must consume promptly —
// slow consumers are dropped (oldest sample is discarded so the
// dashboard always sees the latest).
func (c *Client) SubscribeStateChanges(buffer int) <-chan TunnelStateChanged {
	if buffer < 1 {
		buffer = 16
	}
	ch := make(chan TunnelStateChanged, buffer)
	c.mu.Lock()
	c.stateSubs = append(c.stateSubs, ch)
	c.mu.Unlock()
	return ch
}

// SubscribeStats returns a channel that receives every StatsReport
// event emitted by the dataplane (one every ~5 seconds; PRD §4.7). The
// channel is closed when the Client closes. Like SubscribeStateChanges,
// a slow consumer has its oldest queued sample dropped — the dashboard
// only cares about the latest snapshot.
func (c *Client) SubscribeStats(buffer int) <-chan StatsReport {
	if buffer < 1 {
		buffer = 8
	}
	ch := make(chan StatsReport, buffer)
	c.mu.Lock()
	c.statsSubs = append(c.statsSubs, ch)
	c.mu.Unlock()
	return ch
}

func (c *Client) writeLoop() {
	defer c.wg.Done()
	for {
		select {
		case env, ok := <-c.writeQ:
			if !ok {
				return
			}
			if _, err := WriteFrame(c.conn, env); err != nil {
				c.logger.Warn("ipc: write frame", "err", err)
				c.closeOnce(err)
				return
			}
		case <-c.stopCh:
			return
		}
	}
}

func (c *Client) readLoop() {
	defer c.wg.Done()
	for {
		env, err := ReadFrame(c.conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				c.logger.Debug("ipc: read frame", "err", err)
			}
			c.closeOnce(err)
			return
		}
		c.dispatch(env)
	}
}

func (c *Client) dispatch(env Envelope) {
	switch env.Type {
	case "Reply":
		c.mu.Lock()
		ch, ok := c.pending[env.ID]
		if ok {
			delete(c.pending, env.ID)
		}
		c.mu.Unlock()
		if ok {
			select {
			case ch <- env:
			default:
				c.logger.Debug("ipc: duplicate/unconsumed reply dropped", "id", env.ID)
			}
			return
		}
		c.logger.Debug("ipc: orphan reply", "id", env.ID)
	case "Ready":
		var r ReadyPayload
		if err := json.Unmarshal(env.Payload, &r); err == nil {
			c.readyOnce.Do(func() {
				select {
				case c.ready <- r:
				default:
				}
			})
		}
	case "TunnelStateChanged":
		var e TunnelStateChanged
		if err := json.Unmarshal(env.Payload, &e); err != nil {
			c.logger.Debug("ipc: decode state change", "err", err)
			return
		}
		c.mu.Lock()
		subs := append([]chan TunnelStateChanged(nil), c.stateSubs...)
		c.mu.Unlock()
		for _, ch := range subs {
			select {
			case ch <- e:
			default:
				// Slow consumer — drop the oldest sample and retry.
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- e:
				default:
				}
			}
		}
	case "StatsReport":
		var s StatsReport
		if err := json.Unmarshal(env.Payload, &s); err != nil {
			c.logger.Debug("ipc: decode stats report", "err", err)
			return
		}
		c.mu.Lock()
		subs := append([]chan StatsReport(nil), c.statsSubs...)
		c.mu.Unlock()
		for _, ch := range subs {
			select {
			case ch <- s:
			default:
				// Slow consumer — drop the oldest sample and retry.
				select {
				case <-ch:
				default:
				}
				select {
				case ch <- s:
				default:
				}
			}
		}
	case "LogLine":
		// Phase 12 wires this. For now drop with a debug log.
		c.logger.Debug("ipc: ignored event", "type", env.Type)
	default:
		c.logger.Warn("ipc: unknown event", "type", env.Type)
	}
}
