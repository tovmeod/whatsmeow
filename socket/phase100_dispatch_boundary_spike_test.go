package socket

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Test-only AEAD wrapper pauses inside the real SendFrame after ctx.Err,
// before encryption, synchronous FrameSocket.sendFrame and Conn.Write.
// It delegates to real AES-GCM; no copied send implementation or source overlay.
type phase100PausedCipher struct {
	cipher.AEAD
	paused chan struct{}
	resume chan struct{}
}

func (p *phase100PausedCipher) Seal(dst, nonce, plaintext, extra []byte) []byte {
	close(p.paused)
	<-p.resume
	return p.AEAD.Seal(dst, nonce, plaintext, extra)
}

// Models delayed timer notification only. Deadline changes under a mutex;
// actual CPU/elapsed clock suspension is NOT established by this context.
type phase100DelayedContext struct {
	context.Context
	mu       sync.Mutex
	deadline time.Time
}

func (c *phase100DelayedContext) Deadline() (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.deadline, true
}

func TestPhase100DispatchBoundarySpike(t *testing.T) {
	t.Run("normal_send_positive_control", func(t *testing.T) {
		ns, wire, frames, drained := lifecycleSocket(t, false)
		first, second := make(chan error, 1), make(chan error, 1)
		go func() { first <- ns.SendFrame(context.Background(), []byte("first control")) }()
		lifecycleAwait(t, wire.entered)
		go func() { second <- ns.SendFrame(context.Background(), []byte("second control")) }()
		select {
		case <-first:
			t.Fatal("first returned before physical completion")
		case <-second:
			t.Fatal("second bypassed write serialization")
		case <-time.After(20 * time.Millisecond):
		}
		close(wire.release)
		if err := lifecycleAwait(t, first); err != nil {
			t.Fatal(err)
		}
		if err := lifecycleAwait(t, second); err != nil {
			t.Fatal(err)
		}
		for i, plaintext := range []string{"first control", "second control"} {
			frame := lifecycleAwait(t, frames)
			want := ns.writeKey.Seal(nil, generateIV(uint32(i)), []byte(plaintext), nil)
			if !bytes.Equal(frame, append([]byte{0, 0, byte(len(want))}, want...)) {
				t.Fatal("normal peer frames changed or reordered")
			}
		}
		if wire.completed.Load() != 2 {
			t.Fatal("physical write not complete on return")
		}
		ns.fs.Close(0)
		if writes := lifecycleAwait(t, drained); writes != 2 {
			t.Fatalf("observer positive control: writes=%d", writes)
		}
	})
	for _, candidate := range []string{"baseline", "absolute_snapshot", "connection_teardown"} {
		t.Run(candidate, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			peerResult := make(chan int, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				peer, err := websocket.Accept(w, r, nil)
				if err != nil {
					peerResult <- -1
					return
				}
				defer peer.CloseNow()
				kind, data, err := peer.Read(ctx)
				if err != nil {
					peerResult <- 0
					return
				}
				if kind != websocket.MessageBinary || len(data) < 3 {
					peerResult <- -1
					return
				}
				peerResult <- 1
				// Keep the peer alive until the client completes its write.
				_, _, _ = peer.Read(ctx)
			}))
			defer server.Close()
			fs := NewFrameSocket(waLog.Noop, server.Client())
			fs.URL = "ws" + strings.TrimPrefix(server.URL, "http")
			fs.HTTPHeaders = http.Header{}
			fs.Header = nil
			if err := fs.Connect(ctx); err != nil {
				t.Fatal(err)
			}
			defer fs.Close(0)
			block, err := aes.NewCipher(make([]byte, 32))
			if err != nil {
				t.Fatal(err)
			}
			key, err := cipher.NewGCM(block)
			if err != nil {
				t.Fatal(err)
			}
			pausedKey := &phase100PausedCipher{AEAD: key, paused: make(chan struct{}), resume: make(chan struct{})}
			defer func() {
				select {
				case <-pausedKey.resume:
				default:
					close(pausedKey.resume)
				}
			}()
			ns := &NoiseSocket{fs: fs, writeKey: pausedKey, stopConsumer: make(chan struct{})}
			operation, stopOperation := context.WithCancel(context.Background())
			defer stopOperation()
			delayed := &phase100DelayedContext{Context: context.Background(), deadline: time.Now().Add(time.Hour)}
			done := make(chan error, 1)
			go func() {
				if candidate == "absolute_snapshot" {
					deadline, _ := delayed.Deadline()
					if !time.Now().Before(deadline) {
						done <- context.DeadlineExceeded
						return
					}
				}
				var sendCtx context.Context = operation
				if candidate == "absolute_snapshot" {
					sendCtx = delayed
				}
				done <- ns.SendFrame(sendCtx, []byte("local synthetic payload"))
			}()
			select {
			case <-pausedKey.paused:
			case <-ctx.Done():
				t.Fatal("missing post-check pre-write pause")
			}
			if ns.writeCounter != 0 {
				t.Fatal("a frame was admitted before the pause")
			}
			select {
			case got := <-peerResult:
				t.Fatalf("premature peer observation %d", got)
			default:
			}
			delayed.mu.Lock()
			delayed.deadline = time.Now().Add(-time.Second)
			delayed.mu.Unlock()
			if candidate == "connection_teardown" {
				fs.Close(0)
			}
			stopOperation()
			// This fork-only ordering marker is NOT a database revoke.
			t.Log("revocation marker set while live worker is paused after guard")
			close(pausedKey.resume)
			var sendErr error
			select {
			case sendErr = <-done:
			case <-ctx.Done():
				t.Fatal("worker did not complete")
			}
			if sendErr != nil {
				lifecycleRetired(t, ns)
			} else if candidate != "absolute_snapshot" {
				t.Fatal("cancelled/closed operation unexpectedly succeeded")
			}
			var writes int
			select {
			case writes = <-peerResult:
			case <-ctx.Done():
				t.Fatal("missing actual peer observation")
			}
			if writes < 0 {
				t.Fatal("peer fixture failed")
			}
			wantWrites := 0
			if sendErr == nil {
				wantWrites = 1
			}
			t.Logf("bounded library candidate=%s frame_admissions=%d actual_peer_writes=%d positive_write_completion=%v global_protocol=FAIL", candidate, ns.writeCounter, writes, sendErr == nil)
			if writes != wantWrites || ns.writeCounter != 1 {
				t.Fatalf("physical completion mismatch: admissions=%d writes=%d error=%v", ns.writeCounter, writes, sendErr)
			}
			// A delayed timer permits a positively completed write, never a
			// cancellation ACK. Marker is no database revoke. Reconnect, prepared
			// retry, exact-owner, clock, admin/reaper, pool and Ride locks are unproved.
		})
	}
}
