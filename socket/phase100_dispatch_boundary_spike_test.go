package socket

import (
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
// before encryption, goroutine launch, FrameSocket.SendFrame and Conn.Write.
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
			ns := &NoiseSocket{fs: fs, writeKey: pausedKey}
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
				done <- ns.SendFrame(delayed, []byte("local synthetic payload"))
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
			// This fork-only ordering marker is NOT a database revoke.
			t.Log("revocation marker set while live worker is paused after guard")
			close(pausedKey.resume)
			select {
			case err := <-done:
				if candidate != "connection_teardown" && err != nil {
					t.Fatal(err)
				}
				if candidate == "connection_teardown" && err == nil {
					t.Fatal("closed socket unexpectedly wrote")
				}
			case <-ctx.Done():
				t.Fatal("worker did not complete")
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
			t.Logf("candidate=%s frame_admissions_after_marker=%d actual_peer_writes=%d", candidate, ns.writeCounter, writes)
			if candidate == "baseline" {
				if writes != 1 || ns.writeCounter != 1 {
					t.Fatal("baseline counterexample absent")
				}
				return
			}
			if writes != 0 || ns.writeCounter != 0 {
				t.Errorf("mandatory post-check pre-write pause FAIL: new frame admissions=%d actual writes=%d; want both zero", ns.writeCounter, writes)
			}
		})
	}
}
