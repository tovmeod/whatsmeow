package socket

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Gate the upgraded connection's real Write, without a production test hook.
type lifecycleWire struct {
	io.ReadWriteCloser
	entered, release, closed chan struct{}
	enterOnce, closeOnce     sync.Once
	completed                atomic.Int32
	failPartial              bool
}

func (w *lifecycleWire) Write(p []byte) (int, error) {
	w.enterOnce.Do(func() { close(w.entered) })
	select {
	case <-w.release:
	case <-w.closed:
		return 0, io.ErrClosedPipe
	}
	if w.failPartial {
		n, err := w.ReadWriteCloser.Write(p[:len(p)/2])
		if err != nil {
			return n, err
		}
		return n, io.ErrUnexpectedEOF
	}
	n, err := w.ReadWriteCloser.Write(p)
	w.completed.Add(1)
	return n, err
}

func (w *lifecycleWire) Close() error {
	w.closeOnce.Do(func() { close(w.closed) })
	return w.ReadWriteCloser.Close()
}

type lifecycleTransport struct {
	http.RoundTripper
	wire        chan *lifecycleWire
	failPartial bool
}

func (tr *lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := tr.RoundTripper.RoundTrip(r)
	if err == nil && resp.StatusCode == http.StatusSwitchingProtocols {
		w := &lifecycleWire{ReadWriteCloser: resp.Body.(io.ReadWriteCloser), entered: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{}), failPartial: tr.failPartial}
		resp.Body = w
		tr.wire <- w
	}
	return resp, err
}

func lifecycleSocket(t *testing.T, partial bool) (*NoiseSocket, *lifecycleWire, <-chan []byte, <-chan int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	frames, drained := make(chan []byte, 8), make(chan int, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer, err := websocket.Accept(w, r, nil)
		if err != nil {
			drained <- -1
			return
		}
		defer peer.CloseNow()
		count := 0
		for {
			kind, data, err := peer.Read(ctx)
			if err != nil {
				drained <- count
				return
			}
			if kind != websocket.MessageBinary {
				drained <- -1
				return
			}
			count++
			frames <- data
		}
	}))
	tr := &lifecycleTransport{RoundTripper: server.Client().Transport, wire: make(chan *lifecycleWire, 1), failPartial: partial}
	fs := NewFrameSocket(waLog.Noop, &http.Client{Transport: tr})
	fs.URL, fs.HTTPHeaders, fs.Header = "ws"+strings.TrimPrefix(server.URL, "http"), http.Header{}, nil
	if err := fs.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	wire := <-tr.wire
	block, err := aes.NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	ns := &NoiseSocket{fs: fs, writeKey: key, stopConsumer: make(chan struct{})}
	t.Cleanup(func() { fs.Close(0); cancel(); server.Close() })
	return ns, wire, frames, drained
}

func lifecycleAwait[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case result := <-ch:
		return result
	case <-time.After(3 * time.Second):
		t.Fatal("fixture did not complete")
		var zero T
		return zero
	}
}

func lifecycleRetired(t *testing.T, ns *NoiseSocket) {
	t.Helper()
	if !ns.destroyed.Load() || ns.IsConnected() {
		t.Fatal("nonce-consuming error did not retire the exact session")
	}
	select {
	case <-ns.stopConsumer:
	default:
		t.Fatal("consumer not stopped")
	}
	count := ns.writeCounter
	if err := ns.SendFrame(context.Background(), []byte("must not reuse")); err == nil {
		t.Fatal("retired session accepted another send")
	}
	if ns.writeCounter != count {
		t.Fatal("retired session consumed another nonce")
	}
}

// Hold the connection-close cancellation callback after Done is signalled.
// This arranges a delayed callback, not a clock or global quiescence proof.
type lifecycleDelayedCancel struct {
	context.Context
	done, callbacks chan struct{}
	cancelled       atomic.Bool
}

func (c *lifecycleDelayedCancel) Done() <-chan struct{} { return c.done }
func (c *lifecycleDelayedCancel) Err() error {
	if c.cancelled.Load() {
		return context.Canceled
	}
	return nil
}
func (c *lifecycleDelayedCancel) AfterFunc(fn func()) func() bool {
	var stopped atomic.Bool
	go func() {
		<-c.done
		<-c.callbacks
		if !stopped.Load() {
			fn()
		}
	}()
	return func() bool { return !stopped.Swap(true) }
}

func TestNoiseSocketWriteLifecycle(t *testing.T) {
	t.Run("delayed_callback_positive_completion", func(t *testing.T) {
		ns, wire, frames, drained := lifecycleSocket(t, false)
		ctx := &lifecycleDelayedCancel{Context: context.Background(), done: make(chan struct{}), callbacks: make(chan struct{})}
		defer close(ctx.callbacks)
		done := make(chan error, 1)
		go func() { done <- ns.SendFrame(ctx, []byte("completed")) }()
		lifecycleAwait(t, wire.entered)
		ctx.cancelled.Store(true)
		close(ctx.done)
		select {
		case err := <-done:
			t.Fatalf("returned while physical write is blocked: %v", err)
		case <-time.After(20 * time.Millisecond):
		}
		close(wire.release)
		if err := lifecycleAwait(t, done); err != nil {
			t.Fatalf("completed physical write must report success: %v", err)
		}
		lifecycleAwait(t, frames)
		if wire.completed.Load() != 1 || ns.destroyed.Load() {
			t.Fatal("successful write not positively completed")
		}
		ns.fs.Close(0)
		if got := lifecycleAwait(t, drained); got != 1 {
			t.Fatalf("actual peer writes=%d", got)
		}
	})
	t.Run("cancel_after_guard", func(t *testing.T) {
		ns, wire, _, drained := lifecycleSocket(t, false)
		key := &phase100PausedCipher{AEAD: ns.writeKey, paused: make(chan struct{}), resume: make(chan struct{})}
		ns.writeKey = key
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- ns.SendFrame(ctx, []byte("cancelled")) }()
		lifecycleAwait(t, key.paused)
		cancel()
		close(key.resume)
		if err := lifecycleAwait(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("want cancellation, got %v", err)
		}
		lifecycleRetired(t, ns)
		if ns.writeCounter != 1 {
			t.Fatal("nonce must advance exactly once")
		}
		if got := lifecycleAwait(t, drained); got != 0 || wire.completed.Load() != 0 {
			t.Fatalf("actual peer writes=%d completed=%d", got, wire.completed.Load())
		}
	})
	t.Run("cancel_during_physical_write", func(t *testing.T) {
		ns, wire, _, drained := lifecycleSocket(t, false)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- ns.SendFrame(ctx, []byte("blocked")) }()
		lifecycleAwait(t, wire.entered)
		cancel()
		if err := lifecycleAwait(t, done); !errors.Is(err, context.Canceled) {
			t.Fatalf("want cancellation, got %v", err)
		}
		lifecycleRetired(t, ns)
		if got := lifecycleAwait(t, drained); got != 0 {
			t.Fatalf("peer writes=%d", got)
		}
	})
	t.Run("partial_write_failure", func(t *testing.T) {
		ns, wire, _, drained := lifecycleSocket(t, true)
		close(wire.release)
		if err := ns.SendFrame(context.Background(), []byte("partial")); err == nil {
			t.Fatal("partial write reported success")
		}
		lifecycleRetired(t, ns)
		if ns.writeCounter != 1 {
			t.Fatal("failed nonce was decremented or reused")
		}
		if got := lifecycleAwait(t, drained); got != 0 {
			t.Fatalf("complete peer messages=%d", got)
		}
	})
	t.Run("serialization_and_positive_completion", func(t *testing.T) {
		ns, wire, frames, drained := lifecycleSocket(t, false)
		first, second := make(chan error, 1), make(chan error, 1)
		go func() { first <- ns.SendFrame(context.Background(), []byte("first")) }()
		lifecycleAwait(t, wire.entered)
		go func() { second <- ns.SendFrame(context.Background(), []byte("second")) }()
		select {
		case <-first:
			t.Fatal("returned before physical write")
		case <-second:
			t.Fatal("second send passed blocked write")
		case <-time.After(20 * time.Millisecond):
		}
		close(wire.release)
		if err := lifecycleAwait(t, first); err != nil {
			t.Fatal(err)
		}
		if err := lifecycleAwait(t, second); err != nil {
			t.Fatal(err)
		}
		for i, plaintext := range []string{"first", "second"} {
			frame := lifecycleAwait(t, frames)
			want := ns.writeKey.Seal(nil, generateIV(uint32(i)), []byte(plaintext), nil)
			if !bytes.Equal(frame, append([]byte{0, 0, byte(len(want))}, want...)) {
				t.Fatalf("wire frame %d changed or reordered", i)
			}
		}
		if wire.completed.Load() != 2 || ns.writeCounter != 2 || ns.destroyed.Load() {
			t.Fatal("positive completion/counter/session mismatch")
		}
		ns.fs.Close(0)
		if got := lifecycleAwait(t, drained); got != 2 {
			t.Fatalf("actual peer writes=%d", got)
		}
	})
}
