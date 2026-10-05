// kavtov-fork (55.1-12): unit tests for the readPump EOF classification (Task 4, committed
// last in the plan). isRoutineEOF is extracted from readPump specifically so this is
// testable without a live websocket.

package socket

import (
	"bytes"
	"context"
	"errors"
	"io"
	"testing"
)

func TestFrameSocketSendFrameContext(t *testing.T) {
	ns, wire, frames, drained := lifecycleSocket(t, false)
	close(wire.release)
	ns.fs.Header = []byte("header")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ns.fs.sendFrame(ctx, []byte("cancelled")); !errors.Is(err, context.Canceled) {
		t.Fatalf("original operation context lost: %v", err)
	}
	if wire.completed.Load() != 0 || !ns.IsConnected() {
		t.Fatal("pre-cancelled Frame operation wrote or retired a nonce-free session")
	}
	// Keep the public handshake API and one-time header byte compatibility.
	if err := ns.fs.SendFrame([]byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := ns.fs.SendFrame([]byte("two")); err != nil {
		t.Fatal(err)
	}
	if got := lifecycleAwait(t, frames); !bytes.Equal(got, []byte("header\x00\x00\x03one")) {
		t.Fatalf("first frame=%x", got)
	}
	if got := lifecycleAwait(t, frames); !bytes.Equal(got, []byte("\x00\x00\x03two")) {
		t.Fatalf("second frame=%x", got)
	}
	ns.Stop(true, true)
	if err := ns.SendFrame(context.Background(), []byte("closed")); err == nil {
		t.Fatal("stopped Noise session accepted a send")
	}
	if got := lifecycleAwait(t, drained); got != 2 {
		t.Fatalf("actual peer writes=%d", got)
	}
}

func TestFrameSocket_IsRoutineEOF_EOFWithAutoReconnectEnabled(t *testing.T) {
	if !isRoutineEOF(io.EOF, func() bool { return true }) {
		t.Fatal("want io.EOF with auto-reconnect enabled classified as routine")
	}
}

func TestFrameSocket_IsRoutineEOF_WrappedEOFWithAutoReconnectEnabled(t *testing.T) {
	wrapped := errors.New("wrapper: " + io.EOF.Error())
	if isRoutineEOF(wrapped, func() bool { return true }) {
		t.Fatal("want a same-text-but-not-actually-wrapped error to NOT match errors.Is(io.EOF)")
	}
	properlyWrapped := errWrap{io.EOF}
	if !isRoutineEOF(properlyWrapped, func() bool { return true }) {
		t.Fatal("want a properly wrapped io.EOF to be classified as routine")
	}
}

type errWrap struct{ err error }

func (e errWrap) Error() string { return "wrapped: " + e.err.Error() }
func (e errWrap) Unwrap() error { return e.err }

func TestFrameSocket_IsRoutineEOF_NonEOFStaysNotRoutine(t *testing.T) {
	if isRoutineEOF(errors.New("connection reset by peer"), func() bool { return true }) {
		t.Fatal("want a non-EOF error to stay NOT routine (real failures must stay loud)")
	}
}

func TestFrameSocket_IsRoutineEOF_EOFWithAutoReconnectDisabledStaysNotRoutine(t *testing.T) {
	if isRoutineEOF(io.EOF, func() bool { return false }) {
		t.Fatal("want io.EOF with auto-reconnect disabled to stay NOT routine")
	}
}

func TestFrameSocket_IsRoutineEOF_NilGetterStaysNotRoutine(t *testing.T) {
	if isRoutineEOF(io.EOF, nil) {
		t.Fatal("want io.EOF with no AutoReconnectEnabled getter set (nil) to stay NOT routine")
	}
}
