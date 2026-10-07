// kavtov-fork (55.1-12): unit tests for the readPump EOF classification (Task 4, committed
// last in the plan). isRoutineEOF is extracted from readPump specifically so this is
// testable without a live websocket.

package socket

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"

	waLog "go.mau.fi/whatsmeow/util/log"
)

func TestFrameSocketProcessDataFragmented(t *testing.T) {
	payloads := [][]byte{[]byte("four"), []byte("following"), {}, []byte("last")}
	var stream []byte
	for _, payload := range payloads {
		length := len(payload)
		stream = append(stream, byte(length>>16), byte(length>>8), byte(length))
		stream = append(stream, payload...)
	}

	cases := []struct {
		name   string
		chunks [][]byte
	}{
		{name: "complete_frames", chunks: [][]byte{stream}},
		{name: "empty_chunks", chunks: [][]byte{nil, stream, nil}},
	}
	// Include every header/payload split and continuation carrying the next
	// frame. In particular, prefix + two bytes of a four-byte payload used
	// to record an offset of five and panic on the continuation.
	for split := 1; split < len(stream); split++ {
		cases = append(cases, struct {
			name   string
			chunks [][]byte
		}{fmt.Sprintf("split_%d", split), [][]byte{stream[:split], stream[split:]}})
	}
	var singleBytes [][]byte
	for i := range stream {
		singleBytes = append(singleBytes, stream[i:i+1])
	}
	cases = append(cases, struct {
		name   string
		chunks [][]byte
	}{"byte_at_a_time", singleBytes})

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs := &FrameSocket{log: waLog.Noop, Frames: make(chan []byte, len(payloads)+1)}
			for _, chunk := range tc.chunks {
				fs.processData(chunk)
			}
			if got := len(fs.Frames); got != len(payloads) {
				t.Fatalf("completed frames=%d, want %d", got, len(payloads))
			}
			for i, want := range payloads {
				if got := <-fs.Frames; !bytes.Equal(got, want) {
					t.Fatalf("frame %d=%x, want %x", i, got, want)
				}
			}
			if fs.incoming != nil || fs.partialHeader != nil || fs.incomingLength != 0 || fs.receivedLength != 0 {
				t.Fatal("completed stream retained partial frame state")
			}
		})
	}
}

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
