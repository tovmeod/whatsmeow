// kavtov-fork (55.1-12): unit tests for the readPump EOF classification (Task 4, committed
// last in the plan). isRoutineEOF is extracted from readPump specifically so this is
// testable without a live websocket.

package socket

import (
	"errors"
	"io"
	"testing"
)

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
