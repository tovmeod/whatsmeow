// kavtov-fork (55.1-12): unit tests for the connection-lifecycle fix bar --
//
// Task 1 — device_removed store deletion runs off the handler-queue goroutine:
//   - handleStreamError returns before a slow Store.Delete unblocks.
//   - the Delete error is still logged, once the backgrounded goroutine completes.
//
// Test style: bare &Client{} + captured waLog.Logger, matching receipt_replay_test.go.

package whatsmeow

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"go.mau.fi/util/exsync"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
)

// blockingDeviceContainer is a store.DeviceContainer stub whose DeleteDevice blocks until
// unblock is closed, letting Task 1's test prove handleStreamError doesn't wait on it.
type blockingDeviceContainer struct {
	unblock <-chan struct{}
	called  chan struct{}
	callsMu sync.Mutex
	calls   int
	err     error
}

func (b *blockingDeviceContainer) PutDevice(ctx context.Context, d *store.Device) error {
	return nil
}

func (b *blockingDeviceContainer) DeleteDevice(ctx context.Context, d *store.Device) error {
	b.callsMu.Lock()
	b.calls++
	b.callsMu.Unlock()
	close(b.called)
	<-b.unblock
	return b.err
}

func newDeviceRemovedNode() *waBinary.Node {
	return &waBinary.Node{
		Tag:   "stream:error",
		Attrs: waBinary.Attrs{"code": "401"},
		Content: []waBinary.Node{
			{Tag: "conflict", Attrs: waBinary.Attrs{"type": "device_removed"}},
		},
	}
}

func TestDeviceRemoved_HandleStreamErrorReturnsBeforeStoreDeleteCompletes(t *testing.T) {
	cli, log := newReplayClient()
	cli.expectedDisconnect = exsync.NewEvent()
	unblock := make(chan struct{})
	deleteErr := errors.New("boom: delete failed")
	fake := &blockingDeviceContainer{unblock: unblock, called: make(chan struct{}), err: deleteErr}
	cli.Store = &store.Device{Container: fake}

	done := make(chan struct{})
	go func() {
		cli.handleStreamError(context.Background(), newDeviceRemovedNode())
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("handleStreamError blocked waiting on Store.Delete")
	}

	select {
	case <-fake.called:
	case <-time.After(2 * time.Second):
		t.Fatal("Store.Delete (via DeleteDevice) was never called")
	}

	if log.warnCount() != 0 {
		t.Fatalf("want no Warnf before the backgrounded Delete completes, got %d: %v", log.warnCount(), log.warns)
	}

	close(unblock)

	deadline := time.Now().Add(2 * time.Second)
	for log.warnCount() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("want the Delete error to be logged once the backgrounded goroutine completes")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if log.warnCount() != 1 {
		t.Fatalf("want exactly 1 Warnf for the Delete error, got %d: %v", log.warnCount(), log.warns)
	}
}
