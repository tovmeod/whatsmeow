// kavtov-fork (55.1-12): unit tests for the connection-lifecycle fix bar --
//
// Task 1 — device_removed store deletion runs off the handler-queue goroutine:
//   - handleStreamError returns before a slow Store.Delete unblocks.
//   - the Delete error is still logged, once the backgrounded goroutine completes.
//
// Task 2 — WA-cadence keepalive miss forces an immediate reconnect (no 3-minute tolerance):
//   - forceKeepAliveReconnect increments the observability counter and clears
//     expectedDisconnect (so a subsequent autoReconnect isn't short-circuited).
//   - KeepAliveResponseDeadline matches WA Web's deadSocketTime (20s).
//
// Task 3 — xmlstreamend and 503 are counted, verified-recovery lifecycle (not new teardown
// calls -- see the handleXMLStreamEnd doc comment for why, sourced from wa_protocol):
//   - both increment the shared connectionLifecycleEvents counter exactly once.
//   - isExpectedDisconnect suppresses both (no counter bump, no log).
//   - the 503 case no longer warns ("assuming...").
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

// --- Task 2: WA-cadence keepalive miss ------------------------------------------------------

func TestKeepAlive_ResponseDeadlineMatchesWADeadSocketTime(t *testing.T) {
	if KeepAliveResponseDeadline != 20*time.Second {
		t.Fatalf("want KeepAliveResponseDeadline=20s (WA Web deadSocketTime), got %v", KeepAliveResponseDeadline)
	}
}

func TestKeepAlive_ForceReconnectIncrementsCounterAndClearsExpectedDisconnect(t *testing.T) {
	cli, _ := newReplayClient()
	cli.Store = &store.Device{}
	cli.expectedDisconnect = exsync.NewEvent()
	cli.EnableAutoReconnect = true

	before := keepAliveForcedReconnects.Load()
	cli.forceKeepAliveReconnect(context.Background())
	after := keepAliveForcedReconnects.Load()

	if after != before+1 {
		t.Fatalf("want forced-reconnect counter to increment by 1, got %d -> %d", before, after)
	}
	if cli.isExpectedDisconnect() {
		t.Fatal("want expectedDisconnect cleared after forceKeepAliveReconnect (so autoReconnect proceeds)")
	}
}

// --- Task 3: xmlstreamend + 503 -------------------------------------------------------------

func TestConnectionLifecycle_XMLStreamEndCountedAndNotWarn(t *testing.T) {
	cli, log := newReplayClient()
	cli.expectedDisconnect = exsync.NewEvent()

	before := connectionLifecycleEvents.Load()
	cli.handleXMLStreamEnd()

	if got := connectionLifecycleEvents.Load(); got != before+1 {
		t.Fatalf("want lifecycle counter to increment by 1, got %d -> %d", before, got)
	}
	if log.warnCount() != 0 {
		t.Fatalf("want no Warnf for a handled xmlstreamend, got %d: %v", log.warnCount(), log.warns)
	}
}

func TestConnectionLifecycle_XMLStreamEndSuppressedWhenExpected(t *testing.T) {
	cli, _ := newReplayClient()
	cli.expectedDisconnect = exsync.NewEvent()
	cli.expectedDisconnect.Set()

	before := connectionLifecycleEvents.Load()
	cli.handleXMLStreamEnd()

	if got := connectionLifecycleEvents.Load(); got != before {
		t.Fatalf("want no counter increment when disconnect was expected, got %d -> %d", before, got)
	}
}

func TestConnectionLifecycle_503CountedAndNotWarn(t *testing.T) {
	cli, log := newReplayClient()
	cli.expectedDisconnect = exsync.NewEvent()

	before := connectionLifecycleEvents.Load()
	node := &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}}
	cli.handleStreamError(context.Background(), node)

	if got := connectionLifecycleEvents.Load(); got != before+1 {
		t.Fatalf("want lifecycle counter to increment by 1, got %d -> %d", before, got)
	}
	if log.warnCount() != 0 {
		t.Fatalf("want no Warnf for 503 (verified recovery, not assumed), got %d: %v", log.warnCount(), log.warns)
	}
}

func TestConnectionLifecycle_503SuppressedWhenExpected(t *testing.T) {
	cli, _ := newReplayClient()
	cli.expectedDisconnect = exsync.NewEvent()
	cli.expectedDisconnect.Set()

	before := connectionLifecycleEvents.Load()
	node := &waBinary.Node{Tag: "stream:error", Attrs: waBinary.Attrs{"code": "503"}}
	cli.handleStreamError(context.Background(), node)

	if got := connectionLifecycleEvents.Load(); got != before {
		t.Fatalf("want no counter increment when disconnect was expected, got %d -> %d", before, got)
	}
}
