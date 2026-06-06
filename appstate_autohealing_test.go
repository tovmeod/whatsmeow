// kavtov-fork (D-12): Tests for the bounded ErrMismatchingLTHash retry logic in
// handleAppStateNotification. After N=3 consecutive failures for the same collection,
// FetchAppState(fullSync=true) is called automatically to self-heal the divergence.
// Counter resets on success; disconnect errors do not increment the counter.

package whatsmeow

import (
	"context"
	"sync"
	"testing"

	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// makeAppStateNode builds a server_sync notification node with one collection child.
func makeAppStateNode(name appstate.WAPatchName) *waBinary.Node {
	return &waBinary.Node{
		Tag:   "notification",
		Attrs: waBinary.Attrs{"type": "server_sync"},
		Content: []waBinary.Node{
			{
				Tag: "collection",
				Attrs: waBinary.Attrs{
					"name":    string(name),
					"version": int64(1),
				},
			},
		},
	}
}

// newAppStateTestClient builds a minimal *Client suitable for D-12 tests.
// It seeds appStateSyncFailures so the map is non-nil (matching NewClient behaviour).
func newAppStateTestClient() *Client {
	return &Client{
		Store:                    &store.Device{Log: waLog.Noop},
		Log:                      waLog.Noop,
		appStateSyncFailures:     make(map[appstate.WAPatchName]int),
		appStateFullSyncFailures: make(map[appstate.WAPatchName]int),
	}
}

// TestAppStateAutoResyncAfterNFailures verifies that after exactly N=3 consecutive
// ErrMismatchingLTHash errors on the same collection, FetchAppState(fullSync=true)
// is called and the failure counter resets to 0.
func TestAppStateAutoResyncAfterNFailures(t *testing.T) {
	const collection appstate.WAPatchName = "regular_high"
	ctx := context.Background()
	node := makeAppStateNode(collection)

	var mu sync.Mutex
	var calls []struct{ fullSync bool }

	cli := newAppStateTestClient()
	cli.fetchAppStateFunc = func(_ context.Context, name appstate.WAPatchName, fullSync, _ bool) error {
		mu.Lock()
		calls = append(calls, struct{ fullSync bool }{fullSync})
		n := len(calls)
		mu.Unlock()
		// Calls 1-3 are incremental fetches returning ErrMismatchingLTHash.
		// Call 4 is the fullSync call triggered at threshold — return nil (success).
		if n <= 3 {
			return appstate.ErrMismatchingLTHash
		}
		return nil
	}

	// First two failures: no fullSync yet.
	cli.handleAppStateNotification(ctx, node)
	cli.handleAppStateNotification(ctx, node)
	mu.Lock()
	gotCalls := len(calls)
	mu.Unlock()
	if gotCalls != 2 {
		t.Fatalf("after 2 failures: spy called %d times, want 2", gotCalls)
	}
	// Verify no fullSync triggered yet.
	mu.Lock()
	for i, c := range calls {
		if c.fullSync {
			t.Fatalf("call %d triggered fullSync before threshold", i+1)
		}
	}
	mu.Unlock()

	// Third failure: hits threshold; fullSync must be triggered in the same call.
	cli.handleAppStateNotification(ctx, node)
	mu.Lock()
	gotCalls = len(calls)
	mu.Unlock()
	// Calls: 3 incremental + 1 fullSync = 4 total.
	if gotCalls != 4 {
		t.Fatalf("after 3rd failure: spy called %d times, want 4 (3 incremental + 1 fullSync)", gotCalls)
	}
	mu.Lock()
	if !calls[3].fullSync {
		t.Fatalf("4th call (fullSync trigger) has fullSync=false, want true")
	}
	mu.Unlock()

	// Counter must have been reset to 0 after the successful fullSync.
	cli.appStateSyncFailuresLock.Lock()
	count := cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 0 {
		t.Fatalf("failure counter = %d after successful fullSync, want 0", count)
	}
}

// TestAppStateCounterResetsOnSuccess verifies that a successful incremental fetch
// resets the per-collection counter. After 2 failures + 1 success, a subsequent
// failure starts the counter at 1 and does NOT trigger fullSync (it needs 3 more).
func TestAppStateCounterResetsOnSuccess(t *testing.T) {
	const collection appstate.WAPatchName = "regular_low"
	ctx := context.Background()
	node := makeAppStateNode(collection)

	var mu sync.Mutex
	var calls []struct{ fullSync bool }

	cli := newAppStateTestClient()
	cli.fetchAppStateFunc = func(_ context.Context, name appstate.WAPatchName, fullSync, _ bool) error {
		mu.Lock()
		calls = append(calls, struct{ fullSync bool }{fullSync})
		n := len(calls)
		mu.Unlock()
		switch n {
		case 1, 2:
			return appstate.ErrMismatchingLTHash // 2 failures
		case 3:
			return nil // success — resets counter
		case 4:
			return appstate.ErrMismatchingLTHash // 1 failure after reset
		default:
			return nil
		}
	}

	// 2 failures.
	cli.handleAppStateNotification(ctx, node)
	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	count := cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 2 {
		t.Fatalf("after 2 failures: counter = %d, want 2", count)
	}

	// 1 success — counter must reset.
	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	count = cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 0 {
		t.Fatalf("after success: counter = %d, want 0", count)
	}

	// 1 failure after reset — counter is 1, no fullSync.
	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	count = cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 1 {
		t.Fatalf("1 failure after reset: counter = %d, want 1", count)
	}
	// Confirm no fullSync was triggered across all 4 calls.
	mu.Lock()
	for i, c := range calls {
		if c.fullSync {
			t.Fatalf("call %d unexpectedly triggered fullSync", i+1)
		}
	}
	mu.Unlock()
}

// TestAppStateDisconnectDoesNotIncrementCounter verifies that ErrIQDisconnected
// and ErrNotConnected cause an early return and do NOT increment the failure counter.
func TestAppStateDisconnectDoesNotIncrementCounter(t *testing.T) {
	const collection appstate.WAPatchName = "critical_block"
	ctx := context.Background()
	node := makeAppStateNode(collection)

	cli := newAppStateTestClient()
	cli.fetchAppStateFunc = func(_ context.Context, _ appstate.WAPatchName, _, _ bool) error {
		return ErrIQDisconnected
	}

	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	count := cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 0 {
		t.Fatalf("ErrIQDisconnected: counter = %d, want 0 (disconnect must not increment counter)", count)
	}

	cli.fetchAppStateFunc = func(_ context.Context, _ appstate.WAPatchName, _, _ bool) error {
		return ErrNotConnected
	}
	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	count = cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if count != 0 {
		t.Fatalf("ErrNotConnected: counter = %d, want 0 (disconnect must not increment counter)", count)
	}
}

// TestAppStateCounterPerCollection verifies that failure counters are per-collection:
// failures on collection A do not affect the counter for collection B.
func TestAppStateCounterPerCollection(t *testing.T) {
	const collA appstate.WAPatchName = "regular_high"
	const collB appstate.WAPatchName = "regular_low"
	ctx := context.Background()

	cli := newAppStateTestClient()
	cli.fetchAppStateFunc = func(_ context.Context, _ appstate.WAPatchName, fullSync, _ bool) error {
		if fullSync {
			return nil
		}
		return appstate.ErrMismatchingLTHash
	}

	nodeA := makeAppStateNode(collA)
	nodeB := makeAppStateNode(collB)

	// 2 failures on A.
	cli.handleAppStateNotification(ctx, nodeA)
	cli.handleAppStateNotification(ctx, nodeA)
	// 1 failure on B.
	cli.handleAppStateNotification(ctx, nodeB)

	cli.appStateSyncFailuresLock.Lock()
	countA := cli.appStateSyncFailures[collA]
	countB := cli.appStateSyncFailures[collB]
	cli.appStateSyncFailuresLock.Unlock()

	if countA != 2 {
		t.Fatalf("collA counter = %d, want 2", countA)
	}
	if countB != 1 {
		t.Fatalf("collB counter = %d, want 1 (cross-collection contamination)", countB)
	}
}

// TestAppStateFullSyncGivesUpAfterMaxFailures verifies the D-12 loop fix: when fullSync
// itself keeps failing with ErrMismatchingLTHash (a permanently diverged collection like
// 972527147052/patch-v67292), the consecutive counter resets after each fullSync attempt
// (back-off to one fullSync per appStateSyncFailureThreshold errors) and fullSync stops
// being triggered entirely after maxAppStateFullSyncFailures attempts.
func TestAppStateFullSyncGivesUpAfterMaxFailures(t *testing.T) {
	const collection appstate.WAPatchName = "regular_high"
	ctx := context.Background()
	node := makeAppStateNode(collection)

	var mu sync.Mutex
	var fullSyncCalls int
	cli := newAppStateTestClient()
	cli.fetchAppStateFunc = func(_ context.Context, _ appstate.WAPatchName, fullSync, _ bool) error {
		// Everything fails — the collection cannot be healed by re-fetching.
		if fullSync {
			mu.Lock()
			fullSyncCalls++
			mu.Unlock()
		}
		return appstate.ErrMismatchingLTHash
	}

	// Drive far more notifications than could ever be needed. Without the cap this would
	// fire fullSync on most of them (the original unbounded loop).
	for i := 0; i < 60; i++ {
		cli.handleAppStateNotification(ctx, node)
	}

	mu.Lock()
	gotFullSync := fullSyncCalls
	mu.Unlock()
	if gotFullSync != maxAppStateFullSyncFailures {
		t.Fatalf("fullSync triggered %d times, want %d (must give up after the cap)", gotFullSync, maxAppStateFullSyncFailures)
	}

	cli.appStateSyncFailuresLock.Lock()
	fullSyncFails := cli.appStateFullSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if fullSyncFails != maxAppStateFullSyncFailures {
		t.Fatalf("appStateFullSyncFailures = %d, want %d", fullSyncFails, maxAppStateFullSyncFailures)
	}

	// A later successful sync must re-arm auto-heal (clears the give-up state).
	cli.fetchAppStateFunc = func(_ context.Context, _ appstate.WAPatchName, _, _ bool) error {
		return nil
	}
	cli.handleAppStateNotification(ctx, node)
	cli.appStateSyncFailuresLock.Lock()
	rearmed := cli.appStateFullSyncFailures[collection]
	count := cli.appStateSyncFailures[collection]
	cli.appStateSyncFailuresLock.Unlock()
	if rearmed != 0 || count != 0 {
		t.Fatalf("after a successful sync: fullSyncFails=%d count=%d, want both 0 (auto-heal must re-arm)", rearmed, count)
	}
}
