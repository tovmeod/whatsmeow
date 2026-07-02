// kavtov-fork (D-12): Tests for the bounded ErrMismatchingLTHash retry logic in
// handleAppStateNotification. After N=3 consecutive failures for the same collection,
// FetchAppState(fullSync=true) is called automatically to self-heal the divergence.
// Counter resets on success; disconnect errors do not increment the counter.

package whatsmeow

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waServerSync"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
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

// --- 55.1-10 Task 1: sendAppState / fetchAppState lock-race regression test ---
//
// Root cause (55.1-INVESTIGATION-appstate-connection.md H1): sendAppState's 409-conflict
// branch applied server patches via applyAppStatePatches WITHOUT holding cli.appStateSyncLock,
// while notification-driven fetchAppState holds that same lock across its own call to
// applyAppStatePatches (appstate.go:46-47,84). Concurrent invocations for the same collection
// could interleave writes to the mutation-MAC ledger (storeMACs). The fix wraps sendAppState's
// conflict-application call in an explicit (non-deferred) Lock/Unlock pair.
//
// raceAppStateStore is a fake store.AppStateStore whose write methods detect overlapping
// call windows via an atomic in-flight counter (plus a short sleep to widen the window),
// proving the lock actually serializes the two call sites rather than just compiling.

type raceAppStateStore struct {
	mu      sync.Mutex
	version uint64
	hash    [128]byte

	inFlight        atomic.Int32
	overlapDetected atomic.Bool
}

func (s *raceAppStateStore) enterWrite() {
	if s.inFlight.Add(1) > 1 {
		s.overlapDetected.Store(true)
	}
	time.Sleep(2 * time.Millisecond)
}

func (s *raceAppStateStore) exitWrite() {
	s.inFlight.Add(-1)
}

func (s *raceAppStateStore) PutAppStateVersion(_ context.Context, _ string, version uint64, hash [128]byte) error {
	s.enterWrite()
	defer s.exitWrite()
	s.mu.Lock()
	s.version, s.hash = version, hash
	s.mu.Unlock()
	return nil
}

func (s *raceAppStateStore) GetAppStateVersion(_ context.Context, _ string) (uint64, [128]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.version, s.hash, nil
}

func (s *raceAppStateStore) DeleteAppStateVersion(_ context.Context, _ string) error {
	return nil
}

func (s *raceAppStateStore) PutAppStateMutationMACs(_ context.Context, _ string, _ uint64, _ []store.AppStateMutationMAC) error {
	s.enterWrite()
	defer s.exitWrite()
	return nil
}

func (s *raceAppStateStore) DeleteAppStateMutationMACs(_ context.Context, _ string, _ [][]byte) error {
	s.enterWrite()
	defer s.exitWrite()
	return nil
}

func (s *raceAppStateStore) GetAppStateMutationMAC(_ context.Context, _ string, _ []byte) ([]byte, error) {
	return nil, nil
}

func (s *raceAppStateStore) PutAppStateVersionAndMACs(ctx context.Context, name string, version uint64, hash [128]byte, removedMACs [][]byte, addedMACs []store.AppStateMutationMAC) error {
	if err := s.PutAppStateVersion(ctx, name, version, hash); err != nil {
		return err
	}
	if err := s.DeleteAppStateMutationMACs(ctx, name, removedMACs); err != nil {
		return err
	}
	return s.PutAppStateMutationMACs(ctx, name, version, addedMACs)
}

// raceAppStateKeyStore is a fixed single-key fake store.AppStateSyncKeyStore.
type raceAppStateKeyStore struct {
	keyID []byte
	key   store.AppStateSyncKey
}

func (s *raceAppStateKeyStore) PutAppStateSyncKey(context.Context, []byte, store.AppStateSyncKey) error {
	return nil
}

func (s *raceAppStateKeyStore) GetAppStateSyncKey(_ context.Context, id []byte) (*store.AppStateSyncKey, error) {
	if string(id) != string(s.keyID) {
		return nil, nil
	}
	k := s.key
	return &k, nil
}

func (s *raceAppStateKeyStore) GetLatestAppStateSyncKeyID(context.Context) ([]byte, error) {
	return s.keyID, nil
}

func (s *raceAppStateKeyStore) GetAllAppStateSyncKeys(context.Context) ([]*store.AppStateSyncKey, error) {
	k := s.key
	return []*store.AppStateSyncKey{&k}, nil
}

// newRaceAppStateTestClient builds a minimal *Client backed by raceAppStateStore, wired
// with a real appstate.Processor so applyAppStatePatches exercises the real decode/validate/
// storeMACs path (not a stub).
func newRaceAppStateTestClient(t *testing.T) (*Client, *raceAppStateStore) {
	t.Helper()
	appStateStore := &raceAppStateStore{}
	keyID := []byte("55.1-10-race-key")
	keyStore := &raceAppStateKeyStore{
		keyID: keyID,
		key:   store.AppStateSyncKey{Data: make([]byte, 32)},
	}
	device := &store.Device{
		Log:          waLog.Noop,
		AppState:     appStateStore,
		AppStateKeys: keyStore,
	}
	cli := &Client{
		Store:                    device,
		Log:                      waLog.Noop,
		appStateProc:             appstate.NewProcessor(device, waLog.Noop),
		appStateSyncFailures:     make(map[appstate.WAPatchName]int),
		appStateFullSyncFailures: make(map[appstate.WAPatchName]int),
	}
	return cli, appStateStore
}

// buildRaceTestPatch produces one real, MAC-valid SyncdPatch (a mute action) using the
// real EncodePatch path, so DecodePatches (called inside applyAppStatePatches) exercises
// actual MAC validation and reaches storeMACs — the write path under test. EncodePatch
// never populates the wire-only patch.Version field (the server assigns it and returns it
// in the sync response); it is set here to the same version EncodePatch used internally
// (initial HashState{}.Version + 1) so the decode side's MAC verification matches.
func buildRaceTestPatch(t *testing.T, proc *appstate.Processor, keyID []byte) *waServerSync.SyncdPatch {
	t.Helper()
	target, err := types.ParseJID("15551234567@s.whatsapp.net")
	if err != nil {
		t.Fatalf("ParseJID: %v", err)
	}
	raw, err := proc.EncodePatch(context.Background(), keyID, appstate.HashState{}, appstate.BuildMute(target, true, 0))
	if err != nil {
		t.Fatalf("EncodePatch: %v", err)
	}
	var patch waServerSync.SyncdPatch
	if err := proto.Unmarshal(raw, &patch); err != nil {
		t.Fatalf("unmarshal encoded patch: %v", err)
	}
	patch.Version = &waServerSync.SyncdVersion{Version: proto.Uint64(1)}
	return &patch
}

// TestSendAppStateConflictApplicationSerializesWithFetchAppState exercises the full
// 409-conflict → apply → retry → success sequence (appstate.go:572-592) concurrently with
// fetchAppState's own locked apply (appstate.go:46-47,84) under go test -race. It asserts
// (1) the two applyAppStatePatches invocations never overlap on the MAC-ledger write path,
// and (2) the sequence completes within a timeout — proving no self-deadlock on the
// non-reentrant appStateSyncLock across the recursive-retry / tail-fetch lock re-acquisition.
func TestSendAppStateConflictApplicationSerializesWithFetchAppState(t *testing.T) {
	cli, appStateStore := newRaceAppStateTestClient(t)
	const name = appstate.WAPatchRegularHigh
	keyID, err := cli.Store.AppStateKeys.GetLatestAppStateSyncKeyID(context.Background())
	if err != nil {
		t.Fatalf("GetLatestAppStateSyncKeyID: %v", err)
	}

	fetchPatch := buildRaceTestPatch(t, cli.appStateProc, keyID)
	sendPatch := buildRaceTestPatch(t, cli.appStateProc, keyID)

	done := make(chan struct{})
	go func() {
		defer close(done)
		var wg sync.WaitGroup
		wg.Add(2)

		// Simulates fetchAppState's locked call to applyAppStatePatches.
		go func() {
			defer wg.Done()
			cli.appStateSyncLock.Lock()
			var events []any
			list := &appstate.PatchList{Name: name, Patches: []*waServerSync.SyncdPatch{fetchPatch}}
			_, applyErr := cli.applyAppStatePatches(context.Background(), name, appstate.HashState{}, list, false, &events)
			cli.appStateSyncLock.Unlock()
			if applyErr != nil {
				t.Errorf("fetchAppState-side applyAppStatePatches: %v", applyErr)
			}
		}()

		// Exercises the REAL production code sendAppState calls for its conflict-application
		// region (appstate.go's applyConflictPatches, called from the 409-conflict branch),
		// followed by the recursive-retry / tail-fetch lock re-acquisition it performs after
		// releasing — must not hang on the non-reentrant mutex.
		go func() {
			defer wg.Done()
			var events []any
			list := &appstate.PatchList{Name: name, Patches: []*waServerSync.SyncdPatch{sendPatch}}
			_, applyErr := cli.applyConflictPatches(context.Background(), name, appstate.HashState{}, list, &events)
			if applyErr != nil {
				t.Errorf("sendAppState-side applyConflictPatches: %v", applyErr)
			}
			cli.appStateSyncLock.Lock()
			cli.appStateSyncLock.Unlock()
		}()

		wg.Wait()
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("deadlock: conflict-application / fetch sequence did not complete within timeout")
	}

	if appStateStore.overlapDetected.Load() {
		t.Fatal("overlapping MAC-ledger write windows detected — sendAppState and fetchAppState raced on the same collection")
	}
}
