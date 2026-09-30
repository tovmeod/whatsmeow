// Copyright (c) 2026 Kavtov Platform (Phase 35.2 review fixes)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key_internal_test.go — in-package tests for the WR-04
// coalesced-follower forward-only guard and the WR-05 skipped-key union.
// These need unexported symbols (senderKeyRecoveryReader, donorSenderKeyState,
// unionSkippedKeys, unionSenderKeyStructures), so they live in package
// sqlstore. No DB required.

package sqlstore

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"golang.org/x/sync/singleflight"

	"go.mau.fi/whatsmeow/store"
)

// stubRecoveryInner satisfies store.SenderKeyStore AND the unexported
// senderKeyRecoveryReader, returning a fixed donor from findSenderKeyDonor.
// It lets a test hand TryInlineRecovery a donor whose iteration is AHEAD of
// the caller's targetIter — exactly what a coalesced singleflight follower
// receives when the leader's targetIter was higher (the WR-04 scenario);
// the direct findSenderKeyDonor scan filters those out, so a DB-backed test
// cannot produce this deterministically.
type stubRecoveryInner struct {
	donor *donorSenderKeyState
	// donorForTarget lets tests model the real donor query's target-iteration
	// domain while preserving the fixed donor path used by older tests.
	donorForTarget func(targetIter uint32) *donorSenderKeyState

	// existing, when non-nil, is returned by GetSenderKey — lets a test seed
	// the recovering account's pre-merge structure (a PackFlat blob) for the
	// D-12 merge-cap assertions.
	existing []byte

	findCalls atomic.Int32
	putCalls  atomic.Int32

	// putMu guards lastPut (PutSenderKey is called from multiple goroutines in
	// the coalescing tests).
	putMu   sync.Mutex
	lastPut []byte

	// entered receives one token per findSenderKeyDonor entry (non-blocking
	// send); release, when non-nil, blocks findSenderKeyDonor until closed.
	entered chan struct{}
	release chan struct{}
	findErr error
}

func (s *stubRecoveryInner) findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID, targetIter uint32) (*donorSenderKeyState, error) {
	s.findCalls.Add(1)
	if s.entered != nil {
		select {
		case s.entered <- struct{}{}:
		default:
		}
	}
	if s.release != nil {
		select {
		case <-s.release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.findErr != nil {
		return nil, s.findErr
	}
	if s.donorForTarget != nil {
		return s.donorForTarget(targetIter), nil
	}
	return s.donor, nil
}

func (s *stubRecoveryInner) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	s.putCalls.Add(1)
	s.putMu.Lock()
	s.lastPut = session
	s.putMu.Unlock()
	return nil
}

// lastPutBlob returns the most recent blob handed to PutSenderKey.
func (s *stubRecoveryInner) lastPutBlob() []byte {
	s.putMu.Lock()
	defer s.putMu.Unlock()
	return s.lastPut
}

func (s *stubRecoveryInner) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	return s.existing, nil
}

func (s *stubRecoveryInner) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	return nil, nil
}

var _ store.SenderKeyStore = (*stubRecoveryInner)(nil)
var _ senderKeyRecoveryReader = (*stubRecoveryInner)(nil)

type flatRecoveryRows struct {
	blobs [][]byte
	index int
}

func (r *flatRecoveryRows) Next() bool { return r.index < len(r.blobs) }
func (r *flatRecoveryRows) Scan(dest ...any) error {
	*(dest[0].(*string)) = "donor"
	*(dest[1].(*[]byte)) = r.blobs[r.index]
	r.index++
	return nil
}
func (r *flatRecoveryRows) Err() error { return nil }

// An uncertain scan must be distinguishable from successful absence even
// though the public recovery API still reports no donor without an error.
func TestNoDonorCacheMalformed(t *testing.T) {
	for _, blob := range [][]byte{nil, []byte("malformed-flat")} {
		_, complete, err := scanFlatRows(&flatRecoveryRows{blobs: [][]byte{blob}}, 1, 5, nil)
		if complete || err != nil {
			t.Fatal("uncertain all-negative scan must carry non-cacheable evidence")
		}
	}
}

type uncertainRecoveryInner struct {
	*stubRecoveryInner
	blobs [][]byte
}

func (s *uncertainRecoveryInner) findSenderKeyDonorResult(ctx context.Context, group, sender string, keyID, iteration uint32) (*donorSenderKeyState, bool, error) {
	s.findCalls.Add(1)
	return scanFlatRows(&flatRecoveryRows{blobs: s.blobs}, keyID, iteration, nil)
}

func TestNoDonorCacheMalformedRescansAndValidSibling(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	for _, bad := range [][]byte{nil, []byte("bad-flat")} {
		stub := &stubRecoveryInner{}
		c := newStubCachedStore(t, stub, nil)
		uncertain := &uncertainRecoveryInner{stubRecoveryInner: stub, blobs: [][]byte{bad}}
		c.inner = uncertain
		for i := 0; i < 2; i++ {
			_, ok, err := c.TryInlineRecovery(context.Background(), "malformed", "s_1:0", "s_1", 7, 10)
			if ok || err != nil {
				t.Fatalf("uncertain miss: ok=%v err=%v", ok, err)
			}
		}
		if stub.findCalls.Load() != 2 {
			t.Fatal("uncertain absence was cached")
		}
		valid, packed := store.PackFlat(&groupRecord.SenderKeyStructure{SenderKeyStates: []*groupRecord.SenderKeyStateStructure{{
			KeyID: 7, SenderChainKey: &ratchet.SenderChainKeyStructure{Iteration: 5, ChainKey: make([]byte, 32)}, SigningKeyPublic: stubDonor(7, 5).SigningKeyPublic,
		}}})
		if !packed {
			t.Fatal("valid donor fixture failed to pack")
		}
		uncertain.blobs = [][]byte{bad, valid}
		_, ok, err := c.TryInlineRecovery(context.Background(), "malformed", "s_1:0", "s_1", 7, 10)
		if !ok || err != nil || stub.putCalls.Load() != 1 {
			t.Fatalf("valid sibling recovery: ok=%v err=%v", ok, err)
		}
	}
}

func assertDonorIdle(t *testing.T) {
	t.Helper()
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	if len(donorWaves) != 0 || len(donorFlights) != 0 {
		t.Fatalf("leaked waves=%d flights=%d", len(donorWaves), len(donorFlights))
	}
}

func waitDonorParticipants(t *testing.T, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		noDonorCacheMu.Lock()
		n := 0
		for _, f := range donorFlights {
			n += f.participants
		}
		noDonorCacheMu.Unlock()
		if n == count {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("participants never admitted")
}

func TestInlineRecoveryCanceledFollowerAndLeader(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	stub := &stubRecoveryInner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c := newStubCachedStore(t, stub, nil)
	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	defer cancelLeader()
	leader := make(chan error, 1)
	go func() { _, _, err := c.TryInlineRecovery(leaderCtx, "cancel", "s:0", "s", 1, 5); leader <- err }()
	<-stub.entered
	followerCtx, cancelFollower := context.WithCancel(context.Background())
	defer cancelFollower()
	follower := make(chan error, 1)
	go func() { _, _, err := c.TryInlineRecovery(followerCtx, "cancel", "s:0", "s", 1, 5); follower <- err }()
	waitDonorParticipants(t, 2)
	cancelFollower()
	if !errors.Is(<-follower, context.Canceled) {
		t.Fatal("follower cancellation lost")
	}
	if stub.findCalls.Load() != 1 {
		t.Fatal("follower did not coalesce")
	}
	cancelLeader()
	if !errors.Is(<-leader, context.Canceled) {
		t.Fatal("leader cancellation lost")
	}
	assertDonorIdle(t)
	if noDonorCache.Len() != 0 {
		t.Fatal("canceled work published absence")
	}
	_, _, err := c.TryInlineRecovery(leaderCtx, "cancel", "s:0", "s", 1, 5)
	if !errors.Is(err, context.Canceled) || stub.findCalls.Load() != 1 {
		t.Fatal("pre-canceled call started work")
	}
}

func TestInlineRecoveryLiveFollowerAfterLeaderCancel(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	stub := &stubRecoveryInner{entered: make(chan struct{}, 2), release: make(chan struct{})}
	c := newStubCachedStore(t, stub, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	leader := make(chan error, 1)
	go func() { _, _, err := c.TryInlineRecovery(ctx, "live", "s:0", "s", 1, 5); leader <- err }()
	<-stub.entered
	follower := make(chan error, 1)
	go func() {
		_, _, err := c.TryInlineRecovery(context.Background(), "live", "s:0", "s", 1, 5)
		follower <- err
	}()
	waitDonorParticipants(t, 2)
	cancel()
	if !errors.Is(<-leader, context.Canceled) {
		t.Fatal("leader error lost")
	}
	<-stub.entered // follower performs independent uncached retry
	close(stub.release)
	if err := <-follower; err != nil {
		t.Fatal(err)
	}
	assertDonorIdle(t)
	if noDonorCache.Len() != 0 || stub.findCalls.Load() != 2 {
		t.Fatal("canceled flight retry publication")
	}
}

func TestNoDonorCacheBoundedOverflow(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	donorWorkCapacity = 1
	stub := &stubRecoveryInner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	c := newStubCachedStore(t, stub, nil)
	done := make(chan error, 1)
	go func() { _, _, err := c.TryInlineRecovery(context.Background(), "held", "s:0", "s", 1, 5); done <- err }()
	<-stub.entered
	other := &stubRecoveryInner{donor: stubDonor(1, 2)}
	o := newStubCachedStore(t, other, nil)
	_, ok, err := o.TryInlineRecovery(context.Background(), "overflow", "s:0", "s", 1, 5)
	if !ok || err != nil {
		t.Fatalf("overflow positive failed: %v", err)
	}
	other.donor = nil
	_, _, _ = o.TryInlineRecovery(context.Background(), "overflow-miss", "s:0", "s", 1, 5)
	if noDonorCache.Len() != 0 || noDonorCacheOverflow.Load() != 2 {
		t.Fatal("overflow published or uncounted")
	}
	noDonorCacheMu.Lock()
	if len(donorFlights) != 1 || len(donorWaves) != 1 {
		t.Error("admission cap exceeded")
	}
	noDonorCacheMu.Unlock()
	close(stub.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	assertDonorIdle(t)
	if noDonorCacheCapacity != 10000 {
		t.Fatal("production cap changed")
	}
}

func TestNoDonorCacheABAFixedDeadline(t *testing.T) {
	for _, action := range []string{"expiry", "eviction", "invalidate", "teardown"} {
		t.Run(action, func(t *testing.T) {
			resetNoDonorCacheWithCapacityForTest(1)
			t.Cleanup(resetNoDonorCacheForTest)
			var clock atomic.Int64
			clock.Store(time.Now().UnixNano())
			donorClock = func() time.Time { return time.Unix(0, clock.Load()) }
			entered, release := make(chan struct{}), make(chan struct{})
			stub := &stubRecoveryInner{donorForTarget: func(i uint32) *donorSenderKeyState {
				if i == 5 {
					close(entered)
					<-release
				}
				return nil
			}}
			c := newStubCachedStore(t, stub, nil)
			done := make(chan error, 1)
			go func() { _, _, err := c.TryInlineRecovery(context.Background(), "aba", "s:0", "s", 1, 5); done <- err }()
			<-entered
			_, _, _ = c.TryInlineRecovery(context.Background(), "aba", "s:0", "s", 1, 10)
			switch action {
			case "expiry":
				clock.Add(int64(noDonorCacheTTL))
				_, _, _ = c.TryInlineRecovery(context.Background(), "aba", "s:0", "s", 1, 20)
			case "eviction":
				_, _, _ = c.TryInlineRecovery(context.Background(), "evict", "s:0", "s", 1, 10)
			case "invalidate":
				notifyDonorKeys(stub, "aba", "s", []uint32{1})
			case "teardown":
				clearDonorUniverse(stub)
			}
			close(release)
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if getNoDonorCacheEntry(c.donorKey("aba", "s", 1), 100, donorClock()) {
				t.Fatal("old completion republished absence")
			}
			assertDonorIdle(t)
			before := stub.findCalls.Load()
			_, _, _ = c.TryInlineRecovery(context.Background(), "aba", "s:0", "s", 1, 30)
			if stub.findCalls.Load() != before+1 {
				t.Fatal("fresh wave did not rescan")
			}
			assertDonorIdle(t)
		})
	}
}

func TestNoDonorCacheSQLErrorNotAbsence(t *testing.T) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	failure := errors.New("SQL scan failed")
	stub := &stubRecoveryInner{findErr: failure}
	c := newStubCachedStore(t, stub, nil)
	for i := 0; i < 2; i++ {
		_, _, err := c.TryInlineRecovery(context.Background(), "err", "s:0", "s", 1, 5)
		if !errors.Is(err, failure) {
			t.Fatal(err)
		}
	}
	if stub.findCalls.Load() != 2 || noDonorCache.Len() != 0 {
		t.Fatal("SQL error became absence")
	}
	assertDonorIdle(t)
}

// stubDonor builds a donorSenderKeyState with valid field lengths
// (chainKey=32, signingPub=33) so PackFlat accepts the install on the
// leader path.
func stubDonor(keyID, iter uint32) *donorSenderKeyState {
	pub := make([]byte, 33)
	pub[0] = 0x05
	return &donorSenderKeyState{
		OurJID:           "donor@s.whatsapp.net",
		KeyID:            keyID,
		Iteration:        iter,
		ChainKey:         make([]byte, 32),
		SigningKeyPublic: pub,
	}
}

func newStubCachedStore(t *testing.T, inner *stubRecoveryInner, sf *singleflight.Group) *CachedSenderKeyStore {
	t.Helper()
	byteCache, err := lru.New[string, []byte](16)
	if err != nil {
		t.Fatalf("lru.New byte: %v", err)
	}
	devCache, err := NewSenderKeyDeviceCache(16)
	if err != nil {
		t.Fatalf("lru.New dev: %v", err)
	}
	return NewCachedSenderKeyStore(inner, "follower@s.whatsapp.net", byteCache, devCache, sf)
}

func TestInlineRecoveryDifferentIterationsDoNotCoalesce(t *testing.T) {
	stub := &stubRecoveryInner{
		donorForTarget: func(targetIter uint32) *donorSenderKeyState {
			if targetIter >= 10 {
				return stubDonor(11, 10)
			}
			return nil
		},
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	var sf singleflight.Group
	cs := newStubCachedStore(t, stub, &sf)

	const (
		group      = "iteration-domain@g.us"
		targetID   = "777_1:0"
		senderBare = "777_1"
		keyID      = uint32(11)
	)

	var wg sync.WaitGroup
	var lowerOK, higherOK bool
	var lowerErr, higherErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, lowerOK, lowerErr = cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 5)
	}()
	select {
	case <-stub.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("target-5 scan never entered findSenderKeyDonor")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, higherOK, higherErr = cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 10)
	}()
	select {
	case <-stub.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("target-10 scan was coalesced with target-5 scan")
	}
	close(stub.release)
	wg.Wait()

	if lowerErr != nil || higherErr != nil {
		t.Fatalf("errors: target-5=%v target-10=%v", lowerErr, higherErr)
	}
	if lowerOK {
		t.Error("target-5: want ok=false after its nil donor scan")
	}
	if !higherOK {
		t.Error("target-10: want ok=true after its eligible donor scan")
	}
	if got := stub.findCalls.Load(); got != 2 {
		t.Errorf("findSenderKeyDonor calls = %d, want 2 distinct target-iteration scans", got)
	}
}

// TestInlineRecoveryForwardOnlyFollowerGuard asserts the WR-04 re-check in
// isolation: a donor whose Iteration is past the caller's targetIter (the
// coalesced-follower shape) must yield ok=false with NO install — the
// per-account downgrade guard does not cover this when the caller has no
// existing state for the KeyID.
func TestInlineRecoveryForwardOnlyFollowerGuard(t *testing.T) {
	stub := &stubRecoveryInner{donor: stubDonor(7, 50)}
	cs := newStubCachedStore(t, stub, nil)

	// Caller's target (20) is BEHIND the donor (50): forward-only must reject.
	donorJID, ok, err := cs.TryInlineRecovery(context.Background(), "wr04group@g.us", "555_1:0", "555_1", 7, 20)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if ok {
		t.Error("WR-04: want ok=false for a donor ahead of the caller's target, got true")
	}
	if donorJID != "" {
		t.Errorf("WR-04: want empty donorJID, got %q", donorJID)
	}
	if got := stub.putCalls.Load(); got != 0 {
		t.Errorf("WR-04: want 0 installs (no PutSenderKey), got %d", got)
	}

	// Sanity: the same donor IS applicable when the target is ahead of it.
	_, ok, err = cs.TryInlineRecovery(context.Background(), "wr04group@g.us", "555_1:0", "555_1", 7, 100)
	if err != nil {
		t.Fatalf("TryInlineRecovery (applicable arm): %v", err)
	}
	if !ok {
		t.Error("applicable arm: want ok=true for donor iter=50 <= target=100")
	}
	if got := stub.putCalls.Load(); got != 1 {
		t.Errorf("applicable arm: want exactly 1 install, got %d", got)
	}
}

// TestInlineRecoveryCoalescedFollowerForwardOnly is the two-caller scenario:
// a LEADER with targetIter=100 and a FOLLOWER with targetIter=20 share the
// singleflight donor scan (key excludes targetIter). The shared donor sits at
// iteration 50 — applicable for the leader, AHEAD of the follower's target.
// The follower must get ok=false and no install; the leader installs once.
//
// The stub blocks the leader's scan until the follower has been launched, so
// the follower either coalesces onto the in-flight call (the intended WR-04
// shape) or — if it misses the in-flight window — becomes its own leader and
// receives the same forward-of-target donor; the assertion holds either way.
func TestInlineRecoveryCoalescedFollowerForwardOnly(t *testing.T) {
	stub := &stubRecoveryInner{
		donor:   stubDonor(9, 50),
		entered: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	var sf singleflight.Group
	cs := newStubCachedStore(t, stub, &sf)

	const (
		group      = "wr04coalesce@g.us"
		targetID   = "666_1:0"
		senderBare = "666_1"
		keyID      = uint32(9)
	)

	var wg sync.WaitGroup
	var leaderOK, followerOK bool
	var leaderErr, followerErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, leaderOK, leaderErr = cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 100)
	}()

	// Wait until the leader is inside the donor scan (holding the singleflight
	// in-flight call), then launch the follower with a LOWER target.
	select {
	case <-stub.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("leader never entered findSenderKeyDonor")
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		_, followerOK, followerErr = cs.TryInlineRecovery(context.Background(), group, targetID, senderBare, keyID, 20)
	}()

	// Best-effort: give the follower a moment to park in singleflight.Do; if it
	// has not entered yet it runs its own scan after release — same donor, same
	// assertion (see doc comment).
	time.Sleep(20 * time.Millisecond)
	close(stub.release)
	wg.Wait()

	if leaderErr != nil || followerErr != nil {
		t.Fatalf("errors: leader=%v follower=%v", leaderErr, followerErr)
	}
	if !leaderOK {
		t.Error("leader (target=100): want ok=true for shared donor iter=50")
	}
	if followerOK {
		t.Error("WR-04: follower (target=20) got ok=true for a shared donor at iter=50 — " +
			"forward-only violated for the coalesced follower")
	}
	if got := stub.putCalls.Load(); got != 1 {
		t.Errorf("want exactly 1 install (leader only), got %d", got)
	}
}

// --- WR-05: skipped-key union ---

func mkSkipped(iter uint32, tag byte) *ratchet.SenderMessageKeyStructure {
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = tag + byte(i)
		}
		return b
	}
	return &ratchet.SenderMessageKeyStructure{
		Iteration: iter,
		IV:        fill(16),
		CipherKey: fill(32),
		Seed:      fill(32),
	}
}

func skippedIters(keys []*ratchet.SenderMessageKeyStructure) []uint32 {
	out := make([]uint32, 0, len(keys))
	for _, k := range keys {
		if k != nil {
			out = append(out, k.Iteration)
		}
	}
	return out
}

// TestUnionSkippedKeys asserts the WR-05 merge rule: loser entries whose
// iteration is not covered by the winner are KEPT; winner entries win on
// iteration collision.
func TestUnionSkippedKeys(t *testing.T) {
	existing := []*ratchet.SenderMessageKeyStructure{mkSkipped(3, 0x10), mkSkipped(5, 0x20), mkSkipped(7, 0x30)}
	donor := []*ratchet.SenderMessageKeyStructure{mkSkipped(7, 0x40), mkSkipped(9, 0x50)}

	merged := unionSkippedKeys(existing, donor)

	got := skippedIters(merged)
	want := []uint32{3, 5, 7, 9}
	if len(got) != len(want) {
		t.Fatalf("merged iterations = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("merged iterations = %v, want %v", got, want)
		}
	}
	// Collision at iter 7: the donor (winner) entry must win.
	for _, k := range merged {
		if k.Iteration == 7 && k.IV[0] != 0x40 {
			t.Errorf("iter-7 collision: want donor entry (tag 0x40), got tag %#x", k.IV[0])
		}
	}

	// Empty loser: winner returned unchanged.
	if out := unionSkippedKeys(nil, donor); len(out) != len(donor) {
		t.Errorf("nil loser: want winner unchanged (%d entries), got %d", len(donor), len(out))
	}
}

// TestUnionSenderKeyStructuresKeepsLoserSkippedKeys asserts the WR-05 fix in
// unionSenderKeyStructures: when the secondary (DB) view supersedes the
// primary (cache) view for the same KeyID, the primary state's skipped keys
// are unioned into the chosen state instead of being dropped.
func TestUnionSenderKeyStructuresKeepsLoserSkippedKeys(t *testing.T) {
	mkState := func(keyID, iter uint32, keys ...*ratchet.SenderMessageKeyStructure) *groupRecord.SenderKeyStateStructure {
		pub := make([]byte, 33)
		pub[0] = 0x05
		return &groupRecord.SenderKeyStateStructure{
			KeyID: keyID,
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: iter,
				ChainKey:  make([]byte, 32),
			},
			SigningKeyPublic: pub,
			Keys:             keys,
		}
	}

	// Primary (cache view): K@10 with skipped keys at 3 and 5.
	primary := &groupRecord.SenderKeyStructure{SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
		mkState(42, 10, mkSkipped(3, 0x10), mkSkipped(5, 0x20)),
	}}
	// Secondary (DB view): same KeyID at a higher iteration with its own key at 8.
	secondaryState := mkState(42, 30, mkSkipped(8, 0x60))
	secondary := &groupRecord.SenderKeyStructure{SenderKeyStates: []*groupRecord.SenderKeyStateStructure{secondaryState}}

	merged := unionSenderKeyStructures(primary, secondary)
	if merged == nil || len(merged.SenderKeyStates) != 1 {
		t.Fatalf("merged = %+v, want exactly one state", merged)
	}
	st := merged.SenderKeyStates[0]
	if st.SenderChainKey.Iteration != 30 {
		t.Errorf("chosen iteration = %d, want 30 (secondary supersedes)", st.SenderChainKey.Iteration)
	}
	got := skippedIters(st.Keys)
	want := map[uint32]bool{3: true, 5: true, 8: true}
	if len(got) != 3 {
		t.Fatalf("merged Keys iterations = %v, want {3,5,8}", got)
	}
	for _, it := range got {
		if !want[it] {
			t.Fatalf("merged Keys iterations = %v, want {3,5,8}", got)
		}
	}
	// The handed-in secondary state must NOT have been mutated in place.
	if len(secondaryState.Keys) != 1 {
		t.Errorf("secondary state mutated in place: Keys=%v", skippedIters(secondaryState.Keys))
	}
}

// --- QUICK-SKCAP-01: libsignal-limit caps on the fork's merge paths ---

// mkCapState builds a SenderKeyStateStructure with PackFlat-valid field lengths
// (chainKey=32, signingPub=33) for the cap tests.
func mkCapState(keyID, iter uint32, keys ...*ratchet.SenderMessageKeyStructure) *groupRecord.SenderKeyStateStructure {
	pub := make([]byte, 33)
	pub[0] = 0x05
	return &groupRecord.SenderKeyStateStructure{
		KeyID: keyID,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: iter,
			ChainKey:  make([]byte, 32),
		},
		SigningKeyPublic: pub,
		Keys:             keys,
	}
}

// TestCapSkippedKeys asserts the cap helper in isolation: over-cap inputs keep
// exactly the maxSenderKeyMessageKeys HIGHEST iterations, deterministically;
// under-cap inputs are returned unchanged.
func TestCapSkippedKeys(t *testing.T) {
	// Over-cap: cap+5 entries in a deterministic shuffled order.
	// 7919 is prime and coprime with n, so (i*7919)%n is a permutation of 0..n-1.
	const n = maxSenderKeyMessageKeys + 5
	shuffled := make([]*ratchet.SenderMessageKeyStructure, 0, n)
	for i := 0; i < n; i++ {
		shuffled = append(shuffled, mkSkipped(uint32((i*7919)%n), byte(i)))
	}

	capped := capSkippedKeys(shuffled)
	if len(capped) != maxSenderKeyMessageKeys {
		t.Fatalf("len(capped) = %d, want %d", len(capped), maxSenderKeyMessageKeys)
	}
	// Survivors must be exactly the cap-many HIGHEST iterations (5..n-1).
	seen := make(map[uint32]bool, len(capped))
	for _, k := range capped {
		if k.Iteration < 5 {
			t.Fatalf("iteration %d survived; want only the %d highest (>= 5)", k.Iteration, maxSenderKeyMessageKeys)
		}
		if seen[k.Iteration] {
			t.Fatalf("duplicate iteration %d in capped output", k.Iteration)
		}
		seen[k.Iteration] = true
	}

	// Determinism: same input → identical output sequence.
	capped2 := capSkippedKeys(shuffled)
	for i := range capped {
		if capped[i].Iteration != capped2[i].Iteration {
			t.Fatalf("non-deterministic truncation: run1[%d]=%d run2[%d]=%d",
				i, capped[i].Iteration, i, capped2[i].Iteration)
		}
	}

	// Under-cap: returned unchanged (same length, same entries, same order).
	small := []*ratchet.SenderMessageKeyStructure{mkSkipped(3, 0x10), mkSkipped(1, 0x20)}
	out := capSkippedKeys(small)
	if len(out) != len(small) {
		t.Fatalf("under-cap: len = %d, want %d", len(out), len(small))
	}
	for i := range small {
		if out[i] != small[i] {
			t.Fatalf("under-cap input modified at index %d", i)
		}
	}
}

// TestUnionSkippedKeysCapped asserts that unionSkippedKeys output is bounded at
// maxSenderKeyMessageKeys when loser+winner exceed the cap: the winner still
// wins iteration collisions BEFORE truncation, and the survivors are the
// highest iterations of the merged set. (The existing TestUnionSkippedKeys
// covers the below-cap WR-05 semantics.)
func TestUnionSkippedKeysCapped(t *testing.T) {
	// loser: iterations 0..1499 (the recovering account's own keys).
	loser := make([]*ratchet.SenderMessageKeyStructure, 0, 1500)
	for i := uint32(0); i < 1500; i++ {
		loser = append(loser, mkSkipped(i, 0x10))
	}
	// winner: iterations 1200..2199 (donor) — collisions at 1200..1499.
	winner := make([]*ratchet.SenderMessageKeyStructure, 0, 1000)
	for i := uint32(1200); i < 2200; i++ {
		winner = append(winner, mkSkipped(i, 0x40))
	}

	merged := unionSkippedKeys(loser, winner)
	if len(merged) != maxSenderKeyMessageKeys {
		t.Fatalf("len(merged) = %d, want cap %d", len(merged), maxSenderKeyMessageKeys)
	}
	// Pre-cap union = loser 0..1199 + winner 1200..2199 = 2200 entries; the cap
	// keeps the 2000 highest → iterations 200..2199.
	for _, k := range merged {
		if k.Iteration < 200 {
			t.Fatalf("iteration %d survived; want only the %d highest (>= 200)", k.Iteration, maxSenderKeyMessageKeys)
		}
		if k.Iteration >= 1200 && k.Iteration < 1500 && k.IV[0] != 0x40 {
			t.Fatalf("collision at iteration %d: want winner entry (tag 0x40), got tag %#x", k.Iteration, k.IV[0])
		}
	}
}

// TestCapSenderKeyStates asserts order-preserving prefix truncation at
// maxSenderKeyStates with index 0 (active/donor) preserved as-is.
func TestCapSenderKeyStates(t *testing.T) {
	states := make([]*groupRecord.SenderKeyStateStructure, 0, 7)
	for i := uint32(0); i < 7; i++ {
		states = append(states, mkCapState(100+i, 10*i))
	}

	capped := capSenderKeyStates(states)
	if len(capped) != maxSenderKeyStates {
		t.Fatalf("len(capped) = %d, want %d", len(capped), maxSenderKeyStates)
	}
	if capped[0] != states[0] {
		t.Error("index 0 (active/donor) must be the SAME state pointer")
	}
	for i := 0; i < maxSenderKeyStates; i++ {
		if capped[i] != states[i] {
			t.Errorf("survivor[%d].KeyID = %d, want input[%d].KeyID = %d (order-preserving prefix)",
				i, capped[i].KeyID, i, states[i].KeyID)
		}
	}

	// Under-cap: same slice back, unchanged.
	small := states[:3]
	out := capSenderKeyStates(small)
	if len(out) != 3 || out[0] != small[0] || out[2] != small[2] {
		t.Error("under-cap input must be returned unchanged")
	}
}

// TestUnionSenderKeyStructuresCapped asserts the unionSenderKeyStructures
// output is bounded at maxSenderKeyStates when primary(3) + secondary(4
// disjoint) merge, with primary order preserved (most-recent-first kept).
func TestUnionSenderKeyStructuresCapped(t *testing.T) {
	primary := &groupRecord.SenderKeyStructure{SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
		mkCapState(1, 10), mkCapState(2, 20), mkCapState(3, 30),
	}}
	secondary := &groupRecord.SenderKeyStructure{SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
		mkCapState(4, 40), mkCapState(5, 50), mkCapState(6, 60), mkCapState(7, 70),
	}}

	merged := unionSenderKeyStructures(primary, secondary)
	if merged == nil {
		t.Fatal("merged = nil")
	}
	if len(merged.SenderKeyStates) != maxSenderKeyStates {
		t.Fatalf("merged states = %d, want %d", len(merged.SenderKeyStates), maxSenderKeyStates)
	}
	wantKeyIDs := []uint32{1, 2, 3, 4, 5}
	for i, st := range merged.SenderKeyStates {
		if st.KeyID != wantKeyIDs[i] {
			t.Fatalf("merged[%d].KeyID = %d, want %d", i, st.KeyID, wantKeyIDs[i])
		}
	}
}

// TestInlineRecoveryMergeCapsStatesAndDonorKeys is the D-12 end-to-end cap
// assertion via TryInlineRecovery with the stub harness: an existing structure
// with 6 foreign-KeyID states plus a donor whose own skipped-key list is
// over-cap must install a structure with exactly maxSenderKeyStates states,
// the donor KeyID at index 0, the first 4 (= most recent) foreign states kept,
// and the donor state's Keys bounded at maxSenderKeyMessageKeys.
//
// Install observation: the stub harness has no flusher and no
// PutManySenderKeys, so PutSenderKeyStructureRecovery falls through to
// inner.PutSenderKey with the PackFlat blob — captured by the stub and
// UnpackFlat'd here.
func TestInlineRecoveryMergeCapsStatesAndDonorKeys(t *testing.T) {
	// Existing structure: 6 foreign-KeyID states (none == donor KeyID 7), so
	// the iteration-downgrade guard passes and every state survives the merge
	// loop. PackFlat accepts 6 states (its limit is 255).
	existingStates := make([]*groupRecord.SenderKeyStateStructure, 0, 6)
	for i := uint32(0); i < 6; i++ {
		existingStates = append(existingStates, mkCapState(100+i, 10))
	}
	existingBlob, packOK := store.PackFlat(&groupRecord.SenderKeyStructure{SenderKeyStates: existingStates})
	if !packOK {
		t.Fatal("PackFlat(existing) rejected the seed structure")
	}

	// Fat donor: over-cap skipped-key list (iterations 0..cap+99).
	donor := stubDonor(7, 50)
	for i := uint32(0); i < maxSenderKeyMessageKeys+100; i++ {
		donor.SkippedKeys = append(donor.SkippedKeys, mkSkipped(i, 0x70))
	}

	stub := &stubRecoveryInner{donor: donor, existing: existingBlob}
	cs := newStubCachedStore(t, stub, nil)

	_, recovered, err := cs.TryInlineRecovery(context.Background(), "skcapgroup@g.us", "777_1:0", "777_1", 7, 100)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if !recovered {
		t.Fatal("want ok=true (donor iter=50 <= target=100, all existing KeyIDs foreign)")
	}

	blob := stub.lastPutBlob()
	if blob == nil {
		t.Fatal("no blob reached PutSenderKey")
	}
	installed, err := store.UnpackFlat(blob)
	if err != nil {
		t.Fatalf("installed blob is not flat-codec: %v", err)
	}
	if len(installed.SenderKeyStates) != maxSenderKeyStates {
		t.Fatalf("installed states = %d, want %d", len(installed.SenderKeyStates), maxSenderKeyStates)
	}
	if got := installed.SenderKeyStates[0].KeyID; got != 7 {
		t.Fatalf("state[0].KeyID = %d, want donor KeyID 7 (CR-04 invariant)", got)
	}
	// Survivors after the donor = the FIRST 4 foreign states (most recent).
	for i := 1; i < maxSenderKeyStates; i++ {
		want := uint32(100 + i - 1)
		if got := installed.SenderKeyStates[i].KeyID; got != want {
			t.Fatalf("state[%d].KeyID = %d, want %d", i, got, want)
		}
	}
	// Donor skipped keys capped at the libsignal limit, highest iterations kept
	// (0..2099 input → survivors 100..2099).
	keys := installed.SenderKeyStates[0].Keys
	if len(keys) != maxSenderKeyMessageKeys {
		t.Fatalf("donor state keys = %d, want %d", len(keys), maxSenderKeyMessageKeys)
	}
	for _, k := range keys {
		if k.Iteration < 100 {
			t.Fatalf("skipped-key iteration %d survived; want the %d highest kept (>= 100)",
				k.Iteration, maxSenderKeyMessageKeys)
		}
	}
}

// mkStructState builds a *SenderKeyStateStructure with valid field sizes so
// PackFlat accepts it. chainKey=32B, signingPub=33B (prefix 0x05), no skipped keys.
func mkStructState(keyID, iter uint32) *groupRecord.SenderKeyStateStructure {
	pub := make([]byte, 33)
	pub[0] = 0x05
	return &groupRecord.SenderKeyStateStructure{
		KeyID: keyID,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: iter,
			ChainKey:  make([]byte, 32),
		},
		SigningKeyPublic: pub,
	}
}

// TestPutSenderKeyStructureRecoveryBackwardOnlyGate is the TDD RED/GREEN gate
// for Risk-b (Phase 38.4-03 Task 2). It asserts three behaviors of
// PutSenderKeyStructureRecovery's flat-path ordering gate:
//
//  1. STALE DONOR REJECTED: a donor whose iteration does NOT strictly advance the
//     cached position for that KeyID is rejected (installed=false, no write).
//  2. FORWARD DONOR ACCEPTED: a donor that strictly advances the KeyID iteration
//     is installed (installed=true).
//  3. FOREIGN KEYIDS PRESERVED: a recovery write does not reject on equal-
//     iteration matches for non-donor KeyIDs (D-12 preserved-foreign rule).
//
// RED proof: removing the ported gate from PutSenderKeyStructureRecovery causes
// Case 1 to return installed=true (wrong — stale donor lands in the cache/flusher).
// The GREEN state is gated on the real gate ported in Task 2.
func TestPutSenderKeyStructureRecoveryBackwardOnlyGate(t *testing.T) {
	const (
		group    = "riskbgroup@g.us"
		user     = "555_1:0"
		donorKID = uint32(7)
	)

	// --- Case 1: STALE DONOR REJECTED ---
	// Existing cached state: keyID=7, iter=50.
	existingBlob, packOK := store.PackFlat(&groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{mkStructState(donorKID, 50)},
	})
	if !packOK {
		t.Fatal("PackFlat(existing) rejected the seed structure")
	}
	stub := &stubRecoveryInner{existing: existingBlob}
	cs := newStubCachedStore(t, stub, nil)
	// Seed the cache with the existing blob (mirrors what GetSenderKeyStructure
	// returns from cache after a previous write).
	cs.cache.Add(cs.key(group, user), existingBlob)

	// Donor: keyID=7, iter=40 — does NOT strictly advance (40 < 50).
	staleDonorStruct := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{mkStructState(donorKID, 40)},
	}
	installed, err := cs.PutSenderKeyStructureRecovery(context.Background(), group, user, staleDonorStruct, donorKID)
	if err != nil {
		t.Fatalf("PutSenderKeyStructureRecovery (stale): %v", err)
	}
	if installed {
		t.Error("STALE DONOR: want installed=false (donor iter=40 does not advance cached iter=50), got true (gate missing or broken)")
	}
	if stub.putCalls.Load() != 0 {
		t.Error("STALE DONOR: want 0 writes to inner store, got non-zero (gate missing or broken)")
	}

	// --- Case 2: FORWARD DONOR ACCEPTED ---
	// Fresh donor: keyID=7, iter=60 — strictly advances.
	stub2 := &stubRecoveryInner{existing: existingBlob}
	cs2 := newStubCachedStore(t, stub2, nil)
	cs2.cache.Add(cs2.key(group, user), existingBlob)

	freshDonorStruct := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{mkStructState(donorKID, 60)},
	}
	installed2, err := cs2.PutSenderKeyStructureRecovery(context.Background(), group, user, freshDonorStruct, donorKID)
	if err != nil {
		t.Fatalf("PutSenderKeyStructureRecovery (fresh): %v", err)
	}
	if !installed2 {
		t.Error("FORWARD DONOR: want installed=true (donor iter=60 strictly advances cached iter=50), got false")
	}

	// --- Case 3: FOREIGN KEYIDS PRESERVED ---
	// Cached state has TWO keyIDs: donor keyID=7 at iter=50, and a foreign keyID=8
	// at iter=30. The incoming structure has keyID=7 at iter=60 (donor) and
	// keyID=8 at iter=30 (equal iteration — preserved foreign state). Must ACCEPT.
	existingMultiBlob, packOK := store.PackFlat(&groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			mkStructState(donorKID, 50),
			mkStructState(8, 30), // foreign KeyID
		},
	})
	if !packOK {
		t.Fatal("PackFlat(existingMulti) rejected the seed structure")
	}
	stub3 := &stubRecoveryInner{existing: existingMultiBlob}
	cs3 := newStubCachedStore(t, stub3, nil)
	cs3.cache.Add(cs3.key(group, user), existingMultiBlob)

	// Incoming: donor keyID=7 iter=60 (strictly advances) + foreign keyID=8
	// iter=30 (equal — preserved foreign state, must not reject).
	foreignPreservedStruct := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			mkStructState(donorKID, 60), // donor: advances
			mkStructState(8, 30),        // foreign: equal — accept (D-12 preserved-foreign rule)
		},
	}
	installed3, err := cs3.PutSenderKeyStructureRecovery(context.Background(), group, user, foreignPreservedStruct, donorKID)
	if err != nil {
		t.Fatalf("PutSenderKeyStructureRecovery (foreign): %v", err)
	}
	if !installed3 {
		t.Error("FOREIGN PRESERVED: want installed=true (donor advances, foreign equal), got false (D-12 violated)")
	}
}
