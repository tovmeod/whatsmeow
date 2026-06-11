// Copyright (c) 2026 Kavtov Platform (Phase 35.2 review fixes)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key_internal_test.go — in-package tests for the WR-04
// coalesced-follower forward-only guard. These need unexported symbols
// (senderKeyRecoveryReader, donorSenderKeyState), so they live in package
// sqlstore. No DB required.

package sqlstore

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
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

	findCalls atomic.Int32
	putCalls  atomic.Int32

	// entered receives one token per findSenderKeyDonor entry (non-blocking
	// send); release, when non-nil, blocks findSenderKeyDonor until closed.
	entered chan struct{}
	release chan struct{}
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
		<-s.release
	}
	return s.donor, nil
}

func (s *stubRecoveryInner) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	s.putCalls.Add(1)
	return nil
}

func (s *stubRecoveryInner) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	return nil, nil
}

func (s *stubRecoveryInner) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	return nil, nil
}

var _ store.SenderKeyStore = (*stubRecoveryInner)(nil)
var _ senderKeyRecoveryReader = (*stubRecoveryInner)(nil)

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
	devCache, err := lru.New[string, []string](16)
	if err != nil {
		t.Fatalf("lru.New dev: %v", err)
	}
	return NewCachedSenderKeyStore(inner, "follower@s.whatsapp.net", byteCache, devCache, sf)
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
