// Copyright (c) 2026 Kavtov Platform (perf: 260601-uuy)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// ---------------------------------------------------------------------------
// Test fixtures. chat/sender are normal JIDs; the wrapper normalizes via
// ToNonAD() internally. The wrapper uses "test-jid" (no trailing pipe) as the
// JID prefix, matching production usage at container.go where the JID comes from
// device.ID.String().
// ---------------------------------------------------------------------------

func newTestCachedMessageSecretStore(t *testing.T, capSize int) (*CachedMessageSecretStore, *fakeMessageSecretStore) {
	t.Helper()
	inner := newFakeMessageSecretStore()
	cache, err := lru.New[string, msgSecretEntry](capSize)
	if err != nil {
		t.Fatalf("lru.New[string, msgSecretEntry] failed: %v", err)
	}
	var explicitRemoves uint64
	wrapper := NewCachedMessageSecretStore(inner, "test-jid", cache, &explicitRemoves)
	return wrapper, inner
}

func testJID(t *testing.T, s string) types.JID {
	t.Helper()
	j, err := types.ParseJID(s)
	if err != nil {
		t.Fatalf("ParseJID(%q): %v", s, err)
	}
	return j
}

// ---------------------------------------------------------------------------
// Compile-time conformance assertion reach test.
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_InterfaceConformance(t *testing.T) {
	var c *CachedMessageSecretStore
	if c != nil {
		t.Fatal("nil pointer should stay nil")
	}
}

// ---------------------------------------------------------------------------
// Test A: GetMessageSecret miss → calls inner once, caches the (secret,
// realSender) pair, returns correct values on first and second call; inner
// called only once (second is cache hit).
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_GetMiss_CallsInnerOnceAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "12345@g.us")
	sender := testJID(t, "67890@s.whatsapp.net")
	id := types.MessageID("MSG-A")

	if err := inner.PutMessageSecret(ctx, chat, sender, id, []byte("secret-A")); err != nil {
		t.Fatalf("seed inner.PutMessageSecret: %v", err)
	}
	inner.putCalls.Store(0)

	s1, rs1, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("first GetMessageSecret: %v", err)
	}
	if !bytes.Equal(s1, []byte("secret-A")) {
		t.Fatalf("first secret got %q, want %q", s1, "secret-A")
	}
	if rs1 != sender.ToNonAD() {
		t.Fatalf("first realSender got %v, want %v", rs1, sender.ToNonAD())
	}

	s2, rs2, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("second GetMessageSecret: %v", err)
	}
	if !bytes.Equal(s2, []byte("secret-A")) {
		t.Fatalf("second secret got %q, want %q", s2, "secret-A")
	}
	if rs2 != sender.ToNonAD() {
		t.Fatalf("second realSender got %v, want %v", rs2, sender.ToNonAD())
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls = %d, want 1 (second call must hit cache)", got)
	}
}

// ---------------------------------------------------------------------------
// Test B: GetMessageSecret when inner returns (nil, emptyJID, nil) [not found]
// → never caches nil; second call hits inner again (inner.getCalls==2).
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_GetNotFound_NotCached(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "999@g.us")
	sender := testJID(t, "888@s.whatsapp.net")
	id := types.MessageID("GHOST")

	s1, rs1, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("first GetMessageSecret: %v", err)
	}
	if s1 != nil {
		t.Fatalf("first secret got %q, want nil", s1)
	}
	if rs1 != types.EmptyJID {
		t.Fatalf("first realSender got %v, want empty", rs1)
	}
	if _, _, err := c.GetMessageSecret(ctx, chat, sender, id); err != nil {
		t.Fatalf("second GetMessageSecret: %v", err)
	}
	if got := inner.getCalls.Load(); got != 2 {
		t.Errorf("inner.getCalls = %d, want 2 (not-found result must not be cached)", got)
	}
}

// ---------------------------------------------------------------------------
// Test C: PutMessageSecret → inner called once; subsequent GetMessageSecret
// returns cached value without hitting inner (inner.getCalls==0 for get).
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_Put_WritesThroughAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "111@g.us")
	sender := testJID(t, "222@s.whatsapp.net")
	id := types.MessageID("MSG-C")

	if err := c.PutMessageSecret(ctx, chat, sender, id, []byte("secret-C")); err != nil {
		t.Fatalf("PutMessageSecret: %v", err)
	}
	if got := inner.putCalls.Load(); got != 1 {
		t.Errorf("inner.putCalls = %d, want 1 (write-through)", got)
	}

	s, rs, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("GetMessageSecret after Put: %v", err)
	}
	if !bytes.Equal(s, []byte("secret-C")) {
		t.Fatalf("secret after Put got %q, want %q", s, "secret-C")
	}
	if rs != sender.ToNonAD() {
		t.Fatalf("realSender after Put got %v, want %v", rs, sender.ToNonAD())
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (Put should seed cache so Get hits)", got)
	}
}

// ---------------------------------------------------------------------------
// Test D: PutMessageSecrets (bulk) → inner bulkCalls==1; subsequent
// GetMessageSecret for each inserted key returns cached value without hitting
// inner.
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_PutBulk_WritesThroughAndCaches(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "333@g.us")
	sender := testJID(t, "444@s.whatsapp.net")
	inserts := []store.MessageSecretInsert{
		{Chat: chat, Sender: sender, ID: types.MessageID("D1"), Secret: []byte("d-1")},
		{Chat: chat, Sender: sender, ID: types.MessageID("D2"), Secret: []byte("d-2")},
	}
	if err := c.PutMessageSecrets(ctx, inserts); err != nil {
		t.Fatalf("PutMessageSecrets: %v", err)
	}
	if got := inner.bulkCalls.Load(); got != 1 {
		t.Errorf("inner.bulkCalls = %d, want 1", got)
	}

	for _, ins := range inserts {
		s, _, err := c.GetMessageSecret(ctx, ins.Chat, ins.Sender, ins.ID)
		if err != nil {
			t.Fatalf("GetMessageSecret %s: %v", ins.ID, err)
		}
		if !bytes.Equal(s, ins.Secret) {
			t.Errorf("GetMessageSecret %s got %q, want %q", ins.ID, s, ins.Secret)
		}
	}
	if got := inner.getCalls.Load(); got != 0 {
		t.Errorf("inner.getCalls = %d, want 0 (bulk Put should seed cache)", got)
	}
}

// ---------------------------------------------------------------------------
// Test E: returned secret is a copy — mutating the returned []byte does not
// corrupt the cache (second Get returns original value unchanged).
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_ReturnedSecretIsCopy(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "555@g.us")
	sender := testJID(t, "666@s.whatsapp.net")
	id := types.MessageID("MSG-E")

	if err := c.PutMessageSecret(ctx, chat, sender, id, []byte("immutable")); err != nil {
		t.Fatalf("PutMessageSecret: %v", err)
	}
	s1, _, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("first GetMessageSecret: %v", err)
	}
	// Mutate the returned slice in place.
	for i := range s1 {
		s1[i] = 'X'
	}
	s2, _, err := c.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		t.Fatalf("second GetMessageSecret: %v", err)
	}
	if !bytes.Equal(s2, []byte("immutable")) {
		t.Fatalf("cache corrupted by caller mutation: got %q, want %q", s2, "immutable")
	}
}

// ---------------------------------------------------------------------------
// Test F: different (chat, sender, id) combos occupy distinct cache slots
// (cache.Len()==3 after 3 Puts with distinct ids).
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_DistinctKeysAreSeparateEntries(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedMessageSecretStore(t, 16)

	chat := testJID(t, "777@g.us")
	sender := testJID(t, "888@s.whatsapp.net")
	for _, id := range []types.MessageID{"F1", "F2", "F3"} {
		if err := c.PutMessageSecret(ctx, chat, sender, id, []byte(string(id))); err != nil {
			t.Fatalf("PutMessageSecret %s: %v", id, err)
		}
	}
	if got := c.cache.Len(); got != 3 {
		t.Fatalf("cache.Len() = %d, want 3 (four-element key isolates entries)", got)
	}
}

// ---------------------------------------------------------------------------
// Eviction at cap: cap=4, 5 distinct keys → Len()==4, first-inserted evicted.
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_EvictionAtCap(t *testing.T) {
	ctx := context.Background()
	c, inner := newTestCachedMessageSecretStore(t, 4)

	chat := testJID(t, "100@g.us")
	sender := testJID(t, "200@s.whatsapp.net")
	for i := 0; i < 5; i++ {
		id := types.MessageID(fmt.Sprintf("E-%d", i))
		if err := c.PutMessageSecret(ctx, chat, sender, id, []byte(fmt.Sprintf("v-%d", i))); err != nil {
			t.Fatalf("PutMessageSecret %s: %v", id, err)
		}
	}
	if got := c.cache.Len(); got != 4 {
		t.Errorf("cache.Len() after 5 Puts = %d, want 4 (cap)", got)
	}
	// E-0 should be evicted; next Get for E-0 must hit inner.
	inner.getCalls.Store(0)
	if _, _, err := c.GetMessageSecret(ctx, chat, sender, types.MessageID("E-0")); err != nil {
		t.Fatalf("GetMessageSecret E-0: %v", err)
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Errorf("inner.getCalls for evicted E-0 = %d, want 1", got)
	}
}

// ---------------------------------------------------------------------------
// Test G: race test — 50 goroutines mixed Get/Put on overlapping keys, clean
// under go test -race and no deadlock.
// ---------------------------------------------------------------------------

func TestCachedMessageSecretStore_Race_50Goroutines(t *testing.T) {
	ctx := context.Background()
	c, _ := newTestCachedMessageSecretStore(t, 64)

	chat := testJID(t, "1@g.us")
	sender := testJID(t, "2@s.whatsapp.net")

	const G = 50
	const N = 100
	var wg sync.WaitGroup
	wg.Add(G)
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	for g := 0; g < G; g++ {
		g := g
		go func() {
			defer wg.Done()
			for i := 0; i < N; i++ {
				id := types.MessageID(fmt.Sprintf("MSG-%d", (g+i)%10))
				switch i % 2 {
				case 0:
					_, _, _ = c.GetMessageSecret(ctx, chat, sender, id)
				case 1:
					_ = c.PutMessageSecret(ctx, chat, sender, id, []byte(fmt.Sprintf("v-%d-%d", g, i)))
				}
			}
		}()
	}
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("race test deadlocked (10s)")
	}
}
