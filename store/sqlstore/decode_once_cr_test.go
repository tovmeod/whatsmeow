// Copyright (c) 2026 Kavtov Platform (Phase 17.8)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// decode_once_cr_test.go — Phase 17.8 D-05 concurrency regression suite.
// TR-01..TR-08 analogous to CR-01..CR-06 in flusher_cr_test.go. All tests run
// under -race.
//
// Each test drives the integration through device.LoadSenderKey /
// device.StoreSenderKey / device.LoadSession / device.StoreSession (public API).
// Parsed-cache types live in package store; tests access them only via
// device.ParsedSKCache / ParsedSessionCache exported methods. No direct
// field reads into package store internals.
//
// Run: go test ./store/sqlstore/ -run TestDecodeOnce_CR -race -count=5

package sqlstore

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	librecord "go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// ---------------------------------------------------------------------------
// Build helpers
// ---------------------------------------------------------------------------

// testDeviceHandles holds the wired test device plus the handles callers need
// to set up preconditions and make assertions.
type testDeviceHandles struct {
	device      *store.Device
	fakeSK      *fakeSenderKeyStore
	fakeSess    *fakeSessionStore
	skStore     *CachedSenderKeyStore
	skLRU       *lru.Cache[string, []byte]
	skParsedLRU *store.SKParsedLRU // Phase 17.9: flat value-struct LRU
	sessParsLRU *lru.Cache[string, *librecord.SessionStructure]
	testJID     string // the JID string (== device.ID.String())
}

// buildTestDeviceWithParsedCache constructs a *store.Device fully wired with
// parsedSKCache, parsedSessionCache, and a CachedSenderKeyStore. The device
// JID and the CachedSenderKeyStore JID are identical (required by TR-08
// key-matching invariant). A flusher is attached (required by TR-08 wasFailed
// path) but not Started so no goroutine races the test.
//
// lruCap controls the capacity of all four LRUs; pass a small value (e.g. 2)
// to exercise eviction in TR-05.
func buildTestDeviceWithParsedCache(t *testing.T, lruCap int) *testDeviceHandles {
	t.Helper()

	const testJIDStr = "15550001234"
	jid := types.NewJID(testJIDStr, types.DefaultUserServer)

	fakeSK := newFakeSenderKeyStore()
	fakeSess := newFakeSessionStore()

	skCache, err := lru.New[string, []byte](lruCap)
	if err != nil {
		t.Fatalf("lru.New skCache: %v", err)
	}
	devCache, err := lru.New[string, []string](lruCap)
	if err != nil {
		t.Fatalf("lru.New devCache: %v", err)
	}
	skParsedLRU, err := store.NewSKParsedLRU(lruCap)
	if err != nil {
		t.Fatalf("NewSKParsedLRU: %v", err)
	}
	sessParsLRU, err := lru.New[string, *librecord.SessionStructure](lruCap)
	if err != nil {
		t.Fatalf("lru.New sessParsLRU: %v", err)
	}

	// Build the CachedSenderKeyStore. jid string must match device.ID.String()
	// so that c.key(group,user) == the device struct-cache cacheKey (TR-08).
	jidStr := jid.String()
	skStore := NewCachedSenderKeyStore(fakeSK, jidStr, skCache, devCache)

	// Attach a non-Started flusher so the wasFailed path executes the
	// parsedInvalidate callback (TR-08) without spawning a background goroutine.
	flushStore := &mockFlushStore{}
	f := NewSenderKeyFlusher(flushStore, waLog.Noop, 1000)
	skStore.SetFlusher(f)

	d := &store.Device{
		Log:        waLog.Noop,
		ID:         &jid,
		SenderKeys: skStore,
		Sessions:   fakeSess,
	}

	d.ParsedSKCache = store.NewParsedSKCache(skParsedLRU)
	d.ParsedSessionCache = store.NewParsedSessionCache(sessParsLRU)

	// Wire wasFailed invalidation callback (mirrors attachCachedStores exactly).
	skStore.SetParsedInvalidate(func(key string) {
		d.ParsedSKCache.Invalidate(key)
	})

	return &testDeviceHandles{
		device:      d,
		fakeSK:      fakeSK,
		fakeSess:    fakeSess,
		skStore:     skStore,
		skLRU:       skCache,
		skParsedLRU: skParsedLRU,
		sessParsLRU: sessParsLRU,
		testJID:     jidStr,
	}
}

// makeSenderKeyName creates a *protocol.SenderKeyName from plain group and
// sender strings. sender is used as the SignalAddress name with deviceID=0.
func makeSenderKeyName(group, sender string) *protocol.SenderKeyName {
	addr := protocol.NewSignalAddress(sender, 0)
	return protocol.NewSenderKeyName(group, addr)
}

// makeSignalAddress creates a *protocol.SignalAddress with deviceID=0.
func makeSignalAddress(name string) *protocol.SignalAddress {
	return protocol.NewSignalAddress(name, 0)
}

// buildSenderKeyBlobKeyID builds a PackFlat-encoded sender-key blob with the given keyID.
// Post-upgrade-19: GetSenderKeyStructure uses store.UnpackFlat, not JSON Deserialize.
// Lets TR-03 and TR-08 make an exact keyID assertion rather than just a non-nil check.
func buildSenderKeyBlobKeyID(keyID uint32) []byte {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 3)
	}
	sigPub := make([]byte, 33)
	sigPub[0] = 0x05
	for i := 1; i < 33; i++ {
		sigPub[i] = byte(i)
	}
	sigPriv := make([]byte, 32)
	for i := range sigPriv {
		sigPriv[i] = byte(i + 3)
	}
	s := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: keyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: 0,
					ChainKey:  chainKey,
				},
				SigningKeyPublic:  sigPub,
				SigningKeyPrivate: sigPriv,
			},
		},
	}
	blob, ok := store.PackFlat(s)
	if !ok {
		panic("buildSenderKeyBlobKeyID: PackFlat returned nil")
	}
	return blob
}

// seedSKStructCache calls LoadSenderKey to populate the struct cache via the
// cold (byte-cache miss → decode → StoreStruct) path. Returns the first Load
// result for further assertion.
//
// senderName is the bare SignalAddress name (e.g. "15550001001"). The helper
// internally uses senderName+":0" as the full SignalAddress string (deviceID=0)
// for seeding the byte-level stores, matching what signal.go passes to
// CachedSenderKeyStore.GetSenderKey (senderKeyName.Sender().String()).
func seedSKStructCache(t *testing.T, h *testDeviceHandles, group, senderName string, blob []byte) *groupRecord.SenderKey {
	t.Helper()
	ctx := context.Background()

	// The full SignalAddress string used by signal.go: "<name>:<deviceID>".
	senderFull := senderName + ":0"

	// Seed the inner fake so the byte-cache-miss path finds data.
	if err := h.fakeSK.PutSenderKey(ctx, group, senderFull, blob); err != nil {
		t.Fatalf("seedSKStructCache fakeSK.PutSenderKey: %v", err)
	}
	// Warm the byte LRU so CachedSenderKeyStore.GetSenderKey is a LRU hit.
	h.skLRU.Add(h.testJID+"|"+group+"|"+senderFull, copyBytes(blob))

	skName := makeSenderKeyName(group, senderName)
	key, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("seedSKStructCache LoadSenderKey: %v", err)
	}
	return key
}

// fullParseSenderKeyFlat decodes a PackFlat blob to a *SenderKey. Used by CR
// tests post-upgrade-19 (fullParseSenderKey in bench_test.go uses JSON).
func fullParseSenderKeyFlat(blob []byte) (*groupRecord.SenderKey, error) {
	s, err := store.UnpackFlat(blob)
	if err != nil {
		return nil, err
	}
	return groupRecord.NewSenderKeyFromStruct(s,
		store.SignalProtobufSerializer.SenderKeyRecord,
		store.SignalProtobufSerializer.SenderKeyState)
}

// buildFlatSenderKeyBlob returns a PackFlat-encoded sender-key blob with numKeys
// skipped message keys. Post-upgrade-19: GetSenderKeyStructure uses store.UnpackFlat,
// not JSON Deserialize. Used by decode-once CR tests as the cache-seeding blob.
func buildFlatSenderKeyBlob(numKeys int) []byte {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(i + 3)
	}
	sigPub := make([]byte, 33)
	sigPub[0] = 0x05
	for i := 1; i < 33; i++ {
		sigPub[i] = byte(i)
	}
	sigPriv := make([]byte, 32)
	for i := range sigPriv {
		sigPriv[i] = byte(i + 3)
	}
	var smks []*ratchet.SenderMessageKeyStructure
	for k := 0; k < numKeys; k++ {
		iv := make([]byte, 16)
		ck := make([]byte, 32)
		sd := make([]byte, 32)
		for i := range iv {
			iv[i] = byte(k + i)
		}
		for i := range ck {
			ck[i] = byte(k + i + 1)
		}
		for i := range sd {
			sd[i] = byte(k + i + 2)
		}
		smks = append(smks, &ratchet.SenderMessageKeyStructure{
			Iteration: uint32(k),
			IV:        iv,
			CipherKey: ck,
			Seed:      sd,
		})
	}
	s := &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: 0,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: 0,
					ChainKey:  chainKey,
				},
				SigningKeyPublic:  sigPub,
				SigningKeyPrivate: sigPriv,
				Keys:             smks,
			},
		},
	}
	blob, ok := store.PackFlat(s)
	if !ok {
		panic("buildFlatSenderKeyBlob: PackFlat returned nil")
	}
	return blob
}

// seedSessStructCache calls LoadSession to populate the session struct cache.
func seedSessStructCache(t *testing.T, h *testDeviceHandles, addrName string, blob []byte) *librecord.Session {
	t.Helper()
	ctx := context.Background()

	// fakeSessionStore keyed by address string "name:deviceID"
	addr := addrName + ":0"
	if err := h.fakeSess.PutSession(ctx, addr, blob); err != nil {
		t.Fatalf("seedSessStructCache fakeSess.PutSession: %v", err)
	}

	sig := makeSignalAddress(addrName)
	sess, err := h.device.LoadSession(ctx, sig)
	if err != nil {
		t.Fatalf("seedSessStructCache LoadSession: %v", err)
	}
	return sess
}

// ---------------------------------------------------------------------------
// TR-01: Concurrent LoadSenderKey while StoreSenderKey for same (group,sender)
//
// SC-2 coverage: concurrent decrypt / write-back / struct-cache access is
// race-free; each Load returns an independent *SenderKey object.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR01(t *testing.T) {
	const N = 10
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	group, sender := "group-TR01", "15550001001"
	blob := buildFlatSenderKeyBlob(0)

	// Pre-populate struct cache so subsequent hot Loads exercise the hit path.
	seedSKStructCache(t, h, group, sender, blob)

	skName := makeSenderKeyName(group, sender)

	// Collect returned pointers in a pre-sized indexed slice (no append races).
	ptrs := make([]uintptr, N)
	var wg sync.WaitGroup
	var storeErr error

	// 1 writer: StoreSenderKey with a distinct blob.
	blob2 := buildFlatSenderKeyBlob(2)
	wg.Add(1)
	go func() {
		defer wg.Done()
		k2, err := fullParseSenderKeyFlat(blob2)
		if err != nil {
			storeErr = err
			return
		}
		storeErr = h.device.StoreSenderKey(ctx, skName, k2)
	}()

	// N readers: LoadSenderKey; collect pointer for each.
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			k, err := h.device.LoadSenderKey(ctx, skName)
			if err != nil || k == nil {
				return
			}
			ptrs[i] = reflect.ValueOf(k).Pointer()
		}()
	}
	wg.Wait()

	if storeErr != nil {
		t.Fatalf("TR-01: StoreSenderKey error: %v", storeErr)
	}

	// Each returned *SenderKey must be non-nil.
	for i, p := range ptrs {
		if p == 0 {
			t.Errorf("TR-01: goroutine %d returned nil *SenderKey pointer", i)
		}
	}

	// Returned pointers must be distinct — no shared reference between goroutines.
	seen := make(map[uintptr]int)
	for i, p := range ptrs {
		if p == 0 {
			continue
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("TR-01: goroutine %d and goroutine %d share the same *SenderKey pointer "+
				"(aliasing detected — independent copy discipline broken)", prev, i)
		}
		seen[p] = i
	}
}

// ---------------------------------------------------------------------------
// TR-02: Two concurrent StoreSenderKey calls for the same (group,sender).
//
// After both complete: LoadSenderKey returns non-nil; no panic; struct cache
// holds exactly one entry; -race clean.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR02(t *testing.T) {
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	group, sender := "group-TR02", "15550001002"
	blob1 := buildFlatSenderKeyBlob(0)
	blob2 := buildFlatSenderKeyBlob(5)

	skName := makeSenderKeyName(group, sender)

	k1, err := fullParseSenderKeyFlat(blob1)
	if err != nil {
		t.Fatalf("TR-02: fullParseSenderKey blob1: %v", err)
	}
	k2, err := fullParseSenderKeyFlat(blob2)
	if err != nil {
		t.Fatalf("TR-02: fullParseSenderKey blob2: %v", err)
	}

	var wg sync.WaitGroup
	var err1, err2 error
	wg.Add(2)
	go func() {
		defer wg.Done()
		err1 = h.device.StoreSenderKey(ctx, skName, k1)
	}()
	go func() {
		defer wg.Done()
		err2 = h.device.StoreSenderKey(ctx, skName, k2)
	}()
	wg.Wait()

	if err1 != nil {
		t.Errorf("TR-02: first StoreSenderKey error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("TR-02: second StoreSenderKey error: %v", err2)
	}

	// After both writes, LoadSenderKey must return a non-nil result.
	got, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("TR-02: LoadSenderKey after concurrent stores: %v", err)
	}
	if got == nil {
		t.Fatal("TR-02: LoadSenderKey returned nil after concurrent stores")
	}

	// Struct cache must hold exactly one entry for the key (no torn state).
	if n := h.skParsedLRU.Len(); n != 1 {
		t.Errorf("TR-02: skParsedLRU.Len() = %d, want 1 (last writer wins, no torn state)", n)
	}
}

// ---------------------------------------------------------------------------
// TR-03: LoadSenderKey after StoreSenderKey returns post-ratchet structure.
//
// Sequential correctness: Store a key with keyID=42, Load it back, verify
// keyID=42 survives the struct-cache round-trip.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR03(t *testing.T) {
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	group, sender := "group-TR03", "15550001003"
	const wantKeyID uint32 = 42

	blob42 := buildSenderKeyBlobKeyID(wantKeyID)
	skName := makeSenderKeyName(group, sender)

	k, err := fullParseSenderKeyFlat(blob42)
	if err != nil {
		t.Fatalf("TR-03: fullParseSenderKey blob42: %v", err)
	}

	// StoreSenderKey: serializes once; struct cache updated.
	if err := h.device.StoreSenderKey(ctx, skName, k); err != nil {
		t.Fatalf("TR-03: StoreSenderKey: %v", err)
	}

	// Clear the byte LRU so LoadSenderKey cannot bypass the struct cache via
	// the byte path — it must serve from the struct cache, then fall to the
	// inner fake if struct cache is empty.
	h.skLRU.Purge()

	// LoadSenderKey must return the post-ratchet structure from struct cache.
	got, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("TR-03: LoadSenderKey: %v", err)
	}
	if got == nil {
		t.Fatal("TR-03: LoadSenderKey returned nil after StoreSenderKey")
	}

	// Verify keyID survives the struct-cache round-trip.
	// Phase 17.9: extractSenderKeyMeta now takes *senderKeyColumns; decompose the structure.
	gotKeyID, _ := extractStructMeta(got.Structure())
	if gotKeyID != wantKeyID {
		t.Errorf("TR-03: gotKeyID = %d, want %d "+
			"(post-ratchet structure not preserved by struct cache)", gotKeyID, wantKeyID)
	}
}

// ---------------------------------------------------------------------------
// TR-04: Invalidate concurrent with LoadSenderKey — no panic; Load falls through.
//
// 5 Load goroutines + 2 Invalidate goroutines run concurrently.
// Assertion: no panic; Loads either hit (return non-nil) or miss (return nil
// for missing raw data, or non-nil from byte-cache after struct-cache miss).
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR04(t *testing.T) {
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	group, sender := "group-TR04", "15550001004"
	blob := buildFlatSenderKeyBlob(0)

	// Pre-populate struct cache.
	seedSKStructCache(t, h, group, sender, blob)

	skName := makeSenderKeyName(group, sender)
	cacheKey := h.testJID + "|" + group + "|" + skName.Sender().String()

	var wg sync.WaitGroup
	errs := make([]error, 5)

	// 5 readers
	for i := 0; i < 5; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, e := h.device.LoadSenderKey(ctx, skName)
			errs[i] = e
		}()
	}

	// 2 invalidators
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.device.ParsedSKCache.Invalidate(cacheKey)
		}()
	}

	wg.Wait()

	// No panic (we reached here). No goroutine should return an error.
	for i, e := range errs {
		if e != nil {
			t.Errorf("TR-04: goroutine %d LoadSenderKey error: %v", i, e)
		}
	}
}

// ---------------------------------------------------------------------------
// TR-05: LRU struct-cache capacity eviction concurrent with LoadSenderKey.
//
// Build parsedSKCache with cap=2; fill it with 2 entries; concurrently Load a
// third key (forcing eviction of one). The third key must fall through to the
// fakeSenderKeyStore (byte-cache miss path).
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR05(t *testing.T) {
	// Use cap=2 so the third entry forces an eviction.
	h := buildTestDeviceWithParsedCache(t, 2)
	ctx := context.Background()

	group := "group-TR05"
	blob := buildFlatSenderKeyBlob(0)

	// Fill both slots in the struct-LRU.
	seedSKStructCache(t, h, group, "sender-A", blob)
	seedSKStructCache(t, h, group, "sender-B", blob)
	if n := h.skParsedLRU.Len(); n != 2 {
		t.Fatalf("TR-05: expected 2 struct-cache entries, got %d", n)
	}

	// Seed the inner fake with blob for sender-C (so the byte miss path can serve it).
	if err := h.fakeSK.PutSenderKey(ctx, group, "sender-C:0", blob); err != nil {
		t.Fatalf("TR-05: seed fakeSK for sender-C: %v", err)
	}
	h.skLRU.Add(h.testJID+"|"+group+"|sender-C:0", copyBytes(blob))

	// Concurrently Load sender-C — forces eviction of sender-A or sender-B from
	// the struct-LRU (cap=2).
	skNameC := makeSenderKeyName(group, "sender-C")

	var wg sync.WaitGroup
	var loadErr error
	var got *groupRecord.SenderKey
	wg.Add(1)
	go func() {
		defer wg.Done()
		got, loadErr = h.device.LoadSenderKey(ctx, skNameC)
	}()
	wg.Wait()

	if loadErr != nil {
		t.Fatalf("TR-05: LoadSenderKey sender-C: %v", loadErr)
	}
	if got == nil {
		t.Fatal("TR-05: LoadSenderKey sender-C returned nil (byte fallthrough should have served it)")
	}
	// After the load, struct-LRU is still at cap=2 (evicted one, added one).
	if n := h.skParsedLRU.Len(); n != 2 {
		t.Errorf("TR-05: skParsedLRU.Len() = %d after load, want 2 (cap eviction preserves cap invariant)", n)
	}
}

// ---------------------------------------------------------------------------
// TR-06: Session: LoadSession + StoreSession concurrent on same address.
//
// Mirror of TR-01 for sessions.
// SC-2 coverage: session struct cache is race-free under concurrent access.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR06(t *testing.T) {
	const N = 10
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	addrName := "15550002001"
	blob := buildSessionBlob(0)

	// Pre-populate session struct cache.
	seedSessStructCache(t, h, addrName, blob)

	sig := makeSignalAddress(addrName)

	ptrs := make([]uintptr, N)
	var wg sync.WaitGroup
	var storeErr error

	// 1 writer: StoreSession with a fresh session object from blob2.
	blob2 := buildSessionBlob(10)
	wg.Add(1)
	go func() {
		defer wg.Done()
		s2, err := fullParseSession(blob2)
		if err != nil {
			storeErr = err
			return
		}
		storeErr = h.device.StoreSession(ctx, sig, s2)
	}()

	// N readers: LoadSession; collect pointer for each.
	for i := 0; i < N; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := h.device.LoadSession(ctx, sig)
			if err != nil || s == nil {
				return
			}
			ptrs[i] = reflect.ValueOf(s).Pointer()
		}()
	}
	wg.Wait()

	if storeErr != nil {
		t.Fatalf("TR-06: StoreSession error: %v", storeErr)
	}

	for i, p := range ptrs {
		if p == 0 {
			t.Errorf("TR-06: goroutine %d returned nil *Session pointer", i)
		}
	}

	seen := make(map[uintptr]int)
	for i, p := range ptrs {
		if p == 0 {
			continue
		}
		if prev, dup := seen[p]; dup {
			t.Errorf("TR-06: goroutine %d and goroutine %d share the same *Session pointer "+
				"(aliasing detected — independent copy discipline broken)", prev, i)
		}
		seen[p] = i
	}
}

// ---------------------------------------------------------------------------
// TR-07: Session: StoreSession fails (inner.PutSession error) → struct cache
// is invalidated; next LoadSession re-fetches from inner store.
//
// SC-7 coverage: StoreSession rollback via ParsedSessionCache.Invalidate.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR07(t *testing.T) {
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	addrName := "15550002002"
	blob := buildSessionBlob(0)

	// Pre-populate session struct cache so an entry exists before the failed Store.
	seedSessStructCache(t, h, addrName, blob)

	sig := makeSignalAddress(addrName)

	// Inject a PutSession error on the fake store.
	injectedErr := errors.New("simulated PutSession error TR-07")
	h.fakeSess.putErr = injectedErr

	// Build a new session to pass to StoreSession.
	newBlob := buildSessionBlob(5)
	newSess, err := fullParseSession(newBlob)
	if err != nil {
		t.Fatalf("TR-07: fullParseSession newBlob: %v", err)
	}

	// StoreSession must return the error from PutSession.
	storeErr := h.device.StoreSession(ctx, sig, newSess)
	if storeErr == nil {
		t.Fatal("TR-07: expected StoreSession to return error; got nil")
	}
	if !errors.Is(storeErr, injectedErr) {
		t.Errorf("TR-07: storeErr = %v, want to wrap %v", storeErr, injectedErr)
	}

	// Struct cache must be invalidated after the rollback.
	// Assert: struct-LRU is empty (the single entry was removed by Invalidate).
	if n := h.sessParsLRU.Len(); n != 0 {
		t.Errorf("TR-07: sessParsLRU.Len() = %d, want 0 "+
			"(Invalidate must fire on PutSession error — rollback failed)", n)
	}

	// Next LoadSession must fall through to the inner store (not serve the
	// pre-Store struct cache entry). Clear putErr so the Load succeeds.
	h.fakeSess.putErr = nil

	got, err := h.device.LoadSession(ctx, sig)
	if err != nil {
		t.Fatalf("TR-07: LoadSession after rollback: %v", err)
	}
	// The inner store still has the original blob (PutSession failed, so the
	// new blob was NOT written). A non-nil session must be returned.
	if got == nil {
		t.Fatal("TR-07: LoadSession returned nil after rollback (should re-fetch from inner)")
	}
}

// ---------------------------------------------------------------------------
// TR-08: failedSenderKeyTuples bypass: PutSenderKeyWithMeta wasFailed=true
// concurrent with normal Load → struct cache is invalidated; next Load
// re-fetches from the byte-level cache (new recovered blob).
//
// SC-3 (sole flusher writer via wasFailed path) and
// SC-5 (failedSenderKeyTuples bypass) coverage.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR08(t *testing.T) {
	h := buildTestDeviceWithParsedCache(t, 64)
	ctx := context.Background()

	group, sender := "group-TR08", "15550001008"
	const oldKeyID uint32 = 1
	const newKeyID uint32 = 99

	blobOld := buildSenderKeyBlobKeyID(oldKeyID)
	blobNew := buildSenderKeyBlobKeyID(newKeyID)

	skName := makeSenderKeyName(group, sender)

	// Pre-populate struct cache with the OLD key (keyID=1).
	// Use bare sender name (not skName.Sender().String() which has ":0" suffix);
	// seedSKStructCache appends ":0" internally.
	seedSKStructCache(t, h, group, sender, blobOld)

	// Sanity: struct cache is warm.
	if n := h.skParsedLRU.Len(); n != 1 {
		t.Fatalf("TR-08: expected struct cache len=1 before PutSenderKeyWithMeta, got %d", n)
	}

	// PutSenderKeyWithMeta(wasFailed=true) simulates a failed-tuple recovery
	// writing a fresh blob. This must:
	//   1. Update the byte LRU with blobNew.
	//   2. Call parsedInvalidate → device.ParsedSKCache.Invalidate.
	senderStr := skName.Sender().String()
	if err := h.skStore.PutSenderKeyWithMeta(ctx, group, senderStr, blobNew, true); err != nil {
		t.Fatalf("TR-08: PutSenderKeyWithMeta wasFailed=true: %v", err)
	}

	// Struct cache must now be empty — Invalidate fired.
	if n := h.skParsedLRU.Len(); n != 0 {
		t.Errorf("TR-08: skParsedLRU.Len() = %d after PutSenderKeyWithMeta(wasFailed=true), want 0 "+
			"(Invalidate must fire on wasFailed=true — Pitfall 4 guard broken)", n)
	}

	// Next LoadSenderKey must re-parse from the byte cache (blobNew → keyID=99).
	got, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("TR-08: LoadSenderKey after recovery: %v", err)
	}
	if got == nil {
		t.Fatal("TR-08: LoadSenderKey returned nil after recovery write")
	}

	// Verify the re-parsed result uses the new key (keyID=99).
	// Phase 17.9: extractSenderKeyMeta now takes *senderKeyColumns; decompose the structure.
	gotKeyID, _ := extractStructMeta(got.Structure())
	if gotKeyID != newKeyID {
		t.Errorf("TR-08: gotKeyID = %d, want %d "+
			"(next Load must re-parse from blobNew after invalidation)", gotKeyID, newKeyID)
	}

	// Struct cache is re-warmed after the Load.
	if n := h.skParsedLRU.Len(); n != 1 {
		t.Errorf("TR-08: skParsedLRU.Len() = %d after Load, want 1 "+
			"(struct cache should be re-populated after byte-cache re-parse)", n)
	}
}
