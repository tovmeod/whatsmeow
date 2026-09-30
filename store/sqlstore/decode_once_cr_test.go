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
// Phase 38.4-03: the parsed struct cache is deleted; the single flat []byte
// cache (skLRU) is the only sender-key cache exercised here.
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
	"go.mau.fi/libsignal/keys/chain"
	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/protocol"
	librecord "go.mau.fi/libsignal/state/record"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// ---------------------------------------------------------------------------
// Build helpers
// ---------------------------------------------------------------------------

// testDeviceHandles holds the wired test device plus the handles callers need
// to set up preconditions and make assertions.
//
// Phase 38.4-03: ParsedSKCache / skParsedLRU removed. The single flat []byte
// cache (skLRU) is now the only sender-key cache — no struct cache exists.
type testDeviceHandles struct {
	device   *store.Device
	fakeSK   *fakeSenderKeyStore
	fakeSess *fakeSessionStore
	skStore  *CachedSenderKeyStore
	skLRU    *lru.Cache[string, []byte]
	testJID  string // the JID string (== device.ID.String())
}

// buildTestDevice constructs a *store.Device with a CachedSenderKeyStore
// backed by the flat []byte LRU only (no parsed struct cache — deleted in
// Phase 38.4-03). A non-started flusher is attached so write-back paths
// don't spawn goroutines.
//
// lruCap controls the capacity of the flat byte LRU; pass a small value (e.g. 2)
// to exercise LRU eviction in TR-05.
func buildTestDevice(t *testing.T, lruCap int) *testDeviceHandles {
	t.Helper()

	const testJIDStr = "15550001234"
	jid := types.NewJID(testJIDStr, types.DefaultUserServer)

	fakeSK := newFakeSenderKeyStore()
	fakeSess := newFakeSessionStore()

	skCache, err := lru.New[string, []byte](lruCap)
	if err != nil {
		t.Fatalf("lru.New skCache: %v", err)
	}
	devCache, err := NewSenderKeyDeviceCache(lruCap)
	if err != nil {
		t.Fatalf("lru.New devCache: %v", err)
	}
	// Build the CachedSenderKeyStore. jid string must match device.ID.String()
	// so that c.key(group,user) == the cache key used inside the store.
	jidStr := jid.String()
	skStore := NewCachedSenderKeyStore(fakeSK, jidStr, skCache, devCache, nil)

	// Attach a non-Started flusher so write-back enqueues don't spawn goroutines.
	flushStore := &mockFlushStore{}
	f := NewSenderKeyFlusher(flushStore, waLog.Noop, 1000)
	skStore.SetFlusher(f)

	d := &store.Device{
		Log:        waLog.Noop,
		ID:         &jid,
		SenderKeys: skStore,
		Sessions:   fakeSess,
	}

	return &testDeviceHandles{
		device:   d,
		fakeSK:   fakeSK,
		fakeSess: fakeSess,
		skStore:  skStore,
		skLRU:    skCache,
		testJID:  jidStr,
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

// seedSKFlatCache seeds both the inner fake store and the flat []byte LRU for
// (group, senderName), then calls LoadSenderKey once to warm the cache.
// Returns the first Load result for further assertion.
//
// Phase 38.4-03: renamed from seedSKStructCache; no struct cache exists.
// The flat byte LRU (c.cache) is the only sender-key cache.
//
// senderName is the bare SignalAddress name (e.g. "15550001001"). The helper
// internally uses senderName+":0" as the full SignalAddress string (deviceID=0),
// matching what signal.go passes to CachedSenderKeyStore.GetSenderKey.
func seedSKFlatCache(t *testing.T, h *testDeviceHandles, group, senderName string, blob []byte) *groupRecord.SenderKey {
	t.Helper()
	ctx := context.Background()

	// The full SignalAddress string used by signal.go: "<name>:<deviceID>".
	senderFull := senderName + ":0"

	// Seed the inner fake so the byte-cache-miss path finds data.
	if err := h.fakeSK.PutSenderKey(ctx, group, senderFull, blob); err != nil {
		t.Fatalf("seedSKFlatCache fakeSK.PutSenderKey: %v", err)
	}
	// Warm the flat byte LRU so CachedSenderKeyStore.GetSenderKey is a LRU hit.
	h.skLRU.Add(h.testJID+"|"+group+"|"+senderFull, copyBytes(blob))

	skName := makeSenderKeyName(group, senderName)
	key, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("seedSKFlatCache LoadSenderKey: %v", err)
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
				Keys:              smks,
			},
		},
	}
	blob, ok := store.PackFlat(s)
	if !ok {
		panic("buildFlatSenderKeyBlob: PackFlat returned nil")
	}
	return blob
}

// buildFlatSessionBlob returns a PackFlatSession-encoded session blob with
// numKeys skipped message keys in the first receiver chain.
// Stage 3: LoadSession accepts only flat blobs (byte[0]=0x01); JSON blobs are
// rejected. Use this helper wherever the CR tests previously used buildSessionBlob.
func buildFlatSessionBlob(numKeys int) []byte {
	pub33 := func(seed byte) []byte {
		b := make([]byte, 33)
		b[0] = 0x05
		for i := 1; i < 33; i++ {
			b[i] = seed + byte(i)
		}
		return b
	}
	priv32 := func(seed byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = seed + byte(i+1)
		}
		return b
	}
	key32 := func(seed byte) []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = seed + byte(i+2)
		}
		return b
	}

	var msgKeys []*message.KeysStructure
	for k := 0; k < numKeys; k++ {
		iv := make([]byte, 16)
		ck := make([]byte, 32)
		mk := make([]byte, 32)
		for i := range iv {
			iv[i] = byte(k + i)
		}
		for i := range ck {
			ck[i] = byte(k + i + 1)
		}
		for i := range mk {
			mk[i] = byte(k + i + 2)
		}
		msgKeys = append(msgKeys, &message.KeysStructure{
			CipherKey: ck,
			MacKey:    mk,
			IV:        iv,
			Index:     uint32(k),
		})
	}

	senderChain := &librecord.ChainStructure{
		SenderRatchetKeyPublic:  pub33(0x01),
		SenderRatchetKeyPrivate: priv32(0x02),
		ChainKey:                &chain.KeyStructure{Key: key32(0x03), Index: 0},
		MessageKeys:             nil,
	}
	receiverChain := &librecord.ChainStructure{
		SenderRatchetKeyPublic:  pub33(0x11),
		SenderRatchetKeyPrivate: priv32(0x12),
		ChainKey:                &chain.KeyStructure{Key: key32(0x13), Index: uint32(numKeys)},
		MessageKeys:             msgKeys,
	}

	state := &librecord.StateStructure{
		SessionVersion:       3,
		LocalIdentityPublic:  pub33(0x20),
		RemoteIdentityPublic: pub33(0x30),
		RootKey:              key32(0x40),
		SenderBaseKey:        pub33(0x50),
		SenderChain:          senderChain,
		ReceiverChains:       []*librecord.ChainStructure{receiverChain},
		LocalRegistrationID:  12345,
		RemoteRegistrationID: 67890,
	}

	ss := &librecord.SessionStructure{
		SessionState:   state,
		PreviousStates: nil,
	}

	blob, ok := store.PackFlatSession(ss)
	if !ok {
		panic("buildFlatSessionBlob: PackFlatSession returned !ok (codec bug in test helper)")
	}
	return blob
}

// fullParseFlatSession parses a flat-encoded session blob into a *librecord.Session.
// Stage 3 equivalent of fullParseSession (which used JSON); used by CR tests.
func fullParseFlatSession(blob []byte) (*librecord.Session, error) {
	structure, err := store.UnpackFlatSession(blob)
	if err != nil {
		return nil, err
	}
	return librecord.NewSessionFromStructure(structure, store.SignalProtobufSerializer.Session, store.SignalProtobufSerializer.State)
}

// seedSessStore seeds the fake session store with blob for addrName, then
// calls LoadSession once to warm the byte-cache (CachedSessionStore). Returns
// the loaded session.
// Phase 17.13: struct cache removed (D-04a); this helper no longer seeds a
// struct cache, only the byte-level store.
func seedSessStore(t *testing.T, h *testDeviceHandles, addrName string, blob []byte) *librecord.Session {
	t.Helper()
	ctx := context.Background()

	// fakeSessionStore keyed by address string "name:deviceID"
	addr := addrName + ":0"
	if err := h.fakeSess.PutSession(ctx, addr, blob); err != nil {
		t.Fatalf("seedSessStore fakeSess.PutSession: %v", err)
	}

	sig := makeSignalAddress(addrName)
	sess, err := h.device.LoadSession(ctx, sig)
	if err != nil {
		t.Fatalf("seedSessStore LoadSession: %v", err)
	}
	return sess
}

// ---------------------------------------------------------------------------
// TR-01: Concurrent LoadSenderKey while StoreSenderKey for same (group,sender)
//
// SC-2 coverage: concurrent decrypt / write-back / flat-cache access is
// race-free; each Load returns an independent *SenderKey object.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR01(t *testing.T) {
	const N = 10
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	group, sender := "group-TR01", "15550001001"
	blob := buildFlatSenderKeyBlob(0)

	// Pre-populate flat cache so subsequent hot Loads exercise the hit path.
	seedSKFlatCache(t, h, group, sender, blob)

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
// After both complete: LoadSenderKey returns non-nil; no panic; -race clean.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR02(t *testing.T) {
	h := buildTestDevice(t, 64)
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
}

// ---------------------------------------------------------------------------
// TR-03: LoadSenderKey after StoreSenderKey returns post-ratchet structure.
//
// Sequential correctness: Store a key with keyID=42, Load it back, verify
// keyID=42 survives the flat-cache round-trip.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR03(t *testing.T) {
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	group, sender := "group-TR03", "15550001003"
	const wantKeyID uint32 = 42

	blob42 := buildSenderKeyBlobKeyID(wantKeyID)
	skName := makeSenderKeyName(group, sender)

	k, err := fullParseSenderKeyFlat(blob42)
	if err != nil {
		t.Fatalf("TR-03: fullParseSenderKey blob42: %v", err)
	}

	// StoreSenderKey: encodes to flat bytes; flat cache updated.
	if err := h.device.StoreSenderKey(ctx, skName, k); err != nil {
		t.Fatalf("TR-03: StoreSenderKey: %v", err)
	}

	// LoadSenderKey must return the post-ratchet structure via the flat cache.
	// (The flat cache is warmed by PutSenderKeyStructure's write-through.)
	got, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("TR-03: LoadSenderKey: %v", err)
	}
	if got == nil {
		t.Fatal("TR-03: LoadSenderKey returned nil after StoreSenderKey")
	}

	// Verify keyID survives the flat-cache round-trip.
	gotKeyID, _ := extractStructMeta(got.Structure())
	if gotKeyID != wantKeyID {
		t.Errorf("TR-03: gotKeyID = %d, want %d "+
			"(post-ratchet structure not preserved by flat cache)", gotKeyID, wantKeyID)
	}
}

// ---------------------------------------------------------------------------
// TR-04: Concurrent LoadSenderKey while the flat LRU is being Purged.
//
// Phase 38.4-03: no parsed struct cache exists. The test verifies concurrent
// Load + Purge (flat LRU eviction) is race-free.
// 5 Load goroutines + 2 Purge goroutines run concurrently.
// Assertion: no panic; Loads return non-error results.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR04(t *testing.T) {
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	group, sender := "group-TR04", "15550001004"
	blob := buildFlatSenderKeyBlob(0)

	// Pre-populate flat cache.
	seedSKFlatCache(t, h, group, sender, blob)

	skName := makeSenderKeyName(group, sender)

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

	// 2 flat-cache purgers (evict everything; Loads then fall to inner fake).
	for j := 0; j < 2; j++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h.skStore.Purge()
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
// TR-05: Flat LRU capacity eviction — a third key forces eviction.
//
// Phase 38.4-03: tests the flat []byte LRU directly. Build with cap=2; fill
// with 2 entries; Load a third key (forces eviction of one entry). The third
// key must be served via the inner fake (byte-cache miss path).
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR05(t *testing.T) {
	// Use cap=2 so the third entry forces an eviction.
	h := buildTestDevice(t, 2)
	ctx := context.Background()

	group := "group-TR05"
	blob := buildFlatSenderKeyBlob(0)

	// Fill both slots in the flat byte LRU.
	seedSKFlatCache(t, h, group, "sender-A", blob)
	seedSKFlatCache(t, h, group, "sender-B", blob)
	if n := h.skLRU.Len(); n != 2 {
		t.Fatalf("TR-05: expected 2 flat-cache entries, got %d", n)
	}

	// Seed the inner fake with blob for sender-C (so the DB-miss path can serve it).
	if err := h.fakeSK.PutSenderKey(ctx, group, "sender-C:0", blob); err != nil {
		t.Fatalf("TR-05: seed fakeSK for sender-C: %v", err)
	}

	// Load sender-C — forces eviction of sender-A or sender-B from the flat LRU
	// (cap=2), then adds sender-C.
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
		t.Fatal("TR-05: LoadSenderKey sender-C returned nil (inner fake should have served it)")
	}
	// After the load, flat LRU is still at cap=2 (evicted one, added one).
	if n := h.skLRU.Len(); n != 2 {
		t.Errorf("TR-05: skLRU.Len() = %d after load, want 2 (cap eviction preserves cap invariant)", n)
	}
}

// ---------------------------------------------------------------------------
// TR-06: Session: LoadSession + StoreSession concurrent on same address.
//
// Mirror of TR-01 for sessions.
// Phase 17.13: struct cache removed (D-04a). The race-free invariant now
// applies to the flat-bytes path (CachedSessionStore + transient decode).
// SC-2 coverage: concurrent session Load/Store is race-free; each Load
// returns an independent *Session object.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR06(t *testing.T) {
	const N = 10
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	addrName := "15550002001"
	blob := buildFlatSessionBlob(0) // Stage 3: flat blobs only; JSON rejected by LoadSession

	// Seed the byte-level store and warm the byte-cache.
	seedSessStore(t, h, addrName, blob)

	sig := makeSignalAddress(addrName)

	ptrs := make([]uintptr, N)
	var wg sync.WaitGroup
	var storeErr error

	// 1 writer: StoreSession with a fresh session object from blob2.
	blob2 := buildFlatSessionBlob(10) // Stage 3: flat blobs only
	wg.Add(1)
	go func() {
		defer wg.Done()
		s2, err := fullParseFlatSession(blob2)
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
// TR-07: Session: StoreSession fails (inner.PutSession error) → error
// propagated; next LoadSession re-fetches from inner store.
//
// Phase 17.13: struct cache removed (D-04a). No Invalidate call — no struct
// cache to roll back. Test verifies: error is returned, and subsequent
// LoadSession succeeds from the original (un-overwritten) store.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR07(t *testing.T) {
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	addrName := "15550002002"
	blob := buildFlatSessionBlob(0) // Stage 3: flat blobs only; JSON rejected by LoadSession

	// Seed the byte-level store with the original blob.
	seedSessStore(t, h, addrName, blob)

	sig := makeSignalAddress(addrName)

	// Inject a PutSession error on the fake store.
	injectedErr := errors.New("simulated PutSession error TR-07")
	h.fakeSess.putErr = injectedErr

	// Build a new session to pass to StoreSession.
	newBlob := buildFlatSessionBlob(5) // Stage 3: flat blobs only
	newSess, err := fullParseFlatSession(newBlob)
	if err != nil {
		t.Fatalf("TR-07: fullParseFlatSession newBlob: %v", err)
	}

	// StoreSession must return the error from PutSession.
	storeErr := h.device.StoreSession(ctx, sig, newSess)
	if storeErr == nil {
		t.Fatal("TR-07: expected StoreSession to return error; got nil")
	}
	if !errors.Is(storeErr, injectedErr) {
		t.Errorf("TR-07: storeErr = %v, want to wrap %v", storeErr, injectedErr)
	}

	// Next LoadSession must re-fetch from the inner store (the putCachedSession
	// path did not take, since the context cache is nil during non-send paths).
	// Clear putErr so the Load succeeds.
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
// writes the new blob to the flat byte cache; next Load returns the new key.
//
// Phase 38.4-03: the struct-cache Invalidate path is gone (no struct cache).
// The test verifies the essential correctness invariant that survives deletion:
// a wasFailed=true write lands in the flat byte cache, and the next
// LoadSenderKey returns the new recovered key (not the old stale key).
//
// SC-3 (sole flusher writer via wasFailed path) and
// SC-5 (failedSenderKeyTuples bypass) coverage.
// ---------------------------------------------------------------------------

func TestDecodeOnce_CR_TR08(t *testing.T) {
	h := buildTestDevice(t, 64)
	ctx := context.Background()

	group, sender := "group-TR08", "15550001008"
	const oldKeyID uint32 = 1
	const newKeyID uint32 = 99

	blobOld := buildSenderKeyBlobKeyID(oldKeyID)
	blobNew := buildSenderKeyBlobKeyID(newKeyID)

	skName := makeSenderKeyName(group, sender)

	// Pre-populate flat cache with the OLD key (keyID=1).
	seedSKFlatCache(t, h, group, sender, blobOld)

	// Sanity: flat cache is warm with the old key.
	if n := h.skLRU.Len(); n != 1 {
		t.Fatalf("TR-08: expected flat cache len=1 before PutSenderKeyWithMeta, got %d", n)
	}

	// PutSenderKeyWithMeta(wasFailed=true) simulates a failed-tuple recovery
	// writing a fresh blob. This must update the flat byte LRU with blobNew.
	senderStr := skName.Sender().String()
	if err := h.skStore.PutSenderKeyWithMeta(ctx, group, senderStr, blobNew, true); err != nil {
		t.Fatalf("TR-08: PutSenderKeyWithMeta wasFailed=true: %v", err)
	}

	// Next LoadSenderKey must decode from blobNew → keyID=99.
	got, err := h.device.LoadSenderKey(ctx, skName)
	if err != nil {
		t.Fatalf("TR-08: LoadSenderKey after recovery: %v", err)
	}
	if got == nil {
		t.Fatal("TR-08: LoadSenderKey returned nil after recovery write")
	}

	// Verify the loaded result uses the new key (keyID=99).
	gotKeyID, _ := extractStructMeta(got.Structure())
	if gotKeyID != newKeyID {
		t.Errorf("TR-08: gotKeyID = %d, want %d "+
			"(next Load must decode from blobNew after wasFailed=true write)", gotKeyID, newKeyID)
	}
}
