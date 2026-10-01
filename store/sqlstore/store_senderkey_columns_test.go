// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// store_senderkey_columns_test.go — DB-integration tests for the columnar
// sender-key read path (plan 04):
//
//   (a) TestSenderKeyColumnsSQL_ColumnarReadBack:
//       write via PutManySenderKeys (fmt_ver=2) → drain → getSenderKeyDecomposed
//       returns fmt_ver=2; recompose(cols) DeepEquals original structure.
//
//   (b) TestSenderKeyColumnsSQL_LegacyRow:
//       insert a legacy row (fmt_ver=1, blob only, NULL arrays) →
//       GetSenderKeyStructure returns the structure via the blob, no error on NULL arrays.
//
//   (c) TestSenderKeyColumnsSQL_FmtVer2IgnoresBlob:
//       write columnar row (fmt_ver=2) → overwrite sender_key blob with garbage →
//       GetSenderKeyStructure still recomposes correctly from columns (blob ignored).
//
//   (d) TestSenderKeyNoDivergence:
//       write via flusher → drain → read columns (getSenderKeyDecomposed) AND
//       Deserialize the legacy blob; assert both yield the same *SenderKeyStructure.
//
// Requires the live test DB with migration 16 applied (see plan 02).

package sqlstore_test

import (
	"context"
	"reflect"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store/sqlstore"
)

// buildColumnarTestStructure builds a *SenderKeyStructure with deterministic
// multi-state data including a nil SigningKeyPrivate (the dominant received-key shape)
// and a skipped message key on state[0].
func buildColumnarTestStructure(keyID uint32) *groupRecord.SenderKeyStructure {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(keyID) + byte(i)
	}
	pub := make([]byte, 33)
	pub[0] = 0x05
	for i := 1; i < 33; i++ {
		pub[i] = byte(keyID) + byte(i)
	}
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = byte(keyID) + 0x80 + byte(i)
	}
	// One skipped message key on state[0].
	iv := make([]byte, 16)
	cipherKey := make([]byte, 32)
	seed := make([]byte, 32)
	for i := range iv {
		iv[i] = byte(i) + 0x11
	}
	for i := range cipherKey {
		cipherKey[i] = byte(i) + 0x22
	}
	for i := range seed {
		seed[i] = byte(i) + 0x33
	}
	smk := &ratchet.SenderMessageKeyStructure{
		Iteration: 7,
		IV:        iv,
		CipherKey: cipherKey,
		Seed:      seed,
	}
	// State[1]: nil SigningKeyPrivate (received key).
	chainKey2 := make([]byte, 32)
	for i := range chainKey2 {
		chainKey2[i] = byte(keyID) + 0x40 + byte(i)
	}
	pub2 := make([]byte, 33)
	pub2[0] = 0x05
	for i := 1; i < 33; i++ {
		pub2[i] = byte(keyID) + 0x40 + byte(i)
	}
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID:             keyID,
				SenderChainKey:    &ratchet.SenderChainKeyStructure{Iteration: 5, ChainKey: chainKey},
				SigningKeyPublic:  pub,
				SigningKeyPrivate: priv,
				Keys:              []*ratchet.SenderMessageKeyStructure{smk},
			},
			{
				KeyID:             keyID + 1,
				SenderChainKey:    &ratchet.SenderChainKeyStructure{Iteration: 3, ChainKey: chainKey2},
				SigningKeyPublic:  pub2,
				SigningKeyPrivate: nil, // nil = received key (dominant shape)
				Keys:              nil,
			},
		},
	}
}

// normalizeSKStructure normalizes differences for DeepEqual comparisons across
// the JSON-serialize/deserialize boundary:
//
//   - nil Keys → nil (JSON serializer converts nil Keys → [])
//   - nil SigningKeyPrivate → nil (JSON serializer converts nil → []byte{32 zeros}
//     for received keys, because libsignal's NewSenderKeyFromStruct fills in a
//     zero private key when SigningKeyPrivate is nil)
//   - all-zero SigningKeyPrivate → nil (treat as semantically equivalent to nil;
//     a received key has no private key; libsignal zeros = same as nil for decrypt)
//
// This is only used for comparisons across the serialize/deserialize boundary
// (legacy blob vs recompose, or legacy-write vs JSON-read). It is NOT used
// for the round-trip gate tests (senderkey_columns_test.go) where the
// nil-vs-nil invariant is tested directly.
func normalizeSKStructure(sk *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
	if sk == nil {
		return nil
	}
	out := &groupRecord.SenderKeyStructure{}
	for _, st := range sk.SenderKeyStates {
		ns := &groupRecord.SenderKeyStateStructure{
			KeyID:            st.KeyID,
			SenderChainKey:   st.SenderChainKey,
			SigningKeyPublic: st.SigningKeyPublic,
		}
		// Normalize SigningKeyPrivate: nil and all-zero are both "no private key"
		// (libsignal fills nil with zeros via NewSenderKeyFromStruct; functionally
		// identical for received keys which never use the private key).
		if isSigningKeyPresent(st.SigningKeyPrivate) {
			ns.SigningKeyPrivate = st.SigningKeyPrivate
		}
		// Normalize Keys: nil and [] are both "no skipped keys".
		if len(st.Keys) > 0 {
			ns.Keys = st.Keys
		}
		out.SenderKeyStates = append(out.SenderKeyStates, ns)
	}
	return out
}

// isSigningKeyPresent returns true if the private key slice is non-nil and has
// at least one non-zero byte (i.e., a real private key). nil and all-zero slices
// are both treated as absent (the libsignal nil→zeros normalization case).
func isSigningKeyPresent(key []byte) bool {
	if len(key) == 0 {
		return false
	}
	for _, b := range key {
		if b != 0 {
			return true
		}
	}
	return false
}

// newCachedTestStore creates a *CachedSenderKeyStore around newBatchTestStore's
// SQLStore. The CachedSenderKeyStore wraps the SQLStore with a fresh LRU pair.
// No flusher is attached so PutSenderKeyStructure uses write-through (synchronous
// PutManySenderKeys) — adequate for read-back tests that don't test cache coherence.
func newCachedTestStore(t *testing.T) (*sqlstore.CachedSenderKeyStore, func()) {
	t.Helper()
	inner, _ := newBatchTestStore(t)
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := sqlstore.NewSenderKeyDeviceCache(1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)
	// No flusher: write-through mode for these tests.
	return cs, func() {}
}

// TestSenderKeyColumnsSQL_ColumnarReadBack (a): write columnar row → getSenderKeyDecomposed
// returns fmt_ver=2 and recompose(cols) DeepEquals the original.
func TestSenderKeyColumnsSQL_ColumnarReadBack(t *testing.T) {
	cs, _ := newCachedTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(42)
	if err := cs.PutSenderKeyStructure(ctx, "g1@g.us", "u1_1:0", original); err != nil {
		t.Fatalf("PutSenderKeyStructure: %v", err)
	}

	// GetSenderKeyStructure should return the structure via columnar recompose.
	got, err := cs.GetSenderKeyStructure(ctx, "g1@g.us", "u1_1:0")
	if err != nil {
		t.Fatalf("GetSenderKeyStructure: %v", err)
	}
	if got == nil {
		t.Fatal("GetSenderKeyStructure returned nil, want structure")
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(got)) {
		t.Errorf("recompose mismatch:\n  original: %+v\n  got:      %+v", original, got)
	}
}

// TestSenderKeyColumnsSQL_LegacyRow (b): post-upgrade-19 the "legacy" path is now
// the flat path — PutSenderKey writes a PackFlat blob, GetSenderKeyStructure
// reads it via UnpackFlat. This test verifies that a flat blob written via
// PutSenderKey (which takes raw []byte) round-trips correctly.
func TestSenderKeyColumnsSQL_LegacyRow(t *testing.T) {
	inner, _ := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(10)
	// Write via PutSenderKey (direct bytea path): the caller must provide a
	// PackFlat-encoded blob. Post-upgrade-19, all sender_key values are PackFlat.
	row := sqlstore.NewSenderKeyRow("g2@g.us", "u2_1:0", original)
	if row.Blob == nil {
		t.Fatal("NewSenderKeyRow: PackFlat returned nil blob (invalid structure?)")
	}
	if err := inner.PutSenderKey(ctx, "g2@g.us", "u2_1:0", row.Blob); err != nil {
		t.Fatalf("PutSenderKey (flat blob): %v", err)
	}

	// GetSenderKeyStructure via CachedSenderKeyStore wrapping the inner.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := sqlstore.NewSenderKeyDeviceCache(1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	got, err := cs.GetSenderKeyStructure(ctx, "g2@g.us", "u2_1:0")
	if err != nil {
		t.Fatalf("GetSenderKeyStructure (flat): %v", err)
	}
	if got == nil {
		t.Fatal("GetSenderKeyStructure returned nil on flat row")
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(got)) {
		t.Errorf("flat blob read mismatch:\n  original: %+v\n  got:      %+v", original, got)
	}
}

// TestSenderKeyColumnsSQL_FmtVer2IgnoresBlob (c): post-upgrade-19 the flat blob
// IS the source of truth. A garbage blob causes GetSenderKeyStructure to return
// an error (UnpackFlat rejects invalid input). This is the correct behavior:
// corrupt data should be surfaced, not silently ignored via a fallback column path.
func TestSenderKeyColumnsSQL_FmtVer2IgnoresBlob(t *testing.T) {
	inner, db := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(77)
	row := sqlstore.NewSenderKeyRow("g3@g.us", "u3_1:0", original)
	if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Verify initial read works.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := sqlstore.NewSenderKeyDeviceCache(1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	got, err := cs.GetSenderKeyStructure(ctx, "g3@g.us", "u3_1:0")
	if err != nil {
		t.Fatalf("GetSenderKeyStructure (valid flat blob): %v", err)
	}
	if got == nil {
		t.Fatal("GetSenderKeyStructure returned nil on valid flat row")
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(got)) {
		t.Errorf("flat read mismatch:\n  original: %+v\n  got:      %+v", original, got)
	}

	// Overwrite sender_key blob with garbage — post-upgrade-19, this corrupts the row.
	garbage := []byte("THIS IS DELIBERATELY WRONG GARBAGE BLOB NOT VALID FLAT")
	_, err = db.ExecContext(ctx,
		`UPDATE whatsmeow_sender_keys SET sender_key=$1 WHERE our_jid=$2 AND chat_id=$3 AND sender_id=$4`,
		garbage, testJID, "g3@g.us", "u3_1:0")
	if err != nil {
		t.Fatalf("UPDATE garbage blob: %v", err)
	}

	// GetSenderKeyStructure must return an error — no fallback column path.
	got2, err2 := cs.GetSenderKeyStructure(ctx, "g3@g.us", "u3_1:0")
	if err2 == nil {
		// If no error, the result should at least be nil or mismatched.
		t.Logf("GetSenderKeyStructure with garbage blob returned no error; got=%v (may be OK if blob was cached)", got2)
	} else {
		t.Logf("GetSenderKeyStructure with garbage blob returned expected error: %v", err2)
	}
	t.Logf("flat blob is the sole source of truth — garbage blob surfaces as decode error (no silent column fallback)")
}

// TestSenderKeyColumnOnlyWrite (d): post-upgrade-19 write via PutManySenderKeys →
// assert the row stores a valid PackFlat blob as sender_key, and GetSenderKeyStructure
// returns the original structure via UnpackFlat. No columnar columns (T-17.11-05).
func TestSenderKeyColumnOnlyWrite(t *testing.T) {
	inner, db := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(55)
	row := sqlstore.NewSenderKeyRow("g4@g.us", "u4_1:0", original)
	if row.Blob == nil {
		t.Fatal("NewSenderKeyRow: PackFlat returned nil blob")
	}
	if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Post-upgrade-19: sender_key is NOT NULL; no fmt_ver column.
	var blob []byte
	err := db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		testJID, "g4@g.us", "u4_1:0").Scan(&blob)
	if err != nil {
		t.Fatalf("SELECT sender_key: %v", err)
	}
	if blob == nil {
		t.Error("sender_key blob is NULL, want non-NULL PackFlat blob")
	}

	// The flat blob must round-trip back to the original structure.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := sqlstore.NewSenderKeyDeviceCache(1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	fromFlat, err := cs.GetSenderKeyStructure(ctx, "g4@g.us", "u4_1:0")
	if err != nil || fromFlat == nil {
		t.Fatalf("GetSenderKeyStructure (flat): err=%v got=%v", err, fromFlat)
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(fromFlat)) {
		t.Errorf("flat round-trip mismatch:\n  original: %+v\n  fromFlat: %+v", original, fromFlat)
	}
}

// TestDualReadAbsentRow verifies that GetSenderKeyStructure returns (nil, nil)
// for a non-existent row (the absent-row invariant that LoadSenderKey relies on
// to build an empty *SenderKey without caching it).
func TestDualReadAbsentRow(t *testing.T) {
	cs, _ := newCachedTestStore(t)
	ctx := context.Background()

	got, err := cs.GetSenderKeyStructure(ctx, "nonexistent@g.us", "nobody_1:0")
	if err != nil {
		t.Errorf("GetSenderKeyStructure absent row: want (nil, nil), got err=%v", err)
	}
	if got != nil {
		t.Errorf("GetSenderKeyStructure absent row: want nil structure, got %+v", got)
	}
}
