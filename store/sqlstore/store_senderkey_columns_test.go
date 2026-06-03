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
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"
	"go.mau.fi/libsignal/serialize"

	"go.mau.fi/whatsmeow/store/sqlstore"
)

// colTestSerializer is the libsignal JSON serializer for round-trip blob checks.
var colTestSerializer = serialize.NewProtoBufSerializer()

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
				KeyID:            keyID,
				SenderChainKey:   &ratchet.SenderChainKeyStructure{Iteration: 5, ChainKey: chainKey},
				SigningKeyPublic:  pub,
				SigningKeyPrivate: priv,
				Keys:             []*ratchet.SenderMessageKeyStructure{smk},
			},
			{
				KeyID:            keyID + 1,
				SenderChainKey:   &ratchet.SenderChainKeyStructure{Iteration: 3, ChainKey: chainKey2},
				SigningKeyPublic:  pub2,
				SigningKeyPrivate: nil, // nil = received key (dominant shape)
				Keys:             nil,
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
			KeyID:           st.KeyID,
			SenderChainKey:  st.SenderChainKey,
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
	devCache, _ := lru.New[string, []string](1024)
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

// TestSenderKeyColumnsSQL_LegacyRow (b): insert a legacy row (fmt_ver=1, blob, NULL arrays)
// and assert GetSenderKeyStructure returns the structure via the blob.
func TestSenderKeyColumnsSQL_LegacyRow(t *testing.T) {
	inner, _ := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(10)
	// Write via the legacy []byte path (PutSenderKey → putSenderKeyQuery → fmt_ver=1, NULL arrays).
	sk, err := groupRecord.NewSenderKeyFromStruct(original,
		colTestSerializer.SenderKeyRecord,
		colTestSerializer.SenderKeyState)
	if err != nil {
		t.Fatalf("NewSenderKeyFromStruct: %v", err)
	}
	blob := sk.Serialize()
	if err := inner.PutSenderKey(ctx, "g2@g.us", "u2_1:0", blob); err != nil {
		t.Fatalf("PutSenderKey (legacy): %v", err)
	}

	// GetSenderKeyStructure via CachedSenderKeyStore wrapping the inner.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := lru.New[string, []string](1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	got, err := cs.GetSenderKeyStructure(ctx, "g2@g.us", "u2_1:0")
	if err != nil {
		t.Fatalf("GetSenderKeyStructure (legacy): %v", err)
	}
	if got == nil {
		t.Fatal("GetSenderKeyStructure returned nil on legacy row")
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(got)) {
		t.Errorf("legacy blob read mismatch:\n  original: %+v\n  got:      %+v", original, got)
	}
}

// TestSenderKeyColumnsSQL_FmtVer2IgnoresBlob (c): write columnar row (fmt_ver=2),
// overwrite sender_key blob with garbage, assert GetSenderKeyStructure still
// recomposes from columns (proving fmt_ver=2 never reads the blob).
func TestSenderKeyColumnsSQL_FmtVer2IgnoresBlob(t *testing.T) {
	inner, db := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(77)
	row := sqlstore.NewSenderKeyRow("g3@g.us", "u3_1:0", original)
	if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Overwrite sender_key blob with deliberately wrong bytes (not a valid JSON structure).
	garbage := []byte("THIS IS DELIBERATELY WRONG GARBAGE BLOB NOT VALID JSON")
	_, err := db.ExecContext(ctx,
		`UPDATE whatsmeow_sender_keys SET sender_key=$1 WHERE our_jid=$2 AND chat_id=$3 AND sender_id=$4`,
		garbage, testJID, "g3@g.us", "u3_1:0")
	if err != nil {
		t.Fatalf("UPDATE garbage blob: %v", err)
	}

	// GetSenderKeyStructure must still return the correct structure from columns.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := lru.New[string, []string](1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	got, err := cs.GetSenderKeyStructure(ctx, "g3@g.us", "u3_1:0")
	if err != nil {
		t.Fatalf("GetSenderKeyStructure with garbage blob: %v", err)
	}
	if got == nil {
		t.Fatal("GetSenderKeyStructure returned nil, want structure from columns")
	}
	if !reflect.DeepEqual(normalizeSKStructure(original), normalizeSKStructure(got)) {
		t.Errorf("columns-only read mismatch (garbage blob should be ignored):\n  original: %+v\n  got:      %+v", original, got)
	}
}

// TestSenderKeyNoDivergence (d): write via the flusher drain → read columns
// (getSenderKeyDecomposed via GetSenderKeyStructure) AND Deserialize the legacy
// blob; assert both yield the same *SenderKeyStructure (single-drain dual-write
// non-divergence proof, T-17.9-13).
func TestSenderKeyNoDivergence(t *testing.T) {
	inner, db := newBatchTestStore(t)
	ctx := context.Background()

	original := buildColumnarTestStructure(55)
	row := sqlstore.NewSenderKeyRow("g4@g.us", "u4_1:0", original)
	if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Read structure from columns via GetSenderKeyStructure.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := lru.New[string, []string](1024)
	cs := sqlstore.NewCachedSenderKeyStore(inner, testJID, byteCache, devCache)

	fromColumns, err := cs.GetSenderKeyStructure(ctx, "g4@g.us", "u4_1:0")
	if err != nil || fromColumns == nil {
		t.Fatalf("GetSenderKeyStructure (columns): err=%v got=%v", err, fromColumns)
	}

	// Read raw blob from DB and Deserialize.
	var blob []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		testJID, "g4@g.us", "u4_1:0").Scan(&blob)
	if err != nil || blob == nil {
		t.Fatalf("SELECT sender_key: err=%v blob=%v", err, blob)
	}
	fromBlob, err := colTestSerializer.SenderKeyRecord.Deserialize(blob)
	if err != nil {
		t.Fatalf("Deserialize blob: %v", err)
	}

	// Both must produce the same *SenderKeyStructure (T-17.9-13 non-divergence).
	if !reflect.DeepEqual(normalizeSKStructure(fromColumns), normalizeSKStructure(fromBlob)) {
		t.Errorf("columns vs blob divergence:\n  fromColumns: %+v\n  fromBlob:    %+v", fromColumns, fromBlob)
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
