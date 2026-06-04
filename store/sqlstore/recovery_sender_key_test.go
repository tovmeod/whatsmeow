// Copyright (c) 2026 Kavtov Platform (Phase 17.9 / Phase 17.11)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key_test.go — TestRecoverSenderKeyCrossAccount + TestRecoveryScanQueryFlat
//
// TestRecoverSenderKeyCrossAccount verifies cross-account sender-key recovery (plan 05):
//
//  1. fmt_ver=2 donor arm: seed account A with a columnar row, recover into B.
//  2. fmt_ver=1 legacy-blob donor arm: seed account A with a legacy blob row,
//     recover into B. (T-17.9-20: must work before backfill, when fmt_ver=1 dominates.)
//  3. Forward-only rejection arm: donor with chain_iter > targetIter is rejected.
//  4. Closest-iter arm: two donors ≤ target, the one with the higher iter wins.
//  5. Copy correctness: the recovered row under B is fmt_ver=2 with the correct
//     recipient-independent fields (signing keys + chain key/iter). No NULL-blob.
//
// TestRecoveryScanQueryFlat (Phase 17.11 plan 05) verifies the flat two-path donor scan:
//
//  1. Fast-path arm: single-state donor whose state[0].KeyID == targetKeyID → sk_keyid0
//     index scan finds it; UnpackFlat returns correct KeyID/Iteration.
//  2. Fallback arm: multi-state donor whose targetKeyID is in state[1] only → fast path
//     returns no donor (sk_keyid0 = state[0] mismatch); LIKE-only fallback scans all states
//     and finds it; UnpackFlat returns correct KeyID/Iteration.
//  3. Both arms are DB-backed — SKIP means the test PG is unreachable (GATE FAILURE).
//
// All arms use a donor device suffix DIFFERENT from the recovering account's
// target sender_id to verify the device-tolerant (bare-user LIKE) behavior.
//
// Requires: a live Postgres DB at the test DSN (setup-test-db.sh applied schema + upgrade 19).
// Skips cleanly when the DB is not reachable.

package sqlstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// recovery test JIDs — two separate accounts
const (
	recoveryTestJIDA = "17799990001@s.whatsapp.net" // donor account
	recoveryTestJIDB = "17799990002@s.whatsapp.net" // recovering account
)

// insertRecoveryTestDevice inserts a whatsmeow_device row for the given JID.
// Returns a cleanup function that deletes the device row (cascading to sender_keys).
func insertRecoveryTestDevice(t *testing.T, db *sql.DB, jid string) func() {
	t.Helper()
	ctx := context.Background()
	thirtyTwo := bytes.Repeat([]byte{0x11}, 32)
	sixtyFour := bytes.Repeat([]byte{0x22}, 64)
	_, err := db.ExecContext(ctx, insertTestDeviceQuery,
		jid, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	)
	if err != nil {
		t.Fatalf("insert recovery test device %s: %v", jid, err)
	}
	return func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM whatsmeow_device WHERE jid=$1`, jid)
	}
}

// newRecoveryTestStoreB creates a CachedSenderKeyStore for the recovering account B.
// The CachedSenderKeyStore wraps an inner *SQLStore (bound to B's JID) and is the
// entry-point for RecoverSenderKey (which calls PutSenderKeyStructure internally).
// No flusher is wired — the write-through fallback fires PutManySenderKeys directly,
// which produces a fmt_ver=2 row with a recomposed blob immediately.
//
// NOTE: does NOT close the container on cleanup — the container wraps the shared
// test DB handle; closing it would close the underlying pool used by other arms.
func newRecoveryTestStoreB(t *testing.T, db *sql.DB) *sqlstore.CachedSenderKeyStore {
	t.Helper()
	jidB, err := types.ParseJID(recoveryTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)

	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	return sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache)
}

// buildDonorStructure builds a SenderKeyStructure with one state: the given
// keyID, iteration, and distinct non-nil signing keys (to verify recipient-
// independent field round-trip).
func buildDonorStructure(keyID, iter uint32, tag byte) *groupRecord.SenderKeyStructure {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = tag + byte(i)
	}
	pub := make([]byte, 33)
	pub[0] = 0x05
	for i := 1; i < 33; i++ {
		pub[i] = tag + 0x10 + byte(i)
	}
	priv := make([]byte, 32)
	for i := range priv {
		priv[i] = tag + 0x80 + byte(i)
	}
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: keyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter,
					ChainKey:  chainKey,
				},
				SigningKeyPublic:  pub,
				SigningKeyPrivate: priv,
				Keys:             nil,
			},
		},
	}
}

// insertFlatBlobRow inserts a PackFlat-encoded sender-key row for the given account.
// Post-upgrade-19: all rows are flat (no columnar columns, no fmt_ver).
// Previously called insertLegacyBlobRow; now encodes as PackFlat.
func insertFlatBlobRow(t *testing.T, db *sql.DB, ourJID, group, senderID string, structure *groupRecord.SenderKeyStructure) {
	t.Helper()
	blob, ok := store.PackFlat(structure)
	if !ok {
		t.Fatalf("PackFlat returned nil for %s", senderID)
	}
	_, err := db.ExecContext(context.Background(),
		`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, sender_key)
		 VALUES ($1, $2, $3, $4)
		 ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET
		   sender_key=excluded.sender_key`,
		ourJID, group, senderID, blob,
	)
	if err != nil {
		t.Fatalf("insertFlatBlobRow: %v", err)
	}
}

// normalizeSKNilPriv treats nil and all-zero SigningKeyPrivate as equivalent
// (libsignal stores zeros for nil). Used for round-trip comparison.
func normalizeSKNilPriv(priv []byte) []byte {
	if len(priv) == 0 {
		return nil
	}
	allZero := true
	for _, b := range priv {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		return nil
	}
	return priv
}

// newSeedStoreA creates a *SQLStore for the donor account A (for seeding fmt_ver=2 rows).
//
// NOTE: does NOT close the container on cleanup — the container wraps the shared
// test DB handle; closing it would close the underlying pool used by other arms.
func newSeedStoreA(t *testing.T, db *sql.DB) *sqlstore.SQLStore {
	t.Helper()
	jidA, err := types.ParseJID(recoveryTestJIDA)
	if err != nil {
		t.Fatalf("ParseJID A: %v", err)
	}
	containerA := sqlstore.NewWithDB(db, "postgres", nil)
	return sqlstore.NewSQLStore(containerA, jidA)
}

// TestRecoverSenderKeyCrossAccount verifies cross-account recovery correctness.
func TestRecoverSenderKeyCrossAccount(t *testing.T) {
	// Open the test DB (same DSN as other integration tests).
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	// Insert both test device rows.
	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	// Donor device suffix (A's device) is ":5"; recovering account's target suffix is ":0".
	// This proves device-tolerant: the bare user matches regardless of suffix.
	const (
		group        = "recovtest_group@g.us"
		bareUser     = "55512349876_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		targetKeyID  = uint32(42)
	)
	donorSenderID  := bareUser + donorSuffix  // A's sender_id
	targetSenderID := bareUser + targetSuffix // B's target sender_id for recovery write

	// -----------------------------------------------------------------------
	// Arm 1: fmt_ver=2 donor
	// Seed account A with a columnar row (iter=10, keyID=42).
	// targetIter=15 (donor=10 ≤ 15 → accepted).
	// Expected: recovery succeeds, row under B is fmt_ver=2, iter=10.
	// -----------------------------------------------------------------------
	t.Run("fmt_ver2_donor", func(t *testing.T) {
		ctx := context.Background()

		// Cleanup any leftover rows from previous test runs.
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A: columnar fmt_ver=2 row (iter=10, keyID=42, donor suffix :5).
		donorStruct := buildDonorStructure(targetKeyID, 10, 0xAA)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, donorStruct)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A fmt_ver=2: %v", err)
		}

		// Recover into B with targetIter=15 (donor=10 ≤ 15 → accepted).
		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 15)
		if err != nil {
			t.Fatalf("RecoverSenderKey: %v", err)
		}
		if !ok {
			t.Fatal("RecoverSenderKey: expected true (donor found), got false")
		}

		// Verify the recovered row via UnpackFlat (post-upgrade-19: no columnar columns).
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("read recovered sender_key: err=%v blob=%v", err, blob)
		}
		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil || unpacked == nil || len(unpacked.SenderKeyStates) == 0 {
			t.Fatalf("UnpackFlat recovered row: err=%v got=%v", uErr, unpacked)
		}
		recvState := unpacked.SenderKeyStates[0]
		if recvState.SenderChainKey.Iteration != 10 {
			t.Errorf("fmt_ver2 arm: want iter=10, got %d", recvState.SenderChainKey.Iteration)
		}

		donorState := donorStruct.SenderKeyStates[0]
		if !bytes.Equal(donorState.SigningKeyPublic, recvState.SigningKeyPublic) {
			t.Errorf("fmt_ver2 arm: SigningKeyPublic mismatch:\n  donor: %x\n  recv:  %x",
				donorState.SigningKeyPublic, recvState.SigningKeyPublic)
		}
		if !bytes.Equal(donorState.SenderChainKey.ChainKey, recvState.SenderChainKey.ChainKey) {
			t.Errorf("fmt_ver2 arm: ChainKey mismatch:\n  donor: %x\n  recv:  %x",
				donorState.SenderChainKey.ChainKey, recvState.SenderChainKey.ChainKey)
		}
		normalDonor := normalizeSKNilPriv(donorState.SigningKeyPrivate)
		normalRecv := normalizeSKNilPriv(recvState.SigningKeyPrivate)
		if !reflect.DeepEqual(normalDonor, normalRecv) {
			t.Errorf("fmt_ver2 arm: SigningKeyPrivate mismatch (nil-normalized):\n  donor: %x\n  recv:  %x",
				normalDonor, normalRecv)
		}
		t.Logf("fmt_ver2 arm: PASS — donor iter=10, target=15, recovered iter=%d", recvState.SenderChainKey.Iteration)
	})

	// -----------------------------------------------------------------------
	// Arm 2: flat donor arm (previously fmt_ver=1 legacy blob)
	// Post-upgrade-19: all rows are PackFlat. Seed A with a flat row (iter=20, keyID=42).
	// Recovery must unpack the flat blob and find the donor.
	// -----------------------------------------------------------------------
	t.Run("fmt_ver1_legacy_donor", func(t *testing.T) {
		ctx := context.Background()

		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		csB := newRecoveryTestStoreB(t, db)

		// Seed A: flat PackFlat row (iter=20, keyID=42, donor suffix :5).
		donorStruct := buildDonorStructure(targetKeyID, 20, 0xBB)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		// Recover into B with targetIter=25 (donor=20 ≤ 25 → accepted).
		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 25)
		if err != nil {
			t.Fatalf("RecoverSenderKey (flat arm): %v", err)
		}
		if !ok {
			t.Fatal("RecoverSenderKey (flat arm): expected true (donor found via UnpackFlat), got false")
		}

		// Verify the recovered row via UnpackFlat.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("flat arm: read recovered sender_key: err=%v blob=%v", err, blob)
		}
		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil || unpacked == nil || len(unpacked.SenderKeyStates) == 0 {
			t.Fatalf("flat arm: UnpackFlat recovered row: err=%v got=%v", uErr, unpacked)
		}
		if unpacked.SenderKeyStates[0].SenderChainKey.Iteration != 20 {
			t.Errorf("flat arm: want iter=20, got %d", unpacked.SenderKeyStates[0].SenderChainKey.Iteration)
		}
		t.Logf("flat arm: PASS — flat donor iter=20, target=25, recovered iter=%d", unpacked.SenderKeyStates[0].SenderChainKey.Iteration)
	})

	// -----------------------------------------------------------------------
	// Arm 3: forward-only rejection
	// Seed A with iter=30, targetIter=25 (30 > 25 → must be rejected).
	// Expected: no qualifying donor → RecoverSenderKey returns (false, nil).
	// -----------------------------------------------------------------------
	t.Run("forward_only_rejection", func(t *testing.T) {
		ctx := context.Background()

		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A with a donor at iter=30 (too far ahead).
		forwardDonor := buildDonorStructure(targetKeyID, 30, 0xCC)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, forwardDonor)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A (forward-only arm): %v", err)
		}

		// Attempt recovery with targetIter=25 (donor=30 > 25 → reject).
		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 25)
		if err != nil {
			t.Fatalf("RecoverSenderKey (forward-only arm): %v", err)
		}
		if ok {
			t.Error("forward-only arm: expected false (donor iter=30 > target=25 rejected), got true")
		}
		// Verify nothing was written to B.
		var count int
		_ = db.QueryRowContext(ctx,
			`SELECT COUNT(*) FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&count)
		if count != 0 {
			t.Errorf("forward-only arm: expected 0 rows under B, got %d", count)
		}
		t.Logf("forward-only arm: PASS — donor iter=30 rejected for target=25, nothing written to B")
	})

	// -----------------------------------------------------------------------
	// Arm 4: closest-iter selection (two donors ≤ target, max wins)
	// Seed A with two different sender_ids at iter=5 and iter=12 (both ≤ 15).
	// targetIter=15 → donor with iter=12 should win.
	// We use two device suffixes (:5 and :7) for the same bare user.
	// -----------------------------------------------------------------------
	t.Run("closest_iter_max_wins", func(t *testing.T) {
		ctx := context.Background()

		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		donorSenderID5  := fmt.Sprintf("%s:5", bareUser)
		donorSenderID7 := fmt.Sprintf("%s:7", bareUser)

		struct5  := buildDonorStructure(targetKeyID, 5,  0xD1)
		struct12 := buildDonorStructure(targetKeyID, 12, 0xD2)

		rows := []sqlstore.SenderKeyRow{
			sqlstore.NewSenderKeyRow(group, donorSenderID5,  struct5),
			sqlstore.NewSenderKeyRow(group, donorSenderID7, struct12),
		}
		if err := storeA.PutManySenderKeys(ctx, rows); err != nil {
			t.Fatalf("seed A (closest-iter arm): %v", err)
		}

		// Recover into B with targetIter=15. Best donor = iter=12.
		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 15)
		if err != nil {
			t.Fatalf("RecoverSenderKey (closest-iter arm): %v", err)
		}
		if !ok {
			t.Fatal("closest-iter arm: expected true (two donors), got false")
		}

		// The recovered iter must be 12 (the maximum ≤ 15) — verify via UnpackFlat.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("closest-iter arm: read recovered sender_key: err=%v blob=%v", err, blob)
		}
		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil || unpacked == nil || len(unpacked.SenderKeyStates) == 0 {
			t.Fatalf("closest-iter arm: UnpackFlat: err=%v got=%v", uErr, unpacked)
		}
		recvSt := unpacked.SenderKeyStates[0]
		if recvSt.SenderChainKey.Iteration != 12 {
			t.Errorf("closest-iter arm: want iter=12 (max of {5,12} ≤ 15), got %d", recvSt.SenderChainKey.Iteration)
		}

		// Verify the chain key belongs to struct12 (tag=0xD2).
		expectedChainKey := make([]byte, 32)
		for i := range expectedChainKey {
			expectedChainKey[i] = 0xD2 + byte(i)
		}
		if !bytes.Equal(recvSt.SenderChainKey.ChainKey, expectedChainKey) {
			t.Errorf("closest-iter arm: ChainKey mismatch — want tag=0xD2 (iter=12 donor):\n  got:  %x\n  want: %x",
				recvSt.SenderChainKey.ChainKey, expectedChainKey)
		}
		t.Logf("closest-iter arm: PASS — donors {iter=5, iter=12} for target=15; recovered iter=%d (max wins)", recvSt.SenderChainKey.Iteration)
	})

	// -----------------------------------------------------------------------
	// Arm 5: no donor (different key_id — must not match)
	// -----------------------------------------------------------------------
	t.Run("no_donor_wrong_key_id", func(t *testing.T) {
		ctx := context.Background()

		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A with keyID=99 (≠ targetKeyID=42).
		wrongKeyStruct := buildDonorStructure(99, 5, 0xEE)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, wrongKeyStruct)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A (wrong-key-id arm): %v", err)
		}

		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 10)
		if err != nil {
			t.Fatalf("RecoverSenderKey (wrong-key-id): %v", err)
		}
		if ok {
			t.Error("wrong-key-id arm: expected false (donor keyID=99 ≠ target 42), got true")
		}
		t.Logf("wrong-key-id arm: PASS — keyID mismatch → no recovery")
	})
}

// -----------------------------------------------------------------------
// TestRecoveryScanQueryFlat — Phase 17.11 plan 05 flat two-path scan gate
// -----------------------------------------------------------------------
//
// BLOCKING gate (must be --- PASS, never --- SKIP, when the test DB is reachable):
//
//  Arm 1 — fast path: single-state donor, state[0].KeyID == targetKeyID.
//    recoveryScanQueryFast (chat_id + sk_keyid0=$targetKeyID + LIKE) finds the donor.
//    UnpackFlat returns correct KeyID and Iteration.
//
//  Arm 2 — fallback path: two-state donor, targetKeyID is in state[1] only.
//    recoveryScanQueryFast misses (sk_keyid0 = state[0].KeyID ≠ targetKeyID).
//    recoveryScanQuery (LIKE-only, all states) finds the donor in state[1].
//    UnpackFlat returns correct KeyID and Iteration.
//
// Both arms insert flat PackFlat blobs directly via SQL (not via the columnar
// PutManySenderKeys path — the columnar columns no longer exist after upgrade 19).
// The test is DB-backed; any SKIP is a gate failure.
func TestRecoveryScanQueryFlat(t *testing.T) {
	ctx := context.Background()

	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	// Verify upgrade 19 has been applied (sk_keyid0 column must exist).
	var hasFlatSchema bool
	err = db.QueryRowContext(ctx,
		`SELECT EXISTS(
			SELECT 1 FROM information_schema.columns
			WHERE table_name='whatsmeow_sender_keys' AND column_name='sk_keyid0'
		)`,
	).Scan(&hasFlatSchema)
	if err != nil {
		db.Close()
		t.Fatalf("schema check: %v", err)
	}
	if !hasFlatSchema {
		db.Close()
		t.Skip("upgrade 19 not applied to test DB — run setup-test-db.sh with upgrade 19 first")
	}

	// Two JIDs for flat scan test (separate from cross-account test JIDs).
	const (
		flatTestJIDA = "17799990011@s.whatsapp.net"
		flatTestJIDB = "17799990012@s.whatsapp.net"
	)

	// Insert both test device rows.
	cleanupA := insertRecoveryTestDevice(t, db, flatTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, flatTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		flatGroup    = "recovtest_flat@g.us"
		flatBareUser = "55599871234_2"
	)

	// buildFlatDonorStructure creates a multi-state structure where:
	//   state[0].KeyID = state0KeyID, state[1].KeyID = state1KeyID
	// This lets us test the two-path scan: fast path filters by sk_keyid0 (state[0])
	// while targetKeyID in state[1] only is found by the fallback LIKE-only path.
	buildFlatDonorStructure := func(state0KeyID, state1KeyID uint32, iter0, iter1 uint32, tag byte) *groupRecord.SenderKeyStructure {
		makeChainKey := func(base byte) []byte {
			ck := make([]byte, 32)
			for i := range ck {
				ck[i] = base + byte(i)
			}
			return ck
		}
		makePub := func(base byte) []byte {
			p := make([]byte, 33)
			p[0] = 0x05
			for i := 1; i < 33; i++ {
				p[i] = base + byte(i)
			}
			return p
		}
		makePriv := func(base byte) []byte {
			p := make([]byte, 32)
			for i := range p {
				p[i] = base + 0x80 + byte(i)
			}
			return p
		}
		states := []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: state0KeyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter0,
					ChainKey:  makeChainKey(tag),
				},
				SigningKeyPublic:  makePub(tag),
				SigningKeyPrivate: makePriv(tag),
			},
		}
		if state1KeyID != 0 {
			states = append(states, &groupRecord.SenderKeyStateStructure{
				KeyID: state1KeyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter1,
					ChainKey:  makeChainKey(tag + 0x10),
				},
				SigningKeyPublic:  makePub(tag + 0x10),
				SigningKeyPrivate: makePriv(tag + 0x10),
			})
		}
		return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
	}

	// insertFlatRow inserts a PackFlat blob directly via SQL, bypassing the
	// columnar PutManySenderKeys path (which no longer exists in flat schema).
	insertFlatRow := func(t *testing.T, ourJID, senderID string, s *groupRecord.SenderKeyStructure) {
		t.Helper()
		packed, ok := store.PackFlat(s)
		if !ok {
			t.Fatalf("PackFlat failed for %s", senderID)
		}
		_, err := db.ExecContext(ctx,
			`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, sender_key)
			 VALUES ($1, $2, $3, $4)
			 ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET sender_key=excluded.sender_key`,
			ourJID, flatGroup, senderID, packed,
		)
		if err != nil {
			t.Fatalf("insertFlatRow %s: %v", senderID, err)
		}
	}

	// Arm 1 — fast path: single-state donor, state[0].KeyID=77, iter=15.
	// RecoverSenderKey with targetKeyID=77, targetIter=20 should find this donor
	// via the fast path (sk_keyid0 = 77 = targetKeyID).
	t.Run("fast_path_single_state", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			flatTestJIDA, flatTestJIDB, flatGroup)

		const (
			fastTargetKeyID = uint32(77)
			fastTargetIter  = uint32(20)
			fastDonorIter   = uint32(15)
		)

		// Single-state donor: state[0].KeyID=77, iter=15.
		donorStruct := buildFlatDonorStructure(fastTargetKeyID, 0, fastDonorIter, 0, 0xAA)
		donorSenderID := flatBareUser + ":3"
		insertFlatRow(t, flatTestJIDA, donorSenderID, donorStruct)

		// Recover into B: targetKeyID=77, targetIter=20 (donor=15 ≤ 20 → accepted).
		flatJIDB, _ := types.ParseJID(flatTestJIDB)
		containerB := sqlstore.NewWithDB(db, "postgres", nil)
		innerB := sqlstore.NewSQLStore(containerB, flatJIDB)
		byteCache, _ := lru.New[string, []byte](256)
		devCache, _ := lru.New[string, []string](256)
		csB := sqlstore.NewCachedSenderKeyStore(innerB, flatTestJIDB, byteCache, devCache)

		targetSenderID := flatBareUser + ":0"
		ok, err := csB.RecoverSenderKey(ctx, flatGroup, targetSenderID, flatBareUser, fastTargetKeyID, fastTargetIter)
		if err != nil {
			t.Fatalf("fast-path arm: RecoverSenderKey: %v", err)
		}
		if !ok {
			t.Fatal("fast-path arm: expected true (donor found via sk_keyid0 fast path), got false")
		}

		// Verify: UnpackFlat on the recovered row returns correct KeyID + Iteration.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			flatTestJIDB, flatGroup, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("fast-path arm: read recovered sender_key: err=%v blob=%v", err, blob)
		}
		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil {
			t.Fatalf("fast-path arm: UnpackFlat: %v", uErr)
		}
		if len(unpacked.SenderKeyStates) == 0 {
			t.Fatal("fast-path arm: UnpackFlat returned 0 states")
		}
		gotSt := unpacked.SenderKeyStates[0]
		if gotSt.KeyID != fastTargetKeyID {
			t.Errorf("fast-path arm: KeyID want %d got %d", fastTargetKeyID, gotSt.KeyID)
		}
		if gotSt.SenderChainKey.Iteration != fastDonorIter {
			t.Errorf("fast-path arm: Iteration want %d got %d", fastDonorIter, gotSt.SenderChainKey.Iteration)
		}

		// Verify the ChainKey matches the donor's state[0] chain key.
		donorState0 := donorStruct.SenderKeyStates[0]
		if !bytes.Equal(gotSt.SenderChainKey.ChainKey, donorState0.SenderChainKey.ChainKey) {
			t.Errorf("fast-path arm: ChainKey mismatch:\n  donor: %x\n  got:   %x",
				donorState0.SenderChainKey.ChainKey, gotSt.SenderChainKey.ChainKey)
		}
		t.Logf("fast-path arm: PASS — sk_keyid0 fast path found donor keyID=%d iter=%d", gotSt.KeyID, gotSt.SenderChainKey.Iteration)
	})

	// Arm 2 — fallback path: two-state donor, targetKeyID is in state[1] only.
	// The fast path (sk_keyid0 = state[0].KeyID = 88) misses targetKeyID=99.
	// The LIKE-only fallback scans all states and finds targetKeyID=99 in state[1].
	t.Run("fallback_path_state1_only", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			flatTestJIDA, flatTestJIDB, flatGroup)

		const (
			state0KeyID     = uint32(88) // state[0] — does NOT match targetKeyID
			fallbackTarget  = uint32(99) // state[1] — DOES match targetKeyID
			state0Iter      = uint32(5)
			state1Iter      = uint32(12)
			fallbackTargetIter = uint32(20) // targetIter > both donors → accepted
		)

		// Two-state donor: state[0].KeyID=88 (fast-path miss), state[1].KeyID=99 (fallback hit).
		donorStruct := buildFlatDonorStructure(state0KeyID, fallbackTarget, state0Iter, state1Iter, 0xBB)
		donorSenderID := flatBareUser + ":4"
		insertFlatRow(t, flatTestJIDA, donorSenderID, donorStruct)

		// Recover into B: targetKeyID=99, targetIter=20.
		// Fast path: sk_keyid0 = state[0].KeyID = 88 ≠ 99 → no fast-path donor.
		// Fallback: LIKE scan finds the row, Go decodes both states, finds keyID=99 in state[1].
		flatJIDB, _ := types.ParseJID(flatTestJIDB)
		containerB := sqlstore.NewWithDB(db, "postgres", nil)
		innerB := sqlstore.NewSQLStore(containerB, flatJIDB)
		byteCache, _ := lru.New[string, []byte](256)
		devCache, _ := lru.New[string, []string](256)
		csB := sqlstore.NewCachedSenderKeyStore(innerB, flatTestJIDB, byteCache, devCache)

		targetSenderID := flatBareUser + ":0"
		ok, err := csB.RecoverSenderKey(ctx, flatGroup, targetSenderID, flatBareUser, fallbackTarget, fallbackTargetIter)
		if err != nil {
			t.Fatalf("fallback-path arm: RecoverSenderKey: %v", err)
		}
		if !ok {
			t.Fatal("fallback-path arm: expected true (donor found via LIKE fallback scan), got false")
		}

		// Verify the recovered row: UnpackFlat should return a structure with
		// KeyID=99 (the matching state from state[1]) and Iteration=12.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			flatTestJIDB, flatGroup, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("fallback-path arm: read recovered sender_key: err=%v blob=%v", err, blob)
		}
		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil {
			t.Fatalf("fallback-path arm: UnpackFlat: %v", uErr)
		}
		if len(unpacked.SenderKeyStates) == 0 {
			t.Fatal("fallback-path arm: UnpackFlat returned 0 states")
		}
		gotSt := unpacked.SenderKeyStates[0]
		if gotSt.KeyID != fallbackTarget {
			t.Errorf("fallback-path arm: KeyID want %d got %d", fallbackTarget, gotSt.KeyID)
		}
		if gotSt.SenderChainKey.Iteration != state1Iter {
			t.Errorf("fallback-path arm: Iteration want %d got %d", state1Iter, gotSt.SenderChainKey.Iteration)
		}

		// Verify ChainKey belongs to state[1] (tag=0xBB+0x10=0xCB).
		donorState1 := donorStruct.SenderKeyStates[1]
		if !bytes.Equal(gotSt.SenderChainKey.ChainKey, donorState1.SenderChainKey.ChainKey) {
			t.Errorf("fallback-path arm: ChainKey mismatch (expected state[1] chain key):\n  donor state[1]: %x\n  got:            %x",
				donorState1.SenderChainKey.ChainKey, gotSt.SenderChainKey.ChainKey)
		}
		t.Logf("fallback-path arm: PASS — LIKE fallback found keyID=%d in state[1], recovered iter=%d", gotSt.KeyID, gotSt.SenderChainKey.Iteration)
	})

	// Arm 3 — round-trip: insert flat blob, verify UnpackFlat returns correct structure.
	// This verifies the flat codec (PackFlat/UnpackFlat) end-to-end at the DB level.
	t.Run("flat_round_trip", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			flatTestJIDA, flatTestJIDB, flatGroup)

		const (
			rtKeyID = uint32(55)
			rtIter  = uint32(7)
		)
		rtStruct := buildFlatDonorStructure(rtKeyID, 0, rtIter, 0, 0xDD)
		senderID := flatBareUser + ":6"
		insertFlatRow(t, flatTestJIDA, senderID, rtStruct)

		var blob []byte
		err := db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			flatTestJIDA, flatGroup, senderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("round-trip: read sender_key: err=%v blob=%v", err, blob)
		}

		unpacked, uErr := store.UnpackFlat(blob)
		if uErr != nil {
			t.Fatalf("round-trip: UnpackFlat: %v", uErr)
		}

		// Normalize and DeepEqual
		normState := func(s *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
			for _, st := range s.SenderKeyStates {
				if st.Keys == nil {
					st.Keys = nil // nil stays nil
				}
			}
			return s
		}
		if !reflect.DeepEqual(normState(rtStruct), normState(unpacked)) {
			t.Errorf("round-trip: DeepEqual failed\n  orig:     %+v\n  unpacked: %+v", rtStruct, unpacked)
		}
		t.Logf("round-trip: PASS — PackFlat/UnpackFlat round-trip at DB level, keyID=%d iter=%d", rtKeyID, rtIter)
	})
}
