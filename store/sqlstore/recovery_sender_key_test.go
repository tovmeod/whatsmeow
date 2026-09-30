// Copyright (c) 2026 Kavtov Platform (Phase 17.9 / Phase 17.11)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key_test.go — TestRecoverSenderKeyCrossAccount + TestRecoveryScanQueryFlat
//
// TestRecoverSenderKeyCrossAccount verifies cross-account sender-key recovery
// via TryInlineRecovery (plan 05):
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
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
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
// entry-point for TryInlineRecovery (which calls PutSenderKeyStructure internally).
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
	return sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache, nil)
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
				Keys:              nil,
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
	donorSenderID := bareUser + donorSuffix   // A's sender_id
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
		// Clear the negative-donor cache for this tuple so prior subtests' scan
		// results (which may differ in targetIter) do not bleed into this subtest.
		sqlstore.DeleteNoDonorCacheEntry(group, bareUser, targetKeyID)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A: columnar fmt_ver=2 row (iter=10, keyID=42, donor suffix :5).
		donorStruct := buildDonorStructure(targetKeyID, 10, 0xAA)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, donorStruct)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A fmt_ver=2: %v", err)
		}

		// Recover into B with targetIter=15 (donor=10 ≤ 15 → accepted).
		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 15)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if !ok {
			t.Fatal("TryInlineRecovery: expected true (donor found), got false")
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
		sqlstore.DeleteNoDonorCacheEntry(group, bareUser, targetKeyID)

		csB := newRecoveryTestStoreB(t, db)

		// Seed A: flat PackFlat row (iter=20, keyID=42, donor suffix :5).
		donorStruct := buildDonorStructure(targetKeyID, 20, 0xBB)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		// Recover into B with targetIter=25 (donor=20 ≤ 25 → accepted).
		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 25)
		if err != nil {
			t.Fatalf("TryInlineRecovery (flat arm): %v", err)
		}
		if !ok {
			t.Fatal("TryInlineRecovery (flat arm): expected true (donor found via UnpackFlat), got false")
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
		sqlstore.DeleteNoDonorCacheEntry(group, bareUser, targetKeyID)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A with a donor at iter=30 (too far ahead).
		forwardDonor := buildDonorStructure(targetKeyID, 30, 0xCC)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, forwardDonor)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A (forward-only arm): %v", err)
		}

		// Attempt recovery with targetIter=25 (donor=30 > 25 → reject).
		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 25)
		if err != nil {
			t.Fatalf("TryInlineRecovery (forward-only arm): %v", err)
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
		sqlstore.DeleteNoDonorCacheEntry(group, bareUser, targetKeyID)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		donorSenderID5 := fmt.Sprintf("%s:5", bareUser)
		donorSenderID7 := fmt.Sprintf("%s:7", bareUser)

		struct5 := buildDonorStructure(targetKeyID, 5, 0xD1)
		struct12 := buildDonorStructure(targetKeyID, 12, 0xD2)

		rows := []sqlstore.SenderKeyRow{
			sqlstore.NewSenderKeyRow(group, donorSenderID5, struct5),
			sqlstore.NewSenderKeyRow(group, donorSenderID7, struct12),
		}
		if err := storeA.PutManySenderKeys(ctx, rows); err != nil {
			t.Fatalf("seed A (closest-iter arm): %v", err)
		}

		// Recover into B with targetIter=15. Best donor = iter=12.
		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 15)
		if err != nil {
			t.Fatalf("TryInlineRecovery (closest-iter arm): %v", err)
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
		sqlstore.DeleteNoDonorCacheEntry(group, bareUser, targetKeyID)

		storeA := newSeedStoreA(t, db)
		csB := newRecoveryTestStoreB(t, db)

		// Seed A with keyID=99 (≠ targetKeyID=42).
		wrongKeyStruct := buildDonorStructure(99, 5, 0xEE)
		rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, wrongKeyStruct)
		if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
			t.Fatalf("seed A (wrong-key-id arm): %v", err)
		}

		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 10)
		if err != nil {
			t.Fatalf("TryInlineRecovery (wrong-key-id): %v", err)
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
//	Arm 1 — fast path: single-state donor, state[0].KeyID == targetKeyID.
//	  recoveryScanQueryFast (chat_id + sk_keyid0=$targetKeyID + LIKE) finds the donor.
//	  UnpackFlat returns correct KeyID and Iteration.
//
//	Arm 2 — fallback path: two-state donor, targetKeyID is in state[1] only.
//	  recoveryScanQueryFast misses (sk_keyid0 = state[0].KeyID ≠ targetKeyID).
//	  recoveryScanQuery (LIKE-only, all states) finds the donor in state[1].
//	  UnpackFlat returns correct KeyID and Iteration.
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
	// TryInlineRecovery with targetKeyID=77, targetIter=20 should find this donor
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
		csB := sqlstore.NewCachedSenderKeyStore(innerB, flatTestJIDB, byteCache, devCache, nil)

		targetSenderID := flatBareUser + ":0"
		_, ok, err := csB.TryInlineRecovery(ctx, flatGroup, targetSenderID, flatBareUser, fastTargetKeyID, fastTargetIter)
		if err != nil {
			t.Fatalf("fast-path arm: TryInlineRecovery: %v", err)
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
			state0KeyID        = uint32(88) // state[0] — does NOT match targetKeyID
			fallbackTarget     = uint32(99) // state[1] — DOES match targetKeyID
			state0Iter         = uint32(5)
			state1Iter         = uint32(12)
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
		csB := sqlstore.NewCachedSenderKeyStore(innerB, flatTestJIDB, byteCache, devCache, nil)

		targetSenderID := flatBareUser + ":0"
		_, ok, err := csB.TryInlineRecovery(ctx, flatGroup, targetSenderID, flatBareUser, fallbackTarget, fallbackTargetIter)
		if err != nil {
			t.Fatalf("fallback-path arm: TryInlineRecovery: %v", err)
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

// TestInlineRecoveryCacheResidentRace is the D-13 cache-resident downgrade test
// (CR-01), reconciled to the flat single-cache (Phase 38.4-03).
//
// It reproduces the cache-resident ratchet-downgrade race: account B has an
// ADVANCED sender-key state (KeyID K, Iteration 50) that is cache-resident in the
// flat []byte cache AND in the flusher dirty-set, but the DB row for B is ABSENT
// (the ~1s flusher window held open deterministically by attaching a flusher that
// is never started). Account A has a STALE donor row (KeyID K, Iteration 10) in
// the DB.
//
// Phase 38.4-03: the parsed struct cache is deleted. GetSenderKeyStructure is now
// cache-aware (Plan 02) — it reads the flat c.cache BEFORE the DB. So the
// recovery guard + the ported flat-path backward-only gate (Task 2) see the
// cache-resident advanced state at Iteration=50 and REJECT the stale donor. The
// DB-backed assertion below reads through the cache-aware GetSenderKeyStructure
// and confirms the advanced state survives — the end-to-end twin of the in-package
// TestPutSenderKeyStructureRecoveryBackwardOnlyGate Case 1.
func TestInlineRecoveryCacheResidentRace(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovcache_race_group@g.us"
		bareUser     = "55512349900_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		targetKeyID  = uint32(7)
		advancedIter = uint32(50)
		staleIter    = uint32(10)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// Clean up any leftover rows from previous runs.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Build account B's CachedSenderKeyStore.
	jidB, err := types.ParseJID(recoveryTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)

	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache, nil)

	// Wire a flusher that is NOT started (attached-not-drained = stale DB window).
	flusher := sqlstore.NewSenderKeyFlusher(innerB, nil, 0)
	csB.SetFlusher(flusher)
	// flusher.Start() intentionally NOT called — no goroutine, DB stays absent.

	// Step 1: Warm the flat cache with the ADVANCED state via PutSenderKeyStructure.
	// This lands (write-through) in the flat c.cache + flusher dirty-set; the DB
	// row for B stays absent (flusher never drained).
	advancedStruct := buildDonorStructure(targetKeyID, advancedIter, 0x11)
	if err := csB.PutSenderKeyStructure(ctx, group, targetSenderID, advancedStruct); err != nil {
		t.Fatalf("PutSenderKeyStructure (advanced seed): %v", err)
	}

	// Verify the cache-aware read serves Iteration=50 before the recovery attempt
	// (flat c.cache is consulted before the DB, which is still absent for B).
	warmStruct, err := csB.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		t.Fatalf("pre-condition: GetSenderKeyStructure: %v", err)
	}
	if warmStruct == nil || len(warmStruct.SenderKeyStates) == 0 {
		t.Fatalf("pre-condition: cache-aware read miss for advanced state")
	}
	if warmStruct.SenderKeyStates[0].SenderChainKey.Iteration != advancedIter {
		t.Fatalf("pre-condition: cache iteration = %d, want %d",
			warmStruct.SenderKeyStates[0].SenderChainKey.Iteration, advancedIter)
	}

	// Step 2: Seed account A with a STALE donor row (same KeyID K, Iteration 10).
	staleStruct := buildDonorStructure(targetKeyID, staleIter, 0x22)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, staleStruct)

	// Step 3: Call TryInlineRecovery for B's (group, targetSenderID).
	// GetSenderKeyStructure is now cache-aware (Plan 02): it reads the flat c.cache
	// FIRST, sees the advanced state at Iteration=50, and the downgrade guard +
	// the ported flat-path backward-only gate (Task 2) REJECT the stale donor.
	_, recovered, recErr := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, advancedIter+5)
	if recErr != nil {
		t.Fatalf("TryInlineRecovery: %v", recErr)
	}
	// CR-03: a gate-rejected stale install must NOT be reported as a recovery —
	// ok=false so the caller does not log SENDER_KEY_RECOVERED or retry decrypt
	// against an unchanged cache.
	if recovered {
		t.Error("CR-03: TryInlineRecovery returned ok=true for a gate-rejected stale donor install")
	}

	// Step 4: Assert the cache-aware read still serves Iteration=50 — the stale
	// donor must NOT have downgraded the cache-resident advanced state.
	afterStruct, err := csB.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		t.Fatalf("D-13: GetSenderKeyStructure after recovery: %v", err)
	}
	if afterStruct == nil || len(afterStruct.SenderKeyStates) == 0 {
		t.Fatalf("D-13 FAIL: flat cache evicted after recovery install (want Iter=%d, got miss)", advancedIter)
	}
	gotIter := afterStruct.SenderKeyStates[0].SenderChainKey.Iteration
	if gotIter != advancedIter {
		t.Errorf("D-13 FAIL (CR-01): flat cache degraded — got Iter=%d, want Iter=%d "+
			"(stale donor Iter=%d overwrote cache-resident advanced state — ratchet downgraded)",
			gotIter, advancedIter, staleIter)
	}
	t.Logf("D-13: flat cache after recovery = Iter=%d (want %d)", gotIter, advancedIter)
}

// TestInlineRecoveryIterationGuard asserts the iteration-downgrade protection
// for TryInlineRecovery (the inline path added in Phase 17.12).
//
// If (group, targetSenderID) already has a row with the same KeyID at
// Iteration >= donor.Iteration, TryInlineRecovery must return ("", false, nil)
// and leave the existing row untouched.
//
// Uses only helpers already present in this file (recoveryTestJIDA/B,
// insertRecoveryTestDevice, newRecoveryTestStoreB, insertFlatBlobRow).
func TestInlineRecoveryIterationGuard(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovinline_iterguard_group@g.us"
		bareUser     = "55512340021_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		targetKeyID  = uint32(3)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// Clean up any leftover rows.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Seed donor account A at KeyID=3, Iteration=50.
	donorStruct := buildDonorStructure(targetKeyID, 50, 0xAA)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

	// Seed B's target row at KeyID=3, Iteration=100 (fresher than the donor).
	existingStruct := buildDonorStructure(targetKeyID, 100, 0xBB)
	insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

	// Build the recovering-account store (no running flusher — iteration guard
	// fires before the write, so async vs sync doesn't affect this test).
	csB := newRecoveryTestStoreB(t, db)

	// Phase 38.4-03: the parsed struct cache is gone. TryInlineRecovery's
	// downgrade guard reads the cache-aware GetSenderKeyStructure (flat c.cache,
	// then DB) and correctly sees the existing B row written to the DB above.

	// Attempt inline recovery with donor at iter=50, existing at iter=100.
	// targetIter=60 (donor=50 <= 60 so donor qualifies by forward-only filter),
	// but existing iter=100 >= donor iter=50 for same KeyID=3 → guard must fire.
	donorJID, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, targetKeyID, 60)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if ok {
		t.Fatalf("TryInlineRecovery returned true — expected false (iteration guard should have fired), donorJID=%q", donorJID)
	}
	if donorJID != "" {
		t.Errorf("expected empty donorJID on guard-fired false return, got %q", donorJID)
	}

	// Verify the DB row is still at Iteration=100 (not overwritten by donor iter=50).
	var blobDB []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&blobDB)
	if err != nil {
		t.Fatalf("read B row sender_key: %v", err)
	}
	unpackedB, uErr := store.UnpackFlat(blobDB)
	if uErr != nil || unpackedB == nil || len(unpackedB.SenderKeyStates) == 0 {
		t.Fatalf("UnpackFlat B row: err=%v got=%v", uErr, unpackedB)
	}
	iterFromBlob := unpackedB.SenderKeyStates[0].SenderChainKey.Iteration
	if iterFromBlob != 100 {
		t.Errorf("DB row iteration = %d, want 100 (must not be downgraded by donor iter=50)", iterFromBlob)
	}
	t.Logf("PASS: iteration guard fired — TryInlineRecovery returned (empty, false, nil), DB row preserved at iter=%d", iterFromBlob)
}

// TestSenderKeySubclass verifies the D-03/999.19 classifyNoDonor helper (the
// SENDERKEY_SUBCLASS classifier). It seeds a sender-key row for the recovering
// account (B) in a DIFFERENT group than the failing one, then calls ClassifyNoDonor
// and asserts keys_elsewhere=true (the "sender-alive-never-distributed" signature).
//
// Also verifies the nothing-anywhere case: no rows for B at all → keys_elsewhere=false.
//
// The test does NOT assert the log emission — it exercises only the classifier
// helper that feeds the log (per plan: factor the classification into a testable
// unexported function, keep the log emission at the call site).
func TestSenderKeySubclass(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	const (
		subclassJIDB = "17799990020@s.whatsapp.net" // account under test
		failGroup    = "subclass_fail_group@g.us"   // the group where the key is missing
		otherGroup   = "subclass_other_group@g.us"  // a different group for keys_elsewhere
		senderBare   = "55512340099_sub"
		senderID     = senderBare + ":0"
	)

	cleanupB := insertRecoveryTestDevice(t, db, subclassJIDB)
	t.Cleanup(func() {
		cleanupB()
		db.Close()
	})

	// Build the SQLStore for account B directly (classifyNoDonor takes *SQLStore).
	jidB, err := types.ParseJID(subclassJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)

	ctx := context.Background()

	// Clean up any leftover rows.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id IN ($2,$3)`,
		subclassJIDB, failGroup, otherGroup)

	// Arm 1: nothing-anywhere — no rows for B anywhere.
	// Expected: keys_elsewhere=false.
	t.Run("nothing_anywhere", func(t *testing.T) {
		fields := sqlstore.ClassifyNoDonor(ctx, innerB, subclassJIDB, failGroup, senderBare)
		if fields.KeysElsewhere {
			t.Error("nothing-anywhere arm: expected keys_elsewhere=false, got true")
		}
		t.Logf("nothing-anywhere arm: PASS — lidmap=%s keys_elsewhere=%t", fields.LIDMap, fields.KeysElsewhere)
	})

	// Arm 2: keys_elsewhere=true — B has a sender-key row for senderBare in
	// otherGroup (a different chat) but NOT in failGroup.
	t.Run("keys_elsewhere_true", func(t *testing.T) {
		// Seed B's row in otherGroup.
		keysElsewhereStruct := buildDonorStructure(99, 1, 0xAB)
		insertFlatBlobRow(t, db, subclassJIDB, otherGroup, senderID, keysElsewhereStruct)
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx,
				`DELETE FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2`,
				subclassJIDB, otherGroup)
		})

		fields := sqlstore.ClassifyNoDonor(ctx, innerB, subclassJIDB, failGroup, senderBare)
		if !fields.KeysElsewhere {
			t.Error("keys-elsewhere arm: expected keys_elsewhere=true (row in otherGroup), got false")
		}
		t.Logf("keys-elsewhere arm: PASS — lidmap=%s keys_elsewhere=%t", fields.LIDMap, fields.KeysElsewhere)
	})

	// Arm 3: row in the SAME failGroup does NOT set keys_elsewhere=true.
	// (keys_elsewhere is for OTHER chats only.)
	t.Run("same_group_no_keys_elsewhere", func(t *testing.T) {
		sameGroupStruct := buildDonorStructure(88, 2, 0xCD)
		insertFlatBlobRow(t, db, subclassJIDB, failGroup, senderID, sameGroupStruct)
		t.Cleanup(func() {
			_, _ = db.ExecContext(ctx,
				`DELETE FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2`,
				subclassJIDB, failGroup)
		})

		fields := sqlstore.ClassifyNoDonor(ctx, innerB, subclassJIDB, failGroup, senderBare)
		if fields.KeysElsewhere {
			t.Error("same-group arm: expected keys_elsewhere=false (only row is in failGroup), got true")
		}
		t.Logf("same-group arm: PASS — lidmap=%s keys_elsewhere=%t", fields.LIDMap, fields.KeysElsewhere)
	})
}

// buildMultiStateStructure builds a SenderKeyStructure with two states:
//
//	state[0]: keyID=k1, iter=iter1
//	state[1]: keyID=k2, iter=iter2
func buildMultiStateStructure(k1, iter1, k2, iter2 uint32, tag1, tag2 byte) *groupRecord.SenderKeyStructure {
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
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: k1,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter1,
					ChainKey:  makeChainKey(tag1),
				},
				SigningKeyPublic:  makePub(tag1),
				SigningKeyPrivate: makePriv(tag1),
			},
			{
				KeyID: k2,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: iter2,
					ChainKey:  makeChainKey(tag2),
				},
				SigningKeyPublic:  makePub(tag2),
				SigningKeyPrivate: makePriv(tag2),
			},
		},
	}
}

// findStateByKeyID returns the state with the matching KeyID, or nil.
func findStateByKeyID(s *groupRecord.SenderKeyStructure, keyID uint32) *groupRecord.SenderKeyStateStructure {
	for _, st := range s.SenderKeyStates {
		if st != nil && st.KeyID == keyID {
			return st
		}
	}
	return nil
}

// TestInlineRecoveryDonorMerge exercises D-12: the donor state is MERGED into the
// existing structure rather than full-replacing it. Foreign-KeyID states are
// preserved in the merged result.
//
// Arms:
//  1. replace arm: existing [K1@20, K2@5]; donor K2@9 → merged has K1@20 + K2@9.
//     Against current full-replace code K1 is DROPPED — this arm MUST fail (red).
//  2. add arm: donor provides K3@4 (new KeyID) → merged has K1, K2, K3.
//  3. equal arm: donor provides K2@5 (equal, not strictly fresher) → guard fires, no write.
//  4. nil-existing arm: no existing structure for B → donor installs as single-state.
//  5. warm-cache arm (checker-required D-12 interaction): K1@20 consistent in
//     cache AND DB (write-through, no flusher); donor K2@9; TryInlineRecovery;
//     the cache-aware GetSenderKeyStructure serves K1@20 AND K2@9 (gate must NOT
//     reject on equal K1 in cache).
func TestInlineRecoveryDonorMerge(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovmerge_group@g.us"
		bareUser     = "55512340099_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		k1           = uint32(10)
		k2           = uint32(20)
		k3           = uint32(30)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// -----------------------------------------------------------------------
	// Arm 1: replace — existing [K1@20, K2@5]; donor K2@9 → merged has K1@20 + K2@9.
	// Against current full-replace this FAILS because K1 is dropped.
	// -----------------------------------------------------------------------
	t.Run("replace_preserves_foreign_key", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		// Seed B's existing multi-state row: [K1@20, K2@5].
		existingStruct := buildMultiStateStructure(k1, 20, k2, 5, 0xA1, 0xA2)
		insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

		// Seed A's donor row: K2@9 (strictly fresher than K2@5 in B's existing).
		donorStruct := buildDonorStructure(k2, 9, 0xB1)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		csB := newRecoveryTestStoreB(t, db)

		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k2, 15)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if !ok {
			t.Fatal("TryInlineRecovery: expected true (donor found), got false")
		}

		// Read the recovered row and verify it contains BOTH K1@20 and K2@9.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Fatalf("read recovered row: err=%v blob=%v", err, blob)
		}
		merged, uErr := store.UnpackFlat(blob)
		if uErr != nil || merged == nil {
			t.Fatalf("UnpackFlat: err=%v", uErr)
		}

		k1State := findStateByKeyID(merged, k1)
		k2State := findStateByKeyID(merged, k2)

		// K1 must be preserved at Iteration=20 (foreign-KeyID — not the donor's).
		// Against current full-replace code K1 is DROPPED → this fails (red proof).
		if k1State == nil {
			t.Errorf("D-12 FAIL: K1 (foreign-KeyID) was dropped from merged result (full-replace bug)")
		} else if k1State.SenderChainKey.Iteration != 20 {
			t.Errorf("D-12: K1 iteration = %d, want 20", k1State.SenderChainKey.Iteration)
		}

		// K2 must be updated to Iteration=9 (the donor's strictly fresher state).
		if k2State == nil {
			t.Errorf("D-12: K2 (donor KeyID) missing from merged result")
		} else if k2State.SenderChainKey.Iteration != 9 {
			t.Errorf("D-12: K2 iteration = %d, want 9 (donor)", k2State.SenderChainKey.Iteration)
		}
		t.Logf("replace arm: K1=%v iter=%v, K2=%v iter=%v",
			k1State != nil, func() uint32 {
				if k1State != nil {
					return k1State.SenderChainKey.Iteration
				}
				return 0
			}(),
			k2State != nil, func() uint32 {
				if k2State != nil {
					return k2State.SenderChainKey.Iteration
				}
				return 0
			}())
	})

	// -----------------------------------------------------------------------
	// Arm 2: add — donor provides K3@4 (new KeyID absent from existing).
	// Merged result must have K1, K2, AND K3.
	// -----------------------------------------------------------------------
	t.Run("add_new_keyid", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		existingStruct := buildMultiStateStructure(k1, 20, k2, 5, 0xC1, 0xC2)
		insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

		// K3 is new — not in existing.
		donorStruct := buildDonorStructure(k3, 4, 0xD1)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		csB := newRecoveryTestStoreB(t, db)

		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k3, 10)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if !ok {
			t.Fatal("add arm: expected true, got false")
		}

		var blob []byte
		_ = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		merged, _ := store.UnpackFlat(blob)
		if merged == nil {
			t.Fatal("add arm: UnpackFlat returned nil")
		}
		if findStateByKeyID(merged, k1) == nil {
			t.Error("add arm: K1 missing from merged result")
		}
		if findStateByKeyID(merged, k2) == nil {
			t.Error("add arm: K2 missing from merged result")
		}
		if findStateByKeyID(merged, k3) == nil {
			t.Error("add arm: K3 (new) missing from merged result")
		}
		t.Logf("add arm: merged has %d states (want K1+K2+K3)", len(merged.SenderKeyStates))
	})

	// -----------------------------------------------------------------------
	// Arm 3: equal — donor provides K2@5 (equal to existing K2@5, not strictly fresher).
	// The guard at :342-355 fires and returns false without writing.
	// -----------------------------------------------------------------------
	t.Run("equal_not_fresher_no_write", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		existingStruct := buildMultiStateStructure(k1, 20, k2, 5, 0xE1, 0xE2)
		insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

		// Donor at K2@5 (equal — not strictly fresher, guard fires).
		donorStruct := buildDonorStructure(k2, 5, 0xF1)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		csB := newRecoveryTestStoreB(t, db)

		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k2, 10)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if ok {
			t.Error("equal arm: expected false (equal iter guard), got true")
		}
		t.Logf("equal arm: PASS — donor K2@5 == existing K2@5, no write")
	})

	// -----------------------------------------------------------------------
	// Arm 4: nil-existing — no existing structure for B.
	// Donor installs as a single-state structure (no merge needed).
	// -----------------------------------------------------------------------
	t.Run("no_existing_installs_single_state", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		donorStruct := buildDonorStructure(k1, 15, 0x11)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		csB := newRecoveryTestStoreB(t, db)

		_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k1, 20)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if !ok {
			t.Fatal("nil-existing arm: expected true (donor found), got false")
		}

		var blob []byte
		_ = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		merged, _ := store.UnpackFlat(blob)
		if merged == nil || len(merged.SenderKeyStates) == 0 {
			t.Fatal("nil-existing arm: no recovered row")
		}
		if merged.SenderKeyStates[0].SenderChainKey.Iteration != 15 {
			t.Errorf("nil-existing arm: iter = %d, want 15", merged.SenderKeyStates[0].SenderChainKey.Iteration)
		}
		t.Logf("nil-existing arm: PASS — single-state install at iter=15")
	})

	// -----------------------------------------------------------------------
	// Arm 5: warm-cache (checker-required D-11/D-12 interaction).
	//
	// Seed K1@20 consistently in cache AND DB using the WRITE-THROUGH path
	// (no flusher attached on seeding store — the flat c.cache write-through fires
	// synchronously, DB row also written). Then seed K2@9 for account A. Call
	// TryInlineRecovery. Assert the cache-aware read serves BOTH K1@20 AND K2@9.
	//
	// The critical gate test: the merged union carries K1 at EQUAL iteration to
	// its cache-resident counterpart. The iteration gate must accept this as a
	// preserved foreign state (non-donor KeyID). If the gate incorrectly applies
	// the cipher rule (reject on ANY equal iter) or the naive recovery rule
	// (reject if ANY matching state cached >= new), the merged install is rejected
	// and the cache-aware read returns only K2@9 or a miss — proving the gate is wrong.
	// -----------------------------------------------------------------------
	t.Run("warm_cache_merge_accepted", func(t *testing.T) {
		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		// Build a write-through store (NO flusher) for seeding K1@20 into B.
		// This ensures the flat cache AND DB are both warm at K1@20.
		jidB, err := types.ParseJID(recoveryTestJIDB)
		if err != nil {
			t.Fatalf("ParseJID B: %v", err)
		}
		containerB := sqlstore.NewWithDB(db, "postgres", nil)
		innerBSeed := sqlstore.NewSQLStore(containerB, jidB)
		byteCache, _ := lru.New[string, []byte](256)
		devCache, _ := lru.New[string, []string](256)
		csBSeed := sqlstore.NewCachedSenderKeyStore(innerBSeed, recoveryTestJIDB, byteCache, devCache, nil)
		// No flusher → write-through mode (warms the flat c.cache + writes DB).

		// Seed K1@20 via PutSenderKeyStructure (write-through: writes DB + warms cache).
		seedStruct := buildDonorStructure(k1, 20, 0x31)
		if err := csBSeed.PutSenderKeyStructure(ctx, group, targetSenderID, seedStruct); err != nil {
			t.Fatalf("seed K1@20 write-through: %v", err)
		}

		// Verify the cache-aware read is warm at K1@20.
		warmSt, err := csBSeed.GetSenderKeyStructure(ctx, group, targetSenderID)
		if err != nil {
			t.Fatalf("pre-condition: GetSenderKeyStructure: %v", err)
		}
		if warmSt == nil || findStateByKeyID(warmSt, k1) == nil ||
			findStateByKeyID(warmSt, k1).SenderChainKey.Iteration != 20 {
			t.Fatalf("pre-condition: cache not warm at K1@20")
		}

		// Verify DB is also warm at K1@20.
		var dbBlob []byte
		_ = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&dbBlob)
		if dbBlob == nil {
			t.Fatal("pre-condition: DB row absent after write-through seed")
		}

		// Seed K2@9 for account A (the donor).
		donorStruct := buildDonorStructure(k2, 9, 0x32)
		insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		// Now call TryInlineRecovery using the SAME store (csBSeed) that holds the warm cache.
		// TryInlineRecovery's GetSenderKeyStructure is cache-aware (flat c.cache, then DB),
		// finds K1@20 in existing, checks guard: K2 (donor) not in existing → proceeds.
		// The merged install carries K1@20 (foreign, preserved) + K2@9 (donor).
		// The flat-path gate sees K1 at EQUAL iter in cache (cached=20, new=20) —
		// this must be ACCEPTED as a preserved foreign state (D-12 interaction rule).
		_, ok, err := csBSeed.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k2, 15)
		if err != nil {
			t.Fatalf("TryInlineRecovery: %v", err)
		}
		if !ok {
			t.Fatal("warm-cache arm: expected true (donor found), got false")
		}

		// Assert the cache-aware read serves BOTH K1@20 AND K2@9.
		afterSt, err := csBSeed.GetSenderKeyStructure(ctx, group, targetSenderID)
		if err != nil {
			t.Fatalf("warm-cache arm: GetSenderKeyStructure after recovery: %v", err)
		}
		if afterSt == nil {
			t.Fatal("warm-cache arm: cache-aware read miss after TryInlineRecovery")
		}
		k1AfterState := findStateByKeyID(afterSt, k1)
		k2AfterState := findStateByKeyID(afterSt, k2)
		if k1AfterState == nil {
			t.Error("warm-cache arm: K1 missing from cache after merge (D-12 interaction gate rejected preserved foreign state)")
		} else if k1AfterState.SenderChainKey.Iteration != 20 {
			t.Errorf("warm-cache arm: K1 cache iter = %d, want 20", k1AfterState.SenderChainKey.Iteration)
		}
		if k2AfterState == nil {
			t.Error("warm-cache arm: K2 (donor) missing from cache")
		} else if k2AfterState.SenderChainKey.Iteration != 9 {
			t.Errorf("warm-cache arm: K2 cache iter = %d, want 9", k2AfterState.SenderChainKey.Iteration)
		}
		t.Logf("warm-cache arm: K1=%v iter=%v, K2=%v iter=%v",
			k1AfterState != nil, func() uint32 {
				if k1AfterState != nil {
					return k1AfterState.SenderChainKey.Iteration
				}
				return 0
			}(),
			k2AfterState != nil, func() uint32 {
				if k2AfterState != nil {
					return k2AfterState.SenderChainKey.Iteration
				}
				return 0
			}())
	})
}

// TestInlineRecoveryDonorPrependedAndFlushed is the CR-04 regression test.
//
// Invariant under test: the D-12 merge must place the DONOR state at index 0
// (libsignal's states[0]-most-recent invariant, relied on by extractStructMeta,
// the sk_keyid0 generated column, and the flusher's same-generation dedup), and
// the recovery enqueue must carry the donor's (keyID, iter) meta so a
// pre-existing dirty entry at a FOREIGN generation cannot dedup-skip the
// recovery blob.
//
// Setup: B's existing row [K1@20, K2@5] is in the DB AND enqueued as a dirty
// flusher entry with meta (K1, 20) (the flusher is attached but never started,
// holding the write-back window open). Donor K2@9 is then recovered.
//
// Pre-fix behaviour: the merge kept K1 at state[0], the recovery enqueue meta
// was (K1, 20) from the stale state[0], sameGeneration was true with
// iter 20 <= highIter 20, and the dedup SKIPPED the enqueue — the merged blob
// (with the donor) never replaced the dirty blob, so the drained DB row lacked
// the donor state. Post-fix the merged state[0] is the donor and the enqueue
// meta is (K2, 9): sameGeneration is false, the dirty blob is replaced, and the
// drain persists the donor at state[0].
func TestInlineRecoveryDonorPrependedAndFlushed(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovprepend_group@g.us"
		bareUser     = "55512340777_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		k1           = uint32(10) // foreign generation (pre-existing dirty entry meta)
		k2           = uint32(20) // donor generation
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Seed B's existing multi-state row in the DB: [K1@20, K2@5].
	existingStruct := buildMultiStateStructure(k1, 20, k2, 5, 0x41, 0x42)
	insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

	// Seed A's donor row: K2@9 (strictly fresher than B's K2@5).
	donorStruct := buildDonorStructure(k2, 9, 0x51)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

	// Build B's store with a REAL parsed cache and a flusher that is attached
	// but never started (write-back window held open deterministically).
	jidB, err := types.ParseJID(recoveryTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)
	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache, nil)

	flusher := sqlstore.NewSenderKeyFlusher(innerB, waLog.Noop, 0)
	csB.SetFlusher(flusher)
	// flusher.Start() intentionally NOT called — dirty-set drains only via Drain().

	// Pre-seed a dirty entry at the FOREIGN generation: PutSenderKeyStructure
	// derives meta from state[0] = (K1, 20), so the dirty entry's keyID is K1.
	if err := csB.PutSenderKeyStructure(ctx, group, targetSenderID, existingStruct); err != nil {
		t.Fatalf("PutSenderKeyStructure (dirty pre-seed): %v", err)
	}
	if got := flusher.DirtyCount(); got != 1 {
		t.Fatalf("pre-condition: dirty count = %d, want 1", got)
	}

	// Recover donor K2@9 (targetIter=15: donor 9 <= 15 qualifies).
	_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, k2, 15)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if !ok {
		t.Fatal("TryInlineRecovery: expected true (donor found), got false")
	}

	// Assert 1 (cache): the merged cached structure has the DONOR at state[0].
	// Read through the cache-aware GetSenderKeyStructure (flat c.cache leads the
	// undrained DB) BEFORE Drain().
	cachedSt, err := csB.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		t.Fatalf("CR-04: GetSenderKeyStructure after recovery: %v", err)
	}
	if cachedSt == nil || len(cachedSt.SenderKeyStates) == 0 {
		t.Fatal("CR-04: flat cache miss after recovery install")
	}
	if got := cachedSt.SenderKeyStates[0].KeyID; got != k2 {
		t.Errorf("CR-04: cached state[0].KeyID = %d, want %d (donor must be most-recent)", got, k2)
	}
	if got := cachedSt.SenderKeyStates[0].SenderChainKey.Iteration; got != 9 {
		t.Errorf("CR-04: cached state[0] iteration = %d, want 9 (donor)", got)
	}
	if k1Cached := findStateByKeyID(cachedSt, k1); k1Cached == nil {
		t.Error("CR-04: foreign K1 dropped from cached merge")
	} else if k1Cached.SenderChainKey.Iteration != 20 {
		t.Errorf("CR-04: cached K1 iteration = %d, want 20", k1Cached.SenderChainKey.Iteration)
	}

	// Assert 2 (flusher dedup): the recovery enqueue replaced the dirty blob —
	// drain it and verify the DB row carries the donor at state[0].
	flusher.Drain()
	if got := flusher.DirtyCount(); got != 0 {
		t.Fatalf("Drain left %d dirty entries, want 0", got)
	}

	var blob []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&blob)
	if err != nil || blob == nil {
		t.Fatalf("read drained row: err=%v blob=%v", err, blob)
	}
	drained, uErr := store.UnpackFlat(blob)
	if uErr != nil || drained == nil || len(drained.SenderKeyStates) == 0 {
		t.Fatalf("UnpackFlat drained row: err=%v got=%v", uErr, drained)
	}
	if got := drained.SenderKeyStates[0].KeyID; got != k2 {
		t.Errorf("CR-04: drained DB state[0].KeyID = %d, want %d (recovery blob dedup-skipped?)", got, k2)
	}
	if got := drained.SenderKeyStates[0].SenderChainKey.Iteration; got != 9 {
		t.Errorf("CR-04: drained DB state[0] iteration = %d, want 9 (donor)", got)
	}
	if k1DB := findStateByKeyID(drained, k1); k1DB == nil {
		t.Error("CR-04: foreign K1 dropped from drained DB blob")
	} else if k1DB.SenderChainKey.Iteration != 20 {
		t.Errorf("CR-04: drained K1 iteration = %d, want 20", k1DB.SenderChainKey.Iteration)
	}

	// Assert 3 (sk_keyid0): the generated column indexes the donor generation,
	// so recoveryScanQueryFast can find this row when K2 is the target.
	var keyid0 int32
	err = db.QueryRowContext(ctx,
		`SELECT sk_keyid0 FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&keyid0)
	if err != nil {
		t.Fatalf("read sk_keyid0: %v", err)
	}
	if uint32(keyid0) != k2 {
		t.Errorf("CR-04: sk_keyid0 = %d, want %d (donor generation must be indexable)", keyid0, k2)
	}
	t.Logf("CR-04: drained state[0]=(keyID=%d iter=%d), sk_keyid0=%d (want donor K2@9)",
		drained.SenderKeyStates[0].KeyID, drained.SenderKeyStates[0].SenderChainKey.Iteration, keyid0)
}

// buildNStateStructure builds a SenderKeyStructure with n states: KeyIDs
// baseKeyID..baseKeyID+n-1, iterations baseIter+i, distinct crypto material.
func buildNStateStructure(n int, baseKeyID, baseIter uint32, tag byte) *groupRecord.SenderKeyStructure {
	states := make([]*groupRecord.SenderKeyStateStructure, n)
	for i := 0; i < n; i++ {
		s := buildDonorStructure(baseKeyID+uint32(i), baseIter+uint32(i), tag+byte(i)*3)
		states[i] = s.SenderKeyStates[0]
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// TestInlineRecoveryUncacheableMergeStillPersists — repurposed by
// QUICK-SKCAP-01 as the capped-merge-vs-full-cache e2e test.
//
// HISTORY (CR-03): this test originally exercised the StoreUncacheable branch
// via a D-12 merge of a 6-state existing row + a new donor KeyID = 7 states
// (> flatMaxStates = 6 → flat-uncacheable, but PackFlat-persistable). Since
// QUICK-SKCAP-01 the D-12 merge is capped at maxSenderKeyStates (libsignal
// maxStates = 5) BEFORE install, so the merge path can no longer produce a
// > flatMaxStates structure; the StoreUncacheable branch in
// PutSenderKeyStructureRecovery remains as defense in depth (wrong-length
// fields would also be rejected by PackFlat first).
//
// CURRENT CONTRACT: the same seed (6-state existing row + cache warmed with
// it + new donor KeyID) must now produce a CAPPED install: 5 states persisted,
// donor at index 0 (CR-04), the 4 MOST-RECENT foreign states kept, the 2
// oldest dropped — and StoreStruct's relaxed CR-01 guard ACCEPTS the capped
// merge (cache replaced, not invalidated), so 5+-state senders stay
// recoverable instead of being StoreRejectedStale forever.
func TestInlineRecoveryUncacheableMergeStillPersists(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovuncacheable_group@g.us"
		bareUser     = "55512340888_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		baseKeyID    = uint32(70) // existing 6 states: KeyIDs 70..75
		donorKeyID   = uint32(90) // new generation, absent from existing
		donorIter    = uint32(9)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Seed B's existing row with 6 states (== flatMaxStates: cacheable as-is,
	// but any merge adding a 7th state becomes flat-uncacheable).
	existingStruct := buildNStateStructure(6, baseKeyID, 10, 0x61)
	insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

	// Seed A's donor row: new KeyID 90 @ 9.
	donorStruct := buildDonorStructure(donorKeyID, donorIter, 0x71)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

	// Build B's store: flat single cache, NO flusher (write-through — the DB
	// write is synchronous and warms the flat c.cache).
	jidB, err := types.ParseJID(recoveryTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)
	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache, nil)

	// Warm the flat cache with the (cacheable) 6-state existing structure via the
	// write-through path so the post-recovery cache replacement is observable.
	if err := csB.PutSenderKeyStructure(ctx, group, targetSenderID, existingStruct); err != nil {
		t.Fatalf("pre-condition: warming 6-state entry: %v", err)
	}

	// Recover donor KeyID 90 (targetIter=15: donor 9 <= 15 qualifies). The merge
	// is [donor, 6 existing] = 7 states pre-cap → capped to 5 (QUICK-SKCAP-01).
	_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, donorKeyID, 15)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if !ok {
		t.Error("QUICK-SKCAP-01: TryInlineRecovery returned ok=false for a capped-but-valid donor install " +
			"(CR-01 guard must tolerate cap-dropped oldest states)")
	}

	// Assert 1: the CAPPED merged blob WAS persisted: 5 states, donor at index
	// 0, the 4 most-recent foreign states (70..73) kept, the 2 oldest (74, 75)
	// dropped.
	var blob []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&blob)
	if err != nil || blob == nil {
		t.Fatalf("read persisted row: err=%v blob=%v", err, blob)
	}
	persisted, uErr := store.UnpackFlat(blob)
	if uErr != nil || persisted == nil {
		t.Fatalf("UnpackFlat persisted row: err=%v", uErr)
	}
	if got := len(persisted.SenderKeyStates); got != 5 {
		t.Errorf("QUICK-SKCAP-01: persisted state count = %d, want 5 (libsignal maxStates cap)", got)
	}
	if got := persisted.SenderKeyStates[0].KeyID; got != donorKeyID {
		t.Errorf("CR-04: persisted state[0].KeyID = %d, want %d (donor)", got, donorKeyID)
	}
	for i := 0; i < 4; i++ {
		if findStateByKeyID(persisted, baseKeyID+uint32(i)) == nil {
			t.Errorf("QUICK-SKCAP-01: most-recent foreign KeyID %d dropped from capped merge", baseKeyID+uint32(i))
		}
	}
	for i := 4; i < 6; i++ {
		if findStateByKeyID(persisted, baseKeyID+uint32(i)) != nil {
			t.Errorf("QUICK-SKCAP-01: oldest foreign KeyID %d survived the cap (want dropped)", baseKeyID+uint32(i))
		}
	}

	// Assert 2: the capped 5-state merge is flat-cacheable and the relaxed
	// CR-01 guard accepted it — the flat cache is REPLACED with the merged entry
	// (donor at state[0]). Read through the cache-aware GetSenderKeyStructure.
	cachedStruct, err := csB.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		t.Fatalf("QUICK-SKCAP-01: GetSenderKeyStructure after recovery: %v", err)
	}
	if cachedStruct == nil || len(cachedStruct.SenderKeyStates) == 0 {
		t.Error("QUICK-SKCAP-01: flat cache empty after capped recovery install (want replaced entry)")
	} else if got := cachedStruct.SenderKeyStates[0].KeyID; got != donorKeyID {
		t.Errorf("QUICK-SKCAP-01: cached state[0].KeyID = %d, want donor %d", got, donorKeyID)
	}
	t.Logf("QUICK-SKCAP-01: persisted %d states, state[0].KeyID=%d, cache replaced with capped merge",
		len(persisted.SenderKeyStates), persisted.SenderKeyStates[0].KeyID)
}

// TestInlineRecoveryCacheOnlyGenerationSurvives is the CR-01 regression test.
//
// Loss interleaving under test: a freshly distributed generation B lives ONLY
// in the parsed cache + flusher dirty-set (the ~1s write-back window, held
// open deterministically by an attached-but-never-started flusher); the DB row
// is absent. A decrypt failure for a DIFFERENT generation D of the same
// (group, sender) triggers TryInlineRecovery, whose guard/merge read
// (GetSenderKeyStructure) is DB-only. Pre-fix, the D-12 merge was built from
// the stale (empty) DB snapshot, the iteration gate only compared INCOMING
// states (B was never checked), lru.Add replaced the cached entry — B's chain
// key gone from the cache — and the recovery enqueue replaced the dirty blob —
// B gone from the DB on drain. All subsequent messages on B became permanently
// undecryptable.
//
// Phase 38.4-03: the parsed cache + the parsedLoad union are gone. The merge
// base is now the cache-aware GetSenderKeyStructure (Plan 02), which reads the
// flat c.cache BEFORE the DB — so the cache-resident generation B is carried
// into the merge directly, and the ported flat-path backward-only gate rejects
// any recovery install that would drop a cached generation. The behavioral
// contract is unchanged; only the cache form (flat []byte) differs.
func TestInlineRecoveryCacheOnlyGenerationSurvives(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovcacheonly_group@g.us"
		bareUser     = "55512340999_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		keyB         = uint32(60) // cache-only fresh generation (DB absent)
		keyD         = uint32(61) // donor generation being recovered
		iterB        = uint32(50)
		iterD        = uint32(10)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Build B's store: flat single cache, flusher attached but never started
	// (write-back window held open).
	jidB, err := types.ParseJID(recoveryTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)
	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryTestJIDB, byteCache, devCache, nil)

	flusher := sqlstore.NewSenderKeyFlusher(innerB, waLog.Noop, 0)
	csB.SetFlusher(flusher)
	// flusher.Start() intentionally NOT called — DB row stays absent.

	// Step 1: generation B arrives via the cipher path — flat c.cache + flusher
	// dirty-set only; the DB row for B remains absent.
	structB := buildDonorStructure(keyB, iterB, 0x81)
	if err := csB.PutSenderKeyStructure(ctx, group, targetSenderID, structB); err != nil {
		t.Fatalf("PutSenderKeyStructure (cache-only B seed): %v", err)
	}
	var dbCount int
	_ = db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&dbCount)
	if dbCount != 0 {
		t.Fatalf("pre-condition: DB row exists (count=%d), want absent", dbCount)
	}

	// Step 2: seed account A with the donor for generation D.
	donorStruct := buildDonorStructure(keyD, iterD, 0x91)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

	// Step 3: recover generation D (targetIter=15: donor 10 <= 15 qualifies).
	_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, keyD, 15)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if !ok {
		t.Fatal("TryInlineRecovery: expected true (donor found, merge valid), got false")
	}

	// Assert 1: generation B survives in the flat cache alongside the donor.
	// Read through the cache-aware GetSenderKeyStructure (flat c.cache leads the
	// undrained DB) BEFORE Drain().
	cachedSt, err := csB.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		t.Fatalf("CR-01: GetSenderKeyStructure after recovery: %v", err)
	}
	if cachedSt == nil {
		t.Fatal("CR-01: flat cache miss after recovery install")
	}
	if bCached := findStateByKeyID(cachedSt, keyB); bCached == nil {
		t.Error("CR-01: cache-only generation B dropped from parsed cache by recovery install")
	} else if bCached.SenderChainKey.Iteration != iterB {
		t.Errorf("CR-01: cached B iteration = %d, want %d", bCached.SenderChainKey.Iteration, iterB)
	}
	if dCached := findStateByKeyID(cachedSt, keyD); dCached == nil {
		t.Error("CR-01: donor generation D missing from parsed cache")
	} else if dCached.SenderChainKey.Iteration != iterD {
		t.Errorf("CR-01: cached D iteration = %d, want %d", dCached.SenderChainKey.Iteration, iterD)
	}
	if got := cachedSt.SenderKeyStates[0].KeyID; got != keyD {
		t.Errorf("CR-04: cached state[0].KeyID = %d, want %d (donor most-recent)", got, keyD)
	}

	// Assert 2: generation B survives in the drained DB blob.
	flusher.Drain()
	var blob []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&blob)
	if err != nil || blob == nil {
		t.Fatalf("read drained row: err=%v blob=%v", err, blob)
	}
	drained, uErr := store.UnpackFlat(blob)
	if uErr != nil || drained == nil {
		t.Fatalf("UnpackFlat drained row: err=%v", uErr)
	}
	if bDB := findStateByKeyID(drained, keyB); bDB == nil {
		t.Error("CR-01: cache-only generation B missing from drained DB blob (lost on restart)")
	} else if bDB.SenderChainKey.Iteration != iterB {
		t.Errorf("CR-01: drained B iteration = %d, want %d", bDB.SenderChainKey.Iteration, iterB)
	}
	if dDB := findStateByKeyID(drained, keyD); dDB == nil {
		t.Error("CR-01: donor generation D missing from drained DB blob")
	}
	t.Logf("CR-01: cache states=%d, drained states=%d (want B@%d and D@%d in both)",
		len(cachedSt.SenderKeyStates), len(drained.SenderKeyStates), iterB, iterD)
}

// addSkippedKeysToState appends valid-length skipped message keys (one per
// iteration) to a state, for the WR-05 skipped-key union test. Field lengths
// must satisfy the flat codec invariant (iv=16, cipherKey=32, seed=32).
func addSkippedKeysToState(st *groupRecord.SenderKeyStateStructure, tag byte, iters ...uint32) {
	for _, it := range iters {
		fill := func(n int) []byte {
			b := make([]byte, n)
			for i := range b {
				b[i] = tag + byte(it) + byte(i)
			}
			return b
		}
		st.Keys = append(st.Keys, &ratchet.SenderMessageKeyStructure{
			Iteration: it,
			IV:        fill(16),
			CipherKey: fill(32),
			Seed:      fill(32),
		})
	}
}

// skippedKeyIterSet returns the set of iterations present in a state's Keys.
func skippedKeyIterSet(st *groupRecord.SenderKeyStateStructure) map[uint32]bool {
	out := make(map[uint32]bool, len(st.Keys))
	for _, k := range st.Keys {
		if k != nil {
			out[k.Iteration] = true
		}
	}
	return out
}

// TestInlineRecoveryMergeKeepsExistingSkippedKeys exercises WR-05 end-to-end:
// the D-12 merge supersedes an existing same-KeyID state with the donor, but
// must UNION the existing state's skipped message keys (the recovering
// account's own out-of-order coverage) into the donor state instead of
// dropping them — the donor's higher-iteration chain key cannot re-derive
// earlier iterations (forward-only ratchet).
//
// Scenario: B holds K@10 with skipped keys at iterations 3 and 5; donor A
// holds K@50 with its own skipped key at 7. After recovery the persisted
// structure's K state must sit at iteration 50, at state[0] (CR-04 invariant),
// and carry skipped keys {3, 5, 7}.
func TestInlineRecoveryMergeKeepsExistingSkippedKeys(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryTestDevice(t, db, recoveryTestJIDA)
	cleanupB := insertRecoveryTestDevice(t, db, recoveryTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovwr05_group@g.us"
		bareUser     = "55512340105_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		keyK         = uint32(42)
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryTestJIDA, recoveryTestJIDB, group)

	// Seed B: existing K@10 with skipped keys at iterations 3 and 5.
	existingStruct := buildDonorStructure(keyK, 10, 0xA1)
	addSkippedKeysToState(existingStruct.SenderKeyStates[0], 0x10, 3, 5)
	insertFlatBlobRow(t, db, recoveryTestJIDB, group, targetSenderID, existingStruct)

	// Seed A: donor K@50 with its own skipped key at iteration 7.
	donorStruct := buildDonorStructure(keyK, 50, 0xB1)
	addSkippedKeysToState(donorStruct.SenderKeyStates[0], 0x40, 7)
	insertFlatBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

	csB := newRecoveryTestStoreB(t, db)

	// Recover with targetIter=60 (donor 50 <= 60 qualifies; existing K@10 < 50
	// so the downgrade guard passes and the donor supersedes the existing state).
	_, ok, err := csB.TryInlineRecovery(ctx, group, targetSenderID, bareUser, keyK, 60)
	if err != nil {
		t.Fatalf("TryInlineRecovery: %v", err)
	}
	if !ok {
		t.Fatal("TryInlineRecovery: expected true (donor strictly fresher), got false")
	}

	// Read the persisted row and verify the union.
	var blob []byte
	err = db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryTestJIDB, group, targetSenderID,
	).Scan(&blob)
	if err != nil || blob == nil {
		t.Fatalf("read recovered row: err=%v blob=%v", err, blob)
	}
	merged, uErr := store.UnpackFlat(blob)
	if uErr != nil || merged == nil || len(merged.SenderKeyStates) == 0 {
		t.Fatalf("UnpackFlat: err=%v got=%v", uErr, merged)
	}

	kState := findStateByKeyID(merged, keyK)
	if kState == nil {
		t.Fatal("K state missing from merged result")
	}
	if kState.SenderChainKey.Iteration != 50 {
		t.Errorf("K iteration = %d, want 50 (donor)", kState.SenderChainKey.Iteration)
	}
	if merged.SenderKeyStates[0].KeyID != keyK {
		t.Errorf("state[0].KeyID = %d, want %d (CR-04 donor-most-recent invariant)",
			merged.SenderKeyStates[0].KeyID, keyK)
	}

	iters := skippedKeyIterSet(kState)
	for _, want := range []uint32{3, 5, 7} {
		if !iters[want] {
			t.Errorf("WR-05: skipped key at iteration %d missing from merged K state "+
				"(existing account's out-of-order coverage dropped); have=%v", want, iters)
		}
	}
	if len(kState.Keys) != 3 {
		t.Errorf("WR-05: merged K state carries %d skipped keys, want 3 ({3,5} existing + {7} donor)",
			len(kState.Keys))
	}
	t.Logf("WR-05: merged K@%d at state[0] with skipped iterations %v",
		kState.SenderChainKey.Iteration, iters)
}

// TestClassifyNoDonorLIDMapSuffix is the regression test for the agent-suffix
// stripping fix in classifyNoDonor.
//
// LID Signal-address users arrive as "<digits>_<agent>" (e.g. "238877608562780_1")
// but whatsmeow_lid_map stores bare digits with no suffix. Before the fix,
// subclassLIDMapQuery received the unsuffixed form verbatim and always returned
// "unmapped" for LID senders — corrupting the SENDERKEY_SUBCLASS diagnostic field.
//
// Two arms:
//   - lid_mapped: senderBare="238877608562780_1" (LID with agent suffix);
//     lid_map row has lid="238877608562780"; expected LIDMap="lid-mapped"
//   - pn_mapped: senderBare="972501234567" (pure PN, no underscore);
//     lid_map row has pn="972501234567"; expected LIDMap="pn-mapped"
func TestClassifyNoDonorLIDMapSuffix(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	const (
		classifyTestJID = "17799990030@s.whatsapp.net"
		testLID         = "238877608562780"
		testPN          = "972501234567"
		testSenderLID   = testLID + "_1" // LID Signal-address with agent suffix
		testGroup       = "classifylidmap_test@g.us"
	)

	cleanupDev := insertRecoveryTestDevice(t, db, classifyTestJID)
	t.Cleanup(func() {
		cleanupDev()
		db.Close()
	})

	// Seed a single whatsmeow_lid_map row covering both arms.
	ctx := context.Background()
	_, err = db.ExecContext(ctx,
		`INSERT INTO whatsmeow_lid_map (lid, pn) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
		testLID, testPN,
	)
	if err != nil {
		t.Fatalf("seed whatsmeow_lid_map: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(context.Background(),
			`DELETE FROM whatsmeow_lid_map WHERE lid=$1`, testLID)
	})

	// Build the SQLStore for the test account.
	jid, err := types.ParseJID(classifyTestJID)
	if err != nil {
		t.Fatalf("ParseJID: %v", err)
	}
	classifyContainer := sqlstore.NewWithDB(db, "postgres", nil)
	classifyStore := sqlstore.NewSQLStore(classifyContainer, jid)

	// lid_mapped arm: senderBare carries the agent suffix "_1"; the lid_map row
	// has the bare lid "238877608562780". After the fix, classifyNoDonor strips
	// the suffix and finds the row as "lid-mapped".
	t.Run("lid_mapped", func(t *testing.T) {
		fields := sqlstore.ClassifyNoDonor(ctx, classifyStore, classifyTestJID, testGroup, testSenderLID)
		if fields.LIDMap != "lid-mapped" {
			t.Errorf("lid_mapped arm: LIDMap = %q, want %q (agent-suffix strip missing or broken)",
				fields.LIDMap, "lid-mapped")
		}
		t.Logf("lid_mapped arm: LIDMap=%s KeysElsewhere=%t", fields.LIDMap, fields.KeysElsewhere)
	})

	// pn_mapped arm: senderBare is a plain PN (no underscore). The lid_map row
	// has pn="972501234567". Expected: "pn-mapped".
	t.Run("pn_mapped", func(t *testing.T) {
		fields := sqlstore.ClassifyNoDonor(ctx, classifyStore, classifyTestJID, testGroup, testPN)
		if fields.LIDMap != "pn-mapped" {
			t.Errorf("pn_mapped arm: LIDMap = %q, want %q",
				fields.LIDMap, "pn-mapped")
		}
		t.Logf("pn_mapped arm: LIDMap=%s KeysElsewhere=%t", fields.LIDMap, fields.KeysElsewhere)
	})
}
