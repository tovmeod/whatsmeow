// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key_test.go — TestRecoverSenderKeyCrossAccount
//
// Verifies the cross-account sender-key recovery (plan 05):
//
//  1. fmt_ver=2 donor arm: seed account A with a columnar row, recover into B.
//  2. fmt_ver=1 legacy-blob donor arm: seed account A with a legacy blob row,
//     recover into B. (T-17.9-20: must work before backfill, when fmt_ver=1 dominates.)
//  3. Forward-only rejection arm: donor with chain_iter > targetIter is rejected.
//  4. Closest-iter arm: two donors ≤ target, the one with the higher iter wins.
//  5. Copy correctness: the recovered row under B is fmt_ver=2 with the correct
//     recipient-independent fields (signing keys + chain key/iter). No NULL-blob.
//
// All arms use a donor device suffix DIFFERENT from the recovering account's
// target sender_id to verify the device-tolerant (bare-user LIKE) behavior.
//
// Requires: a live Postgres DB at the test DSN (setup-test-db.sh applied schema).
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

// insertLegacyBlobRow inserts a fmt_ver=1 sender-key row (legacy blob only) for
// the given account. Simulates the common pre-backfill state.
func insertLegacyBlobRow(t *testing.T, db *sql.DB, ourJID, group, senderID string, structure *groupRecord.SenderKeyStructure) {
	t.Helper()
	sk, err := groupRecord.NewSenderKeyFromStruct(structure,
		pbSerializer.SenderKeyRecord, pbSerializer.SenderKeyState)
	if err != nil {
		t.Fatalf("NewSenderKeyFromStruct: %v", err)
	}
	blob := sk.Serialize()
	if blob == nil {
		t.Fatal("Serialize returned nil blob")
	}
	_, err = db.ExecContext(context.Background(),
		`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, fmt_ver, sender_key)
		 VALUES ($1, $2, $3, 1, $4)
		 ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET
		   fmt_ver=1, sender_key=excluded.sender_key,
		   st_key_id=NULL, st_chain_key_iteration=NULL, st_chain_key=NULL,
		   st_signing_key_public=NULL, st_signing_key_private=NULL,
		   smk_state_idx=NULL, smk_iteration=NULL, smk_iv=NULL,
		   smk_cipher_key=NULL, smk_seed=NULL`,
		ourJID, group, senderID, blob,
	)
	if err != nil {
		t.Fatalf("insertLegacyBlobRow: %v", err)
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

		// Verify the row under B: fmt_ver=2, iter=10.
		var fmtVerDB, iterDB sql.NullInt64
		err = db.QueryRowContext(ctx,
			`SELECT fmt_ver, st_chain_key_iteration[1] FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&fmtVerDB, &iterDB)
		if err != nil {
			t.Fatalf("read recovered row (fmt_ver=2 arm): %v", err)
		}
		if !fmtVerDB.Valid || fmtVerDB.Int64 != 2 {
			t.Errorf("fmt_ver2 arm: want fmt_ver=2, got %v", fmtVerDB)
		}
		if !iterDB.Valid || iterDB.Int64 != 10 {
			t.Errorf("fmt_ver2 arm: want iter=10, got %v", iterDB)
		}

		// Verify the blob is NOT NULL and round-trips the signing keys.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil {
			t.Fatalf("read blob: %v", err)
		}
		if blob == nil {
			t.Error("sender_key blob is NULL — recompose did not fire at drain")
		}
		// Deserialize the blob and compare signing keys against the donor structure.
		if blob != nil {
			recovered, err := pbSerializer.SenderKeyRecord.Deserialize(blob)
			if err != nil {
				t.Fatalf("Deserialize recovered blob: %v", err)
			}
			if len(recovered.SenderKeyStates) == 0 {
				t.Fatal("recovered blob has 0 states")
			}
			donorState := donorStruct.SenderKeyStates[0]
			recvState := recovered.SenderKeyStates[0]
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
		}
		t.Logf("fmt_ver2 arm: PASS — donor iter=10, target=15, recovered iter=%d, fmt_ver=%d", iterDB.Int64, fmtVerDB.Int64)
	})

	// -----------------------------------------------------------------------
	// Arm 2: fmt_ver=1 legacy blob donor (T-17.9-20)
	// Seed account A with a raw fmt_ver=1 legacy-blob row (iter=20, keyID=42).
	// Recovery must parse the blob and find the donor.
	// -----------------------------------------------------------------------
	t.Run("fmt_ver1_legacy_donor", func(t *testing.T) {
		ctx := context.Background()

		_, _ = db.ExecContext(ctx,
			`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
			recoveryTestJIDA, recoveryTestJIDB, group)

		csB := newRecoveryTestStoreB(t, db)

		// Seed A: fmt_ver=1 legacy-blob row (iter=20, keyID=42, donor suffix :5).
		donorStruct := buildDonorStructure(targetKeyID, 20, 0xBB)
		insertLegacyBlobRow(t, db, recoveryTestJIDA, group, donorSenderID, donorStruct)

		// Sanity: verify the row is fmt_ver=1.
		var seedFmtVer int
		err := db.QueryRowContext(ctx,
			`SELECT fmt_ver FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDA, group, donorSenderID,
		).Scan(&seedFmtVer)
		if err != nil || seedFmtVer != 1 {
			t.Fatalf("expected fmt_ver=1 for seeded legacy row, got %d (err=%v)", seedFmtVer, err)
		}

		// Recover into B with targetIter=25 (donor=20 ≤ 25 → accepted).
		ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 25)
		if err != nil {
			t.Fatalf("RecoverSenderKey (legacy arm): %v", err)
		}
		if !ok {
			t.Fatal("RecoverSenderKey (legacy arm): expected true (donor found via blob parse), got false")
		}

		// Verify: fmt_ver=2 written under B, iter=20.
		var fmtVerDB, iterDB sql.NullInt64
		err = db.QueryRowContext(ctx,
			`SELECT fmt_ver, st_chain_key_iteration[1] FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&fmtVerDB, &iterDB)
		if err != nil {
			t.Fatalf("read recovered row (legacy arm): %v", err)
		}
		if !fmtVerDB.Valid || fmtVerDB.Int64 != 2 {
			t.Errorf("legacy arm: want fmt_ver=2 (upgraded on write), got %v", fmtVerDB)
		}
		if !iterDB.Valid || iterDB.Int64 != 20 {
			t.Errorf("legacy arm: want iter=20, got %v", iterDB)
		}
		// Verify not-NULL blob.
		var blob []byte
		err = db.QueryRowContext(ctx,
			`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&blob)
		if err != nil || blob == nil {
			t.Errorf("legacy arm: sender_key blob is NULL or error: %v", err)
		}
		t.Logf("legacy arm: PASS — fmt_ver=1 donor iter=20, target=25, recovered iter=%d fmt_ver=%d", iterDB.Int64, fmtVerDB.Int64)
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

		// The recovered iter must be 12 (the maximum ≤ 15).
		var iterDB sql.NullInt64
		err = db.QueryRowContext(ctx,
			`SELECT st_chain_key_iteration[1] FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&iterDB)
		if err != nil {
			t.Fatalf("read recovered row (closest-iter arm): %v", err)
		}
		if !iterDB.Valid || iterDB.Int64 != 12 {
			t.Errorf("closest-iter arm: want iter=12 (max of {5,12} ≤ 15), got %v", iterDB)
		}

		// Verify the chain key belongs to struct12 (tag=0xD2).
		var chainKeyDB []byte
		_ = db.QueryRowContext(ctx,
			`SELECT st_chain_key[1] FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
			recoveryTestJIDB, group, targetSenderID,
		).Scan(&chainKeyDB)
		expectedChainKey := make([]byte, 32)
		for i := range expectedChainKey {
			expectedChainKey[i] = 0xD2 + byte(i)
		}
		if !bytes.Equal(chainKeyDB, expectedChainKey) {
			t.Errorf("closest-iter arm: ChainKey mismatch — want tag=0xD2 (iter=12 donor):\n  got:  %x\n  want: %x",
				chainKeyDB, expectedChainKey)
		}
		t.Logf("closest-iter arm: PASS — donors {iter=5, iter=12} for target=15; recovered iter=%d (max wins)", iterDB.Int64)
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
