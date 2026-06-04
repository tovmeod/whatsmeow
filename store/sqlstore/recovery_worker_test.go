// Copyright (c) 2026 Kavtov Platform (Phase 17.11 plan 02 + plan 03)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_worker_test.go — TestRecoverySyncWriteDeviceVisibility (BLOCKING GATE),
// TestRecoveryIterationGuard, and TestNegativeRecoveryCache.
//
// TestRecoverySyncWriteDeviceVisibility (blocking gate):
//   Proves that after RecoverSenderKey returns (true, nil), a subsequent
//   GetSenderKeyDevices call IMMEDIATELY returns the targetSenderID — without
//   sleeping or manually ticking the flusher. With the old async PutSenderKeyStructure
//   path the flusher is ticked by a 1-second timer; this test fails RED because the
//   device cache is cold after updateDeviceCache evicts, but the row isn't in DB yet.
//
// TestRecoveryIterationGuard:
//   Proves that RecoverSenderKey returns (false, nil) when the existing key for
//   (group, targetSenderID) already has the same KeyID at Iteration >= donor.Iteration,
//   and that the DB row is NOT overwritten.
//
// TestNegativeRecoveryCache:
//   Proves that the SenderKeyRecoveryWorker's negative-result cache deduplicates
//   re-scans for unrecoverable tuples within the TTL window, and that after TTL
//   expiry a fresh scan is attempted. Calls handle() directly (synchronous) so
//   the test is deterministic without sleeps racing the jittered goroutine.
//
// Requires: live Postgres at batchTestDSN() (kavtov-driver-go/scripts/setup-test-db.sh).
// Skips cleanly when the DB is not reachable.

package sqlstore_test

import (
	"context"
	"database/sql"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// recovery worker test JIDs — separate from the cross-account recovery test JIDs
// to avoid row collision across parallel test runs.
const (
	recoveryWorkerTestJIDA = "17799990011@s.whatsapp.net" // donor account
	recoveryWorkerTestJIDB = "17799990012@s.whatsapp.net" // recovering account
)

// newRecoveryWorkerTestStoreB creates a CachedSenderKeyStore for the recovering
// account B with a REAL RUNNING SenderKeyFlusher. This is the critical
// distinction from newRecoveryTestStoreB in recovery_sender_key_test.go — with a
// running flusher, PutSenderKeyStructure routes through the async Enqueue path,
// making TestRecoverySyncWriteDeviceVisibility fail RED with the pre-fix code.
//
// The flusher is stopped in t.Cleanup. The DB container is NOT closed (see
// newRecoveryTestStoreB for the rationale).
func newRecoveryWorkerTestStoreB(t *testing.T, db *sql.DB) *sqlstore.CachedSenderKeyStore {
	t.Helper()
	jidB, err := types.ParseJID(recoveryWorkerTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)

	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryWorkerTestJIDB, byteCache, devCache)

	// Wire a REAL running flusher — critical for the gate to be non-hollow.
	// With flusher running, PutSenderKeyStructure takes the Enqueue path (async),
	// which means the recovered row is not in DB until the 1-second tick fires.
	// The sync-write fix (recoverySyncWrite) bypasses the flusher entirely.
	flusher := sqlstore.NewSenderKeyFlusher(innerB, waLog.Noop, 256000)
	flusher.Start()
	t.Cleanup(flusher.Stop)
	csB.SetFlusher(flusher)

	return csB
}

// insertRecoveryWorkerTestDevice inserts a whatsmeow_device row for the given JID.
// Returns a cleanup function that deletes the device row (cascading to sender_keys).
func insertRecoveryWorkerTestDevice(t *testing.T, db *sql.DB, jid string) func() {
	t.Helper()
	return insertRecoveryTestDevice(t, db, jid)
}

// TestRecoverySyncWriteDeviceVisibility is the BLOCKING GATE for the R7 sync-write fix.
//
// It asserts: after RecoverSenderKey returns (true, nil), GetSenderKeyDevices
// immediately returns targetSenderID — without sleeping or manually ticking
// the flusher. The test uses a real running async flusher to make the pre-fix
// async path fail RED.
//
// With the pre-fix code:
//   - RecoverSenderKey calls PutSenderKeyStructure → Enqueue (async, 1s tick)
//   - updateDeviceCache evicts the cached empty-set (device cache is cold)
//   - GetSenderKeyDevices misses cache → queries DB → row absent (pre-drain)
//   - GetSenderKeyDevices returns [] → test FAILS
//
// With the fix (recoverySyncWrite):
//   - RecoverSenderKey calls recoverySyncWrite → PutManySenderKeys (synchronous)
//   - Row is in DB before updateDeviceCache evicts
//   - GetSenderKeyDevices misses cache → queries DB → finds targetSenderID
//   - GetSenderKeyDevices returns [targetSenderID] → test PASSES
func TestRecoverySyncWriteDeviceVisibility(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDA)
	cleanupB := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovworker_syncwrite_group@g.us"
		bareUser     = "55512340001_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		targetKeyID  = uint32(7) // low keyID, well below boundaryN=500 to avoid flush signal
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// Clean up any leftover rows from previous test runs.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryWorkerTestJIDA, recoveryWorkerTestJIDB, group)

	// Build the recovering-account store WITH a real running flusher.
	csB := newRecoveryWorkerTestStoreB(t, db)

	// Seed donor account A with a columnar fmt_ver=2 row (iter=10, keyID=7).
	jidA, err := types.ParseJID(recoveryWorkerTestJIDA)
	if err != nil {
		t.Fatalf("ParseJID A: %v", err)
	}
	containerA := sqlstore.NewWithDB(db, "postgres", nil)
	storeA := sqlstore.NewSQLStore(containerA, jidA)

	donorStruct := buildDonorStructure(targetKeyID, 10, 0x11)
	rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, donorStruct)
	if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
		t.Fatalf("seed donor A: %v", err)
	}

	// Step 1: prime the device cache with an empty set (simulates first decrypt miss).
	// GetSenderKeyDevices on a cold key reads DB (no row for B yet) and caches [].
	devices0, err := csB.GetSenderKeyDevices(ctx, group, bareUser)
	if err != nil {
		t.Fatalf("GetSenderKeyDevices (prime): %v", err)
	}
	if len(devices0) != 0 {
		t.Fatalf("expected empty device list before recovery, got %v", devices0)
	}

	// Step 2: recover the sender key.
	// With the OLD code (PutSenderKeyStructure → async flusher), the row is not
	// yet in DB when we call GetSenderKeyDevices below. The device cache was
	// evicted by updateDeviceCache, so GetSenderKeyDevices cold-reads DB → empty.
	//
	// With the FIX (recoverySyncWrite → PutManySenderKeys sync), the row IS in DB
	// before updateDeviceCache evicts, so the next cold read finds targetSenderID.
	ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 15)
	if err != nil {
		t.Fatalf("RecoverSenderKey: %v", err)
	}
	if !ok {
		t.Fatal("RecoverSenderKey: expected true (donor found), got false")
	}

	// Step 3: IMMEDIATELY (no sleep, no flusher tick) check device visibility.
	// This is the blocking gate: fails with the async path, passes with sync-write.
	devices1, err := csB.GetSenderKeyDevices(ctx, group, bareUser)
	if err != nil {
		t.Fatalf("GetSenderKeyDevices (after recovery): %v", err)
	}
	if !containsStrings(devices1, targetSenderID) {
		t.Fatalf("device not visible immediately after RecoverSenderKey: got %v, want %q",
			devices1, targetSenderID)
	}
	t.Logf("PASS: GetSenderKeyDevices returned %v immediately after RecoverSenderKey (no sleep)", devices1)
}

// TestRecoveryIterationGuard asserts the iteration-downgrade protection:
//
// If (group, targetSenderID) already has a row with the same KeyID at
// Iteration >= donor.Iteration, RecoverSenderKey must return (false, nil) and
// leave the existing row untouched.
func TestRecoveryIterationGuard(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDA)
	cleanupB := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovworker_iterguard_group@g.us"
		bareUser     = "55512340002_1"
		donorSuffix  = ":5"
		targetSuffix = ":0"
		targetKeyID  = uint32(1) // deliberately low to stay below boundaryN=500
	)
	donorSenderID := bareUser + donorSuffix
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// Clean up any leftover rows.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		recoveryWorkerTestJIDA, recoveryWorkerTestJIDB, group)

	jidA, err := types.ParseJID(recoveryWorkerTestJIDA)
	if err != nil {
		t.Fatalf("ParseJID A: %v", err)
	}
	containerA := sqlstore.NewWithDB(db, "postgres", nil)
	storeA := sqlstore.NewSQLStore(containerA, jidA)

	jidB, err := types.ParseJID(recoveryWorkerTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)
	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	// No running flusher needed here — the iteration guard fires BEFORE the write,
	// so whether the flusher is running or not doesn't affect this test's outcome.
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryWorkerTestJIDB, byteCache, devCache)

	// Seed donor A at KeyID=1, Iteration=50.
	donorStruct := buildDonorStructure(targetKeyID, 50, 0xAA)
	rowA := sqlstore.NewSenderKeyRow(group, donorSenderID, donorStruct)
	if err := storeA.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowA}); err != nil {
		t.Fatalf("seed donor A: %v", err)
	}

	// Seed B's target row at KeyID=1, Iteration=100 (fresher than donor).
	existingStruct := buildDonorStructure(targetKeyID, 100, 0xBB)
	rowB := sqlstore.NewSenderKeyRow(group, targetSenderID, existingStruct)
	if err := innerB.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{rowB}); err != nil {
		t.Fatalf("seed existing B row: %v", err)
	}

	// Attempt recovery with donor at iter=50, existing at iter=100.
	// targetIter=60 (donor=50 <= 60 so donor qualifies by forward-only filter,
	// but the existing iter=100 >= donor iter=50 for same KeyID=1, so guard fires).
	ok, err := csB.RecoverSenderKey(ctx, group, targetSenderID, bareUser, targetKeyID, 60)
	if err != nil {
		t.Fatalf("RecoverSenderKey: %v", err)
	}
	if ok {
		t.Fatal("RecoverSenderKey returned true — expected false (iteration guard should have fired)")
	}

	// Verify DB row is still at Iteration=100 (not overwritten by donor iter=50).
	var iterDB sql.NullInt64
	err = db.QueryRowContext(ctx,
		`SELECT st_chain_key_iteration[1] FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		recoveryWorkerTestJIDB, group, targetSenderID,
	).Scan(&iterDB)
	if err != nil {
		t.Fatalf("read B row iteration: %v", err)
	}
	if !iterDB.Valid || iterDB.Int64 != 100 {
		t.Errorf("DB row iteration = %v, want 100 (must not be downgraded by donor iter=50)", iterDB)
	}
	t.Logf("PASS: iteration guard fired — RecoverSenderKey returned false, DB row preserved at iter=%d", iterDB.Int64)
}

// containsStrings is a helper to check if a string slice contains a target string.
func containsStrings(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

// TestNegativeRecoveryCache verifies that SenderKeyRecoveryWorker's negative-result
// cache deduplicates re-scans for unrecoverable tuples within the TTL window, and
// re-scans after TTL expiry.
//
// Design: calls handle() directly (synchronous) so the test doesn't race the
// jittered goroutine startup. RecoverSenderKey returns (false, nil) because no
// donor exists for the test tuple — that result is cached. A second handle() call
// within the TTL must not call RecoverSenderKey again. After sleeping past TTL,
// a third handle() call must call RecoverSenderKey again.
func TestNegativeRecoveryCache(t *testing.T) {
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	cleanupA := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDA)
	cleanupB := insertRecoveryWorkerTestDevice(t, db, recoveryWorkerTestJIDB)
	t.Cleanup(func() {
		cleanupA()
		cleanupB()
		db.Close()
	})

	const (
		group        = "recovneg_cache_group@g.us"
		bareUser     = "55512340009_1"
		targetSuffix = ":0"
		targetKeyID  = uint32(999) // keyID nobody has a donor for
	)
	targetSenderID := bareUser + targetSuffix

	ctx := context.Background()

	// Clean up any leftover rows from previous test runs.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2`,
		recoveryWorkerTestJIDB, group)

	// Build a CachedSenderKeyStore for B (the recovering account).
	jidB, err := types.ParseJID(recoveryWorkerTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidB)
	byteCache, _ := lru.New[string, []byte](256)
	devCache, _ := lru.New[string, []string](256)
	csB := sqlstore.NewCachedSenderKeyStore(innerB, recoveryWorkerTestJIDB, byteCache, devCache)

	// Atomic counter to count how many times RecoverSenderKey is actually called.
	var scanCount atomic.Int64

	// Construct a SenderKeyRecoveryWorker with:
	//   - negTTL = 1ms (instant expiry for test)
	//   - jitterMax = 0 (no jitter; Start() goroutine starts immediately but we
	//     don't call Start() — we call handle() directly for determinism)
	//   - scanCounter injected via the test constructor
	worker := sqlstore.NewSenderKeyRecoveryWorkerForTest(csB, waLog.Noop, 1*time.Millisecond, &scanCount)

	task := store.RecoveryTask{
		Group:          group,
		TargetSenderID: targetSenderID,
		SenderBare:     bareUser,
		TargetKeyID:    targetKeyID,
		TargetIter:     10,
	}

	// Call 1: no donor (keyID=999 has no row), RecoverSenderKey returns (false, nil).
	// scan count goes 0→1; negative cache entry added.
	worker.HandleForTest(ctx, task)
	if got := scanCount.Load(); got != 1 {
		t.Fatalf("call 1: expected scanCount=1, got=%d", got)
	}

	// Call 2: within TTL=1ms — if the scan finishes faster than 1ms the cache may
	// have already expired. Re-check immediately without sleep; we rely on the Add
	// timestamp being fresh enough. In practice the TTL is 1ms which is well within
	// a test cycle. If this becomes flaky, raise to 5ms.
	worker.HandleForTest(ctx, task)
	if got := scanCount.Load(); got != 1 {
		t.Errorf("call 2 (within TTL): expected scanCount still=1 (neg-cache hit), got=%d", got)
	}

	// Wait for the TTL to expire (2ms > 1ms TTL).
	time.Sleep(2 * time.Millisecond)

	// Call 3: TTL expired — negative cache entry evicted; must scan again.
	worker.HandleForTest(ctx, task)
	if got := scanCount.Load(); got != 2 {
		t.Errorf("call 3 (after TTL): expected scanCount=2 (cache expired, re-scan), got=%d", got)
	}

	t.Logf("PASS: negative-result cache deduped second call; re-scanned after TTL expiry (scanCount=%d)", scanCount.Load())
}
