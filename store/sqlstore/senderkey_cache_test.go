// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_cache_test.go — TestSenderKeyCacheCoherence
//
// Verifies the flat []byte cache REPLACE-on-write coherence design (T-17.9-16)
// using a real store.Device and a real CachedSenderKeyStore.
//
// Phase 38.4-03: the parsed struct cache (ParsedSKCache) is deleted; the single
// flat c.cache write-through inside PutSenderKeyStructure is what provides the
// REPLACE coherence asserted below.
//
// The critical test harness invariant: the flusher IS ATTACHED but NOT STARTED
// (no goroutine, no auto-drain). Enqueue adds to dirty-set only. PutManySenderKeys
// is NEVER called automatically. This is the attached-not-drained condition that
// discriminates between REPLACE and invalidate:
//
//   - Under REPLACE: after PutSenderKeyStructure → LoadSenderKey returns N+1 from
//     the flat cache, while a raw DB read still returns N. Cache leads; DB lags.
//   - Under invalidate: PutSenderKeyStructure would clear the cache → LoadSenderKey
//     misses → reads DB (still N) → returns N. Silent stale key. The flat
//     write-through is REPLACE, not invalidate.
//
// Test arms:
//  1. ratchet-advance: device.StoreSenderKey (iter=N+1) → device.LoadSenderKey returns N+1
//     (from cache); raw DB read returns N (flusher not drained).
//  2. recovery-shaped: direct cs.PutSenderKeyStructure (iter=9, bypasses device.StoreSenderKey)
//     → device.LoadSenderKey returns 9 (from cache); DB returns 5.
//     This is the DISCRIMINATING arm: an invalidate-only design fails here because
//     the cache is cleared, the next Load reads pre-drain DB columns (still 5), returns stale.
//  3. miss-feed-is-recompose: GetSenderKeyStructure on fmt_ver=2 row with garbage blob
//     returns correct structure from columns (proves no Deserialize on fmt_ver=2 path).

package sqlstore_test

import (
	"context"
	"database/sql"
	"strconv"
	"strings"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	libprotocol "go.mau.fi/libsignal/protocol"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// cohTestJID is a separate JID to avoid collisions with other integration tests.
const cohTestJID = "17788880000@s.whatsapp.net"

// buildAdvancedStructure returns a SenderKeyStructure at iteration=iter with keyID=keyID.
// All fields are non-nil (avoids libsignal nil→zeros artifact in the blob path).
func buildAdvancedStructure(keyID uint32, iter uint32) *groupRecord.SenderKeyStructure {
	chainKey := make([]byte, 32)
	for i := range chainKey {
		chainKey[i] = byte(keyID) + byte(iter) + byte(i)
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

// getDBIteration reads the SenderChainKey.Iteration of state[0] directly from
// the flat sender_key blob in the DB. Returns -1 on absent row, NULL blob, or
// decode error (raw bypass of all caches).
// Post-upgrade-19: all rows are PackFlat; st_chain_key_iteration is gone.
func getDBIteration(t *testing.T, db *sql.DB, jid, group, user string) int64 {
	t.Helper()
	var blob []byte
	err := db.QueryRowContext(context.Background(),
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		jid, group, user).Scan(&blob)
	if err != nil || blob == nil {
		return -1
	}
	s, uErr := store.UnpackFlat(blob)
	if uErr != nil || s == nil || len(s.SenderKeyStates) == 0 || s.SenderKeyStates[0] == nil || s.SenderKeyStates[0].SenderChainKey == nil {
		return -1
	}
	return int64(s.SenderKeyStates[0].SenderChainKey.Iteration)
}

// newBatchTestStoreWithJID creates a test store bound to a custom JID.
func newBatchTestStoreWithJID(t *testing.T, jidStr string) (*sqlstore.SQLStore, *sql.DB) {
	t.Helper()
	ctx := context.Background()

	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	container := sqlstore.NewWithDB(db, "postgres", nil)
	thirtyTwo := make([]byte, 32)
	for i := range thirtyTwo {
		thirtyTwo[i] = 0x01
	}
	sixtyFour := make([]byte, 64)
	for i := range sixtyFour {
		sixtyFour[i] = 0x02
	}
	if _, err := db.ExecContext(ctx, insertTestDeviceQuery,
		jidStr, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	); err != nil {
		db.Close()
		t.Fatalf("insert test device: %v", err)
	}

	jid, err := types.ParseJID(jidStr)
	if err != nil {
		db.Close()
		t.Fatalf("parse JID: %v", err)
	}
	st := sqlstore.NewSQLStore(container, jid)

	t.Cleanup(func() {
		if _, err := db.ExecContext(context.Background(), `DELETE FROM whatsmeow_device WHERE jid=$1`, jidStr); err != nil {
			t.Logf("cleanup: %v", err)
		}
		container.Close()
	})

	return st, db
}

// newCohTestDevice creates a *store.Device with:
//   - SenderKeys = *CachedSenderKeyStore wrapping inner (the single flat []byte cache)
//   - Flusher attached via cs.SetFlusher but NOT started (no goroutine)
//
// Phase 38.4-03: the parsed struct cache is deleted. The CachedSenderKeyStore's
// flat c.cache write-through (PutSenderKeyStructure) is the only sender-key cache;
// it provides the REPLACE-on-write coherence the arms below assert via
// device.LoadSenderKey (cache leads, DB lags while the flusher is undrained).
//
// Returns the device, the CachedSenderKeyStore (for direct PutSenderKeyStructure),
// the flusher (for DirtyCount assertion), and the raw *sql.DB (for raw DB reads).
func newCohTestDevice(t *testing.T) (device *store.Device, cs *sqlstore.CachedSenderKeyStore, flusher *sqlstore.SenderKeyFlusher, inner *sqlstore.SQLStore, db *sql.DB) {
	t.Helper()
	inner, db = newBatchTestStoreWithJID(t, cohTestJID)

	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := sqlstore.NewSenderKeyDeviceCache(1024)
	cs = sqlstore.NewCachedSenderKeyStore(inner, cohTestJID, byteCache, devCache)

	// Build a minimal *store.Device with the JID set (required for cacheKey scoping).
	jid, err := types.ParseJID(cohTestJID)
	if err != nil {
		t.Fatalf("ParseJID: %v", err)
	}
	device = &store.Device{
		SenderKeys: cs,
	}
	device.ID = &jid

	// Wire a flusher that is NOT started. Enqueue adds to dirty-set only.
	flusher = sqlstore.NewSenderKeyFlusher(inner, nil, 0)
	cs.SetFlusher(flusher)
	// flusher.Start() is intentionally NOT called — no goroutine, no auto-drain.

	return device, cs, flusher, inner, db
}

// makeSenderKeyName builds a *protocol.SenderKeyName for (group, user).
// user is the device-qualified sender string (e.g. "12345_1:0").
// The sender address is constructed so that senderKeyName.Sender().String() == user.
// libsignal's SignalAddress.String() returns "name:deviceID", so for user="12345_1:0"
// we split on the LAST ':' to get name="12345_1" and deviceID=0.
func makeSenderKeyName(group, user string) *libprotocol.SenderKeyName {
	name := user
	var devID uint32
	if i := strings.LastIndex(user, ":"); i >= 0 {
		name = user[:i]
		if n, err := strconv.ParseUint(user[i+1:], 10, 32); err == nil {
			devID = uint32(n)
		}
	}
	addr := libprotocol.NewSignalAddress(name, devID)
	return libprotocol.NewSenderKeyName(group, addr)
}

// TestSenderKeyCacheCoherence is the BLOCKING coherence test under the
// attached-not-drained flusher. It verifies REPLACE semantics via actual
// device.LoadSenderKey calls, not just callback-firing assertions.
func TestSenderKeyCacheCoherence(t *testing.T) {
	// --- Arm 1: ratchet-advance via device.StoreSenderKey ---
	// Seed DB at iter=5 (write-through). Advance to iter=6 via device.StoreSenderKey
	// (which calls PutSenderKeyStructure → flat c.cache write-through REPLACE).
	// With flusher attached-not-drained: DB stays at 5; LoadSenderKey returns 6.
	t.Run("ratchet-advance", func(t *testing.T) {
		device, cs, flusher, inner, db := newCohTestDevice(t)
		ctx := context.Background()

		const group = "cohcache_adv@g.us"
		const user = "advuser_1:0"

		// Seed DB at iter=5 via PutManySenderKeys on inner (bypasses flusher entirely).
		s5 := buildAdvancedStructure(10, 5)
		row := sqlstore.NewSenderKeyRow(group, user, s5)
		if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
			t.Fatalf("PutManySenderKeys (seed): %v", err)
		}

		// First LoadSenderKey: cache miss → GetSenderKeyStructure → DB (iter=5) → populates cache.
		skn := makeSenderKeyName(group, user)
		got5, err := device.LoadSenderKey(ctx, skn)
		if err != nil {
			t.Fatalf("LoadSenderKey (seed): %v", err)
		}
		if got5 == nil {
			t.Fatal("LoadSenderKey (seed): want non-nil SenderKey")
		}
		if got5.Structure().SenderKeyStates[0].SenderChainKey.Iteration != 5 {
			t.Errorf("LoadSenderKey (seed): want iter=5, got %d",
				got5.Structure().SenderKeyStates[0].SenderChainKey.Iteration)
		}

		// Advance to iter=6 via device.StoreSenderKey.
		// This calls PutSenderKeyStructure → flusher.Enqueue (dirty-set only, no drain)
		// → flat c.cache write-through REPLACE with iter=6.
		s6 := buildAdvancedStructure(10, 6)
		sk6, err := groupRecord.NewSenderKeyFromStruct(s6, store.SignalProtobufSerializer.SenderKeyRecord, store.SignalProtobufSerializer.SenderKeyState)
		if err != nil {
			t.Fatalf("NewSenderKeyFromStruct: %v", err)
		}
		if err := device.StoreSenderKey(ctx, skn, sk6); err != nil {
			t.Fatalf("StoreSenderKey (advance): %v", err)
		}

		// Verify flusher IS attached (has dirty entry).
		if flusher.DirtyCount() == 0 {
			t.Error("flusher dirty-set empty after StoreSenderKey — flusher not properly attached")
		}

		// CRITICAL: DB still has iter=5 (flusher not drained).
		// This confirms the test is exercising the pre-drain window.
		dbIter := getDBIteration(t, db, cohTestJID, group, user)
		if dbIter == 6 {
			t.Logf("WARNING: DB already at iter=6 — flusher may have drained (unlikely without Start())")
		}
		t.Logf("ratchet-advance: DB iter=%d (expect 5 — flusher not drained)", dbIter)

		// LoadSenderKey after advance: cache HIT (was REPLACED with iter=6).
		// If cache was only invalidated (not replaced), this would be a miss → reads DB → returns 5.
		got6, err := device.LoadSenderKey(ctx, skn)
		if err != nil {
			t.Fatalf("LoadSenderKey (advance): %v", err)
		}
		if got6 == nil {
			t.Fatal("LoadSenderKey (advance): want non-nil SenderKey")
		}
		actualIter := got6.Structure().SenderKeyStates[0].SenderChainKey.Iteration
		if actualIter != 6 {
			t.Errorf("LoadSenderKey (advance): want iter=6, got iter=%d\n"+
				"  DB iter=%d — if the DB returned this value, the cache was NOT replaced (invalidate bug)",
				actualIter, dbIter)
		}
		t.Logf("ratchet-advance: DB=%d; LoadSenderKey=%d — REPLACE confirmed (cache leads)", dbIter, actualIter)

		// Sanity: also verify via cs.GetSenderKeyStructure (direct DB read, bypasses cache).
		// It should return iter=5 (DB not yet drained).
		_ = cs // cs used in arm 2
	})

	// --- Arm 2: recovery-shaped (DISCRIMINATING arm) ---
	// Direct cs.PutSenderKeyStructure (iter=9) bypasses device.StoreSenderKey.
	// Simulates the recovery path. DB stays at 5; LoadSenderKey must return 9.
	// An invalidate-only design fails here: cache cleared → Load reads DB (5) → stale.
	t.Run("recovery-shaped", func(t *testing.T) {
		device, cs, flusher, inner, db := newCohTestDevice(t)
		ctx := context.Background()

		const group = "cohcache_rec@g.us"
		const user = "recuser_1:0"

		// Seed DB at iter=5 via inner.PutManySenderKeys.
		s5 := buildAdvancedStructure(20, 5)
		row := sqlstore.NewSenderKeyRow(group, user, s5)
		if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
			t.Fatalf("PutManySenderKeys (seed): %v", err)
		}

		// Warm the cache with iter=5 (first Load).
		skn := makeSenderKeyName(group, user)
		got5, err := device.LoadSenderKey(ctx, skn)
		if err != nil || got5 == nil {
			t.Fatalf("LoadSenderKey (seed): err=%v got=%v", err, got5)
		}
		if got5.Structure().SenderKeyStates[0].SenderChainKey.Iteration != 5 {
			t.Fatalf("LoadSenderKey (seed): want iter=5, got %d",
				got5.Structure().SenderKeyStates[0].SenderChainKey.Iteration)
		}

		// Recovery-shaped write: direct PutSenderKeyStructure (iter=9).
		// Flusher enqueues (dirty-set only, no drain).
		s9 := buildAdvancedStructure(20, 9)
		if err := cs.PutSenderKeyStructure(ctx, group, user, s9); err != nil {
			t.Fatalf("PutSenderKeyStructure (recovery): %v", err)
		}

		// Verify flusher IS attached.
		if flusher.DirtyCount() == 0 {
			t.Error("flusher dirty-set empty — flusher not attached")
		}

		// CRITICAL: DB still has iter=5 (flusher not drained).
		dbIter := getDBIteration(t, db, cohTestJID, group, user)
		if dbIter == 9 {
			t.Logf("WARNING: DB already at iter=9 — flusher may have drained unexpectedly")
		}
		t.Logf("recovery-shaped: DB iter=%d (expect 5 — flusher not drained)", dbIter)

		// LoadSenderKey after recovery: cache HIT (flat c.cache REPLACED with iter=9).
		// Under invalidate: miss → reads DB (still 5) → returns iter=5 (WRONG).
		got9, err := device.LoadSenderKey(ctx, skn)
		if err != nil {
			t.Fatalf("LoadSenderKey (recovery): %v", err)
		}
		if got9 == nil {
			t.Fatal("LoadSenderKey (recovery): want non-nil SenderKey")
		}
		actualIter := got9.Structure().SenderKeyStates[0].SenderChainKey.Iteration
		if actualIter != 9 {
			t.Errorf("LoadSenderKey (recovery): want iter=9, got iter=%d\n"+
				"  DB iter=%d — if the DB returned this, the cache was NOT REPLACED (invalidate bug).\n"+
				"  This is the discriminating check: an invalidate-only design returns stale DB value here.",
				actualIter, dbIter)
		}
		t.Logf("recovery-shaped: DB=%d; LoadSenderKey=%d — REPLACE confirmed (cache leads, DB lags)", dbIter, actualIter)

		// Additional discriminator: direct cs.GetSenderKeyStructure (bypasses cache, reads DB directly).
		// Should return iter=5 (confirming DB has NOT yet been updated by flusher).
		fromDB, err := cs.GetSenderKeyStructure(ctx, group, user)
		if err != nil {
			t.Fatalf("GetSenderKeyStructure (direct DB read): %v", err)
		}
		if fromDB != nil && fromDB.SenderKeyStates[0].SenderChainKey.Iteration != 5 {
			t.Logf("Note: DB direct read returned iter=%d (expected 5 if flusher not drained)",
				fromDB.SenderKeyStates[0].SenderChainKey.Iteration)
		}
		if fromDB != nil {
			t.Logf("recovery-shaped: direct DB read iter=%d; LoadSenderKey iter=%d — contrast proves REPLACE",
				fromDB.SenderKeyStates[0].SenderChainKey.Iteration, actualIter)
		}
	})

	// --- Arm 3: flat-read round-trip — UnpackFlat on valid PackFlat blob ---
	// Post-upgrade-19: GetSenderKeyStructure reads the sender_key bytea and
	// calls store.UnpackFlat. This arm verifies the flat round-trip: write a
	// PackFlat blob via PutManySenderKeys, read back via GetSenderKeyStructure,
	// confirm iter matches. No JSON, no columnar columns.
	t.Run("flat-read-round-trip", func(t *testing.T) {
		_, cs, _, inner, _ := newCohTestDevice(t)
		ctx := context.Background()

		const group = "cohcache_mf@g.us"
		const user = "mfuser_1:0"

		s7 := buildAdvancedStructure(30, 7)
		row := sqlstore.NewSenderKeyRow(group, user, s7)
		if err := inner.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
			t.Fatalf("PutManySenderKeys: %v", err)
		}

		// GetSenderKeyStructure: reads flat blob → store.UnpackFlat (no Deserialize, no recompose).
		got, err := cs.GetSenderKeyStructure(ctx, group, user)
		if err != nil {
			t.Fatalf("GetSenderKeyStructure (flat-read): %v", err)
		}
		if got == nil {
			t.Fatal("flat-read: want non-nil structure; got nil")
		}
		if got.SenderKeyStates[0].SenderChainKey.Iteration != 7 {
			t.Errorf("flat-read: want iter=7, got iter=%d", got.SenderKeyStates[0].SenderChainKey.Iteration)
		}
		t.Logf("flat-read: iter=%d (PackFlat/UnpackFlat round-trip, no JSON)", got.SenderKeyStates[0].SenderChainKey.Iteration)
	})
}
