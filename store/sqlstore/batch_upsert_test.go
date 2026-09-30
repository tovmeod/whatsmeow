// Copyright (c) 2026 Kavtov Platform (Phase 17.7 / Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"reflect"
	"testing"

	lru "github.com/hashicorp/golang-lru/v2"
	_ "github.com/jackc/pgx/v5/stdlib"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/serialize"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// pbSerializer is the libsignal JSON serializer used to round-trip
// SenderKeyStructure ↔ []byte (for read-back verification).
var pbSerializer = serialize.NewProtoBufSerializer()

// testDSN is the dockerized Postgres test DB applied by
// kavtov-driver-go/scripts/setup-test-db.sh (which also applies the fork's
// 00-latest-schema.sql, creating the whatsmeow_* tables). Overridable via
// TEST_DSN (also honors KAVTOV_TEST_DSN for parity with the sibling driver
// module's testPool).
const defaultTestDSN = "postgresql://kavtov_test:kavtov_test@localhost:5433/kavtov_test"

// testJID is a fixed, non-real JID used by all batch-upsert tests. Its device
// row is created in newBatchTestStore and removed (ON DELETE CASCADE clears its
// sender_keys) in t.Cleanup.
const testJID = "17700000000@s.whatsapp.net"

func batchTestDSN() string {
	if dsn := os.Getenv("TEST_DSN"); dsn != "" {
		return dsn
	}
	if dsn := os.Getenv("KAVTOV_TEST_DSN"); dsn != "" {
		return dsn
	}
	return defaultTestDSN
}

// insertTestDeviceQuery creates the minimal whatsmeow_device row that the
// whatsmeow_sender_keys.our_jid FK requires. The adv_*/key columns have NOT NULL
// + length CHECK constraints, so we bind correctly-sized dummy bytea values.
// A fresh Container.NewDevice() cannot be persisted via PutDevice here because
// device.Account is nil until pairing, so a targeted raw INSERT is used instead.
const insertTestDeviceQuery = `
	INSERT INTO whatsmeow_device (jid, registration_id, noise_key, identity_key,
								  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
								  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
	ON CONFLICT (jid) DO NOTHING
`

// newBatchTestStore opens the real Postgres test DB, ensures the test device
// row exists, and returns an *sqlstore.SQLStore bound to testJID. Cleanup
// deletes the device row (cascading to its sender_keys) and closes the DB.
func newBatchTestStore(t *testing.T) (*sqlstore.SQLStore, *sql.DB) {
	t.Helper()
	ctx := context.Background()

	// driver name is "pgx" (pgx stdlib); dbutil dialect is "postgres".
	db, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable at %s (run kavtov-driver-go/scripts/setup-test-db.sh): %v", batchTestDSN(), err)
	}

	// Schema is pre-applied by setup-test-db.sh; do NOT call container.Upgrade.
	container := sqlstore.NewWithDB(db, "postgres", nil)

	thirtyTwo := bytes.Repeat([]byte{0x01}, 32)
	sixtyFour := bytes.Repeat([]byte{0x02}, 64)
	_, err = db.ExecContext(ctx, insertTestDeviceQuery,
		testJID, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	)
	if err != nil {
		db.Close()
		t.Fatalf("insert test device: %v", err)
	}

	jid, err := types.ParseJID(testJID)
	if err != nil {
		db.Close()
		t.Fatalf("parse test JID: %v", err)
	}
	store := sqlstore.NewSQLStore(container, jid)

	t.Cleanup(func() {
		// Delete the device first (needs an open db); ON DELETE CASCADE clears
		// its sender_keys. Then Container.Close() cancels the metrics goroutine
		// (Phase 17.5.1 WR-01) before closing the underlying db — do not close
		// the raw db directly, which would leak the goroutine and invert the
		// teardown ordering Close() guarantees.
		if _, err := db.ExecContext(context.Background(), `DELETE FROM whatsmeow_device WHERE jid=$1`, testJID); err != nil {
			t.Logf("cleanup delete device: %v", err)
		}
		container.Close()
	})

	return store, db
}

// buildTestSenderKeyStructure creates a simple *SenderKeyStructure with one
// state (keyID=1, iteration=1, non-nil keys) suitable for batch upsert tests.
func buildTestSenderKeyStructure(keyID uint32) *groupRecord.SenderKeyStructure {
	key32 := make([]byte, 32)
	for i := range key32 {
		key32[i] = byte(keyID + uint32(i))
	}
	pub33 := make([]byte, 33)
	pub33[0] = 0x05
	for i := 1; i < 33; i++ {
		pub33[i] = byte(keyID + uint32(i))
	}
	return &groupRecord.SenderKeyStructure{
		SenderKeyStates: []*groupRecord.SenderKeyStateStructure{
			{
				KeyID: keyID,
				SenderChainKey: &ratchet.SenderChainKeyStructure{
					Iteration: 1,
					ChainKey:  key32,
				},
				SigningKeyPublic:  pub33,
				SigningKeyPrivate: key32,
			},
		},
	}
}

// readBackAndVerify reads the sender_key blob from DB for (group, user),
// deserializes it, and checks the first state's KeyID matches wantKeyID.
func readBackAndVerify(t *testing.T, s *sqlstore.SQLStore, group, user string, wantKeyID uint32) {
	t.Helper()
	ctx := context.Background()
	// Dual-READ only (no dual-write): column-only rows have no sender_key blob,
	// so verify through the columnar read path (GetSenderKeyStructure), which is
	// the production read path.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := lru.New[string, []string](1024)
	cs := sqlstore.NewCachedSenderKeyStore(s, testJID, byteCache, devCache, nil)
	structure, err := cs.GetSenderKeyStructure(ctx, group, user)
	if err != nil {
		t.Fatalf("GetSenderKeyStructure(%s,%s): %v", group, user, err)
	}
	if structure == nil {
		t.Fatalf("GetSenderKeyStructure(%s,%s): returned nil (row not found)", group, user)
	}
	if len(structure.SenderKeyStates) == 0 {
		t.Fatalf("no states in recomposed structure for (%s,%s)", group, user)
	}
	if structure.SenderKeyStates[0].KeyID != wantKeyID {
		t.Errorf("GetSenderKeyStructure(%s,%s) → keyID = %d, want %d", group, user, structure.SenderKeyStates[0].KeyID, wantKeyID)
	}
}

func TestBatchUpsertSenderKeys(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	// Build columnar rows using the exported NewSenderKeyRow constructor.
	rows := []sqlstore.SenderKeyRow{
		sqlstore.NewSenderKeyRow("111@g.us", "100_1:0", buildTestSenderKeyStructure(1)),
		sqlstore.NewSenderKeyRow("111@g.us", "200_1:0", buildTestSenderKeyStructure(2)),
		sqlstore.NewSenderKeyRow("222@g.us", "100_1:0", buildTestSenderKeyStructure(3)),
	}
	if err := store.PutManySenderKeys(ctx, rows); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Read back and verify: the blob round-trips through recomposed sender_key.
	readBackAndVerify(t, store, "111@g.us", "100_1:0", 1)
	readBackAndVerify(t, store, "111@g.us", "200_1:0", 2)
	readBackAndVerify(t, store, "222@g.us", "100_1:0", 3)
}

func TestBatchUpsertSenderKeysOverwrite(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{
		sqlstore.NewSenderKeyRow("333@g.us", "300_1:0", buildTestSenderKeyStructure(10)),
	}); err != nil {
		t.Fatalf("PutManySenderKeys (initial): %v", err)
	}
	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{
		sqlstore.NewSenderKeyRow("333@g.us", "300_1:0", buildTestSenderKeyStructure(20)),
	}); err != nil {
		t.Fatalf("PutManySenderKeys (overwrite): %v", err)
	}

	// After overwrite, keyID should be 20 (not 10).
	readBackAndVerify(t, store, "333@g.us", "300_1:0", 20)
}

func TestBatchUpsertSenderKeysEmpty(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	if err := store.PutManySenderKeys(ctx, nil); err != nil {
		t.Errorf("PutManySenderKeys(nil) = %v, want nil", err)
	}
	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{}); err != nil {
		t.Errorf("PutManySenderKeys(empty) = %v, want nil", err)
	}
}

func TestBatchUpsertSenderKeysChunking(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	const n = 250
	rows := make([]sqlstore.SenderKeyRow, n)
	for i := 0; i < n; i++ {
		rows[i] = sqlstore.NewSenderKeyRow(
			"444@g.us",
			fmt.Sprintf("%d_1:0", 5000+i),
			buildTestSenderKeyStructure(uint32(i+1)),
		)
	}
	if err := store.PutManySenderKeys(ctx, rows); err != nil {
		t.Fatalf("PutManySenderKeys(250): %v", err)
	}

	for i := 0; i < n; i++ {
		readBackAndVerify(t, store, rows[i].Group, rows[i].User, uint32(i+1))
	}
}

// TestBatchUpsertColumnRoundTrip verifies that PutManySenderKeys writes a valid
// PackFlat blob and GetSenderKeyStructure reads it back correctly (flat round-trip).
// Post-upgrade-19: no columnar columns; sender_key is the flat blob.
// Requires a live DB (skips if unavailable).
func TestBatchUpsertColumnRoundTrip(t *testing.T) {
	store, db := newBatchTestStore(t)
	ctx := context.Background()

	// Write a structure with known fields.
	original := buildTestSenderKeyStructure(77)
	row := sqlstore.NewSenderKeyRow("555@g.us", "777_1:0", original)
	if row.Blob == nil {
		t.Fatal("NewSenderKeyRow: PackFlat returned nil blob")
	}
	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{row}); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	// Post-upgrade-19: verify the flat blob was written (sender_key NOT NULL).
	var blob []byte
	err := db.QueryRowContext(ctx,
		`SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`,
		testJID, "555@g.us", "777_1:0").Scan(&blob)
	if err != nil {
		t.Fatalf("QueryRow sender_key: %v", err)
	}
	if blob == nil {
		t.Error("sender_key blob is NULL, want non-NULL PackFlat blob")
	}

	// Verify round-trip through GetSenderKeyStructure → store.UnpackFlat.
	byteCache, _ := lru.New[string, []byte](1024)
	devCache, _ := lru.New[string, []string](1024)
	cs := sqlstore.NewCachedSenderKeyStore(store, testJID, byteCache, devCache, nil)
	structure, err := cs.GetSenderKeyStructure(ctx, "555@g.us", "777_1:0")
	if err != nil || structure == nil {
		t.Fatalf("GetSenderKeyStructure: err=%v got=%v", err, structure)
	}
	if !reflect.DeepEqual(normalizeSenderKeyStructure(original), normalizeSenderKeyStructure(structure)) {
		t.Errorf("flat round-trip mismatch:\n  original:    %+v\n  roundtripped: %+v", original, structure)
	}
}

// normalizeSenderKeyStructure normalizes nil-vs-empty-slice differences in a
// *SenderKeyStructure for DeepEqual comparison. The JSON serializer converts
// nil Keys to []... on write; Deserialize returns [] not nil.
func normalizeSenderKeyStructure(sk *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
	if sk == nil {
		return nil
	}
	result := &groupRecord.SenderKeyStructure{}
	for _, st := range sk.SenderKeyStates {
		ns := &groupRecord.SenderKeyStateStructure{
			KeyID:             st.KeyID,
			SigningKeyPublic:  st.SigningKeyPublic,
			SigningKeyPrivate: st.SigningKeyPrivate,
			SenderChainKey:    st.SenderChainKey,
		}
		// Normalize Keys: treat nil and [] as equivalent (both mean "no skipped keys").
		if len(st.Keys) > 0 {
			ns.Keys = st.Keys
		}
		result.SenderKeyStates = append(result.SenderKeyStates, ns)
	}
	return result
}
