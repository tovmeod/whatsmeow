// Copyright (c) 2026 Kavtov Platform (Phase 17.7)
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
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

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

func TestBatchUpsertSenderKeys(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	rows := []sqlstore.SenderKeyRow{
		{Group: "111@g.us", User: "100_1:0", Session: []byte("session-a")},
		{Group: "111@g.us", User: "200_1:0", Session: []byte("session-b")},
		{Group: "222@g.us", User: "100_1:0", Session: []byte("session-c")},
	}
	if err := store.PutManySenderKeys(ctx, rows); err != nil {
		t.Fatalf("PutManySenderKeys: %v", err)
	}

	for _, r := range rows {
		got, err := store.GetSenderKey(ctx, r.Group, r.User)
		if err != nil {
			t.Fatalf("GetSenderKey(%s,%s): %v", r.Group, r.User, err)
		}
		if !bytes.Equal(got, r.Session) {
			t.Errorf("GetSenderKey(%s,%s) = %q, want %q", r.Group, r.User, got, r.Session)
		}
	}
}

func TestBatchUpsertSenderKeysOverwrite(t *testing.T) {
	store, _ := newBatchTestStore(t)
	ctx := context.Background()

	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{
		{Group: "333@g.us", User: "300_1:0", Session: []byte("old-blob")},
	}); err != nil {
		t.Fatalf("PutManySenderKeys (initial): %v", err)
	}
	if err := store.PutManySenderKeys(ctx, []sqlstore.SenderKeyRow{
		{Group: "333@g.us", User: "300_1:0", Session: []byte("new-blob")},
	}); err != nil {
		t.Fatalf("PutManySenderKeys (overwrite): %v", err)
	}

	got, err := store.GetSenderKey(ctx, "333@g.us", "300_1:0")
	if err != nil {
		t.Fatalf("GetSenderKey: %v", err)
	}
	if !bytes.Equal(got, []byte("new-blob")) {
		t.Errorf("after overwrite GetSenderKey = %q, want %q", got, "new-blob")
	}
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
		rows[i] = sqlstore.SenderKeyRow{
			Group:   "444@g.us",
			User:    fmt.Sprintf("%d_1:0", 5000+i),
			Session: []byte(fmt.Sprintf("blob-%d", i)),
		}
	}
	if err := store.PutManySenderKeys(ctx, rows); err != nil {
		t.Fatalf("PutManySenderKeys(250): %v", err)
	}

	for i := 0; i < n; i++ {
		got, err := store.GetSenderKey(ctx, rows[i].Group, rows[i].User)
		if err != nil {
			t.Fatalf("GetSenderKey(%s): %v", rows[i].User, err)
		}
		if !bytes.Equal(got, rows[i].Session) {
			t.Errorf("GetSenderKey(%s) = %q, want %q", rows[i].User, got, rows[i].Session)
		}
	}
}
