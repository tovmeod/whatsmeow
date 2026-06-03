// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore_test

import (
	"context"
	"database/sql"
	"strings"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"go.mau.fi/whatsmeow/store/sqlstore"
)

// TestUpgradeChainAppliesV17 runs the real Container.Upgrade against a FRESH
// empty database and asserts the full embedded migration chain (v0->v15 schema
// snapshot -> v16 columns -> v17 DROP NOT NULL) lands the prod-faithful state:
// the columnar columns exist AND sender_key is nullable.
//
// Why this test exists: setup-test-db.sh only applies the v0->v15 snapshot, and
// the package's other tests skip Container.Upgrade entirely (pre-applied
// schema). That leaves the embed -> RegisterFS -> Upgrade Run loop — the exact
// path prod uses on driver startup — UNEXERCISED. A manual `ALTER ... DROP NOT
// NULL` on the shared test DB masks whether migration 17 actually runs. If it
// does not, the first column-only sender-key write on prod hits a NOT NULL
// violation on the per-message write path. This test exercises that path end to
// end on a throwaway database.
func TestUpgradeChainAppliesV17(t *testing.T) {
	ctx := context.Background()
	baseDSN := batchTestDSN()

	admin, err := sql.Open("pgx", baseDSN)
	if err != nil {
		t.Skipf("cannot open admin DB (%s): %v", baseDSN, err)
	}
	defer admin.Close()
	if err := admin.PingContext(ctx); err != nil {
		t.Skipf("test DB not reachable (%s): %v", baseDSN, err)
	}

	const scratch = "kavtov_v17_upgradecheck"
	// CREATE/DROP DATABASE cannot run inside a transaction; plain Exec is fine.
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop pre-existing scratch DB: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("create scratch DB: %v", err)
	}
	t.Cleanup(func() {
		// Reconnect for cleanup (the scratch handle is closed below).
		admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
	})

	scratchDSN := swapDBName(baseDSN, scratch)
	scratchDB, err := sql.Open("pgx", scratchDSN)
	if err != nil {
		t.Fatalf("open scratch DB: %v", err)
	}
	defer scratchDB.Close()

	// Run the real upgrade chain from an empty DB (version 0).
	container := sqlstore.NewWithDB(scratchDB, "postgres", nil)
	if err := container.Upgrade(ctx); err != nil {
		t.Fatalf("Container.Upgrade on fresh DB: %v", err)
	}

	// 1) The columnar columns from v16 must exist.
	var hasCol bool
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_name='whatsmeow_sender_keys' AND column_name='st_key_id')`).Scan(&hasCol); err != nil {
		t.Fatalf("check st_key_id column: %v", err)
	}
	if !hasCol {
		t.Error("st_key_id column missing — migration 16 did not run")
	}

	// 2) sender_key must be NULLABLE after v17 (the decisive assertion).
	var isNullable string
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT is_nullable FROM information_schema.columns
		 WHERE table_name='whatsmeow_sender_keys' AND column_name='sender_key'`).Scan(&isNullable); err != nil {
		t.Fatalf("check sender_key nullability: %v", err)
	}
	if isNullable != "YES" {
		t.Errorf("sender_key is_nullable = %q, want YES — migration 17 (DROP NOT NULL) did not run via the embed/Upgrade path", isNullable)
	}

	// 3) The recorded version must have advanced to >= v18 (v17 + v18 applied).
	var version int
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT version FROM whatsmeow_version LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("read whatsmeow_version: %v", err)
	}
	if version < 18 {
		t.Errorf("recorded schema version = %d, want >= 18", version)
	}

	// 4) Migration 18: the sender_id column of the sender-key pkey index must use
	// text_pattern_ops (enables the prefix-LIKE range seek). Verify the opclass.
	var tpoCols int
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT count(*) FROM pg_index i
		   JOIN pg_class c ON c.oid = i.indexrelid
		   JOIN pg_opclass oc ON oc.oid = ANY(i.indclass::oid[])
		  WHERE c.relname = 'whatsmeow_sender_keys_pkey'
		    AND oc.opcname = 'text_pattern_ops'`).Scan(&tpoCols); err != nil {
		t.Fatalf("check pkey opclass: %v", err)
	}
	if tpoCols == 0 {
		t.Error("whatsmeow_sender_keys_pkey does not use text_pattern_ops — migration 18 did not run via the embed/Upgrade path")
	}

	// 5) ON CONFLICT (column inference) must still RESOLVE against the swapped
	// unique index — the per-message upsert path depends on it. We use a fake
	// our_jid, so the statement hits the our_jid->whatsmeow_device foreign key
	// (23503); that's fine and EXPECTED — it proves arbiter inference succeeded
	// and execution reached the FK check. The only failure we care about is
	// "no unique or exclusion constraint matching" (42P10), which would mean the
	// text_pattern_ops index can't be inferred.
	_, err = scratchDB.ExecContext(ctx,
		`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, fmt_ver)
		 VALUES ('e2e@x','g@g.us','s_1:0',2)
		 ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET fmt_ver=excluded.fmt_ver`)
	if err != nil && strings.Contains(err.Error(), "no unique or exclusion constraint matching") {
		t.Errorf("ON CONFLICT could not infer the text_pattern_ops pkey: %v", err)
	}

	t.Logf("PASS: fresh-DB upgrade chain reached version %d; st_key_id present; sender_key nullable; pkey uses text_pattern_ops; ON CONFLICT works", version)
}

// swapDBName replaces the database path in a postgres DSN (the last /segment).
func swapDBName(dsn, newName string) string {
	q := ""
	if i := strings.IndexByte(dsn, '?'); i >= 0 {
		q = dsn[i:]
		dsn = dsn[:i]
	}
	if i := strings.LastIndexByte(dsn, '/'); i >= 0 {
		return dsn[:i+1] + newName + q
	}
	return dsn
}
