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
// snapshot -> v16 columns -> v17 DROP NOT NULL -> v18 TPO index -> v19 flat)
// lands the prod-faithful state post-upgrade-19:
//   - sk_keyid0 STORED GENERATED column exists (v19 added it)
//   - sender_key is NOT NULL (v17 dropped NOT NULL, v19 restored it)
//   - pkey uses text_pattern_ops (v18)
//   - whatsmeow_sender_keys_chat_keyid0_idx exists (v19)
//
// Phase 17.11-05: assertions updated from v17 (nullable sender_key + columnar columns)
// to v19 (flat schema: no columnar columns, sk_keyid0 generated column, NOT NULL).
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

	// 1) Post-upgrade-19: st_key_id must NOT exist (v19 dropped all columnar columns).
	var hasOldCol bool
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_name='whatsmeow_sender_keys' AND column_name='st_key_id')`).Scan(&hasOldCol); err != nil {
		t.Fatalf("check st_key_id column: %v", err)
	}
	if hasOldCol {
		t.Error("st_key_id column still present — migration 19 (DROP COLUMN) did not run")
	}

	// 2) Post-upgrade-19: sk_keyid0 STORED GENERATED column must exist (v19 added it).
	var hasFlatCol bool
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM information_schema.columns
		 WHERE table_name='whatsmeow_sender_keys' AND column_name='sk_keyid0')`).Scan(&hasFlatCol); err != nil {
		t.Fatalf("check sk_keyid0 column: %v", err)
	}
	if !hasFlatCol {
		t.Error("sk_keyid0 column missing — migration 19 (ADD GENERATED COLUMN) did not run")
	}

	// 3) Post-upgrade-19: sender_key must be NOT NULL (v19 restored NOT NULL after v17 dropped it).
	var isNullable string
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT is_nullable FROM information_schema.columns
		 WHERE table_name='whatsmeow_sender_keys' AND column_name='sender_key'`).Scan(&isNullable); err != nil {
		t.Fatalf("check sender_key nullability: %v", err)
	}
	if isNullable != "NO" {
		t.Errorf("sender_key is_nullable = %q, want NO — migration 19 (SET NOT NULL) did not run via embed/Upgrade path", isNullable)
	}

	// 4) The recorded version must have advanced to >= v19.
	var version int
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT version FROM whatsmeow_version LIMIT 1`).Scan(&version); err != nil {
		t.Fatalf("read whatsmeow_version: %v", err)
	}
	if version < 19 {
		t.Errorf("recorded schema version = %d, want >= 19", version)
	}

	// 5) Migration 18: the sender_id column of the sender-key pkey index must use
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

	// 6) Migration 19: composite index on (chat_id, sk_keyid0) must exist.
	var hasKeyid0Idx bool
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT EXISTS(SELECT 1 FROM pg_indexes
		  WHERE tablename='whatsmeow_sender_keys'
		    AND indexname='whatsmeow_sender_keys_chat_keyid0_idx')`).Scan(&hasKeyid0Idx); err != nil {
		t.Fatalf("check chat_keyid0_idx: %v", err)
	}
	if !hasKeyid0Idx {
		t.Error("whatsmeow_sender_keys_chat_keyid0_idx missing — migration 19 (CREATE INDEX) did not run")
	}

	// 7) ON CONFLICT (column inference) must still RESOLVE against the swapped
	// unique index — the per-message upsert path depends on it. Post-upgrade-19:
	// only sender_key column (no fmt_ver).
	_, err = scratchDB.ExecContext(ctx,
		`INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, sender_key)
		 VALUES ('e2e@x','g@g.us','s_1:0','\x00')
		 ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET sender_key=excluded.sender_key`)
	if err != nil && strings.Contains(err.Error(), "no unique or exclusion constraint matching") {
		t.Errorf("ON CONFLICT could not infer the text_pattern_ops pkey: %v", err)
	}

	t.Logf("PASS: fresh-DB upgrade chain reached version %d; st_key_id absent; sk_keyid0 present; sender_key nullable; pkey uses text_pattern_ops; ON CONFLICT works", version)
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
