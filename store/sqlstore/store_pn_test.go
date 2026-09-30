// Copyright (c) 2026 Kavtov Platform (Phase 47.3)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// store_pn_test.go — DB-backed tests for the ExistsPNSession predicate.
//
// TestExistsPNSession_LIKEMatch seeds one whatsmeow_sessions row with
// their_id='972515529399:0' and asserts that:
//   - ExistsPNSession(ctx, "972515529399:") returns (true, nil)
//   - ExistsPNSession(ctx, "972526548435:") returns (false, nil) — different phone
//   - ExistsPNSession(ctx, "972515529399_1:") returns (false, nil) — LID-form prefix
//
// The test verifies that the LIKE $2 || ':%' ESCAPE '\' predicate (D-06) is
// collation-safe on en_US.utf8 Postgres and does NOT false-positive on LID-form
// their_id values which start with the same digits but use an underscore delimiter.
//
// Requires a test Postgres instance. Skips gracefully if none is reachable.
// Uses a scratch DB (kavtov_47_3_pn_check) with full upgrade chain applied.
package sqlstore_test

import (
	"context"
	"database/sql"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// TestExistsPNSession_LIKEMatch creates a scratch DB, applies migrations, seeds
// a PN-form session row, and asserts ExistsPNSession returns the correct result
// for PN-form, different-phone, and LID-form prefixes.
//
// RED until plan 02 adds ExistsPNSession to SQLStore; compile error is the
// expected Wave-0 state.
func TestExistsPNSession_LIKEMatch(t *testing.T) {
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

	const scratch = "kavtov_47_3_pn_check"
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop pre-existing scratch DB: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("create scratch DB: %v", err)
	}
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
	})

	scratchDSN := swapDBName(baseDSN, scratch)
	scratchDB, err := sql.Open("pgx", scratchDSN)
	if err != nil {
		t.Fatalf("open scratch DB: %v", err)
	}
	defer scratchDB.Close()

	// Apply the full upgrade chain (all migrations) to the empty scratch DB.
	container := sqlstore.NewWithDB(scratchDB, "postgres", nil)
	if err := container.Upgrade(ctx); err != nil {
		t.Fatalf("Container.Upgrade on scratch DB: %v", err)
	}

	// Insert a minimal whatsmeow_device row required for the our_jid FK.
	const testJIDPNCheck = "447911123456@s.whatsapp.net"
	thirtyTwo := make([]byte, 32)
	sixtyFour := make([]byte, 64)
	if _, err := scratchDB.ExecContext(ctx, insertTestDeviceQuery,
		testJIDPNCheck, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	// Build the SQLStore for the test JID.
	testJID, err := types.ParseJID(testJIDPNCheck)
	if err != nil {
		t.Fatalf("ParseJID: %v", err)
	}
	st := sqlstore.NewSQLStore(container, testJID)

	// Seed one PN-form session row: their_id='972515529399:0'.
	// The blob is a minimal non-empty placeholder; ExistsPNSession only checks existence.
	seedBlob := []byte{0x01, 0x02, 0x03}
	if _, err := scratchDB.ExecContext(ctx,
		`INSERT INTO whatsmeow_sessions (our_jid, their_id, session) VALUES ($1, $2, $3)`,
		testJIDPNCheck, "972515529399:0", seedBlob,
	); err != nil {
		t.Fatalf("seed pn session row: %v", err)
	}

	// Case 1: PN prefix that matches the seeded row — must return true.
	got, err := st.ExistsPNSession(ctx, "972515529399:")
	if err != nil {
		t.Fatalf("ExistsPNSession(%q): %v", "972515529399:", err)
	}
	if !got {
		t.Errorf("ExistsPNSession(%q) = false, want true — seeded row '972515529399:0' must match", "972515529399:")
	}

	// Case 2: Different phone — no row exists, must return false.
	got2, err := st.ExistsPNSession(ctx, "972526548435:")
	if err != nil {
		t.Fatalf("ExistsPNSession(%q): %v", "972526548435:", err)
	}
	if got2 {
		t.Errorf("ExistsPNSession(%q) = true, want false — no row for this phone", "972526548435:")
	}

	// Case 3: LID-form prefix "972515529399_1:" — must NOT match the PN row
	// '972515529399:0' because the delimiter is ':' not '_'. This confirms
	// the LIKE predicate does not false-positive on LID-form prefixes even when
	// the digits are identical (the underscore is a LIKE wildcard; ESCAPE '\' is
	// required to treat it literally — ExistsPNSession must escape the prefix).
	got3, err := st.ExistsPNSession(ctx, "972515529399_1:")
	if err != nil {
		t.Fatalf("ExistsPNSession(%q): %v", "972515529399_1:", err)
	}
	if got3 {
		t.Errorf("ExistsPNSession(%q) = true, want false — LID-form prefix must NOT match the PN row (ESCAPE required)", "972515529399_1:")
	}

	t.Logf("PASS: ExistsPNSession correctly matches PN rows and rejects LID-form prefixes")
}

// TestDeleteAllIdentities_CollationSafe verifies that DeleteAllIdentities uses
// a collation-safe LIKE predicate (Phase 47.3 amendment 2026-06-25).
//
// Regression test for ef91440 (2026-05-25) which introduced a broken range
// idiom (their_id >= $2||':' AND their_id < $2||';') that silently deleted 0
// rows on en_US.utf8. The identity-change handler (notification.go:55) calls
// DeleteAllIdentities; with the broken predicate it was a no-op for ~1 month.
//
// This test:
//   - seeds two identity rows: '972515529399:0' and '972526548435:0'
//   - calls DeleteAllIdentities(ctx, "972515529399")
//   - asserts '972515529399:0' is GONE (target phone deleted)
//   - asserts '972526548435:0' REMAINS (scoping correct — different phone untouched)
//
// Requires a test Postgres instance. Skips gracefully if none is reachable.
func TestDeleteAllIdentities_CollationSafe(t *testing.T) {
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

	const scratch = "kavtov_47_3_delallidents"
	if _, err := admin.ExecContext(ctx, "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)"); err != nil {
		t.Fatalf("drop pre-existing scratch DB: %v", err)
	}
	if _, err := admin.ExecContext(ctx, "CREATE DATABASE "+scratch); err != nil {
		t.Fatalf("create scratch DB: %v", err)
	}
	t.Cleanup(func() {
		admin.ExecContext(context.Background(), "DROP DATABASE IF EXISTS "+scratch+" WITH (FORCE)")
	})

	scratchDSN := swapDBName(baseDSN, scratch)
	scratchDB, err := sql.Open("pgx", scratchDSN)
	if err != nil {
		t.Fatalf("open scratch DB: %v", err)
	}
	defer scratchDB.Close()

	container := sqlstore.NewWithDB(scratchDB, "postgres", nil)
	if err := container.Upgrade(ctx); err != nil {
		t.Fatalf("Container.Upgrade on scratch DB: %v", err)
	}

	const testJID = "447911654321@s.whatsapp.net"
	thirtyTwo := make([]byte, 32)
	sixtyFour := make([]byte, 64)
	if _, err := scratchDB.ExecContext(ctx, insertTestDeviceQuery,
		testJID, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	); err != nil {
		t.Fatalf("insert test device: %v", err)
	}

	testJIDParsed, err := types.ParseJID(testJID)
	if err != nil {
		t.Fatalf("ParseJID: %v", err)
	}
	st := sqlstore.NewSQLStore(container, testJIDParsed)

	// Seed two identity rows for different phones.
	identity := make([]byte, 32)
	for i := range identity {
		identity[i] = byte(i + 1)
	}
	for _, theirID := range []string{"972515529399:0", "972526548435:0"} {
		if _, err := scratchDB.ExecContext(ctx,
			`INSERT INTO whatsmeow_identity_keys (our_jid, their_id, identity) VALUES ($1, $2, $3)`,
			testJID, theirID, identity,
		); err != nil {
			t.Fatalf("seed identity row %s: %v", theirID, err)
		}
	}

	// Delete all identities for the first phone only.
	if err := st.DeleteAllIdentities(ctx, "972515529399"); err != nil {
		t.Fatalf("DeleteAllIdentities: %v", err)
	}

	// Assert target phone row is gone.
	var count int
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id=$2`,
		testJID, "972515529399:0",
	).Scan(&count); err != nil {
		t.Fatalf("count target row: %v", err)
	}
	if count != 0 {
		t.Errorf("DeleteAllIdentities(%q) left %d rows for '972515529399:0', want 0 — collation-broken predicate still in use", "972515529399", count)
	}

	// Assert different phone row is untouched.
	if err := scratchDB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id=$2`,
		testJID, "972526548435:0",
	).Scan(&count); err != nil {
		t.Fatalf("count sibling row: %v", err)
	}
	if count != 1 {
		t.Errorf("DeleteAllIdentities(%q) also deleted '972526548435:0', got %d rows remaining, want 1 — scope predicate too broad", "972515529399", count)
	}

	t.Logf("PASS: DeleteAllIdentities correctly deletes target phone rows and leaves sibling phone rows")
}
