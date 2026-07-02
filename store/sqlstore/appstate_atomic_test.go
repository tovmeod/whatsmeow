// Copyright (c) 2026 Kavtov Platform (Phase 55.1 plan 10)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore_test

import (
	"bytes"
	"context"
	"testing"

	"go.mau.fi/whatsmeow/store"
)

// TestPutAppStateVersionAndMACs_AtomicOnFailure proves 55.1-10 Task 2: a failure partway
// through PutAppStateVersionAndMACs must roll back ALL of its writes (version cursor +
// removed MACs + added MACs), not just abort the one failing statement. A malformed
// index_mac (wrong length — whatsmeow_app_state_mutation_macs CHECKs length(index_mac)=32)
// forces the added-MAC insert to fail after the version-cursor write would already have
// succeeded under the old non-transactional storeMACs. Asserting the version cursor did
// NOT advance proves the whole call rolled back, closing the exact cursor-ahead-of-ledger
// corruption pattern the class 14 investigation identified (H2,
// 55.1-INVESTIGATION-appstate-connection.md).
func TestPutAppStateVersionAndMACs_AtomicOnFailure(t *testing.T) {
	s, db := newBatchTestStore(t)
	ctx := context.Background()
	const name = "regular_high"

	t.Cleanup(func() {
		if _, err := db.ExecContext(ctx, `DELETE FROM whatsmeow_app_state_version WHERE jid=$1 AND name=$2`, testJID, name); err != nil {
			t.Logf("cleanup delete app state version: %v", err)
		}
	})

	version, hash, err := s.GetAppStateVersion(ctx, name)
	if err != nil {
		t.Fatalf("baseline GetAppStateVersion: %v", err)
	}
	if version != 0 {
		t.Fatalf("baseline version = %d, want 0 (fresh device)", version)
	}

	badMAC := store.AppStateMutationMAC{
		IndexMAC: []byte{0x01, 0x02},        // wrong length — schema requires 32 bytes
		ValueMAC: bytes.Repeat([]byte{0x03}, 32),
	}
	err = s.PutAppStateVersionAndMACs(ctx, name, 5, hash, nil, []store.AppStateMutationMAC{badMAC})
	if err == nil {
		t.Fatal("PutAppStateVersionAndMACs with a malformed index_mac unexpectedly succeeded")
	}

	versionAfter, _, err := s.GetAppStateVersion(ctx, name)
	if err != nil {
		t.Fatalf("post-failure GetAppStateVersion: %v", err)
	}
	if versionAfter != 0 {
		t.Fatalf("version cursor advanced to %d despite the MAC insert failing — atomicity violated (cursor-ahead-of-ledger)", versionAfter)
	}
}
