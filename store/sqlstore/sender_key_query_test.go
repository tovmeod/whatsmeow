// Copyright (c) 2026 Kavtov Platform (Phase 27)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"strings"
	"testing"
)

// TestGetSenderKeyDevicesQueryForm pins the production device-set enumerate query
// and its LIKE escaper to the collation-stable form whose behavior is proven
// against real en_US.utf8 Postgres by the driver-module integration test
// TestSenderKeyDevicesCollation (internal/driver/sender_key_collation_test.go).
//
// This is the drift guard: it fails if a future edit reintroduces the
// collation-broken range bound (`sender_id >= $3||':' AND sender_id < $3||';'`)
// that silently returned 0 rows under en_US.utf8 and left the Phase-26 fallback
// inert (the 2026.05.64/65 regression). It needs no database, so it runs in the
// fork's driver-less test environment; the behavioral proof lives in the driver
// module where a Postgres driver is available.
func TestGetSenderKeyDevicesQueryForm(t *testing.T) {
	if !strings.Contains(getSenderKeyDevicesQuery, `sender_id LIKE $3 || ':%' ESCAPE '\'`) {
		t.Errorf("getSenderKeyDevicesQuery lost the collation-stable escaped-LIKE form:\n%s", getSenderKeyDevicesQuery)
	}
	// The collation-broken range bound must NOT come back.
	if strings.Contains(getSenderKeyDevicesQuery, `|| ';'`) || strings.Contains(getSenderKeyDevicesQuery, `< $3`) {
		t.Errorf("getSenderKeyDevicesQuery reintroduced the collation-broken range bound:\n%s", getSenderKeyDevicesQuery)
	}
	// The escaper must escape all three LIKE metacharacters, backslash first
	// (single-pass; inserted backslashes must not be double-escaped).
	if got := senderKeyLikeEscaper.Replace(`a_b%c\d`); got != `a\_b\%c\\d` {
		t.Errorf("senderKeyLikeEscaper.Replace = %q, want %q", got, `a\_b\%c\\d`)
	}
}
