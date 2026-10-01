// Copyright (c) 2026 Kavtov Platform (Phase 35.2 plan 05)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// export_test.go — test-only exports for unexported symbols.
// Package sqlstore_test cannot reach unexported identifiers directly; this file
// re-exports them under exported names compiled only during `go test`.

package sqlstore

import (
	"strconv"
)

// DeleteNoDonorCacheEntry removes a single entry from the negative-donor cache.
// Test-only: allows DB-backed integration tests (package sqlstore_test) to
// evict a specific sfKey so the cache does not bleed across subtests that share
// the same (group, senderBare, keyID) tuple but use different donor/targetIter
// scenarios.
func DeleteNoDonorCacheEntry(group, senderBare string, keyID uint32) {
	sfKey := group + "|" + senderBare + "|" + strconv.FormatUint(uint64(keyID), 10)
	removeNoDonorCacheEntry(sfKey)
}
