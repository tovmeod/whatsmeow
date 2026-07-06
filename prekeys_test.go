// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import "testing"

// TestWantedPreKeyCountMatchesBrowserBatch: WantedPreKeyCount must match the browser-realistic
// prekey batch size (812), matching the already-conformant initial-upload batch (D-08 #3,
// 60-CONTEXT.md). uploadPreKeys's wire behavior is not independently unit-testable without a full
// sendIQ mock, so pinning the constant is the proportionate automated check here.
func TestWantedPreKeyCountMatchesBrowserBatch(t *testing.T) {
	if WantedPreKeyCount != 812 {
		t.Errorf("WantedPreKeyCount = %d, want 812 (ongoing prekey refills must match the initial-upload batch size)", WantedPreKeyCount)
	}
}
