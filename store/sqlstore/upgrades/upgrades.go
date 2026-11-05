// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package upgrades

import (
	"context"
	"embed"

	"go.mau.fi/util/dbutil"
)

//go:embed *.sql
var upgrades embed.FS

var Table = dbutil.BuildUpgradeTable().WithFS(upgrades).
	WithRaw(22, 23, 8, "Index signal-address prefix queries", dbutil.TxnModeOff, upgradeSignalPrefixIndexes).
	WithRaw(23, 24, 8, "Index cross-account sender-key recovery", dbutil.TxnModeOff, upgradeSenderKeyRecoveryIndex).
	Finish()

func upgradeSenderKeyRecoveryIndex(ctx context.Context, db *dbutil.Database) error {
	if db.Dialect != dbutil.Postgres {
		return nil
	}
	return ensureConcurrentIndex(ctx, db, "whatsmeow_sender_keys_recovery_idx", "whatsmeow_sender_keys (chat_id, sender_id text_pattern_ops)")
}
