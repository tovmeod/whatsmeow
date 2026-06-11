// Copyright (c) 2026 Kavtov Platform (quick 260612-0af)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_prune.go — one-time, env-gated shrink of oversized
// whatsmeow_sender_keys rows.
//
// Before QUICK-SKCAP-01 the fork's recovery-merge helpers could grow sender-key
// records past libsignal's own limits (2000 skipped keys per state, 5 states
// per record); prod rows reached 1.6MB (~35k skipped keys), and every
// group-message rewrite of a fat row generated dead TOAST churn (~80GB/day —
// the 2026-06-11 disk-full outage). The merge paths are capped now
// (senderkey_caps.go); this sweep shrinks the EXISTING fat rows once.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"go.mau.fi/whatsmeow/store"
)

// senderKeyPruneThresholdBytes is the fat-row scan threshold: rows whose
// sender_key blob is at or under this size are never even decoded. Prod
// measurement (2026-06-12): 9.6M rows total, ~89k TOASTed (>2KB), only ~345
// rows >100KB — the threshold-filtered collect phase is small and bounded.
const senderKeyPruneThresholdBytes = 100000

const pruneScanQuery = `
	SELECT our_jid, chat_id, sender_id
	FROM whatsmeow_sender_keys
	WHERE octet_length(sender_key) > $1
`

const pruneGetQuery = `
	SELECT sender_key FROM whatsmeow_sender_keys
	WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3
`

const pruneUpdateQuery = `
	UPDATE whatsmeow_sender_keys SET sender_key=$4
	WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3
`

// PruneOversizedSenderKeysIfEnabled shrinks existing over-cap
// whatsmeow_sender_keys rows (cross-account: rows span our_jid, so this lives
// on *Container, which owns the shared db handle) by decoding each fat row via
// the flat codec, applying capSenderKeyStructure (libsignal limits: 2000
// skipped keys per state, 5 states per record), and re-writing ONLY the rows
// the cap actually changed. A legit >100KB row that is already within both
// caps is left untouched.
//
// Env gate: runs only when KAVTOV_SENDERKEY_PRUNE_ONCE=1 — the operator
// enables it for exactly one boot, verifies SENDERKEY_PRUNE_DONE in the log,
// then removes the variable.
//
// Driver wiring (one line, early in boot BEFORE accounts connect / caches
// warm, right after the sqlstore Container is constructed):
//
//	if n, err := container.PruneOversizedSenderKeysIfEnabled(ctx); err != nil { log.Errorf("senderkey prune: %v", err) } else if n > 0 { log.Infof("senderkey prune: %d rows shrunk", n) }
//
// WHY before-warm matters: the sweep writes the DB directly, bypassing the
// parsed cache and the write-back flusher. A cache-resident fat entry flushed
// later would overwrite the pruned row with the fat blob again — so the sweep
// must run before any account attaches its cached stores.
//
// Failure posture: per-row decode/pack/update problems are logged and skipped
// (one corrupt row never fails the sweep); each UPDATE is its own autocommit
// statement (no sweep-spanning transaction — bounded TOAST churn per
// statement). NO DDL.
func (c *Container) PruneOversizedSenderKeysIfEnabled(ctx context.Context) (pruned int, err error) {
	if os.Getenv("KAVTOV_SENDERKEY_PRUNE_ONCE") != "1" {
		return 0, nil
	}

	// Phase 1 (collect): gather the key triples of all fat rows first, then
	// close the cursor — the row-at-a-time rewrite below must not run inside
	// an open cursor on the same connection.
	type senderKeyRowKey struct {
		ourJID, chatID, senderID string
	}
	var keys []senderKeyRowKey
	rows, err := c.db.Query(ctx, pruneScanQuery, senderKeyPruneThresholdBytes)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var k senderKeyRowKey
		if err := rows.Scan(&k.ourJID, &k.chatID, &k.senderID); err != nil {
			rows.Close()
			return 0, err
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, err
	}
	rows.Close()

	// Phase 2 (row-at-a-time): decode, cap, re-write only when changed.
	for _, k := range keys {
		var blob []byte
		err := c.db.QueryRow(ctx, pruneGetQuery, k.ourJID, k.chatID, k.senderID).Scan(&blob)
		if errors.Is(err, sql.ErrNoRows) {
			continue // row deleted between phases — fine
		}
		if err != nil {
			c.log.Warnf("SENDERKEY_PRUNE read error row=%s/%s/%s: %v", k.ourJID, k.chatID, k.senderID, err)
			continue
		}
		if blob == nil {
			continue
		}

		s, err := store.UnpackFlat(blob)
		if err != nil {
			c.log.Warnf("SENDERKEY_PRUNE decode error row=%s/%s/%s: %v", k.ourJID, k.chatID, k.senderID, err)
			continue
		}

		capped, changed := capSenderKeyStructure(s)
		if !changed {
			// Legit fat row within both caps — leave untouched (write ONLY
			// when capping actually truncated something).
			continue
		}

		newBlob, ok := store.PackFlat(capped)
		if !ok {
			c.log.Warnf("SENDERKEY_PRUNE pack rejected row=%s/%s/%s (capped structure not flat-packable)",
				k.ourJID, k.chatID, k.senderID)
			continue
		}

		if _, err := c.db.Exec(ctx, pruneUpdateQuery, k.ourJID, k.chatID, k.senderID, newBlob); err != nil {
			c.log.Warnf("SENDERKEY_PRUNE update error row=%s/%s/%s: %v", k.ourJID, k.chatID, k.senderID, err)
			continue
		}
		c.log.Infof("SENDERKEY_PRUNE row=%s/%s/%s before=%d after=%d states=%d->%d",
			k.ourJID, k.chatID, k.senderID, len(blob), len(newBlob),
			len(s.SenderKeyStates), len(capped.SenderKeyStates))
		pruned++
	}

	c.log.Infof("SENDERKEY_PRUNE_DONE scanned=%d pruned=%d threshold=%d",
		len(keys), pruned, senderKeyPruneThresholdBytes)
	return pruned, nil
}
