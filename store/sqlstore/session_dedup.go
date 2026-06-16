// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// session_dedup.go — one-time, env-gated, LOSSLESS shrink of fat
// whatsmeow_sessions rows by dropping byte-identical archived states.
//
// The establishSessionWithSender bug (removed 2026-06-16) re-established the same
// peer repeatedly; reusing a prekey bundle produced byte-identical SessionStates,
// each archived with its own copy of a ~2000-key receiver chain. Prod measurement:
// ~55% of the fattest sessions' bytes are these exact-duplicate archived states,
// with ZERO same-root-but-divergent cases. This sweep removes those duplicates.
// It is lossless (a dropped state is byte-identical to a retained one) and is NOT
// the out-of-line split — total stored states only shrink by exact redundancy.
//
// Throwaway: once this has run once and been re-measured, this file + store/
// session_dedup.go + the manager wiring are removed.
package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"

	"go.mau.fi/whatsmeow/store"
)

// sessionDedupThresholdBytes is the fat-row scan threshold. A healthy session is
// well under 4KB; only rows above this can carry duplicate archived states worth
// dropping. Below it nothing is even decoded. Prod: ~26k rows > 4KB.
const sessionDedupThresholdBytes = 4096

const sessionDedupScanQuery = `
	SELECT our_jid, their_id
	FROM whatsmeow_sessions
	WHERE octet_length(session) > $1
`

const sessionDedupGetQuery = `
	SELECT session FROM whatsmeow_sessions
	WHERE our_jid=$1 AND their_id=$2
`

const sessionDedupUpdateQuery = `
	UPDATE whatsmeow_sessions SET session=$3
	WHERE our_jid=$1 AND their_id=$2
`

// DedupFatSessionsIfEnabled removes byte-identical archived states from fat
// whatsmeow_sessions rows (cross-account: rows span our_jid, so this lives on
// *Container, which owns the shared db handle). Each fat row is decoded via the
// flat codec, deduped via store.DedupSessionStates, and re-written ONLY when a
// duplicate was actually dropped. A fat row whose archived states are all unique
// is left untouched.
//
// Env gate: runs only when KAVTOV_SESSION_DEDUP_ONCE=1 — the operator enables it
// for exactly one boot, verifies SESSION_DEDUP_DONE in the log, then removes the
// variable.
//
// Driver wiring (one line, early in boot BEFORE accounts connect / caches warm,
// right after the sqlstore Container is constructed):
//
//	if n, err := container.DedupFatSessionsIfEnabled(ctx); err != nil { log.Errorf("session dedup: %v", err) } else if n > 0 { log.Infof("session dedup: %d rows shrunk", n) }
//
// WHY before-warm matters: the sweep writes the DB directly, bypassing the cached
// session store and write-back flusher. A cache-resident fat session flushed later
// would overwrite the deduped row with the fat blob again — so the sweep must run
// before any account attaches its cached stores (cold cache = no race).
//
// Failure posture: per-row decode/dedup/pack/update problems are logged and
// skipped (one bad row never fails the sweep, and a row that won't serialize is
// NEVER written — no partial dedup). Each UPDATE is its own autocommit statement.
// NO DDL.
func (c *Container) DedupFatSessionsIfEnabled(ctx context.Context) (deduped int, err error) {
	if os.Getenv("KAVTOV_SESSION_DEDUP_ONCE") != "1" {
		return 0, nil
	}

	// Phase 1 (collect): gather the (our_jid, their_id) of all fat rows, then
	// close the cursor before the row-at-a-time rewrite.
	type sessionRowKey struct {
		ourJID, theirID string
	}
	var keys []sessionRowKey
	rows, err := c.db.Query(ctx, sessionDedupScanQuery, sessionDedupThresholdBytes)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var k sessionRowKey
		if err := rows.Scan(&k.ourJID, &k.theirID); err != nil {
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

	var totalStatesDropped, totalBytesSaved int

	// Phase 2 (row-at-a-time): decode, dedup, re-write only when changed.
	for _, k := range keys {
		var blob []byte
		err := c.db.QueryRow(ctx, sessionDedupGetQuery, k.ourJID, k.theirID).Scan(&blob)
		if errors.Is(err, sql.ErrNoRows) {
			continue // row deleted between phases — fine
		}
		if err != nil {
			c.log.Warnf("SESSION_DEDUP read error row=%s/%s: %v", k.ourJID, k.theirID, err)
			continue
		}
		if blob == nil {
			continue
		}

		s, err := store.UnpackFlatSession(blob)
		if err != nil {
			c.log.Warnf("SESSION_DEDUP decode error row=%s/%s: %v", k.ourJID, k.theirID, err)
			continue
		}

		dd, dropped, ok := store.DedupSessionStates(s)
		if !ok {
			c.log.Warnf("SESSION_DEDUP skip row=%s/%s (state failed to serialize — left untouched)",
				k.ourJID, k.theirID)
			continue
		}
		if dropped == 0 {
			continue // all archived states unique — leave untouched
		}

		newBlob, packOK := store.PackFlatSession(dd)
		if !packOK {
			c.log.Warnf("SESSION_DEDUP pack rejected row=%s/%s (deduped structure not flat-packable — left untouched)",
				k.ourJID, k.theirID)
			continue
		}

		if _, err := c.db.Exec(ctx, sessionDedupUpdateQuery, k.ourJID, k.theirID, newBlob); err != nil {
			c.log.Warnf("SESSION_DEDUP update error row=%s/%s: %v", k.ourJID, k.theirID, err)
			continue
		}
		c.log.Infof("SESSION_DEDUP row=%s/%s before=%d after=%d states=%d->%d dropped=%d",
			k.ourJID, k.theirID, len(blob), len(newBlob),
			len(s.PreviousStates)+1, len(dd.PreviousStates)+1, dropped)
		totalStatesDropped += dropped
		totalBytesSaved += len(blob) - len(newBlob)
		deduped++
	}

	c.log.Infof("SESSION_DEDUP_DONE scanned=%d shrunk=%d statesDropped=%d bytesSaved=%d threshold=%d",
		len(keys), deduped, totalStatesDropped, totalBytesSaved, sessionDedupThresholdBytes)
	return deduped, nil
}
