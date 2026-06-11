// Copyright (c) 2026 Kavtov Platform (Phase 17.9 / Phase 17.11)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_sender_key.go — cross-account sender-key recovery (Phase 17.9 plan 05,
// iteration guard Phase 17.11 plan 02, inline path Phase 17.12)
//
// When an account is missing a sender-key state, TryInlineRecovery finds a usable
// donor across ALL accounts: match by key_id (the real crypto identifier),
// device-tolerant on the sender's device suffix, picking the closest
// chain_key_iteration <= target.
//
// Correctness invariants:
//   - Anchor on key_id (not device suffix): same key_id ⇒ same key, decryptable
//     regardless of the ':0' vs ':5' suffix inconsistency left by LID migration.
//   - Forward-only: a donor with chain_iter > target is useless (the chain ratchets
//     forward; you cannot go back). Reject such donors.
//   - Recipient-independent: signing keys + sender chain key/iter are not tied to
//     the recipient. Write the recovered state under the recovering account's own
//     (our_jid, chat_id, target_sender_id) via PutSenderKeyStructure (fires
//     parsedReplace synchronously). The inline retry reads from the warm
//     parsedReplace cache — no DB round-trip needed. No async flusher, no raw
//     INSERT, no NULL-blob.
//   - Both fmt_ver=1 (legacy blob) and fmt_ver=2 (column) donors are consulted.
//     At deploy, most rows are fmt_ver=1 (no backfill yet), so column-only scan
//     would miss nearly all donors. Recovery parses fmt_ver=1 blobs here — this
//     is allowed (recovery is off the per-message hot path; explicitly outside the
//     no-JSON grep-gate of plan 04 which covers senderkey_columns.go, store.go,
//     cached_sender_key_store.go, signal.go — NOT this file).
//   - No iteration downgrade: if the existing row for (group, targetSenderID) has
//     the same KeyID at Iteration >= donor.Iteration, the write is skipped. A
//     concurrent inbound SKDM can advance the ratchet between findSenderKeyDonor
//     and PutSenderKeyStructure; the guard prevents clobbering it.
//
// No recovery index is added (DESIGN-DECISIONS line 56: measure-first).

package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"sync/atomic"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/groups/ratchet"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// D-05 fallback-scan instrumentation counters.
// fallbackScanEntered counts how often recoveryScanQuery (the LIKE-only fallback
// path) is entered. fallbackScanDonorFound counts how often it returns a non-nil
// donor. The ratio fallbackScanDonorFound/fallbackScanEntered is the hit rate of
// the LIKE-only fallback; a low ratio means the fallback rarely succeeds (most
// misses are fleet-correlated no-donor cases). Both counters are logged every 500
// fallback entries so the operator can measure without a prod restart.
var (
	fallbackScanEntered    atomic.Uint64
	fallbackScanDonorFound atomic.Uint64
)

// D-01 singleflight coalescing counters (Gap 1 / 29-08).
// donorSFTotal counts every TryInlineRecovery singleflight attempt (each account that
// enters the sf.Do call, whether or not the call was coalesced). donorSFShared counts
// the subset where shared=true (the call returned a cached result from a concurrent
// goroutine — the coalescing benefit). The ratio donorSFShared/donorSFTotal is the
// coalescing rate; a low ratio means the singleflight coalesces rarely (have=none
// dominant, no donor to share). Logged every donorSFLogEvery total attempts so the
// operator can measure collapse magnitude without a prod restart.
var (
	donorSFTotal  atomic.Uint64
	donorSFShared atomic.Uint64
)

// donorSFLogEvery is the sampling period for the DONOR_SF_COALESCED log line.
// 100 yields observable lines within minutes given the ~10/min donor-attempt rate.
const donorSFLogEvery = 100

// senderKeyRecoveryReader is the local interface that *SQLStore satisfies to
// expose the cross-account donor scan. Using a local interface avoids exposing
// findSenderKeyDonor as a public method while letting CachedSenderKeyStore
// access it via type-assertion.
type senderKeyRecoveryReader interface {
	findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error)
}

// donorSenderKeyState is the recipient-independent crypto state extracted from a
// cross-account donor row. Signing keys and SenderChainKey are from a single
// SenderKeyStateStructure whose KeyID == targetKeyID and
// SenderChainKey.Iteration is the closest value <= targetIter across all donors.
type donorSenderKeyState struct {
	// OurJID is the donor account's JID (our_jid column), populated by
	// scanFlatRows for D-08 donor-jid logging in TryInlineRecovery.
	OurJID string
	// KeyID of the matching SenderKeyState (== targetKeyID).
	KeyID uint32
	// SenderChainKey at the chosen iteration.
	Iteration uint32
	ChainKey  []byte // 32-byte chain key (SenderChainKey.ChainKey — NOT Seed)
	// Signing key pair (recipient-independent).
	SigningKeyPublic  []byte
	SigningKeyPrivate []byte // nil on received (non-own) keys — preserved
	// Skipped message keys for this state, if any (forwarded for completeness).
	SkippedKeys []*ratchet.SenderMessageKeyStructure
}

// D-03 / 999.19: SENDERKEY_SUBCLASS sampler — classifies why no donor was found.
// Default rate 10 (1-in-10 no-donor events); 0 disables. Declared as a var (not
// const) so internal tests can override the rate without restarting the process.
// Configured via env KAVTOV_SENDERKEY_SUBCLASS.
const senderKeySubclassDefaultRate = 10

var senderKeySubclassRate = func() int {
	s := os.Getenv("KAVTOV_SENDERKEY_SUBCLASS")
	if s == "0" {
		return 0
	}
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return senderKeySubclassDefaultRate
}()

// senderKeySubclassCounter is the per-process counter driving the subclass sampler.
var senderKeySubclassCounter atomic.Uint64

// senderKeySubclassShouldSample returns true on 1-in-senderKeySubclassRate calls.
// Always false when rate == 0 (disabled path never touches the counter).
func senderKeySubclassShouldSample() bool {
	rate := senderKeySubclassRate
	if rate == 0 {
		return false
	}
	n := senderKeySubclassCounter.Add(1)
	return n%uint64(rate) == 0
}

// subclassLIDMapQuery checks whatsmeow_lid_map for the sender's identifier.
// Returns one of: "pn-mapped" (sender resolves as a PN→LID pair),
// "lid-mapped" (sender resolves as a LID→PN pair), "unmapped" (no entry),
// or "err" if the query fails (errors are swallowed — diagnostic only).
//
// The sender identifier from the Signal address is the user part of a
// @s.whatsapp.net JID (a phone number string) or a LID user.
// getLIDForPNQuery / getPNForLIDQuery cover both directions; the first hit wins.
const subclassLIDMapQuery = `
	SELECT 'pn-mapped' AS kind FROM whatsmeow_lid_map WHERE pn=$1
	UNION ALL
	SELECT 'lid-mapped' AS kind FROM whatsmeow_lid_map WHERE lid=$1
	LIMIT 1
`

// subclassKeysElsewhereQuery checks if ANY whatsmeow_sender_keys row exists for
// (our_jid, sender LIKE prefix) in a DIFFERENT chat. This is the
// "sender-alive-never-distributed" signature: the sender has shared keys with us
// elsewhere, but not in this specific group.
//
// Uses the same LIKE device-tolerance as the donor scan (sender_id LIKE senderBare||':%').
// Single indexed EXISTS/LIMIT 1 — read-only, no write.
const subclassKeysElsewhereQuery = `
	SELECT EXISTS(
		SELECT 1 FROM whatsmeow_sender_keys
		WHERE our_jid=$1
		  AND chat_id <> $2
		  AND sender_id LIKE $3 || ':%' ESCAPE '\'
		LIMIT 1
	)
`

// noDonorFields is the result of classifyNoDonor — factored out so tests can
// assert the field values without triggering the log emission.
type noDonorFields struct {
	LIDMap       string // "pn-mapped", "lid-mapped", "unmapped", or "err"
	KeysElsewhere bool   // true = sender has keys with us in at least one other group
}

// classifyNoDonor runs the two sampled read-only queries against s to produce
// the SENDERKEY_SUBCLASS field values. Errors are swallowed with fallback field
// values so the fail path never gets slower or fails because of diagnostics.
//
//   - ourJID:     the recovering account's own JID string (our_jid in the table)
//   - group:      the group chat ID (chat_id of the failing decrypt)
//   - senderBare: the bare Signal-address user (no device suffix, no @server)
//
// This function is called only when the sampler fires; it is NOT on the hot path.
func classifyNoDonor(ctx context.Context, s *SQLStore, ourJID, group, senderBare string) noDonorFields {
	fields := noDonorFields{LIDMap: "err", KeysElsewhere: false}

	// (a) LID-map state: does senderBare appear in whatsmeow_lid_map as either
	// a PN or a LID?
	var lidKind string
	err := s.db.QueryRow(ctx, subclassLIDMapQuery, senderBare).Scan(&lidKind)
	if errors.Is(err, sql.ErrNoRows) {
		fields.LIDMap = "unmapped"
	} else if err == nil {
		fields.LIDMap = lidKind
	}
	// else: fields.LIDMap stays "err"

	// (b) Keys-elsewhere: does this our_jid have ANY sender-key row for senderBare
	// in a chat_id != group?
	escapedBare := senderKeyLikeEscaper.Replace(senderBare)
	err = s.db.QueryRow(ctx, subclassKeysElsewhereQuery, ourJID, group, escapedBare).Scan(&fields.KeysElsewhere)
	if err != nil {
		// swallow error; KeysElsewhere stays false (safe conservative default)
		fields.KeysElsewhere = false
	}

	return fields
}

// recoveryScanQueryFast is the indexed fast-path donor query (R8).
// Filters by chat_id + sk_keyid0 (STORED GENERATED column = state[0].KeyID in PackFlat)
// + sender_id LIKE prefix, seeking the composite (chat_id, sk_keyid0) index.
// Finds single-state donors (and multi-state donors where state[0].KeyID == targetKeyID).
// Does NOT find multi-state donors where targetKeyID is only in state[1+]; those are
// covered by the LIKE-only fallback (recoveryScanQuery).
//
// Device-tolerant: LIKE userBare||':%' ESCAPE '\' matches any device suffix.
const recoveryScanQueryFast = `
	SELECT our_jid, sender_key
	FROM whatsmeow_sender_keys
	WHERE chat_id=$1 AND sk_keyid0=$3 AND sender_id LIKE $2 || ':%' ESCAPE '\'
`

// recoveryScanQuery is the LIKE-only fallback donor scan, used when recoveryScanQueryFast
// finds no qualifying donor (target KeyID is in state[1+] of some multi-state row).
// Fetches all rows for (chat_id, LIKE sender_id prefix) across ALL accounts and lets
// the Go loop scan all states for the matching KeyID.
//
// Device-tolerant: LIKE userBare||':%' ESCAPE '\' matches any device suffix.
const recoveryScanQuery = `
	SELECT our_jid, sender_key
	FROM whatsmeow_sender_keys
	WHERE chat_id=$1 AND sender_id LIKE $2 || ':%' ESCAPE '\'
`

// scanFlatRows scans a row cursor from either recoveryScanQueryFast or
// recoveryScanQuery (both SELECT our_jid, sender_key) and updates best with the
// best qualifying donor state found. Returns the updated best (may be unchanged).
func scanFlatRows(rows interface {
	Next() bool
	Scan(dest ...any) error
	Err() error
}, targetKeyID, targetIter uint32, best *donorSenderKeyState) (*donorSenderKeyState, error) {
	for rows.Next() {
		var (
			ourJID string
			blob   []byte
		)
		if err := rows.Scan(&ourJID, &blob); err != nil {
			return best, err
		}
		if blob == nil {
			continue // NULL blob — skip (should not happen post-upgrade-19)
		}

		structure, err := store.UnpackFlat(blob)
		if err != nil {
			// Corrupt flat blob in a donor row — skip this row, try others.
			continue
		}
		if structure == nil {
			continue
		}

		// Scan each state for a matching key_id with chain_iter <= targetIter.
		for _, st := range structure.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				continue
			}
			if st.KeyID != targetKeyID {
				continue // wrong key generation
			}
			donorIter := st.SenderChainKey.Iteration
			if donorIter > targetIter {
				continue // forward-only: donor is past the target, useless
			}
			if best != nil && donorIter <= best.Iteration {
				continue // not better than current best
			}
			// This state is a candidate — collect skipped keys.
			var skipped []*ratchet.SenderMessageKeyStructure
			for _, smk := range st.Keys {
				if smk != nil {
					skipped = append(skipped, &ratchet.SenderMessageKeyStructure{
						Iteration: smk.Iteration,
						IV:        smk.IV,
						CipherKey: smk.CipherKey,
						Seed:      smk.Seed,
					})
				}
			}
			best = &donorSenderKeyState{
				OurJID:           ourJID,
				KeyID:            st.KeyID,
				Iteration:        donorIter,
				ChainKey:         st.SenderChainKey.ChainKey,
				SigningKeyPublic:  st.SigningKeyPublic,
				SigningKeyPrivate: st.SigningKeyPrivate,
				SkippedKeys:      skipped,
			}
		}
	}
	if err := rows.Err(); err != nil {
		return best, err
	}
	return best, nil
}

// findSenderKeyDonor scans all rows for (group, senderBare LIKE) across every
// account (no our_jid filter) and returns the best donor state: the one with
// KeyID == targetKeyID and the maximum chain_key_iteration <= targetIter.
//
// TWO-PATH SCAN (R8):
//  1. Fast path (recoveryScanQueryFast): filters chat_id + sk_keyid0=targetKeyID + LIKE,
//     seeking the composite (chat_id, sk_keyid0) index. Finds donors where
//     state[0].KeyID == targetKeyID without scanning the full group row-set.
//  2. Fallback path (recoveryScanQuery): runs ONLY when the fast path finds no qualifying
//     donor. LIKE-only scan covers multi-state donors where targetKeyID is in state[1+].
//
// All donor rows are PackFlat-encoded. Decode with store.UnpackFlat.
// Returns (nil, nil) when no qualifying donor exists.
func (s *SQLStore) findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error) {
	escapedBare := senderKeyLikeEscaper.Replace(senderBare)

	// Fast path: indexed scan on (chat_id, sk_keyid0).
	// $3 = targetKeyID as int32 (sk_keyid0 is INT4).
	fastRows, err := s.db.Query(ctx, recoveryScanQueryFast, group, escapedBare, int32(targetKeyID))
	if err != nil {
		return nil, err
	}
	best, err := scanFlatRows(fastRows, targetKeyID, targetIter, nil)
	fastRows.Close()
	if err != nil {
		return nil, err
	}

	if best != nil {
		// Fast path found a qualifying donor — skip the fallback scan.
		return best, nil
	}

	// Fallback path: LIKE-only scan (covers multi-state donors, state[1+] KeyID match).
	// D-05: count entries and donor hits so the operator can measure hit-rate post-deploy.
	if n := fallbackScanEntered.Add(1); n%500 == 0 {
		s.log.Infof("D05_FALLBACK_SCAN entered=%d donorFound=%d group=%s",
			n, fallbackScanDonorFound.Load(), group)
	}
	fbRows, err := s.db.Query(ctx, recoveryScanQuery, group, escapedBare)
	if err != nil {
		return nil, err
	}
	defer fbRows.Close()
	fbBest, err := scanFlatRows(fbRows, targetKeyID, targetIter, nil)
	if err != nil {
		return nil, err
	}
	if fbBest != nil {
		fallbackScanDonorFound.Add(1)
	}
	return fbBest, nil
}

// TryInlineRecovery is the cross-account recovery entry-point for
// CachedSenderKeyStore. It satisfies the store.SenderKeyInlineRecoverer
// interface and is called directly from decryptGroupSenderKey in message.go on
// a sender-key miss.
//
//   - Returns (donorJID string, ok bool, err error) so the caller can log the
//     donor's account JID in SENDER_KEY_RECOVERED (D-08).
//   - Installs via PutSenderKeyStructure (warm parsedReplace cache). The inline
//     retry constructs the cipher directly from the parsedReplace cache without
//     calling GetSenderKeyDevices (D-03/D-04).
//
// Iteration-downgrade guard (T-1712-01 mitigation): a concurrent inbound SKDM
// can advance the ratchet between findSenderKeyDonor and PutSenderKeyStructure;
// the guard prevents clobbering a naturally-advanced key.
func (c *CachedSenderKeyStore) TryInlineRecovery(ctx context.Context, group, targetSenderID, senderBare string, targetKeyID, targetIter uint32) (donorJID string, ok bool, err error) {
	r, rOk := c.inner.(senderKeyRecoveryReader)
	if !rOk {
		// inner does not implement the recovery reader (test stub / pre-wiring).
		return "", false, nil
	}

	// D-01: coalesce concurrent findSenderKeyDonor calls for the same
	// (group, senderBare, keyID) via the process-global singleflight.Group.
	// N accounts missing the same key will share ONE donor DB scan; each
	// account then independently runs the downgrade guard + install below.
	// targetIter is excluded from the key (RESEARCH Open Q1); because the
	// shared closure captures the LEADER's targetIter, every coalesced caller
	// must re-check the returned donor against its OWN targetIter (the WR-04
	// forward-only re-check below — the per-account downgrade guard alone does
	// NOT cover the no-existing-state case).
	// The "|" separator prevents key collisions between distinct tuples that
	// share a prefix (T-29-01-01 mitigation).
	sfKey := group + "|" + senderBare + "|" + strconv.FormatUint(uint64(targetKeyID), 10)

	var donor *donorSenderKeyState
	if c.sf != nil {
		v, sfErr, shared := c.sf.Do(sfKey, func() (any, error) {
			return r.findSenderKeyDonor(ctx, group, senderBare, targetKeyID, targetIter)
		})
		// D-01: count total attempts and coalesced followers; emit every donorSFLogEvery
		// total attempts so the coalescing rate is observable even when shared=0 (have=none
		// dominant). Keyed on total (not shared) so lines appear regardless of coalescing.
		n := donorSFTotal.Add(1)
		if shared {
			donorSFShared.Add(1)
		}
		if n%donorSFLogEvery == 0 {
			// Obtain a logger via the inner SQLStore; guard nil so test contexts without
			// a Container do not panic. The type assertion is intra-package (both types
			// live in package sqlstore) so accessing Container.log (unexported) is legal.
			var sfLog waLog.Logger
			if sq, ok := c.inner.(*SQLStore); ok {
				sfLog = sq.log
			}
			if sfLog != nil {
				sfLog.Infof("DONOR_SF_COALESCED total=%d shared=%d", n, donorSFShared.Load())
			}
		}
		if sfErr != nil {
			return "", false, sfErr
		}
		if v != nil {
			donor = v.(*donorSenderKeyState)
		}
	} else {
		// No singleflight wired (test context); call directly.
		var findErr error
		donor, findErr = r.findSenderKeyDonor(ctx, group, senderBare, targetKeyID, targetIter)
		if findErr != nil {
			return "", false, findErr
		}
	}
	// WR-04 (2026-06-10): forward-only re-check against the CALLER's own
	// targetIter. The singleflight key excludes targetIter and the shared
	// closure captures the LEADER's targetIter, so a coalesced FOLLOWER with a
	// lower target can receive a shared donor whose iteration is AHEAD of its
	// target. The per-account downgrade guard below only compares
	// existing-vs-donor and passes when the follower has NO existing state for
	// the KeyID — installing a donor the failing message cannot use
	// (forward-only ratchet: a higher-iteration chain key cannot re-derive an
	// earlier iteration, and the donor's skipped keys are unlikely to cover
	// it), returning ok=true, and burning the inline decrypt retry. Mirror
	// findSenderKeyDonor's own donorIter > targetIter filter here.
	if donor != nil && donor.Iteration > targetIter {
		return "", false, nil // not recovered: shared donor is past this caller's target
	}
	if donor == nil {
		// D-03 / 999.19: sampled SENDERKEY_SUBCLASS classifier.
		// Runs only when the sampler fires (default 1-in-10); reads whatsmeow_lid_map
		// and whatsmeow_sender_keys (read-only, no writes). Errors are swallowed
		// inside classifyNoDonor — the fail path must never get slower because of
		// diagnostics.
		if senderKeySubclassShouldSample() {
			if sq, ok := c.inner.(*SQLStore); ok {
				fields := classifyNoDonor(ctx, sq, c.jid, group, senderBare)
				if sq.log != nil {
					n := senderKeySubclassCounter.Load()
					sq.log.Infof("SENDERKEY_SUBCLASS sender=%s group=%s lidmap=%s keys_elsewhere=%t sampled_n=%d",
						senderBare, group, fields.LIDMap, fields.KeysElsewhere, n)
				}
			}
		}
		return "", false, nil // no qualifying donor
	}

	// Iteration-downgrade guard (T-1712-01 mitigation):
	// A concurrent inbound SKDM can advance the ratchet between findSenderKeyDonor
	// and PutSenderKeyStructure. If the existing row already has the same KeyID at
	// Iteration >= donor.Iteration, the donor is stale — skip the write to avoid
	// clobbering the naturally-advanced key.
	existing, err := c.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		return "", false, err
	}
	// CR-01 (2026-06-10): GetSenderKeyStructure reads the DB ONLY; under
	// write-back the DB lags the parsed cache + flusher dirty-set by up to a
	// flush interval. Building the guard + D-12 merge from the DB snapshot
	// alone can silently drop a cache-only fresh generation from BOTH the
	// cache (the recovery install replaces the whole cached entry) and the DB
	// (the enqueued merged blob replaces the dirty blob that carried it).
	// Union the cache-resident structure with the DB read, preferring the
	// higher iteration per KeyID, so the merge base is the freshest visible
	// state. StoreStruct additionally rejects any recovery install whose
	// state-set is missing a cached KeyID (defense in depth).
	if c.parsedLoad != nil {
		if cached, hit := c.parsedLoad(c.key(group, targetSenderID)); hit && cached != nil {
			existing = unionSenderKeyStructures(cached, existing)
		}
	}
	if existing != nil {
		for _, st := range existing.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				continue
			}
			if st.KeyID == donor.KeyID && st.SenderChainKey.Iteration >= donor.Iteration {
				return "", false, nil // donor is not fresher; skip write
			}
		}
	}

	// Build a *SenderKeyStructure from the recipient-independent donor state.
	skippedKeys := make([]*ratchet.SenderMessageKeyStructure, len(donor.SkippedKeys))
	for i, smk := range donor.SkippedKeys {
		skippedKeys[i] = &ratchet.SenderMessageKeyStructure{
			Iteration: smk.Iteration,
			IV:        smk.IV,
			CipherKey: smk.CipherKey,
			Seed:      smk.Seed,
		}
	}
	donorState := &groupRecord.SenderKeyStateStructure{
		KeyID: donor.KeyID,
		SenderChainKey: &ratchet.SenderChainKeyStructure{
			Iteration: donor.Iteration,
			ChainKey:  donor.ChainKey,
		},
		SigningKeyPublic:  donor.SigningKeyPublic,
		SigningKeyPrivate: donor.SigningKeyPrivate,
		Keys:              skippedKeys,
	}

	// D-12: merge the donor state into the existing structure rather than
	// full-replacing it. The guard read above already holds existing.
	//
	// CR-04 (2026-06-10): the donor state is PREPENDED at index 0. libsignal's
	// invariant is that SenderKeyStates[0] is the most-recent/active state —
	// relied on by extractStructMeta (flusher Enqueue meta), the sk_keyid0
	// generated column (recoveryScanQueryFast index), and the flusher's
	// same-generation dedup. Appending the donor at the end (or replacing it
	// in place) left a stale foreign state at index 0, so the recovery enqueue
	// carried the foreign generation's meta and could be silently dedup-skipped
	// — the donor blob never reached the DB. Foreign-KeyID states keep their
	// existing relative order after the donor; an existing state with the
	// donor's KeyID is dropped (superseded by the strictly-fresher donor).
	//
	// If there is no existing structure, this degenerates to the single-state
	// install (same behaviour as before D-12 for the nil-existing case).
	mergedStates := []*groupRecord.SenderKeyStateStructure{donorState}
	if existing != nil {
		for _, st := range existing.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				// Defensive skip (malformed state from prior versions).
				continue
			}
			if st.KeyID == donor.KeyID {
				// Superseded by the strictly-fresher donor state at index 0.
				// WR-05 (2026-06-10): the superseded state's Keys are the
				// RECOVERING account's accumulated skipped message keys —
				// covering out-of-order messages it has not yet received. The
				// donor's higher-iteration chain key cannot re-derive earlier
				// iterations (forward-only ratchet), so dropping them would
				// make any pending message at those iterations permanently
				// undecryptable. Union them into the donor state (donor
				// entries win on iteration collision).
				donorState.Keys = unionSkippedKeys(st.Keys, donorState.Keys)
				continue
			}
			// Preserve foreign-KeyID state unchanged, after the donor.
			mergedStates = append(mergedStates, st)
		}
	}

	structure := &groupRecord.SenderKeyStructure{SenderKeyStates: mergedStates}

	// Install via PutSenderKeyStructureRecovery (fires parsedReplace with the donor
	// KeyID so the iteration gate applies the recovery rule: reject unless donor
	// strictly advances cached position for that KeyID).
	// D-11 ordering: gate verdict evaluated BEFORE flusher.Enqueue inside the method.
	installed, err := c.PutSenderKeyStructureRecovery(ctx, group, targetSenderID, structure, donor.KeyID)
	if err != nil {
		return "", false, err
	}
	if !installed {
		// CR-03: the iteration gate rejected the install (stale vs the
		// cache-resident state) — nothing changed anywhere. Report ok=false so
		// the caller does not retry decrypt against an unchanged cache or log
		// SENDER_KEY_RECOVERED for a recovery that never happened.
		return "", false, nil
	}
	return donor.OurJID, true, nil
}

// unionSenderKeyStructures merges two views of the same sender-key record,
// preferring the state with the higher SenderChainKey.Iteration per KeyID
// (CR-01). primary's state order is preserved (it is the parsed-cache view,
// whose order reflects libsignal's most-recent-first prepends); states whose
// KeyID exists only in secondary are appended after. Either argument may be
// nil; malformed states (nil state or nil SenderChainKey) are skipped.
func unionSenderKeyStructures(primary, secondary *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
	if primary == nil {
		return secondary
	}
	if secondary == nil {
		return primary
	}
	var merged []*groupRecord.SenderKeyStateStructure
	seen := make(map[uint32]bool, len(primary.SenderKeyStates))
	for _, pst := range primary.SenderKeyStates {
		if pst == nil || pst.SenderChainKey == nil {
			continue
		}
		seen[pst.KeyID] = true
		chosen := pst
		for _, sst := range secondary.SenderKeyStates {
			if sst == nil || sst.SenderChainKey == nil || sst.KeyID != pst.KeyID {
				continue
			}
			if sst.SenderChainKey.Iteration > chosen.SenderChainKey.Iteration {
				chosen = sst
			}
		}
		if chosen != pst && len(pst.Keys) > 0 {
			// WR-05 (2026-06-10): the secondary view superseded the primary for
			// this KeyID — the primary state's skipped message keys would be
			// silently dropped (same loss shape as the D-12 donor replace; the
			// forward-only ratchet cannot re-derive them). Union them into a
			// shallow copy of the winning state (winner's entries win on
			// iteration collision); copy so the per-call structures handed in
			// are never mutated in place.
			withKeys := *chosen
			withKeys.Keys = unionSkippedKeys(pst.Keys, chosen.Keys)
			chosen = &withKeys
		}
		merged = append(merged, chosen)
	}
	for _, sst := range secondary.SenderKeyStates {
		if sst == nil || sst.SenderChainKey == nil || seen[sst.KeyID] {
			continue
		}
		merged = append(merged, sst)
	}
	if len(merged) == 0 {
		return nil
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: merged}
}

// unionSkippedKeys merges two skipped-message-key lists for the same sender-key
// state (WR-05). Entries from winner win on iteration collision; entries from
// loser whose iteration is not covered by winner are KEPT — they are the
// recovering account's own skipped keys for out-of-order messages it has not
// yet received, and the forward-only ratchet cannot re-derive them. Order:
// surviving loser entries first (preserving their relative order), then
// winner's. The flat codec (packSkipped/unpackSkipped) imposes no ordering
// constraint on Keys and libsignal consumes skipped keys by iteration lookup,
// so any order is valid. nil entries are skipped. Returns winner unchanged
// when loser is empty (the common no-skipped-keys case allocates nothing).
func unionSkippedKeys(loser, winner []*ratchet.SenderMessageKeyStructure) []*ratchet.SenderMessageKeyStructure {
	if len(loser) == 0 {
		return winner
	}
	winnerIters := make(map[uint32]bool, len(winner))
	for _, smk := range winner {
		if smk != nil {
			winnerIters[smk.Iteration] = true
		}
	}
	merged := make([]*ratchet.SenderMessageKeyStructure, 0, len(loser)+len(winner))
	for _, smk := range loser {
		if smk == nil || winnerIters[smk.Iteration] {
			continue
		}
		merged = append(merged, smk)
	}
	for _, smk := range winner {
		if smk != nil {
			merged = append(merged, smk)
		}
	}
	return merged
}

// Compile-time assertion: *SQLStore satisfies the upstream store.SenderKeyStore
// interface (GetSenderKey, PutSenderKey, GetSenderKeyDevices). The columnar
// additions live behind fork-local interfaces (senderKeyColumnarStore,
// senderKeyRecoveryReader) that the upstream interface does not declare, so a
// future upstream-whatsmeow merge of the base interface still compiles.
//
// This assertion is complementary to the var _ store.AllSessionSpecificStores =
// (*SQLStore)(nil) line in store.go — that one covers the full bundle; this
// one is a focused, named assertion for sender-key interface stability.
var _ store.SenderKeyStore = (*SQLStore)(nil)

// Compile-time assertion: *SQLStore satisfies the fork-local recovery reader
// interface. If findSenderKeyDonor is removed or its signature drifts, this
// line becomes a BUILD ERROR, preventing RecoverSenderKey from silently
// falling back to (false, nil) via the type-assertion above.
var _ senderKeyRecoveryReader = (*SQLStore)(nil)

// Compile-time assertion: *CachedSenderKeyStore satisfies the new inline
// recovery interface. If TryInlineRecovery is removed or its signature drifts,
// this line becomes a BUILD ERROR, preventing silent nil-fallback at the call site.
var _ store.SenderKeyInlineRecoverer = (*CachedSenderKeyStore)(nil)

// flatRecoveryNote: post-upgrade-19 all sender_key values are PackFlat format.
// findSenderKeyDonor uses store.UnpackFlat for all rows. The fast path
// (recoveryScanQueryFast + sk_keyid0 index) reduces per-scan cost for the common
// single-state donor case. The LIKE-only fallback covers multi-state donors.
