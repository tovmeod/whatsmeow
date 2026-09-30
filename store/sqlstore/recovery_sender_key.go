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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

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

// noDonorCacheEntry describes the query domain covered by one negative donor
// scan. A no-donor result at iteration N also covers targets <= N, but must
// never suppress a scan at a later target iteration.
type noDonorCacheEntry struct {
	expiresAt             time.Time
	maxNegativeTargetIter uint32
}

const noDonorCacheCapacity = 10_000

// noDonorCache is process-wide and bounded. The base key is
// group|senderBare|keyID; each value records the target-iteration bound of the
// exact donor query that produced its negative result.
var (
	noDonorCacheMu sync.Mutex
	noDonorCache   = mustNewNoDonorCache(noDonorCacheCapacity)
)

// noDonorCacheTTL is the time-to-live for negative-donor cache entries.
// A no-donor tuple is re-scanned at most once per this period instead of on
// every miss. 5 minutes cuts the scan rate from ~per-miss (~111k/3.25h at 1am)
// to once-per-tuple-per-5-min. Raise for more reduction (no message loss: phone
// recovery covers the window; a bot that remains donorless never recovers anyway).
const noDonorCacheTTL = 5 * time.Minute

// noDonorCacheSkips counts how often a miss was served from the negative cache
// (the donor scan was skipped because a non-expired entry existed). Logged every
// donorSFLogEvery skips for observability (same cadence as DONOR_SF_COALESCED).
var noDonorCacheSkips atomic.Uint64

// noDonorCacheEvictions counts bounded-cache evictions. An eviction affects
// scan volume only: an evicted tuple runs its normal donor query next time.
var noDonorCacheEvictions atomic.Uint64

func mustNewNoDonorCache(capacity int) *lru.Cache[string, noDonorCacheEntry] {
	cache, err := lru.New[string, noDonorCacheEntry](capacity)
	if err != nil {
		panic(err)
	}
	return cache
}

func getNoDonorCacheEntry(key string, targetIter uint32, now time.Time) bool {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()

	entry, found := noDonorCache.Get(key)
	if !found {
		return false
	}
	if !now.Before(entry.expiresAt) {
		noDonorCache.Remove(key)
		return false
	}
	return targetIter <= entry.maxNegativeTargetIter
}

func addNoDonorCacheEntry(key string, targetIter uint32, now time.Time) bool {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	return noDonorCache.Add(key, noDonorCacheEntry{
		expiresAt:             now.Add(noDonorCacheTTL),
		maxNegativeTargetIter: targetIter,
	})
}

func removeNoDonorCacheEntry(key string) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	noDonorCache.Remove(key)
}

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
	LIDMap        string // "pn-mapped", "lid-mapped", "unmapped", or "err"
	KeysElsewhere bool   // true = sender has keys with us in at least one other group
}

// classifyNoDonor runs two read-only queries against s to classify why no donor
// was found for a failed decrypt. Errors are swallowed with fallback field
// values so the fail path never gets slower or fails because of diagnostics.
//
//   - ourJID:     the recovering account's own JID string (our_jid in the table)
//   - group:      the group chat ID (chat_id of the failing decrypt)
//   - senderBare: the bare Signal-address user (no device suffix, no @server)
//
// Not on the hot path — no production caller (D-12 removed the sampled
// SENDERKEY_SUBCLASS log line this fed); exercised directly by
// TestSenderKeySubclass / TestClassifyNoDonorLIDMapSuffix via export_test.go.
func classifyNoDonor(ctx context.Context, s *SQLStore, ourJID, group, senderBare string) noDonorFields {
	fields := noDonorFields{LIDMap: "err", KeysElsewhere: false}

	// (a) LID-map state: does senderBare appear in whatsmeow_lid_map as either
	// a PN or a LID?
	//
	// LID Signal-address users arrive as "<digits>_<agent>" (e.g.
	// "238877608562780_1") but whatsmeow_lid_map stores bare digits with no
	// suffix. Strip everything from the first underscore before querying so
	// that LID senders are not silently reported as "unmapped".
	// PN users (pure digits, never contain underscore) are unaffected.
	// senderBare (original, possibly suffixed) is kept unchanged for section
	// (b)'s LIKE match against whatsmeow_sender_keys.
	lidMapKey, _, _ := strings.Cut(senderBare, "_")
	var lidKind string
	err := s.db.QueryRow(ctx, subclassLIDMapQuery, lidMapKey).Scan(&lidKind)
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
				OurJID:            ourJID,
				KeyID:             st.KeyID,
				Iteration:         donorIter,
				ChainKey:          st.SenderChainKey.ChainKey,
				SigningKeyPublic:  st.SigningKeyPublic,
				SigningKeyPrivate: st.SigningKeyPrivate,
				SkippedKeys:       skipped,
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

	// D-01: coalesce concurrent findSenderKeyDonor calls for the same exact
	// (group, senderBare, keyID, targetIter) query via process-global singleflight.
	// N accounts missing the same key will share ONE donor DB scan; each
	// account then independently runs the downgrade guard + install below.
	// The "|" separator prevents key collisions between distinct tuples that
	// share a prefix (T-29-01-01 mitigation).
	sfKey := group + "|" + senderBare + "|" + strconv.FormatUint(uint64(targetKeyID), 10)
	workKey := sfKey + "|" + strconv.FormatUint(uint64(targetIter), 10)

	// A live negative entry only covers target iterations at or below the exact
	// scan that produced it. Expired entries are removed before a normal re-scan.
	if getNoDonorCacheEntry(sfKey, targetIter, time.Now()) {
		n := noDonorCacheSkips.Add(1)
		if n%donorSFLogEvery == 0 {
			var skipLog waLog.Logger
			if sq, sqOk := c.inner.(*SQLStore); sqOk {
				skipLog = sq.log
			}
			if skipLog != nil {
				skipLog.Infof("NO_DONOR_CACHE_SKIP skips=%d", n)
			}
		}
		return "", false, nil
	}

	var donor *donorSenderKeyState
	if c.sf != nil {
		v, sfErr, shared := c.sf.Do(workKey, func() (any, error) {
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
	// Keep this caller-side forward-only guard as defense in depth for custom
	// readers. Exact target-iteration work keys prevent cross-domain sharing.
	if donor != nil && donor.Iteration > targetIter {
		return "", false, nil // not recovered: shared donor is past this caller's target
	}

	// Store only genuine negatives. Each write replaces the observed coverage
	// bound and expiry; positives never populate or refresh this cache.
	if donor == nil {
		if addNoDonorCacheEntry(sfKey, targetIter, time.Now()) {
			n := noDonorCacheEvictions.Add(1)
			if n%donorSFLogEvery == 0 {
				var evictLog waLog.Logger
				if sq, sqOK := c.inner.(*SQLStore); sqOK {
					evictLog = sq.log
				}
				if evictLog != nil {
					evictLog.Infof("NO_DONOR_CACHE_EVICT evictions=%d", n)
				}
			}
		}
	}

	if donor == nil {
		return "", false, nil // no qualifying donor
	}

	// Iteration-downgrade guard (T-1712-01 mitigation):
	// A concurrent inbound SKDM can advance the ratchet between findSenderKeyDonor
	// and PutSenderKeyStructure. If the existing row already has the same KeyID at
	// Iteration >= donor.Iteration, the donor is stale — skip the write to avoid
	// clobbering the naturally-advanced key.
	// Phase 38.4-03: GetSenderKeyStructure is now cache-aware (Plan 02) — it
	// checks the flat c.cache BEFORE the DB read. The parsedLoad union (CR-01)
	// that previously merged the parsed-cache view with the DB read is no longer
	// needed: the freshest visible state is already in c.cache (written by
	// PutSenderKeyStructure's write-through at every cipher/recovery write).
	// The flat cache IS the freshest view; no union is required.
	existing, err := c.GetSenderKeyStructure(ctx, group, targetSenderID)
	if err != nil {
		return "", false, err
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
	// QUICK-SKCAP-01: a fat donor row can itself carry more than libsignal's
	// 2000-key limit — cap before install so the fork never re-persists an
	// over-cap list verbatim.
	skippedKeys = capSkippedKeys(skippedKeys)
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
	// QUICK-SKCAP-01: bound the merged record at libsignal's maxStates (5).
	// Prefix truncation keeps the donor at index 0 (the CR-04 hard invariant —
	// extractStructMeta, sk_keyid0, flusher same-generation dedup) and the
	// first 4 foreign states = the 4 most recent (the merge loop preserves
	// existing most-recent-first order).
	mergedStates = capSenderKeyStates(mergedStates)

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
	// QUICK-SKCAP-01: bound the merged view at libsignal's maxStates (5).
	// Primary order is preserved (most-recent-first), so prefix truncation
	// keeps the 5 most recent states.
	return &groupRecord.SenderKeyStructure{SenderKeyStates: capSenderKeyStates(merged)}
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
// when loser is empty and under the cap (the common no-skipped-keys case
// allocates nothing).
//
// QUICK-SKCAP-01: the output is ALWAYS bounded at maxSenderKeyMessageKeys
// (libsignal's per-state limit) via capSkippedKeys — winner wins collisions
// BEFORE truncation, then the highest-iteration entries survive. Uncapped
// unions let prod records grow to ~35k skipped keys (1.6MB rows, dead-TOAST
// churn → disk-full outage).
func unionSkippedKeys(loser, winner []*ratchet.SenderMessageKeyStructure) []*ratchet.SenderMessageKeyStructure {
	if len(loser) == 0 {
		return capSkippedKeys(winner)
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
	return capSkippedKeys(merged)
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
