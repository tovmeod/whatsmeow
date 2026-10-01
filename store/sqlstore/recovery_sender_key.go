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
	"errors"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store"
)

// Absence suppresses all target iterations until the first completion's fixed
// deadline. D-08/D-09 accept delayed later recovery and possible original-message
// loss: expiry enables another lookup; it neither replays originals nor proves
// phone recovery covered them.
type noDonorCacheEntry struct {
	expiresAt time.Time
}

type donorQueryKey struct {
	universe      any
	group, sender string
	keyID         uint32
}

type donorWorkKey struct {
	donorQueryKey
	iteration uint32
}

// One wave survives until every participant finishes, including across eviction
// and expiry. Its first negative deadline cannot be republished or refreshed.
type donorWave struct {
	participants int
	invalid      bool
	deadline     time.Time
}

type donorFlight struct {
	done         chan struct{}
	wave         *donorWave
	participants int
	donor        *donorSenderKeyState
	err          error
}

const noDonorCacheCapacity = 10_000

// One existing process-wide bounded LRU, partitioned by the donor SQL universe.
// No recipient/target iteration appears in absence identity.
var (
	noDonorCacheMu    sync.Mutex
	noDonorCache      = mustNewNoDonorCache(noDonorCacheCapacity)
	donorWaves        = make(map[donorQueryKey]*donorWave)
	donorFlights      = make(map[donorWorkKey]*donorFlight)
	donorWorkCapacity = noDonorCacheCapacity
	donorClock        = time.Now
)

// noDonorCacheTTL is the time-to-live for negative-donor cache entries.
// A genuine negative lasts exactly five minutes without sliding on later hits.
const noDonorCacheTTL = 5 * time.Minute

func mustNewNoDonorCache(capacity int) *lru.Cache[donorQueryKey, noDonorCacheEntry] {
	cache, err := lru.New[donorQueryKey, noDonorCacheEntry](capacity)
	if err != nil {
		panic(err)
	}
	return cache
}

func noDonorCacheHitLocked(key donorQueryKey, now time.Time) bool {
	entry, found := noDonorCache.Get(key)
	if !found {
		return false
	}
	if !now.Before(entry.expiresAt) {
		noDonorCache.Remove(key)
		return false
	}
	return true
}

func (c *CachedSenderKeyStore) donorKey(group, sender string, keyID uint32) donorQueryKey {
	return donorQueryKey{universe: c.deviceKey(group, sender).universe, group: group, sender: senderKeyUserBare(sender), keyID: keyID}
}

// Compatibility for external-package test exports only. Production invalidation
// uses the complete structured key, never a delimited identity.

func invalidateDonorLocked(key donorQueryKey) {
	noDonorCache.Remove(key)
	if wave := donorWaves[key]; wave != nil {
		wave.invalid = true
	}
}

// notifyDonorKeys is called only once keys are observable in this SQL universe.
// All accounts share donor SQL eligibility. Match exact bare identities and key
// IDs; no global flush on unrelated keys. Invalid active waves remain until their
// participants finish, preventing an old scan from publishing into a new wave.
func notifyDonorKeys(universe any, group, sender string, keyIDs []uint32) {
	observeDonorKeys(universe, group, sender, keyIDs, true)
}

// Buffered acceptance fences active scans, but keeps absence until the donor
// query can see SQL. Unknown raw IDs only touch bounded matching resident work.
func observeDonorKeys(universe any, group, sender string, keyIDs []uint32, committed bool) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	sender = senderKeyUserBare(sender)
	observe := func(key donorQueryKey) {
		if committed {
			invalidateDonorLocked(key)
		} else if wave := donorWaves[key]; wave != nil {
			wave.invalid = true
		}
	}
	if keyIDs == nil {
		for _, key := range noDonorCache.Keys() {
			if key.universe == universe && key.group == group && key.sender == sender {
				observe(key)
			}
		}
		for key, wave := range donorWaves {
			if key.universe == universe && key.group == group && key.sender == sender {
				wave.invalid = true
			}
		}
		return
	}
	for _, id := range keyIDs {
		observe(donorQueryKey{universe, group, sender, id})
	}
}

func clearDonorUniverse(universe any) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	for _, key := range noDonorCache.Keys() {
		if key.universe == universe {
			invalidateDonorLocked(key)
		}
	}
	for key, wave := range donorWaves {
		if key.universe == universe {
			wave.invalid = true
			delete(donorWaves, key)
		}
	}
	for key := range donorFlights {
		if key.universe == universe {
			delete(donorFlights, key)
		}
	}
}

// Locks protect only bookkeeping, never SQL, waits, crypto/install or callbacks.
func (c *CachedSenderKeyStore) lookupDonor(ctx context.Context, r senderKeyRecoveryReader, key donorQueryKey, targetIter uint32) (*donorSenderKeyState, error) {
	if c.retired.Load() {
		return nil, errSenderKeyStoreRetired
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	work := donorWorkKey{key, targetIter}
	noDonorCacheMu.Lock()
	if c.retired.Load() {
		noDonorCacheMu.Unlock()
		return nil, errSenderKeyStoreRetired
	}
	if noDonorCacheHitLocked(key, donorClock()) {
		noDonorCacheMu.Unlock()
		return nil, nil
	}
	flight := donorFlights[work]
	leader := flight == nil
	if leader && len(donorFlights) >= donorWorkCapacity {
		noDonorCacheMu.Unlock()
		return r.findSenderKeyDonor(ctx, key.group, key.sender, key.keyID, targetIter)
	}
	if leader {
		wave := donorWaves[key]
		if wave == nil {
			wave = &donorWave{}
			donorWaves[key] = wave
		}
		flight = &donorFlight{done: make(chan struct{}), wave: wave}
		donorFlights[work] = flight
	}
	flight.participants++
	flight.wave.participants++
	noDonorCacheMu.Unlock()
	defer func() {
		noDonorCacheMu.Lock()
		flight.participants--
		flight.wave.participants--
		if flight.participants == 0 && donorFlights[work] == flight {
			delete(donorFlights, work)
		}
		if flight.wave.participants == 0 && donorWaves[key] == flight.wave {
			delete(donorWaves, key)
		}
		noDonorCacheMu.Unlock()
	}()
	if !leader {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-flight.done:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if errors.Is(flight.err, context.Canceled) || errors.Is(flight.err, context.DeadlineExceeded) {
				// A live follower retries a canceled leader uncached; no publication.
				return r.findSenderKeyDonor(ctx, key.group, key.sender, key.keyID, targetIter)
			}
			return flight.donor, flight.err
		}
	}
	// Another target-specific flight may have published absence after admission.
	// Recheck just before SQL, then release the owner lock for the entire query.
	noDonorCacheMu.Lock()
	if noDonorCacheHitLocked(key, donorClock()) {
		close(flight.done)
		noDonorCacheMu.Unlock()
		return nil, nil
	}
	noDonorCacheMu.Unlock()
	donor, complete, err := readDonor(ctx, r, key, targetIter)
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	noDonorCacheMu.Lock()
	flight.donor, flight.err = donor, err
	now := donorClock()
	if donor == nil && complete && err == nil && !flight.wave.invalid && !c.retired.Load() {
		if flight.wave.deadline.IsZero() {
			flight.wave.deadline = now.Add(noDonorCacheTTL)
			noDonorCache.Add(key, noDonorCacheEntry{expiresAt: flight.wave.deadline})
		}
	}
	close(flight.done)
	noDonorCacheMu.Unlock()
	return donor, err
}

// senderKeyRecoveryReader is the local interface that *SQLStore satisfies to
// expose the cross-account donor scan. Using a local interface avoids exposing
// findSenderKeyDonor as a public method while letting CachedSenderKeyStore
// access it via type-assertion.
type senderKeyRecoveryReader interface {
	findSenderKeyDonor(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, error)
}

type senderKeyRecoveryCompleteReader interface {
	findSenderKeyDonorResult(context.Context, string, string, uint32, uint32) (*donorSenderKeyState, bool, error)
}

func readDonor(ctx context.Context, r senderKeyRecoveryReader, key donorQueryKey, iteration uint32) (*donorSenderKeyState, bool, error) {
	if complete, ok := r.(senderKeyRecoveryCompleteReader); ok {
		return complete.findSenderKeyDonorResult(ctx, key.group, key.sender, key.keyID, iteration)
	}
	donor, err := r.findSenderKeyDonor(ctx, key.group, key.sender, key.keyID, iteration)
	return donor, err == nil, err
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
}, targetKeyID, targetIter uint32, best *donorSenderKeyState) (*donorSenderKeyState, bool, error) {
	complete := true
	for rows.Next() {
		var (
			ourJID string
			blob   []byte
		)
		if err := rows.Scan(&ourJID, &blob); err != nil {
			return best, false, err
		}
		if blob == nil {
			complete = false
			continue // NULL blob — skip (should not happen post-upgrade-19)
		}

		structure, err := store.UnpackFlat(blob)
		if err != nil {
			complete = false
			// Corrupt flat blob in a donor row — skip this row, try others.
			continue
		}
		if structure == nil {
			complete = false
			continue
		}

		// Scan each state for a matching key_id with chain_iter <= targetIter.
		for _, st := range structure.SenderKeyStates {
			if st == nil || st.SenderChainKey == nil {
				complete = false
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
		return best, false, err
	}
	return best, complete, nil
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
	donor, _, err := s.findSenderKeyDonorResult(ctx, group, senderBare, targetKeyID, targetIter)
	return donor, err
}

func (s *SQLStore) findSenderKeyDonorResult(ctx context.Context, group, senderBare string, targetKeyID uint32, targetIter uint32) (*donorSenderKeyState, bool, error) {
	escapedBare := senderKeyLikeEscaper.Replace(senderBare)

	// Fast path: indexed scan on (chat_id, sk_keyid0).
	// $3 = targetKeyID as int32 (sk_keyid0 is INT4).
	fastRows, err := s.db.Query(ctx, recoveryScanQueryFast, group, escapedBare, int32(targetKeyID))
	if err != nil {
		return nil, false, err
	}
	best, fastComplete, err := scanFlatRows(fastRows, targetKeyID, targetIter, nil)
	fastRows.Close()
	if err != nil {
		return nil, false, err
	}

	if best != nil {
		// Fast path found a qualifying donor — skip the fallback scan.
		return best, fastComplete, nil
	}

	// Fallback path: LIKE-only scan (covers multi-state donors, state[1+] KeyID match).
	fbRows, err := s.db.Query(ctx, recoveryScanQuery, group, escapedBare)
	if err != nil {
		return nil, false, err
	}
	defer fbRows.Close()
	fbBest, fallbackComplete, err := scanFlatRows(fbRows, targetKeyID, targetIter, nil)
	if err != nil {
		return nil, false, err
	}
	return fbBest, fastComplete && fallbackComplete, nil
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

	donor, findErr := c.lookupDonor(ctx, r, c.donorKey(group, senderBare, targetKeyID), targetIter)
	if findErr != nil {
		return "", false, findErr
	}
	// Every caller independently retains key-generation and forward-only checks.
	if donor == nil || donor.KeyID != targetKeyID || donor.Iteration > targetIter {
		return "", false, nil
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
