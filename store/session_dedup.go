// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Phase 38.3 — lossless archived-state deduplication for whatsmeow_sessions.
//
// The establishSessionWithSender bug (removed 2026-06-16) re-established the same
// peer repeatedly; when it reused the same prekey bundle it produced byte-identical
// SessionStates, each archived with its own copy of a ~2000-key receiver chain.
// Measured on prod: ~55% of the fattest sessions' bytes are these exact-duplicate
// archived states (0 divergent groups — every same-root state is byte-identical).
//
// DedupSessionStates drops archived previous states that are byte-for-byte
// identical to the current state or to an earlier retained previous state. This is
// LOSSLESS: a dropped state is an exact copy of one that is retained, so every
// message key (and thus every decryptable message) is still present, and libsignal
// routes to the surviving copy identically. It is NOT the out-of-line split and it
// removes nothing unique — only redundant copies.
//
// This is throwaway cleanup code: once the one-time startup dedup pass has run and
// been re-measured, this file and the driver pass that calls it are removed.

package store

import (
	"crypto/sha256"

	"go.mau.fi/libsignal/state/record"
)

// packStateBytes serializes one StateStructure to its exact on-wire bytes (the
// same encoding packState writes into a whole-blob, with no header). Returns
// (nil, false) on any field-length violation — identical refusal semantics to
// PackFlatSession, so the caller skips the whole session rather than dropping it.
func packStateBytes(st *record.StateStructure) ([]byte, bool) {
	buf := make([]byte, stateRecordSize(st))
	off, ok := packState(buf, 0, st)
	if !ok || off != len(buf) {
		return nil, false
	}
	return buf, true
}

// stateHash returns the sha256 of a state's exact packed bytes. Two states with
// the same hash are byte-identical (sha256 collision is infeasible), so dropping
// one when the other is retained loses no data.
func stateHash(st *record.StateStructure) (string, bool) {
	b, ok := packStateBytes(st)
	if !ok {
		return "", false
	}
	sum := sha256.Sum256(b)
	return string(sum[:]), true
}

// DedupSessionStates returns a copy of s with archived previous states that are
// byte-identical to the current state or to an earlier retained previous state
// removed. The current SessionState is never dropped; retained previous states
// keep their original order. Returns (deduped, droppedCount, true) on success.
//
// On any state that fails to serialize it returns (s, 0, false) — the caller MUST
// skip that session (never write a partially-deduped session). When nothing is
// dropped it returns (s, 0, true) so the caller can skip a no-op write.
//
// Lossless: every retained state set is a superset of the distinct states in the
// input, so no message key is lost.
func DedupSessionStates(s *record.SessionStructure) (*record.SessionStructure, int, bool) {
	if s == nil || s.SessionState == nil {
		return s, 0, false
	}

	seen := make(map[string]struct{}, len(s.PreviousStates)+1)
	h, ok := stateHash(s.SessionState)
	if !ok {
		return s, 0, false
	}
	seen[h] = struct{}{}

	kept := make([]*record.StateStructure, 0, len(s.PreviousStates))
	dropped := 0
	for _, st := range s.PreviousStates {
		hp, ok := stateHash(st)
		if !ok {
			return s, 0, false
		}
		if _, dup := seen[hp]; dup {
			dropped++
			continue
		}
		seen[hp] = struct{}{}
		kept = append(kept, st)
	}

	if dropped == 0 {
		return s, 0, true
	}
	return &record.SessionStructure{SessionState: s.SessionState, PreviousStates: kept}, dropped, true
}
