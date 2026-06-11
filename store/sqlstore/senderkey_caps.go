// Copyright (c) 2026 Kavtov Platform (quick 260612-0af)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_caps.go — fork-local mirrors of libsignal's record-size limits and
// the cap helpers that enforce them on the fork's own structure-building paths.
//
// libsignal (go.mau.fi/libsignal@v0.2.1) trims its in-memory records at
// maxMessageKeys (2000 skipped keys per state) and maxStates (5 states per
// record), but BOTH constants are unexported and the trims fire only inside
// libsignal's own AddSenderMessageKey / AddSenderKeyState paths. The fork's
// recovery-merge helpers (recovery_sender_key.go) build SenderKeyStructures
// DIRECTLY, bypassing those trims — which let prod records grow to 1.6MB
// (~35k skipped keys) and generate dead-TOAST churn on every rewrite. These
// helpers re-impose the same limits at every fork-side structure-building site.
package sqlstore

import (
	"sort"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store"
)

// maxSenderKeyStates is a fork-local mirror of libsignal's unexported maxStates
// (go.mau.fi/libsignal@v0.2.1 groups/state/record/SenderKeyRecord.go:10). The
// fork's merge helpers build structures directly and bypass libsignal's trim.
// Sourced from store.MaxSenderKeyStates: StoreStruct's CR-01 missing-KeyID
// guard (store/parsedcache.go) must agree on the same cap to tolerate
// cap-dropped oldest states — a drifted value would make every capped recovery
// install StoreRejectedStale.
const maxSenderKeyStates = store.MaxSenderKeyStates

// maxSenderKeyMessageKeys is a fork-local mirror of libsignal's unexported
// maxMessageKeys (go.mau.fi/libsignal@v0.2.1 groups/state/record/SenderKeyState.go:9).
const maxSenderKeyMessageKeys = 2000

// capSkippedKeys bounds a skipped-message-key list at maxSenderKeyMessageKeys.
// An under-cap input is returned unchanged (same slice, no allocation — the
// common case). An over-cap input keeps the maxSenderKeyMessageKeys
// HIGHEST-iteration entries: this matches libsignal's own trim-oldest semantics
// (the oldest skipped keys cover the messages least likely to still arrive).
//
// Deterministic: copy + stable sort ascending by Iteration, keep the trailing
// cap-many. The resulting iteration-sorted order is valid — the flat codec
// imposes no ordering constraint on Keys and libsignal consumes skipped keys by
// iteration lookup (see unionSkippedKeys). nil entries sort first so they are
// truncated away before any real key. The input slice is never mutated.
func capSkippedKeys(keys []*ratchet.SenderMessageKeyStructure) []*ratchet.SenderMessageKeyStructure {
	if len(keys) <= maxSenderKeyMessageKeys {
		return keys
	}
	sorted := make([]*ratchet.SenderMessageKeyStructure, len(keys))
	copy(sorted, keys)
	sort.SliceStable(sorted, func(i, j int) bool {
		switch {
		case sorted[i] == nil:
			return sorted[j] != nil
		case sorted[j] == nil:
			return false
		default:
			return sorted[i].Iteration < sorted[j].Iteration
		}
	})
	return sorted[len(sorted)-maxSenderKeyMessageKeys:]
}

// capSenderKeyStates bounds a state slice at maxSenderKeyStates via
// order-preserving prefix truncation. Index 0 (the active/donor state — the
// CR-04 hard invariant relied on by extractStructMeta, the sk_keyid0 generated
// column, and the flusher's same-generation dedup) is untouched; the survivors
// after it are the first 4 = the 4 most-recent foreign states (the fork's merge
// helpers preserve libsignal's most-recent-first state order; verified during
// planning). An under-cap input is returned unchanged (same slice).
func capSenderKeyStates(states []*groupRecord.SenderKeyStateStructure) []*groupRecord.SenderKeyStateStructure {
	if len(states) <= maxSenderKeyStates {
		return states
	}
	return states[:maxSenderKeyStates]
}

// capSenderKeyStructure applies both caps to a whole structure: states at
// maxSenderKeyStates, and each surviving state's Keys at
// maxSenderKeyMessageKeys. Returns changed=false (and the SAME pointer) when
// nothing was truncated — callers (the prune sweep) use that to skip the DB
// write. When changing, the input is NEVER mutated in place: a state whose Keys
// are truncated is shallow-copied (same pattern as the WR-05 withKeys copy in
// unionSenderKeyStructures) and a fresh structure is returned.
func capSenderKeyStructure(s *groupRecord.SenderKeyStructure) (out *groupRecord.SenderKeyStructure, changed bool) {
	if s == nil {
		return nil, false
	}
	states := capSenderKeyStates(s.SenderKeyStates)
	statesTruncated := len(states) != len(s.SenderKeyStates)

	newStates := make([]*groupRecord.SenderKeyStateStructure, len(states))
	keysChanged := false
	for i, st := range states {
		if st == nil {
			newStates[i] = nil
			continue
		}
		capped := capSkippedKeys(st.Keys)
		if len(capped) != len(st.Keys) {
			withKeys := *st // shallow copy — never mutate the caller's state
			withKeys.Keys = capped
			newStates[i] = &withKeys
			keysChanged = true
		} else {
			newStates[i] = st
		}
	}
	if !statesTruncated && !keysChanged {
		return s, false
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: newStates}, true
}
