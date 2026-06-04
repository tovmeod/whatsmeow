// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Phase 17.13 — flat, pointer-light binary codec for whatsmeow_sessions.
//
// # Why this exists
//
// The JSON serializer (assigned by NewProtoBufSerializer to .Session/.State)
// is the #1 driver allocation source: PutSession = 35% of driver allocations,
// json.Marshal = 14% of all allocation. At ~11,296 PutSession/min in prod,
// the cost compounds into a GC mark-storm on a 250k-cap parsed-session LRU
// (17.8 GC regression class). This flat codec replaces JSON for new writes:
// single make([]byte, totalLen) + binary.BigEndian puts (1 allocation total),
// zero reflection, zero JSON escape, zero base64.
//
// # Format
//
// [0]    0x01  magic/version discriminator (NEVER 0x7B — JSON starts with '{')
// [1]    u8    nPreviousStates (0..255; libsignal logical max=40)
// [2..]  (1+nPreviousStates) stateRecord encodings: current first, then previous
//
// See RESEARCH §R1 for the full layout. The codec is self-describing and
// discriminated from JSON by byte[0]: flat blobs start with 0x01, JSON blobs
// start with 0x7B ('{').
//
// # Correctness boundary (CORRECTNESS-CRITICAL)
//
// PackFlatSession ENFORCES the per-field byte-length invariant rather than
// assuming it. A wrong length returns (nil, false) — the caller MUST fall back
// to JSON serialization (ALLOW-JSON-DRAIN-BLOB-SESSION safety net in signal.go)
// rather than dropping the session. A DM session has no replayable genesis;
// PackFlatSession refuse + drop = permanent session loss (RESEARCH Pitfall 6).
//
// UnpackFlatSession is fully bounds-checked: every variable-length segment
// checks len(b) >= off+fieldLen before reading. Returns (nil, error) on any
// malformed input. NEVER panics.
//
// # D-03: No codec-added cap
//
// The codec refuses ONLY at wire-type ceilings (u8 > 255, u32 > 4294967295),
// NOT at libsignal's logical caps (maxReceiverChains=5, archivedStates=40,
// maxMessageKeys=2000). Enforcing a codec-level cap at the logical bound
// silently drops keys — the 17.9 silent-loss class (RESEARCH Pitfall 2).
//
// # libsignal version-check annotation
//
// Verified against libsignal v0.2.1. StateStructure, ChainStructure,
// PendingPreKeyStructure, PendingKeyExchangeStructure, and optional.Uint32
// are all immutable value types after construction. If libsignal is upgraded,
// re-audit: grep for any field renames or new fields in those four files.

package store

import (
	"encoding/binary"
	"fmt"

	"go.mau.fi/libsignal/keys/chain"
	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/optional"
)

// Fixed per-field byte-field sizes (verified on libsignal v0.2.1 sources).
const (
	flatSessIdentityKeyLen   = 33 // LocalIdentityPublic, RemoteIdentityPublic (0x05 || 32-byte Curve25519)
	flatSessRootKeyLen       = 32 // RootKey
	flatSessSenderBaseKeyLen = 33 // SenderBaseKey (0x05-prefixed; nullable — hasSenderBaseKey flag)
	flatSessRatchetPubLen    = 33 // SenderRatchetKeyPublic (0x05-prefixed Curve25519)
	flatSessRatchetPrivLen   = 32 // SenderRatchetKeyPrivate (nullable — hasRatchetPrivate flag)
	flatSessChainKeyLen      = 32 // ChainKey.Key
	flatSessMsgCipherKeyLen  = 32 // message.KeysStructure.CipherKey
	flatSessMsgMacKeyLen     = 32 // message.KeysStructure.MacKey
	flatSessMsgIVLen         = 16 // message.KeysStructure.IV
	flatSessPendingBaseKeyLen = 33 // PendingPreKeyStructure.BaseKey (0x05-prefixed)
	flatSessExchangeKeyLen   = 32 // PendingKeyExchangeStructure keys: raw DjbECKey, NOT 0x05-prefixed (Pitfall 8)

	// flatSessMsgKeyLen is the fixed on-wire size per messageKeyRecord:
	// u32 index + 32 cipherKey + 32 macKey + 16 iv = 84 bytes.
	flatSessMsgKeyLen = 4 + flatSessMsgCipherKeyLen + flatSessMsgMacKeyLen + flatSessMsgIVLen // 84

	// flatSessionMagic is byte[0] in every PackFlatSession output.
	// It discriminates flat blobs from JSON blobs (JSON starts with 0x7B = '{').
	flatSessionMagic = byte(0x01)
)

// stateRecordSize computes the total serialized byte count for one StateStructure.
// It must match the layout written by packState.
// We compute this dynamically because ReceiverChains, MessageKeys are variable.
func stateRecordSize(st *record.StateStructure) int {
	// u32 sessionVersion + [33] localIdentityPublic + [33] remoteIdentityPublic
	// + [32] rootKey + u32 previousCounter + u32 localRegistrationID + u32 remoteRegistrationID
	// + u8 needsRefresh + u8 hasSenderBaseKey + [33] senderBaseKey (always 33, zeroed when absent)
	size := 4 + flatSessIdentityKeyLen + flatSessIdentityKeyLen + flatSessRootKeyLen + 4 + 4 + 4 + 1 + 1 + flatSessSenderBaseKeyLen

	// senderChain
	size += chainRecordSize(st.SenderChain)

	// u8 nReceiverChains + each receiver chain
	size += 1
	for _, rc := range st.ReceiverChains {
		size += chainRecordSize(rc)
	}

	// u8 hasPendingPreKey
	size += 1
	if st.PendingPreKey != nil {
		// u8 preKeyIDState + [if state=2: u32 preKeyIDValue] + u32 signedPreKeyID + [33] baseKey
		size += 1 // preKeyIDState
		if st.PendingPreKey.PreKeyID != nil && !st.PendingPreKey.PreKeyID.IsEmpty {
			size += 4 // u32 preKeyIDValue (only when state=2)
		}
		size += 4 + flatSessPendingBaseKeyLen // u32 signedPreKeyID + [33] baseKey
	}

	// u8 hasPendingKeyExchange
	size += 1
	if st.PendingKeyExchange != nil {
		// u32 sequence + 6 × [32] keys
		size += 4 + 6*flatSessExchangeKeyLen
	}

	return size
}

// chainRecordSize computes the total serialized byte count for one ChainStructure.
func chainRecordSize(ch *record.ChainStructure) int {
	// [33] ratchetPub + u8 hasRatchetPrivate + [32] ratchetPrivate (always 32, zeroed when absent)
	// + [32] chainKey + u32 chainKeyIndex
	// + u32 nMessageKeys + nMessageKeys * 84
	size := flatSessRatchetPubLen + 1 + flatSessRatchetPrivLen + flatSessChainKeyLen + 4 + 4
	size += len(ch.MessageKeys) * flatSessMsgKeyLen
	return size
}

// PackFlatSession serializes a *record.SessionStructure to a self-complete []byte
// for storage in whatsmeow_sessions.session.
//
// Returns (nil, false) when any field-length invariant is violated:
//   - nPreviousStates > 255
//   - any fixed-size field has the wrong byte length
//   - nReceiverChains > 255
//   - any MessageKey field has the wrong length
//
// Does NOT refuse at libsignal's logical caps (D-03).
// NEVER emits 0x7B at byte[0] (guaranteed by flatSessionMagic = 0x01).
func PackFlatSession(s *record.SessionStructure) ([]byte, bool) {
	if s == nil || s.SessionState == nil {
		return nil, false
	}

	nPrev := len(s.PreviousStates)
	if nPrev > 255 {
		return nil, false
	}

	// Compute total buffer size before allocating.
	totalSize := 2 // magic + nPreviousStates
	totalSize += stateRecordSize(s.SessionState)
	for _, prev := range s.PreviousStates {
		totalSize += stateRecordSize(prev)
	}

	buf := make([]byte, totalSize)
	buf[0] = flatSessionMagic
	buf[1] = uint8(nPrev)
	off := 2

	var ok bool
	off, ok = packState(buf, off, s.SessionState)
	if !ok {
		return nil, false
	}
	for _, prev := range s.PreviousStates {
		off, ok = packState(buf, off, prev)
		if !ok {
			return nil, false
		}
	}

	if off != totalSize {
		// Should never happen if stateRecordSize and packState agree.
		return nil, false
	}

	return buf, true
}

// packState writes one StateStructure into buf at off, returning (newOff, ok).
// Returns ok=false on any field-length violation.
func packState(buf []byte, off int, st *record.StateStructure) (int, bool) {
	// Validate fixed-size fields before writing.
	if len(st.LocalIdentityPublic) != flatSessIdentityKeyLen {
		return off, false
	}
	if len(st.RemoteIdentityPublic) != flatSessIdentityKeyLen {
		return off, false
	}
	if len(st.RootKey) != flatSessRootKeyLen {
		return off, false
	}
	if st.SenderBaseKey != nil && len(st.SenderBaseKey) != flatSessSenderBaseKeyLen {
		return off, false
	}
	if st.SenderChain == nil {
		return off, false
	}
	if len(st.ReceiverChains) > 255 {
		return off, false
	}

	// u32 sessionVersion
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(st.SessionVersion))
	off += 4

	// [33] localIdentityPublic
	off += copy(buf[off:off+flatSessIdentityKeyLen], st.LocalIdentityPublic)

	// [33] remoteIdentityPublic
	off += copy(buf[off:off+flatSessIdentityKeyLen], st.RemoteIdentityPublic)

	// [32] rootKey
	off += copy(buf[off:off+flatSessRootKeyLen], st.RootKey)

	// u32 previousCounter
	binary.BigEndian.PutUint32(buf[off:off+4], st.PreviousCounter)
	off += 4

	// u32 localRegistrationID
	binary.BigEndian.PutUint32(buf[off:off+4], st.LocalRegistrationID)
	off += 4

	// u32 remoteRegistrationID
	binary.BigEndian.PutUint32(buf[off:off+4], st.RemoteRegistrationID)
	off += 4

	// u8 needsRefresh
	if st.NeedsRefresh {
		buf[off] = 1
	} else {
		buf[off] = 0
	}
	off++

	// u8 hasSenderBaseKey + [33] senderBaseKey (zeroed when flag=0)
	if st.SenderBaseKey != nil {
		buf[off] = 1
		off++
		off += copy(buf[off:off+flatSessSenderBaseKeyLen], st.SenderBaseKey)
	} else {
		buf[off] = 0
		off++
		off += flatSessSenderBaseKeyLen // zeroed by make
	}

	// senderChain
	var ok bool
	off, ok = packChain(buf, off, st.SenderChain)
	if !ok {
		return off, false
	}

	// u8 nReceiverChains
	buf[off] = uint8(len(st.ReceiverChains))
	off++

	// nReceiverChains × chainRecord
	for _, rc := range st.ReceiverChains {
		off, ok = packChain(buf, off, rc)
		if !ok {
			return off, false
		}
	}

	// u8 hasPendingPreKey
	if st.PendingPreKey != nil {
		buf[off] = 1
		off++
		off, ok = packPendingPreKey(buf, off, st.PendingPreKey)
		if !ok {
			return off, false
		}
	} else {
		buf[off] = 0
		off++
	}

	// u8 hasPendingKeyExchange
	if st.PendingKeyExchange != nil {
		buf[off] = 1
		off++
		off, ok = packPendingKeyExchange(buf, off, st.PendingKeyExchange)
		if !ok {
			return off, false
		}
	} else {
		buf[off] = 0
		off++
	}

	return off, true
}

// packChain writes one ChainStructure into buf at off. Returns (newOff, ok).
func packChain(buf []byte, off int, ch *record.ChainStructure) (int, bool) {
	if len(ch.SenderRatchetKeyPublic) != flatSessRatchetPubLen {
		return off, false
	}
	if ch.SenderRatchetKeyPrivate != nil && len(ch.SenderRatchetKeyPrivate) != flatSessRatchetPrivLen {
		return off, false
	}
	if ch.ChainKey == nil || len(ch.ChainKey.Key) != flatSessChainKeyLen {
		return off, false
	}

	// [33] senderRatchetKeyPublic
	off += copy(buf[off:off+flatSessRatchetPubLen], ch.SenderRatchetKeyPublic)

	// u8 hasRatchetPrivate + [32] senderRatchetKeyPrivate (zeroed when flag=0)
	if ch.SenderRatchetKeyPrivate != nil {
		buf[off] = 1
		off++
		off += copy(buf[off:off+flatSessRatchetPrivLen], ch.SenderRatchetKeyPrivate)
	} else {
		buf[off] = 0
		off++
		off += flatSessRatchetPrivLen // zeroed by make
	}

	// [32] chainKey.Key
	off += copy(buf[off:off+flatSessChainKeyLen], ch.ChainKey.Key)

	// u32 chainKey.Index
	binary.BigEndian.PutUint32(buf[off:off+4], ch.ChainKey.Index)
	off += 4

	// u32 nMessageKeys — refuse only if count > uint32 ceiling (D-03: never refuse at 2000)
	nMK := len(ch.MessageKeys)
	// uint32 max is 4294967295; int on 64-bit can exceed this, but nMK > 4294967295 is unreachable
	// in practice. The explicit check is here for correctness completeness.
	if uint64(nMK) > uint64(^uint32(0)) {
		return off, false
	}
	binary.BigEndian.PutUint32(buf[off:off+4], uint32(nMK))
	off += 4

	// nMessageKeys × messageKeyRecord (84 bytes each)
	for _, mk := range ch.MessageKeys {
		if len(mk.CipherKey) != flatSessMsgCipherKeyLen {
			return off, false
		}
		if len(mk.MacKey) != flatSessMsgMacKeyLen {
			return off, false
		}
		if len(mk.IV) != flatSessMsgIVLen {
			return off, false
		}
		binary.BigEndian.PutUint32(buf[off:off+4], mk.Index)
		off += 4
		off += copy(buf[off:off+flatSessMsgCipherKeyLen], mk.CipherKey)
		off += copy(buf[off:off+flatSessMsgMacKeyLen], mk.MacKey)
		off += copy(buf[off:off+flatSessMsgIVLen], mk.IV)
	}

	return off, true
}

// packPendingPreKey writes one PendingPreKeyStructure into buf at off.
// preKeyIDState encoding: 0=nil ptr, 1=IsEmpty, 2=has value.
func packPendingPreKey(buf []byte, off int, ppk *record.PendingPreKeyStructure) (int, bool) {
	if len(ppk.BaseKey) != flatSessPendingBaseKeyLen {
		return off, false
	}

	// u8 preKeyIDState
	var preKeyIDState uint8
	if ppk.PreKeyID == nil {
		preKeyIDState = 0
	} else if ppk.PreKeyID.IsEmpty {
		preKeyIDState = 1
	} else {
		preKeyIDState = 2
	}
	buf[off] = preKeyIDState
	off++

	// u32 preKeyIDValue (only when state=2)
	if preKeyIDState == 2 {
		binary.BigEndian.PutUint32(buf[off:off+4], ppk.PreKeyID.Value)
		off += 4
	}

	// u32 signedPreKeyID
	binary.BigEndian.PutUint32(buf[off:off+4], ppk.SignedPreKeyID)
	off += 4

	// [33] baseKey
	off += copy(buf[off:off+flatSessPendingBaseKeyLen], ppk.BaseKey)

	return off, true
}

// packPendingKeyExchange writes one PendingKeyExchangeStructure into buf at off.
// All keys are 32 bytes (raw DjbECKey, NOT 0x05-prefixed — Pitfall 8).
func packPendingKeyExchange(buf []byte, off int, pke *record.PendingKeyExchangeStructure) (int, bool) {
	if len(pke.LocalBaseKeyPublic) != flatSessExchangeKeyLen ||
		len(pke.LocalBaseKeyPrivate) != flatSessExchangeKeyLen ||
		len(pke.LocalRatchetKeyPublic) != flatSessExchangeKeyLen ||
		len(pke.LocalRatchetKeyPrivate) != flatSessExchangeKeyLen ||
		len(pke.LocalIdentityKeyPublic) != flatSessExchangeKeyLen ||
		len(pke.LocalIdentityKeyPrivate) != flatSessExchangeKeyLen {
		return off, false
	}

	// u32 sequence
	binary.BigEndian.PutUint32(buf[off:off+4], pke.Sequence)
	off += 4

	// 6 × [32] key fields
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalBaseKeyPublic)
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalBaseKeyPrivate)
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalRatchetKeyPublic)
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalRatchetKeyPrivate)
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalIdentityKeyPublic)
	off += copy(buf[off:off+flatSessExchangeKeyLen], pke.LocalIdentityKeyPrivate)

	return off, true
}

// UnpackFlatSession deserializes a PackFlatSession []byte back to a
// *record.SessionStructure.
//
// Fully bounds-checked: returns (nil, error) on any truncation or malformed
// input. NEVER panics. Caller should pass only blobs where b[0]==0x01;
// this function checks the magic byte and returns an error for any other value
// (including 0x7B for JSON blobs).
func UnpackFlatSession(b []byte) (*record.SessionStructure, error) {
	if len(b) < 2 {
		return nil, fmt.Errorf("UnpackFlatSession: buffer too short (%d bytes, need at least 2)", len(b))
	}
	if b[0] != flatSessionMagic {
		return nil, fmt.Errorf("UnpackFlatSession: wrong magic byte 0x%02X (expected 0x%02X); not a flat session blob", b[0], flatSessionMagic)
	}

	nPrev := int(b[1])
	off := 2

	// Parse current state + nPrev previous states.
	currentState, newOff, err := unpackState(b, off)
	if err != nil {
		return nil, fmt.Errorf("UnpackFlatSession: current state: %w", err)
	}
	off = newOff

	previousStates := make([]*record.StateStructure, nPrev)
	for i := 0; i < nPrev; i++ {
		previousStates[i], newOff, err = unpackState(b, off)
		if err != nil {
			return nil, fmt.Errorf("UnpackFlatSession: previous state %d: %w", i, err)
		}
		off = newOff
	}

	return &record.SessionStructure{
		SessionState:   currentState,
		PreviousStates: previousStates,
	}, nil
}

// unpackState decodes one StateStructure from b starting at off.
// Returns (state, newOff, error).
func unpackState(b []byte, off int) (*record.StateStructure, int, error) {
	// u32 sessionVersion
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at sessionVersion (need %d, have %d)", off+4, len(b))
	}
	sessionVersion := int(binary.BigEndian.Uint32(b[off : off+4]))
	off += 4

	// [33] localIdentityPublic
	if len(b) < off+flatSessIdentityKeyLen {
		return nil, off, fmt.Errorf("truncated at localIdentityPublic")
	}
	localIdentityPublic := make([]byte, flatSessIdentityKeyLen)
	off += copy(localIdentityPublic, b[off:off+flatSessIdentityKeyLen])

	// [33] remoteIdentityPublic
	if len(b) < off+flatSessIdentityKeyLen {
		return nil, off, fmt.Errorf("truncated at remoteIdentityPublic")
	}
	remoteIdentityPublic := make([]byte, flatSessIdentityKeyLen)
	off += copy(remoteIdentityPublic, b[off:off+flatSessIdentityKeyLen])

	// [32] rootKey
	if len(b) < off+flatSessRootKeyLen {
		return nil, off, fmt.Errorf("truncated at rootKey")
	}
	rootKey := make([]byte, flatSessRootKeyLen)
	off += copy(rootKey, b[off:off+flatSessRootKeyLen])

	// u32 previousCounter
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at previousCounter")
	}
	previousCounter := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// u32 localRegistrationID
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at localRegistrationID")
	}
	localRegistrationID := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// u32 remoteRegistrationID
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at remoteRegistrationID")
	}
	remoteRegistrationID := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// u8 needsRefresh
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at needsRefresh")
	}
	needsRefresh := b[off] != 0
	off++

	// u8 hasSenderBaseKey + [33] senderBaseKey
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at hasSenderBaseKey flag")
	}
	hasSenderBaseKey := b[off]
	off++
	if len(b) < off+flatSessSenderBaseKeyLen {
		return nil, off, fmt.Errorf("truncated at senderBaseKey")
	}
	var senderBaseKey []byte
	if hasSenderBaseKey != 0 {
		senderBaseKey = make([]byte, flatSessSenderBaseKeyLen)
		copy(senderBaseKey, b[off:off+flatSessSenderBaseKeyLen])
	}
	off += flatSessSenderBaseKeyLen

	// senderChain
	senderChain, newOff, err := unpackChain(b, off)
	if err != nil {
		return nil, off, fmt.Errorf("senderChain: %w", err)
	}
	off = newOff

	// u8 nReceiverChains
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at nReceiverChains")
	}
	nRC := int(b[off])
	off++

	receiverChains := make([]*record.ChainStructure, nRC)
	for i := 0; i < nRC; i++ {
		receiverChains[i], newOff, err = unpackChain(b, off)
		if err != nil {
			return nil, off, fmt.Errorf("receiverChain %d: %w", i, err)
		}
		off = newOff
	}

	// u8 hasPendingPreKey
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at hasPendingPreKey flag")
	}
	hasPPK := b[off]
	off++
	var pendingPreKey *record.PendingPreKeyStructure
	if hasPPK != 0 {
		pendingPreKey, newOff, err = unpackPendingPreKey(b, off)
		if err != nil {
			return nil, off, fmt.Errorf("pendingPreKey: %w", err)
		}
		off = newOff
	}

	// u8 hasPendingKeyExchange
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at hasPendingKeyExchange flag")
	}
	hasPKE := b[off]
	off++
	var pendingKeyExchange *record.PendingKeyExchangeStructure
	if hasPKE != 0 {
		pendingKeyExchange, newOff, err = unpackPendingKeyExchange(b, off)
		if err != nil {
			return nil, off, fmt.Errorf("pendingKeyExchange: %w", err)
		}
		off = newOff
	}

	return &record.StateStructure{
		SessionVersion:       sessionVersion,
		LocalIdentityPublic:  localIdentityPublic,
		RemoteIdentityPublic: remoteIdentityPublic,
		RootKey:              rootKey,
		PreviousCounter:      previousCounter,
		LocalRegistrationID:  localRegistrationID,
		RemoteRegistrationID: remoteRegistrationID,
		NeedsRefresh:         needsRefresh,
		SenderBaseKey:        senderBaseKey, // nil when hasSenderBaseKey=0
		SenderChain:          senderChain,
		ReceiverChains:       receiverChains,
		PendingPreKey:        pendingPreKey,
		PendingKeyExchange:   pendingKeyExchange,
	}, off, nil
}

// unpackChain decodes one ChainStructure from b starting at off.
func unpackChain(b []byte, off int) (*record.ChainStructure, int, error) {
	// [33] senderRatchetKeyPublic
	if len(b) < off+flatSessRatchetPubLen {
		return nil, off, fmt.Errorf("truncated at senderRatchetKeyPublic")
	}
	ratchetPub := make([]byte, flatSessRatchetPubLen)
	off += copy(ratchetPub, b[off:off+flatSessRatchetPubLen])

	// u8 hasRatchetPrivate + [32] senderRatchetKeyPrivate
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at hasRatchetPrivate flag")
	}
	hasRatchetPriv := b[off]
	off++
	if len(b) < off+flatSessRatchetPrivLen {
		return nil, off, fmt.Errorf("truncated at senderRatchetKeyPrivate")
	}
	var ratchetPriv []byte
	if hasRatchetPriv != 0 {
		ratchetPriv = make([]byte, flatSessRatchetPrivLen)
		copy(ratchetPriv, b[off:off+flatSessRatchetPrivLen])
	}
	off += flatSessRatchetPrivLen

	// [32] chainKey.Key
	if len(b) < off+flatSessChainKeyLen {
		return nil, off, fmt.Errorf("truncated at chainKey")
	}
	chainKeyBytes := make([]byte, flatSessChainKeyLen)
	off += copy(chainKeyBytes, b[off:off+flatSessChainKeyLen])

	// u32 chainKey.Index
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at chainKeyIndex")
	}
	chainKeyIndex := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// u32 nMessageKeys
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at nMessageKeys")
	}
	nMK := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// Pre-check that nMK × 84 bytes are available before entering the loop.
	needMKBytes := int64(nMK) * int64(flatSessMsgKeyLen)
	if int64(len(b)-off) < needMKBytes {
		return nil, off, fmt.Errorf("truncated: nMessageKeys=%d implies %d bytes, have %d", nMK, needMKBytes, len(b)-off)
	}

	messageKeys := make([]*message.KeysStructure, nMK)
	for i := uint32(0); i < nMK; i++ {
		// u32 index
		idx := binary.BigEndian.Uint32(b[off : off+4])
		off += 4

		// [32] cipherKey
		cipherKey := make([]byte, flatSessMsgCipherKeyLen)
		off += copy(cipherKey, b[off:off+flatSessMsgCipherKeyLen])

		// [32] macKey
		macKey := make([]byte, flatSessMsgMacKeyLen)
		off += copy(macKey, b[off:off+flatSessMsgMacKeyLen])

		// [16] iv
		iv := make([]byte, flatSessMsgIVLen)
		off += copy(iv, b[off:off+flatSessMsgIVLen])

		messageKeys[i] = &message.KeysStructure{
			Index:     idx,
			CipherKey: cipherKey,
			MacKey:    macKey,
			IV:        iv,
		}
	}

	return &record.ChainStructure{
		SenderRatchetKeyPublic:  ratchetPub,
		SenderRatchetKeyPrivate: ratchetPriv, // nil when hasRatchetPriv=0
		ChainKey: &chain.KeyStructure{
			Key:   chainKeyBytes,
			Index: chainKeyIndex,
		},
		MessageKeys: messageKeys,
	}, off, nil
}

// unpackPendingPreKey decodes one PendingPreKeyStructure from b starting at off.
// preKeyIDState: 0=nil ptr, 1=IsEmpty, 2=has u32 value.
func unpackPendingPreKey(b []byte, off int) (*record.PendingPreKeyStructure, int, error) {
	// u8 preKeyIDState
	if len(b) < off+1 {
		return nil, off, fmt.Errorf("truncated at preKeyIDState")
	}
	preKeyIDState := b[off]
	off++

	var preKeyID *optional.Uint32
	switch preKeyIDState {
	case 0:
		preKeyID = nil
	case 1:
		preKeyID = &optional.Uint32{IsEmpty: true}
	case 2:
		if len(b) < off+4 {
			return nil, off, fmt.Errorf("truncated at preKeyIDValue (state=2 requires u32)")
		}
		val := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		preKeyID = &optional.Uint32{IsEmpty: false, Value: val}
	default:
		return nil, off, fmt.Errorf("unknown preKeyIDState %d (expected 0, 1, or 2)", preKeyIDState)
	}

	// u32 signedPreKeyID
	if len(b) < off+4 {
		return nil, off, fmt.Errorf("truncated at signedPreKeyID")
	}
	signedPreKeyID := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// [33] baseKey
	if len(b) < off+flatSessPendingBaseKeyLen {
		return nil, off, fmt.Errorf("truncated at pendingPreKey baseKey")
	}
	baseKey := make([]byte, flatSessPendingBaseKeyLen)
	off += copy(baseKey, b[off:off+flatSessPendingBaseKeyLen])

	return &record.PendingPreKeyStructure{
		PreKeyID:       preKeyID,
		SignedPreKeyID: signedPreKeyID,
		BaseKey:        baseKey,
	}, off, nil
}

// unpackPendingKeyExchange decodes one PendingKeyExchangeStructure from b starting at off.
// All 6 key fields are 32 bytes (raw DjbECKey, NOT 0x05-prefixed — Pitfall 8).
func unpackPendingKeyExchange(b []byte, off int) (*record.PendingKeyExchangeStructure, int, error) {
	need := 4 + 6*flatSessExchangeKeyLen // 4 + 192 = 196
	if len(b) < off+need {
		return nil, off, fmt.Errorf("truncated at pendingKeyExchange (need %d bytes, have %d)", need, len(b)-off)
	}

	// u32 sequence
	sequence := binary.BigEndian.Uint32(b[off : off+4])
	off += 4

	// 6 × [32] keys
	readKey := func() []byte {
		k := make([]byte, flatSessExchangeKeyLen)
		copy(k, b[off:off+flatSessExchangeKeyLen])
		off += flatSessExchangeKeyLen
		return k
	}

	localBaseKeyPublic := readKey()
	localBaseKeyPrivate := readKey()
	localRatchetKeyPublic := readKey()
	localRatchetKeyPrivate := readKey()
	localIdentityKeyPublic := readKey()
	localIdentityKeyPrivate := readKey()

	return &record.PendingKeyExchangeStructure{
		Sequence:                sequence,
		LocalBaseKeyPublic:      localBaseKeyPublic,
		LocalBaseKeyPrivate:     localBaseKeyPrivate,
		LocalRatchetKeyPublic:   localRatchetKeyPublic,
		LocalRatchetKeyPrivate:  localRatchetKeyPrivate,
		LocalIdentityKeyPublic:  localIdentityKeyPublic,
		LocalIdentityKeyPrivate: localIdentityKeyPrivate,
	}, off, nil
}
