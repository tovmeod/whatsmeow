// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Phase 17.9 — flat, near-pointer-free value representation of a sender-key
// structure for the parsed sender-key cache.
//
// # Why this exists (GC redesign)
//
// The 17.8/17.9 parsed cache stored *groupRecord.SenderKeyStructure — a
// pointer-dense libsignal graph ([]*SenderKeyStateStructure, each with []byte
// keys and []*SenderMessageKeyStructure). Go's tracing GC scans every live
// pointer every cycle; at prod scale the cache warmed to ~18M live objects
// (~1.4 GB), exceeding GOMEMLIMIT and triggering a continuous-GC death-spiral
// (85% of CPU in gcBgMarkWorker → scanobject). flatSenderKey holds its per-state
// crypto material in fixed-size value arrays (ZERO pointers) and routes the rare
// (~17%) skipped-key tail through a SINGLE []byte (nil for 83% of keys). The
// cache LRU stores flatSenderKey BY VALUE; lru.Get copies it out, so callers
// never alias the cached entry.
//
// # Correctness boundary (CORRECTNESS-CRITICAL)
//
// This is a production crypto store. flatFromStructure ENFORCES the per-field
// byte-length invariant (chainKey=32, signingPub=33, signingPriv=32, iv=16,
// cipherKey=32, seed=32) rather than assuming it: a wrong length, 0 states, or
// > flatMaxStates states returns ok=false → the caller SKIPS caching and falls
// through to the uncached read path (correct, just not cached). A blind
// copy(arr[:], src) with an unexpected len(src) would silently truncate/zero-pad
// into a corrupted key → silent group-decryption failure. The refuse-to-cache
// guard converts "lengths are fixed (observed)" into "lengths are enforced
// (invariant)".
//
// # libsignal version-check annotation
//
// Verified against libsignal v0.2.1. The fixed-array state fields are per-Get
// value copies (the [flatMaxStates]flatState array is copied by lru.Get), so
// they are never aliased across Gets. The skipped []byte backing array WAS the
// one shared-mutation foot-gun in the pointer-dense design; here unpackSkipped
// COPIES IV/CipherKey/Seed out of the tail into fresh slices on every decode, so
// the rebuilt *SenderMessageKeyStructure never aliases the cached backing array.
// NewSenderKeyFromStruct (v0.2.1) aliases the structure's []byte fields into the
// *SenderKey without copying, and v0.2.1 does not mutate those bytes after
// construction — but because we copy-on-unpack and value-copy the states, the
// cache entry is immutable from the caller's view regardless. If libsignal is
// upgraded, re-audit: grep for mutation of chainKey / signingKey / iv /
// cipherKey / seed in the new version's groups/ratchet and groups/state packages.

package store

import (
	"encoding/binary"
	"fmt"

	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// Fixed per-state byte-field sizes (verified on 20,000 prod fmt_ver=2 rows).
const (
	flatChainKeyLen    = 32 // SenderChainKey.ChainKey
	flatSigningPubLen  = 33 // SigningKeyPublic (serialized DjbECPublicKey: 0x05||32)
	flatSigningPrivLen = 32 // SigningKeyPrivate (nullable; zeroed + hasPriv=false when absent)

	flatIVLen        = 16 // SenderMessageKey.IV
	flatCipherKeyLen = 32 // SenderMessageKey.CipherKey
	flatSeedLen      = 32 // SenderMessageKey.Seed
)

// flatMaxStates is the per-key state cap the flat form supports. Prod max
// observed is 6 (libsignal maxStates=5, but load is uncapped and the trim is
// -1-on-add, so 6 is the stable ceiling). Keys with more states return
// ok=false from flatFromStructure and stay uncached (correct, just slower).
const flatMaxStates = 6

// MaxSenderKeyStates is a fork-local mirror of libsignal's unexported
// maxStates (go.mau.fi/libsignal@v0.2.1 groups/state/record/SenderKeyRecord.go:10).
// QUICK-SKCAP-01: the fork's recovery-merge helpers (sqlstore/senderkey_caps.go)
// cap merged records at this limit, and StoreStruct's CR-01 missing-KeyID guard
// (parsedcache.go) tolerates cap-dropped oldest states against it. Exported so
// both packages share one source of truth.
const MaxSenderKeyStates = 5

// flatState is one SenderKeyState worth of crypto material, packed into fixed
// value arrays. ZERO pointers — the whole struct is scanned by the GC as plain
// bytes.
type flatState struct {
	keyID       uint32
	chainIter   uint32                   // SenderChainKey.Iteration
	chainKey    [flatChainKeyLen]byte    // SenderChainKey.ChainKey
	signingPub  [flatSigningPubLen]byte  // SigningKeyPublic
	signingPriv [flatSigningPrivLen]byte // SigningKeyPrivate (zeroed when absent)
	hasPriv     bool                     // SigningKeyPrivate != nil
}

// flatSenderKey is the cache value type. The states array is by value
// (pointer-free); skipped is the ONLY pointer field and is nil for the ~83% of
// keys that carry no skipped message keys.
type flatSenderKey struct {
	nStates uint8
	states  [flatMaxStates]flatState
	skipped []byte // nil when there are no skipped keys; packed tail otherwise
}

// flatFromStructure converts a *SenderKeyStructure to its flat form, enforcing
// the per-field byte-length invariant. It returns ok=false (DO NOT CACHE) when:
//   - len(states) == 0 or > flatMaxStates
//   - any state has the wrong chainKey / signingPub / signingPriv length
//   - any skipped key has the wrong iv / cipherKey / seed length
//
// nil SigningKeyPrivate is preserved as hasPriv=false (NOT []byte{}) — received
// keys carry a nil private key and decompose preserves that distinction.
func flatFromStructure(s *groupRecord.SenderKeyStructure) (flatSenderKey, bool) {
	n := len(s.SenderKeyStates)
	if n == 0 || n > flatMaxStates {
		return flatSenderKey{}, false
	}

	var f flatSenderKey
	f.nStates = uint8(n)

	for i, st := range s.SenderKeyStates {
		ck := st.SenderChainKey.ChainKey
		pub := st.SigningKeyPublic
		priv := st.SigningKeyPrivate
		if len(ck) != flatChainKeyLen || len(pub) != flatSigningPubLen {
			return flatSenderKey{}, false
		}
		if priv != nil && len(priv) != flatSigningPrivLen {
			return flatSenderKey{}, false
		}

		fs := &f.states[i]
		fs.keyID = st.KeyID
		fs.chainIter = st.SenderChainKey.Iteration
		copy(fs.chainKey[:], ck)
		copy(fs.signingPub[:], pub)
		if priv != nil {
			fs.hasPriv = true
			copy(fs.signingPriv[:], priv)
		}
		// priv == nil → hasPriv stays false, signingPriv stays zeroed.
	}

	skipped, ok := packSkipped(s)
	if !ok {
		return flatSenderKey{}, false
	}
	f.skipped = skipped

	return f, true
}

// flatToStructure rebuilds a *SenderKeyStructure from the flat form. It returns
// nil if the skipped tail is malformed (treated by LoadStruct as a cache miss,
// never a panic). SigningKeyPrivate is nil when !hasPriv (NOT []byte{}). The
// IV/CipherKey/Seed of each skipped key are COPIED out of the tail into fresh
// slices so the rebuilt structure never aliases the cached backing array.
func flatToStructure(f flatSenderKey) *groupRecord.SenderKeyStructure {
	n := int(f.nStates)
	states := make([]*groupRecord.SenderKeyStateStructure, n)
	for i := 0; i < n; i++ {
		fs := &f.states[i]
		chainKey := make([]byte, flatChainKeyLen)
		copy(chainKey, fs.chainKey[:])
		signingPub := make([]byte, flatSigningPubLen)
		copy(signingPub, fs.signingPub[:])
		var signingPriv []byte
		if fs.hasPriv {
			signingPriv = make([]byte, flatSigningPrivLen)
			copy(signingPriv, fs.signingPriv[:])
		}
		states[i] = &groupRecord.SenderKeyStateStructure{
			KeyID: fs.keyID,
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: fs.chainIter,
				ChainKey:  chainKey,
			},
			SigningKeyPublic:  signingPub,
			SigningKeyPrivate: signingPriv, // nil when !hasPriv
		}
	}

	if err := unpackSkipped(f.skipped, states); err != nil {
		return nil
	}

	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// skippedRecordLen is the fixed on-wire size of one packed skipped key:
// [uint8 stateIdx][uint32 iteration][16]iv[32]cipherKey[32]seed.
const skippedRecordLen = 1 + 4 + flatIVLen + flatCipherKeyLen + flatSeedLen // 85

// packSkipped serializes all skipped message keys across all states into a flat,
// fixed-width byte tail, or returns (nil, true) when there are none. The layout
// mirrors the sqlstore columnar codec's smk_* flat arrays:
//
//	[uint32 count]
//	  repeated count times:
//	    [uint8 stateIdx][uint32 iteration][16]iv[32]cipherKey[32]seed   (85 bytes)
//
// A wrong iv / cipherKey / seed length returns ok=false (same refuse-to-cache
// guard as the per-state fields).
func packSkipped(s *groupRecord.SenderKeyStructure) ([]byte, bool) {
	total := 0
	for _, st := range s.SenderKeyStates {
		total += len(st.Keys)
	}
	if total == 0 {
		return nil, true
	}

	buf := make([]byte, 4+total*skippedRecordLen)
	binary.BigEndian.PutUint32(buf[0:4], uint32(total))
	off := 4
	for i, st := range s.SenderKeyStates {
		for _, smk := range st.Keys {
			if len(smk.IV) != flatIVLen || len(smk.CipherKey) != flatCipherKeyLen || len(smk.Seed) != flatSeedLen {
				return nil, false
			}
			buf[off] = uint8(i)
			off++
			binary.BigEndian.PutUint32(buf[off:off+4], smk.Iteration)
			off += 4
			off += copy(buf[off:off+flatIVLen], smk.IV)
			off += copy(buf[off:off+flatCipherKeyLen], smk.CipherKey)
			off += copy(buf[off:off+flatSeedLen], smk.Seed)
		}
	}
	return buf, true
}

// perStateLen is the fixed on-wire size per state in the PackFlat format:
// u32 keyID + u32 chainIter + 32 chainKey + 33 signingPub + u8 hasPriv + 32 signingPriv = 106 bytes.
const perStateLen = 4 + 4 + flatChainKeyLen + flatSigningPubLen + 1 + flatSigningPrivLen // 106

// flatHeaderOff is the byte offset of state[0].KeyID in a PackFlat buffer.
// state[0].KeyID is at bytes [1..4] (after the u8 nStates header).
// Used by the R8 byte-prefilter in the donor scan.
const flatHeaderOff = 1

// PackFlat serializes a *SenderKeyStructure to a self-complete []byte for storage.
// Unlike flatFromStructure, PackFlat supports unbounded state count (up to 255 states,
// limited only by u8 nStates). Exported for use by sqlstore and migration tool
// (package boundary — lowercase would not compile from sqlstore or main packages).
//
// Returns (nil, false) when:
//   - len(states) == 0 or > 255
//   - any state has the wrong chainKey / signingPub / signingPriv length
//   - any skipped key has the wrong iv / cipherKey / seed length
func PackFlat(s *groupRecord.SenderKeyStructure) ([]byte, bool) {
	n := len(s.SenderKeyStates)
	if n == 0 || n > 255 {
		return nil, false
	}

	buf := make([]byte, 1+n*perStateLen)
	buf[0] = uint8(n)
	off := 1
	for _, st := range s.SenderKeyStates {
		ck := st.SenderChainKey.ChainKey
		pub := st.SigningKeyPublic
		priv := st.SigningKeyPrivate
		if len(ck) != flatChainKeyLen || len(pub) != flatSigningPubLen {
			return nil, false
		}
		if priv != nil && len(priv) != flatSigningPrivLen {
			return nil, false
		}
		binary.BigEndian.PutUint32(buf[off:off+4], st.KeyID)
		off += 4
		binary.BigEndian.PutUint32(buf[off:off+4], st.SenderChainKey.Iteration)
		off += 4
		off += copy(buf[off:off+flatChainKeyLen], ck)
		off += copy(buf[off:off+flatSigningPubLen], pub)
		if priv != nil {
			buf[off] = 1
			off++
			off += copy(buf[off:off+flatSigningPrivLen], priv)
		} else {
			buf[off] = 0
			off++
			off += flatSigningPrivLen // signingPriv is zeroed (make initializes to 0)
		}
	}

	// Append the skipped-key tail. packSkipped returns nil when there are no
	// skipped keys (not a 4-zero-byte slice) — substitute the explicit count=0
	// header so UnpackFlat always finds the 4-byte count prefix.
	skipped, ok := packSkipped(s)
	if !ok {
		return nil, false
	}
	if skipped == nil {
		buf = append(buf, 0, 0, 0, 0)
	} else {
		buf = append(buf, skipped...)
	}

	return buf, true
}

// UnpackFlat deserializes a PackFlat []byte back to a *SenderKeyStructure.
// Fully bounds-checked: returns (nil, error) on any truncation or malformed input.
// Never panics. Exported for use by sqlstore and migration tool (cross-package).
//
// Caller treats a non-nil error as a cache/DB miss and falls through to uncached path.
func UnpackFlat(b []byte) (*groupRecord.SenderKeyStructure, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("UnpackFlat: buffer too short for nStates header (%d bytes)", len(b))
	}
	n := int(b[0])
	if n == 0 {
		return nil, fmt.Errorf("UnpackFlat: nStates=0 is not valid PackFlat output")
	}
	minLen := 1 + n*perStateLen + 4
	if len(b) < minLen {
		return nil, fmt.Errorf("UnpackFlat: buffer too short: need %d bytes for %d states, have %d", minLen, n, len(b))
	}

	states := make([]*groupRecord.SenderKeyStateStructure, n)
	off := 1
	for i := 0; i < n; i++ {
		keyID := binary.BigEndian.Uint32(b[off : off+4])
		off += 4
		chainIter := binary.BigEndian.Uint32(b[off : off+4])
		off += 4

		chainKey := make([]byte, flatChainKeyLen)
		off += copy(chainKey, b[off:off+flatChainKeyLen])

		signingPub := make([]byte, flatSigningPubLen)
		off += copy(signingPub, b[off:off+flatSigningPubLen])

		hasPriv := b[off]
		off++
		var signingPriv []byte
		if hasPriv != 0 {
			signingPriv = make([]byte, flatSigningPrivLen)
			off += copy(signingPriv, b[off:off+flatSigningPrivLen])
		} else {
			off += flatSigningPrivLen // skip zeroed bytes
		}

		states[i] = &groupRecord.SenderKeyStateStructure{
			KeyID: keyID,
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: chainIter,
				ChainKey:  chainKey,
			},
			SigningKeyPublic:  signingPub,
			SigningKeyPrivate: signingPriv, // nil when !hasPriv
		}
	}

	// Decode the skipped-key tail. After the state records, the remaining bytes
	// are the packed skipped tail (4-byte count + records). unpackSkipped accepts
	// an empty/nil slice as a no-op, but PackFlat always writes the 4-byte count
	// header, so we pass the full tail slice.
	tail := b[1+n*perStateLen:]
	if err := unpackSkipped(tail, states); err != nil {
		return nil, fmt.Errorf("UnpackFlat: skipped tail: %w", err)
	}

	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}, nil
}

// unpackSkipped decodes the packed skipped tail and routes each key back to its
// owning state's Keys slice. It is fully bounds-checked: a malformed tail (short
// buffer, count/length mismatch, or out-of-range stateIdx) returns an error and
// NEVER panics. IV/CipherKey/Seed are copied into fresh slices (no aliasing of
// the shared cache backing array). A nil/empty tail is a valid no-op.
func unpackSkipped(buf []byte, states []*groupRecord.SenderKeyStateStructure) error {
	if len(buf) == 0 {
		return nil
	}
	if len(buf) < 4 {
		return fmt.Errorf("flat skipped tail too short for count: %d bytes", len(buf))
	}
	count := binary.BigEndian.Uint32(buf[0:4])
	if int64(len(buf)) != int64(4)+int64(count)*int64(skippedRecordLen) {
		return fmt.Errorf("flat skipped tail size mismatch: count=%d implies %d bytes, have %d",
			count, 4+int64(count)*int64(skippedRecordLen), len(buf))
	}

	off := 4
	for i := uint32(0); i < count; i++ {
		stateIdx := int(buf[off])
		off++
		if stateIdx < 0 || stateIdx >= len(states) {
			return fmt.Errorf("flat skipped key %d: stateIdx %d out of range [0,%d)", i, stateIdx, len(states))
		}
		iteration := binary.BigEndian.Uint32(buf[off : off+4])
		off += 4

		iv := make([]byte, flatIVLen)
		off += copy(iv, buf[off:off+flatIVLen])
		cipherKey := make([]byte, flatCipherKeyLen)
		off += copy(cipherKey, buf[off:off+flatCipherKeyLen])
		seed := make([]byte, flatSeedLen)
		off += copy(seed, buf[off:off+flatSeedLen])

		st := states[stateIdx]
		st.Keys = append(st.Keys, &ratchet.SenderMessageKeyStructure{
			Iteration: iteration,
			IV:        iv,
			CipherKey: cipherKey,
			Seed:      seed,
		})
	}
	return nil
}
