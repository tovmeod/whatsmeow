// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// flat_senderkey_test.go — Phase 17.9 GC redesign.
//
// Two layers of correctness coverage for the flat sender-key cache value:
//
//  1. Round-trip property test: flatToStructure(flatFromStructure(x)) must
//     deep-equal x for 0/1/5/6 states, 0/1/10/100/2602 skipped keys, and BOTH
//     nil and non-nil private keys — INCLUDING the nil ≠ []byte{} distinction
//     on the private key. Refuse cases (0 states, 7 states, wrong field length)
//     must return ok=false.
//
//  2. Decrypt-equivalence test (the real gate): a real libsignal group session
//     is built end-to-end; the SAME ciphertext is decrypted from a *SenderKey
//     rebuilt (a) directly from the original structure and (b) from
//     flatToStructure(flatFromStructure(structure)). Identical plaintext proves
//     the flat codec preserves the exact crypto material. Covered for a
//     zero-skip key AND a with-skipped-keys key (driven via real out-of-order
//     decryption). FULL group-cipher round-trip is used (see report).
package store

import (
	"context"
	"reflect"
	"testing"

	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/groups/ratchet"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/protocol"
)

// ---------------------------------------------------------------------------
// builders
// ---------------------------------------------------------------------------

func filled(n int, b byte) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(int(b) + i)
	}
	return out
}

// makeStructure builds a *SenderKeyStructure with nStates states and a total of
// totalSkipped skipped message keys distributed across the states. When
// withPriv is false, every state's SigningKeyPrivate is nil (received-key case;
// exercises hasPriv=false / nil ≠ []byte{}).
func makeStructure(nStates, totalSkipped int, withPriv bool) *groupRecord.SenderKeyStructure {
	states := make([]*groupRecord.SenderKeyStateStructure, nStates)
	for i := 0; i < nStates; i++ {
		var priv []byte
		if withPriv {
			priv = filled(flatSigningPrivLen, byte(0x30+i))
		}
		states[i] = &groupRecord.SenderKeyStateStructure{
			KeyID: uint32(1000 + i),
			SenderChainKey: &ratchet.SenderChainKeyStructure{
				Iteration: uint32(i),
				ChainKey:  filled(flatChainKeyLen, byte(0x10+i)),
			},
			SigningKeyPublic:  filled(flatSigningPubLen, byte(0x20+i)),
			SigningKeyPrivate: priv, // nil when !withPriv
		}
	}
	// Round-robin the skipped keys across states so smkStateIdx routing is
	// exercised for multi-state structures.
	for j := 0; j < totalSkipped; j++ {
		st := states[j%nStates]
		st.Keys = append(st.Keys, &ratchet.SenderMessageKeyStructure{
			Iteration: uint32(j),
			IV:        filled(flatIVLen, byte(j)),
			CipherKey: filled(flatCipherKeyLen, byte(j+1)),
			Seed:      filled(flatSeedLen, byte(j+2)),
		})
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// ---------------------------------------------------------------------------
// TestFlatSenderKeyRoundTrip — property test
// ---------------------------------------------------------------------------

func TestFlatSenderKeyRoundTrip(t *testing.T) {
	stateCounts := []int{1, 5, 6}
	skipCounts := []int{0, 1, 10, 100, 2602}
	for _, ns := range stateCounts {
		for _, sk := range skipCounts {
			for _, withPriv := range []bool{true, false} {
				orig := makeStructure(ns, sk, withPriv)
				f, ok := flatFromStructure(orig)
				if !ok {
					t.Fatalf("flatFromStructure refused a valid structure (states=%d skipped=%d priv=%v)", ns, sk, withPriv)
				}
				got := flatToStructure(f)
				if got == nil {
					t.Fatalf("flatToStructure returned nil (states=%d skipped=%d priv=%v)", ns, sk, withPriv)
				}
				if !reflect.DeepEqual(got, orig) {
					t.Fatalf("round-trip mismatch (states=%d skipped=%d priv=%v):\n got %+v\nwant %+v", ns, sk, withPriv, got, orig)
				}
				// Explicit nil-vs-[]byte{} guard on the private key — reflect.DeepEqual
				// distinguishes them, but assert directly so a regression is unambiguous.
				for i, st := range got.SenderKeyStates {
					if withPriv {
						if st.SigningKeyPrivate == nil {
							t.Fatalf("state %d: private key became nil when withPriv=true", i)
						}
					} else {
						if st.SigningKeyPrivate != nil {
							t.Fatalf("state %d: private key is %v (len %d); want nil (received-key case)", i, st.SigningKeyPrivate, len(st.SigningKeyPrivate))
						}
					}
				}
			}
		}
	}
}

// TestFlatSenderKeyRoundTripZeroStateSkipped covers a structure with 0 skipped
// keys explicitly verifying skipped == nil (the 83% common path: the only
// pointer field is nil).
func TestFlatSenderKeyRoundTripNilSkipped(t *testing.T) {
	orig := makeStructure(1, 0, true)
	f, ok := flatFromStructure(orig)
	if !ok {
		t.Fatal("flatFromStructure refused a valid 0-skip structure")
	}
	if f.skipped != nil {
		t.Fatalf("skipped tail should be nil for 0 skipped keys, got %d bytes", len(f.skipped))
	}
	got := flatToStructure(f)
	if !reflect.DeepEqual(got, orig) {
		t.Fatalf("0-skip round-trip mismatch:\n got %+v\nwant %+v", got, orig)
	}
}

// ---------------------------------------------------------------------------
// TestFlatSenderKeyRefuse — the refuse-to-cache guard
// ---------------------------------------------------------------------------

func TestFlatSenderKeyRefuse(t *testing.T) {
	t.Run("zero_states", func(t *testing.T) {
		s := &groupRecord.SenderKeyStructure{SenderKeyStates: nil}
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for 0 states")
		}
	})
	t.Run("too_many_states", func(t *testing.T) {
		s := makeStructure(flatMaxStates+1, 0, true) // 7 states
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for >flatMaxStates states")
		}
	})
	t.Run("wrong_chainkey_len", func(t *testing.T) {
		s := makeStructure(1, 0, true)
		s.SenderKeyStates[0].SenderChainKey.ChainKey = filled(31, 0x10) // 31 != 32
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for wrong chainKey length")
		}
	})
	t.Run("wrong_signingpub_len", func(t *testing.T) {
		s := makeStructure(1, 0, true)
		s.SenderKeyStates[0].SigningKeyPublic = filled(32, 0x20) // 32 != 33
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for wrong signingPub length")
		}
	})
	t.Run("wrong_signingpriv_len", func(t *testing.T) {
		s := makeStructure(1, 0, true)
		s.SenderKeyStates[0].SigningKeyPrivate = filled(16, 0x30) // 16 != 32 (non-nil)
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for wrong (non-nil) signingPriv length")
		}
	})
	t.Run("wrong_skipped_iv_len", func(t *testing.T) {
		s := makeStructure(1, 1, true)
		s.SenderKeyStates[0].Keys[0].IV = filled(15, 0x00) // 15 != 16
		if _, ok := flatFromStructure(s); ok {
			t.Fatal("expected ok=false for wrong skipped IV length")
		}
	})
}

// TestFlatStateUnpackSkippedMalformed asserts a corrupt tail is reported as an
// error (never a panic), and that flatToStructure maps it to a nil structure
// (which LoadStruct treats as a clean miss).
func TestFlatStateUnpackSkippedMalformed(t *testing.T) {
	states := []*groupRecord.SenderKeyStateStructure{{
		SenderChainKey: &ratchet.SenderChainKeyStructure{},
	}}
	// count=1 but no record bytes follow → size mismatch.
	bad := []byte{0x00, 0x00, 0x00, 0x01}
	if err := unpackSkipped(bad, states); err == nil {
		t.Fatal("expected error for size-mismatched tail")
	}
	// too short to even hold the count.
	if err := unpackSkipped([]byte{0x00, 0x01}, states); err == nil {
		t.Fatal("expected error for sub-4-byte tail")
	}
	// well-formed length but stateIdx out of range.
	rec := make([]byte, 4+skippedRecordLen)
	rec[3] = 1            // count = 1
	rec[4] = 9            // stateIdx = 9 (only 1 state exists)
	if err := unpackSkipped(rec, states); err == nil {
		t.Fatal("expected error for out-of-range stateIdx")
	}

	// flatToStructure with a corrupt tail returns nil (clean miss, no panic).
	f := flatSenderKey{nStates: 1, skipped: bad}
	if got := flatToStructure(f); got != nil {
		t.Fatalf("flatToStructure with corrupt tail: want nil, got %+v", got)
	}
}

// ---------------------------------------------------------------------------
// Decrypt-equivalence — the real gate
// ---------------------------------------------------------------------------

// memSenderKeyStore is a minimal in-memory libsignal SenderKey store used to
// drive a real group-cipher session in the test (libsignal v0.2.1 ships no
// in-memory implementation). It is NOT the production cache; it exists only to
// produce genuine post-ratchet structures and ciphertext.
type memSenderKeyStore struct {
	m map[string]*groupRecord.SenderKey
}

func newMemSenderKeyStore() *memSenderKeyStore {
	return &memSenderKeyStore{m: make(map[string]*groupRecord.SenderKey)}
}

func (s *memSenderKeyStore) StoreSenderKey(_ context.Context, name *protocol.SenderKeyName, rec *groupRecord.SenderKey) error {
	s.m[name.Sender().String()+"|"+name.GroupID()] = rec
	return nil
}

func (s *memSenderKeyStore) LoadSenderKey(_ context.Context, name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	if rec, ok := s.m[name.Sender().String()+"|"+name.GroupID()]; ok {
		return rec, nil
	}
	return groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState), nil
}

// roundTripped rebuilds a *SenderKey from a structure run through the flat codec.
func roundTripped(t *testing.T, structure *groupRecord.SenderKeyStructure) *groupRecord.SenderKey {
	t.Helper()
	f, ok := flatFromStructure(structure)
	if !ok {
		t.Fatal("flatFromStructure refused the post-ratchet structure")
	}
	rebuilt := flatToStructure(f)
	if rebuilt == nil {
		t.Fatal("flatToStructure returned nil for a valid structure")
	}
	rec, err := groupRecord.NewSenderKeyFromStruct(rebuilt, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	if err != nil {
		t.Fatalf("NewSenderKeyFromStruct(roundtripped): %v", err)
	}
	return rec
}

// decryptEquivalence is the shared core: given the receiver's post-ratchet
// structure and a ciphertext, decrypt it from (a) a record built directly from
// the structure and (b) a record built from the flat-round-tripped structure,
// asserting identical plaintext.
func decryptEquivalence(t *testing.T, name *protocol.SenderKeyName, structure *groupRecord.SenderKeyStructure, ciphertext *protocol.SenderKeyMessage, wantPlaintext []byte) {
	t.Helper()
	ctx := context.Background()

	direct, err := groupRecord.NewSenderKeyFromStruct(structure, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	if err != nil {
		t.Fatalf("NewSenderKeyFromStruct(direct): %v", err)
	}
	rt := roundTripped(t, structure)

	// GroupCipher.Decrypt mutates the message in place (cipher.DecryptCbc
	// decrypts the ciphertext buffer in place; the post-decrypt buffer holds
	// plaintext). Reusing the same *SenderKeyMessage across two decrypts would
	// make the second decrypt's signature verification run over the now-mutated
	// ciphertext and fail. Snapshot the pristine ciphertext/signature ONCE here
	// and rebuild a fresh message (with a fresh ciphertext buffer) per decrypt.
	// NewSenderKeyMessageFromStruct stores the provided signature verbatim (it
	// does NOT re-sign), so the original signature still verifies.
	keyID := ciphertext.KeyID()
	iter := ciphertext.Iteration()
	origCT := append([]byte(nil), ciphertext.Ciphertext()...)
	sig := ciphertext.Signature() // [64]byte value
	freshMsg := func() *protocol.SenderKeyMessage {
		m, mErr := protocol.NewSenderKeyMessageFromStruct(&protocol.SenderKeyMessageStructure{
			Version:    protocol.CurrentVersion,
			ID:         keyID,
			Iteration:  iter,
			CipherText: append([]byte(nil), origCT...),
			Signature:  sig[:],
		}, SignalProtobufSerializer.SenderKeyMessage)
		if mErr != nil {
			t.Fatalf("rebuild SenderKeyMessage: %v", mErr)
		}
		return m
	}

	decryptWith := func(label string, rec *groupRecord.SenderKey) []byte {
		st := newMemSenderKeyStore()
		_ = st.StoreSenderKey(ctx, name, rec)
		builder := groups.NewGroupSessionBuilder(st, SignalProtobufSerializer)
		cipher := groups.NewGroupCipher(builder, name, st)
		pt, decErr := cipher.Decrypt(ctx, freshMsg())
		if decErr != nil {
			t.Fatalf("Decrypt(%s): %v", label, decErr)
		}
		return pt
	}

	ptDirect := decryptWith("direct", direct)
	ptRT := decryptWith("roundtripped", rt)

	if string(ptDirect) != string(wantPlaintext) {
		t.Fatalf("direct decrypt plaintext mismatch: got %q want %q", ptDirect, wantPlaintext)
	}
	if string(ptRT) != string(ptDirect) {
		t.Fatalf("round-tripped decrypt differs from direct: got %q want %q", ptRT, ptDirect)
	}
}

// TestFlatSenderKeyDecryptEquivalenceZeroSkip builds a real group session,
// encrypts one message, and proves the flat-round-tripped receiver key decrypts
// it identically to the directly-built key. The receiver's key has a nil
// private (hasPriv=false) and zero skipped keys — the 83% common path.
func TestFlatSenderKeyDecryptEquivalenceZeroSkip(t *testing.T) {
	ctx := context.Background()
	groupID := "test-group"
	sender := protocol.NewSenderKeyName(groupID, protocol.NewSignalAddress("alice", 1))

	// Sender side: create the session and encrypt.
	senderStore := newMemSenderKeyStore()
	senderBuilder := groups.NewGroupSessionBuilder(senderStore, SignalProtobufSerializer)
	senderCipher := groups.NewGroupCipher(senderBuilder, sender, senderStore)
	skdm, err := senderBuilder.Create(ctx, sender)
	if err != nil {
		t.Fatalf("builder.Create: %v", err)
	}
	plaintext := []byte("hello group, zero-skip path")
	ct, err := senderCipher.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	skMsg := ct.(*protocol.SenderKeyMessage)

	// Receiver side: process the SKDM (creates a received key with nil private).
	recvStore := newMemSenderKeyStore()
	recvBuilder := groups.NewGroupSessionBuilder(recvStore, SignalProtobufSerializer)
	if err := recvBuilder.Process(ctx, sender, skdm); err != nil {
		t.Fatalf("builder.Process: %v", err)
	}
	recvRec, err := recvStore.LoadSenderKey(ctx, sender)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	structure := recvRec.Structure()

	// Sanity: this is the received-key (nil private) case.
	if structure.SenderKeyStates[0].SigningKeyPrivate != nil {
		t.Fatal("expected received key to have nil SigningKeyPrivate")
	}

	decryptEquivalence(t, sender, structure, skMsg, plaintext)
}

// TestFlatSenderKeyDecryptEquivalenceWithSkipped drives REAL out-of-order
// decryption so the receiver's state accumulates skipped message keys, then
// proves the flat-round-tripped key (carrying the packed skipped tail) decrypts
// an earlier (skipped) message identically to the directly-built key.
func TestFlatSenderKeyDecryptEquivalenceWithSkipped(t *testing.T) {
	ctx := context.Background()
	groupID := "test-group-skip"
	sender := protocol.NewSenderKeyName(groupID, protocol.NewSignalAddress("bob", 1))

	senderStore := newMemSenderKeyStore()
	senderBuilder := groups.NewGroupSessionBuilder(senderStore, SignalProtobufSerializer)
	senderCipher := groups.NewGroupCipher(senderBuilder, sender, senderStore)
	skdm, err := senderBuilder.Create(ctx, sender)
	if err != nil {
		t.Fatalf("builder.Create: %v", err)
	}

	// Encrypt several messages in order (iterations 0..4).
	const nMsgs = 5
	plaintexts := make([][]byte, nMsgs)
	ciphertexts := make([]*protocol.SenderKeyMessage, nMsgs)
	for i := 0; i < nMsgs; i++ {
		plaintexts[i] = []byte("msg " + string(rune('A'+i)))
		ct, encErr := senderCipher.Encrypt(ctx, plaintexts[i])
		if encErr != nil {
			t.Fatalf("Encrypt %d: %v", i, encErr)
		}
		ciphertexts[i] = ct.(*protocol.SenderKeyMessage)
	}

	// Receiver processes the SKDM, then decrypts the LAST message first. This
	// forces the ratchet forward and accumulates skipped keys for iterations
	// 0..nMsgs-2 in the receiver's state.
	recvStore := newMemSenderKeyStore()
	recvBuilder := groups.NewGroupSessionBuilder(recvStore, SignalProtobufSerializer)
	if err := recvBuilder.Process(ctx, sender, skdm); err != nil {
		t.Fatalf("builder.Process: %v", err)
	}
	recvCipher := groups.NewGroupCipher(recvBuilder, sender, recvStore)
	if _, err := recvCipher.Decrypt(ctx, ciphertexts[nMsgs-1]); err != nil {
		t.Fatalf("Decrypt(last): %v", err)
	}

	recvRec, err := recvStore.LoadSenderKey(ctx, sender)
	if err != nil {
		t.Fatalf("LoadSenderKey: %v", err)
	}
	structure := recvRec.Structure()

	// Sanity: skipped keys must now be present, and the flat form must carry them.
	totalSkipped := 0
	for _, st := range structure.SenderKeyStates {
		totalSkipped += len(st.Keys)
	}
	if totalSkipped == 0 {
		t.Fatal("expected accumulated skipped keys after out-of-order decrypt")
	}
	f, ok := flatFromStructure(structure)
	if !ok {
		t.Fatal("flatFromStructure refused the with-skipped structure")
	}
	if f.skipped == nil {
		t.Fatal("flat skipped tail is nil despite accumulated skipped keys")
	}

	// Decrypt an EARLIER (skipped) message from both the directly-built and the
	// flat-round-tripped key; both must yield identical plaintext. This is the
	// gate that proves the packed skipped tail carries byte-exact key material.
	decryptEquivalence(t, sender, structure, ciphertexts[0], plaintexts[0])
}
