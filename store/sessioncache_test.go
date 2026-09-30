// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// sessioncache_test.go — regression test for the WithCachedSessions flat-read gap.
//
// Bug (where-response-479-flat-read): Phase 17.13 migrated whatsmeow_sessions to
// the flat-bytea codec (byte0=0x01) and converted the single-read path
// (LoadSession) and the write paths (StoreSession / PutCachedSessions), but the
// send-path prefetch WithCachedSessions still decoded with the old
// record.NewSessionFromBytes (JSON). Flat blobs failed that decode and the address
// was silently dropped from the per-context cache → Found=false → ContainsSession
// short-circuited to false → ErrNoSession → WhatsApp ack 479.
//
// Pre-fix: WithCachedSessions reports Found=false for a valid flat blob.
// Post-fix: Found=true and ContainsSession returns true.

package store

import (
	"context"
	"testing"

	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"

	"go.mau.fi/whatsmeow/types"
)

// flatSessionFakeStore is a minimal SessionStore that serves a fixed set of raw
// blobs from GetManySessions. Only the read methods used by WithCachedSessions
// and ContainsSession's DB fallback are exercised; the rest panic to catch
// unexpected calls.
type flatSessionFakeStore struct {
	blobs map[string][]byte
}

func (f *flatSessionFakeStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	return f.blobs[address], nil
}

func (f *flatSessionFakeStore) HasSession(ctx context.Context, address string) (bool, error) {
	_, ok := f.blobs[address]
	return ok, nil
}

func (f *flatSessionFakeStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	out := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		if b, ok := f.blobs[addr]; ok {
			out[addr] = b
		}
	}
	return out, nil
}

func (f *flatSessionFakeStore) PutSession(ctx context.Context, address string, session []byte) error {
	panic("not used in this test")
}

func (f *flatSessionFakeStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	panic("not used in this test")
}

func (f *flatSessionFakeStore) DeleteAllSessions(ctx context.Context, phone string) error {
	panic("not used in this test")
}

func (f *flatSessionFakeStore) DeleteSession(ctx context.Context, address string) error {
	panic("not used in this test")
}

func (f *flatSessionFakeStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	panic("not used in this test")
}

// buildLiveFlatSession establishes a real X3DH session between Alice and Bob
// (reusing the dmHarness from flat_session_test.go), exchanges one message so
// Bob holds a real post-X3DH *record.Session with valid Curve25519 keys, and
// returns the flat-codec encoding of Bob's session keyed by Alice's address.
// Synthetic fill-byte structures do not survive record.NewSessionFromStructure
// (DecodePoint rejects non-curve key bytes), so a live session is required to
// exercise the full read→record path inside WithCachedSessions.
func buildLiveFlatSession(t *testing.T) (addr *protocol.SignalAddress, flat []byte) {
	t.Helper()
	ctx := context.Background()

	alice := newDMHarness(t, "alice-sc", 1)
	bob := newDMHarness(t, "bob-sc", 2)

	aliceToBobBuilder := session.NewBuilder(
		alice.sessionStore, alice.preKeyStore, alice.signedPreKeyStore,
		alice.identityStore, bob.address, alice.serializer,
	)
	if err := aliceToBobBuilder.ProcessBundle(ctx, bobBundle(bob)); err != nil {
		t.Fatalf("ProcessBundle: %v", err)
	}
	bobFromAliceBuilder := session.NewBuilder(
		bob.sessionStore, bob.preKeyStore, bob.signedPreKeyStore,
		bob.identityStore, alice.address, bob.serializer,
	)

	msg0 := encryptDM(t, aliceToBobBuilder, bob.address, alice, []byte("session init"))
	decryptDM(t, bobFromAliceBuilder, alice.address, msg0)

	bobSess, err := bob.sessionStore.LoadSession(ctx, alice.address)
	if err != nil {
		t.Fatalf("LoadSession (setup): %v", err)
	}

	packed, ok := PackFlatSession(bobSess.Structure())
	if !ok {
		t.Fatal("PackFlatSession refused a valid live session structure")
	}
	if len(packed) == 0 || packed[0] != 0x01 {
		t.Fatalf("expected flat blob with byte0=0x01, got len=%d byte0=0x%02x", len(packed), firstByte(packed))
	}
	// Bob's session is keyed by Alice's address.
	return alice.address, packed
}

// TestWithCachedSessionsFlatReadRegression is the guard for where-response-479-flat-read.
// It seeds a valid flat session blob (byte0=0x01) for an address, runs it through
// the send-path prefetch WithCachedSessions, and asserts the address is present
// with Found=true and that ContainsSession returns true.
//
// On the pre-fix code (record.NewSessionFromBytes on flat bytes), the flat blob
// failed to deserialize and the address was dropped → Found=false → this test
// fails. On the fixed code it passes.
func TestWithCachedSessionsFlatReadRegression(t *testing.T) {
	addr, flat := buildLiveFlatSession(t)
	addrString := addr.String()

	device := &Device{
		Sessions: &flatSessionFakeStore{
			blobs: map[string][]byte{addrString: flat},
		},
	}

	ctx := context.Background()

	existing, ctx, err := device.WithCachedSessions(ctx, []string{addrString})
	if err != nil {
		t.Fatalf("WithCachedSessions returned error for a valid flat blob: %v", err)
	}

	// The regression assertion: the flat session must be recognized as present.
	if !existing[addrString] {
		t.Fatalf("WithCachedSessions reported Found=false for a valid flat session %q "+
			"(flat-read gap regression — send would hit ErrNoSession → WhatsApp 479)", addrString)
	}

	// And the cache must expose it as a usable record (not a freshly-minted empty one).
	if rec := getCachedSession(ctx, addrString); rec == nil {
		t.Fatalf("WithCachedSessions left no cached record for %q", addrString)
	}

	// ContainsSession reads the per-context cache first; it must report true.
	has, err := device.ContainsSession(ctx, addr)
	if err != nil {
		t.Fatalf("ContainsSession returned error: %v", err)
	}
	if !has {
		t.Fatalf("ContainsSession reported false for a cached flat session %q "+
			"(this is the exact short-circuit that produced ErrNoSession → 479)", addrString)
	}
}

// TestWithCachedSessionsRejectsNonFlatBlob asserts the fix surfaces a non-flat /
// corrupt blob loudly (wrapped error) instead of silently dropping the address.
// Silently dropping is the original bug's failure mode; a future codec mismatch
// must fail visibly rather than reproduce a 479.
func TestWithCachedSessionsRejectsNonFlatBlob(t *testing.T) {
	addr := protocol.NewSignalAddress("260821116530796_1", 0)
	addrString := addr.String()

	// A JSON-shaped blob (byte0='{' = 0x7b) — the format the read path no longer accepts.
	device := &Device{
		Sessions: &flatSessionFakeStore{
			blobs: map[string][]byte{addrString: []byte("{not-flat}")},
		},
	}

	_, _, err := device.WithCachedSessions(context.Background(), []string{addrString})
	if err == nil {
		t.Fatal("WithCachedSessions silently accepted a non-flat blob; it must return a loud error")
	}
}

func firstByte(b []byte) byte {
	if len(b) == 0 {
		return 0
	}
	return b[0]
}
