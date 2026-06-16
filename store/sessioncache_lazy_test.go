// Copyright (c) 2026 Kavtov Platform Authors
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// sessioncache_lazy_test.go — Phase 38.4 current-only send-path decode.
//
// Proves the two safety properties:
//   1. Codec: UnpackFlatSessionCurrentOnly + raw-tail reassembly is byte-identical
//      to the original whole-blob (no archived state lost), for any nPrev.
//   2. Wiring: a fat session loaded current-only, marked dirty as the cipher does
//      (StoreSession → putCachedSession), and flushed is byte-identical to the
//      original — i.e. putCachedSession preserves the tail (the data-loss trap) and
//      Found stays true (the ErrNoSession/479 trap).

package store

import (
	"context"
	"reflect"
	"testing"
)

func TestUnpackFlatSessionCurrentOnlyRoundTrip(t *testing.T) {
	orig := makeSessionStructure(10, 3, 200, true, true)
	full, ok := PackFlatSession(orig)
	if !ok {
		t.Fatal("PackFlatSession refused fixture")
	}

	cur, tail, nPrev, err := UnpackFlatSessionCurrentOnly(full)
	if err != nil {
		t.Fatalf("UnpackFlatSessionCurrentOnly: %v", err)
	}
	if nPrev != 10 {
		t.Fatalf("nPrev=%d, want 10", nPrev)
	}
	if len(cur.PreviousStates) != 0 {
		t.Fatalf("current-only has %d previous states, want 0", len(cur.PreviousStates))
	}

	// Reassemble current + raw tail; must equal the original blob byte-for-byte.
	live, ok := PackFlatSession(cur) // [0x01][0][current]
	if !ok {
		t.Fatal("PackFlatSession refused current-only")
	}
	reassembled := append(append([]byte{}, live...), tail...)
	reassembled[1] = byte(len(cur.PreviousStates) + nPrev) // 10
	if !reflect.DeepEqual(reassembled, full) {
		t.Fatalf("reassembled (%d B) != original (%d B): tail re-attach not byte-identical", len(reassembled), len(full))
	}

	// And it still decodes to all 10 archived states (nothing lost).
	got, err := UnpackFlatSession(reassembled)
	if err != nil {
		t.Fatalf("UnpackFlatSession(reassembled): %v", err)
	}
	if len(got.PreviousStates) != 10 {
		t.Fatalf("decoded %d archived states, want 10", len(got.PreviousStates))
	}
}

func TestUnpackFlatSessionCurrentOnlyNoPrev(t *testing.T) {
	full, _ := PackFlatSession(makeSessionStructure(0, 2, 10, false, false))
	cur, tail, nPrev, err := UnpackFlatSessionCurrentOnly(full)
	if err != nil {
		t.Fatalf("UnpackFlatSessionCurrentOnly: %v", err)
	}
	if nPrev != 0 || len(tail) != 0 || len(cur.PreviousStates) != 0 {
		t.Fatalf("nPrev=%d tailLen=%d prev=%d, want 0/0/0", nPrev, len(tail), len(cur.PreviousStates))
	}
}

func TestLazySendPathRoundTrip(t *testing.T) {
	old := lazySessionDecode
	lazySessionDecode = true
	defer func() { lazySessionDecode = old }()

	// A live current state (real Curve25519 keys, so NewSessionFromStructure
	// accepts it) plus a synthetic archived tail. The lazy path never decodes the
	// tail, so opaque bytes correctly exercise the carry-through.
	addr, liveBlob := buildLiveFlatSession(t)
	addrStr := addr.String()
	fakeTail := []byte{0x11, 0x22, 0x33, 0x44, 0x55}
	fatBlob := append(append([]byte{}, liveBlob...), fakeTail...)
	fatBlob[1] = 2 // pretend 2 archived states (count is metadata for the lazy path)

	store := newConcurrentFakeSessionStore()
	store.data[addrStr] = append([]byte{}, fatBlob...)
	dev := &Device{Sessions: store}

	existing, ctx, err := dev.WithCachedSessions(context.Background(), []string{addrStr})
	if err != nil {
		t.Fatalf("WithCachedSessions: %v", err)
	}
	if !existing[addrStr] {
		t.Fatal("Found=false for a valid flat session — would short-circuit to ErrNoSession/479")
	}

	rec := getCachedSession(ctx, addrStr)
	if rec == nil {
		t.Fatal("no cached record after lazy load")
	}
	// Simulate the cipher's post-encrypt StoreSession; must preserve the lazy tail.
	if !putCachedSession(ctx, addrStr, rec) {
		t.Fatal("putCachedSession returned false")
	}
	if err := dev.PutCachedSessions(ctx); err != nil {
		t.Fatalf("PutCachedSessions: %v", err)
	}

	got := store.data[addrStr]
	if !reflect.DeepEqual(got, fatBlob) {
		t.Fatalf("lazy write-back not byte-identical: got %d B, want %d B — archived tail dropped?", len(got), len(fatBlob))
	}
}
