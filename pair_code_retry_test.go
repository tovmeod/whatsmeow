// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

func TestPhonePairingRetransmissionPreservesConfirmationSecret(t *testing.T) {
	cli := NewClient(&store.Device{IdentityKey: keys.NewKeyPair()}, nil)
	_, wrappedKey, code := generateCompanionEphemeralKey()
	cli.phoneLinkingCache.Store(&phoneLinkingCache{
		jid:         types.NewJID("972500000001", types.DefaultUserServer),
		keyPair:     keys.NewKeyPair(),
		linkingCode: code,
		pairingRef:  "pairing-reference",
	})
	notification := &waBinary.Node{
		Tag: "notification",
		Content: []waBinary.Node{{
			Tag:   "link_code_companion_reg",
			Attrs: waBinary.Attrs{"stage": "primary_hello"},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_ref", Content: []byte("pairing-reference")},
				{Tag: "link_code_pairing_wrapped_primary_ephemeral_pub", Content: wrappedKey},
				{Tag: "primary_identity_pub", Content: keys.NewKeyPair().Pub[:]},
			},
		}},
	}
	ctx := context.Background()
	if err := cli.handleCodePairNotification(ctx, notification); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("first notification: expected disconnected send, got %v", err)
	}
	// This is the HMAC the primary would compute from the first companion finish.
	// Invalid proto data stops the test before account signature checks or storage.
	details := []byte{0xff}
	mac := hmac.New(sha256.New, cli.Store.AdvSecretKey)
	mac.Write(details)
	identity := &waAdv.ADVSignedDeviceIdentityHMAC{
		Details: details,
		HMAC:    mac.Sum(nil),
	}
	confirmation, err := proto.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.handleCodePairNotification(ctx, notification); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("retransmission: expected disconnected send, got %v", err)
	}
	err = cli.handlePair(ctx, confirmation, "pair-success", "", "", types.EmptyJID, types.EmptyJID)
	var protoErr *PairProtoError
	if !errors.As(err, &protoErr) {
		t.Fatalf("pairing confirmation was rejected before device identity parsing: %v", err)
	}
	identity.HMAC[0] ^= 1
	tampered, err := proto.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.handlePair(ctx, tampered, "pair-success", "", "", types.EmptyJID, types.EmptyJID); !errors.Is(err, ErrPairInvalidDeviceIdentityHMAC) {
		t.Fatalf("tampered confirmation should fail authentication, got %v", err)
	}

	cli.paired.Store(true)
	if err := cli.handleCodePairNotification(ctx, notification); err != nil {
		t.Fatalf("late retransmission should be ignored after pairing, got %v", err)
	}
	if !cli.paired.Load() {
		t.Fatal("late retransmission cleared the completed pairing")
	}
}
