// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/libsignal/ecc"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"go.mau.fi/whatsmeow/util/keys"
)

func pairingTestClient(t *testing.T) (context.Context, *Client, *phonePairingOwner) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	cli := NewClient(&store.Device{IdentityKey: keys.NewKeyPair()}, nil)
	owner := newPhonePairingOwner(nil)
	go owner.run(ctx.Done())
	cli.phonePairing.Store(owner)
	t.Cleanup(func() { cancel(); <-owner.done })
	return ctx, cli, owner
}

func beginPairingTestAttempt(t *testing.T, ctx context.Context, owner *phonePairingOwner, ref string) *phonePairingAttempt {
	t.Helper()
	phone := "972500000001"
	if ref == "second-account" {
		phone = "972500000002"
	}
	attempt := &phonePairingAttempt{
		jid:         types.NewJID(phone, types.DefaultUserServer),
		keyPair:     keys.NewKeyPair(),
		linkingCode: "ABCD1234",
		ready:       make(chan struct{}),
	}
	if err := owner.begin(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	if err := owner.register(ctx, attempt, ref); err != nil {
		t.Fatal(err)
	}
	return attempt
}

func submitTestPhoneResponse(t *testing.T, ctx context.Context, cli *Client, attempt *phonePairingAttempt, ref string) []byte {
	t.Helper()
	notification := &waBinary.Node{
		Tag: "notification",
		Content: []waBinary.Node{{
			Tag:   "link_code_companion_reg",
			Attrs: waBinary.Attrs{"stage": "primary_hello"},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_ref", Content: []byte(ref)},
				{Tag: "link_code_pairing_wrapped_primary_ephemeral_pub", Content: wrapPrimaryPairingKey(attempt.linkingCode, keys.NewKeyPair().Pub[:])},
				{Tag: "primary_identity_pub", Content: keys.NewKeyPair().Pub[:]},
			},
		}},
	}
	if err := cli.handleCodePairNotification(ctx, notification); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected a reply and disconnected send, got %v", err)
	}
	secret, err := phonePairingDo(ctx, cli.phonePairing.Load(), func(s *phonePairingState) ([]byte, error) {
		return s.replies[len(s.replies)-1].secret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return secret
}

func signedPairingConfirmation(t *testing.T, cli *Client, secret []byte) []byte {
	t.Helper()
	details, err := proto.Marshal(&waAdv.ADVDeviceIdentity{})
	if err != nil {
		t.Fatal(err)
	}
	accountKey := keys.NewKeyPair()
	sig := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*accountKey.Priv), concatBytes(AdvAccountSignaturePrefix, details, cli.Store.IdentityKey.Pub[:]))
	identity, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentity{Details: details, AccountSignature: sig[:], AccountSignatureKey: accountKey.Pub[:]})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(identity)
	confirmed, err := proto.Marshal(&waAdv.ADVSignedDeviceIdentityHMAC{Details: identity, HMAC: mac.Sum(nil)})
	if err != nil {
		t.Fatal(err)
	}
	return confirmed
}

type pairingTestStore struct {
	store.NoopStore
	saves  atomic.Int32
	saved  []byte
	onSave func()
}

func (s *pairingTestStore) PutDevice(_ context.Context, device *store.Device) error {
	s.saves.Add(1)
	s.saved = bytes.Clone(device.AdvSecretKey)
	if s.onSave != nil {
		s.onSave()
	}
	return nil
}

func usePairingTestStore(cli *Client, onSave func()) *pairingTestStore {
	s := &pairingTestStore{onSave: onSave}
	cli.Store.Container = s
	cli.Store.Identities = s
	cli.Store.LIDs = s
	return s
}

func wrapPrimaryPairingKey(code string, publicKey []byte) []byte {
	wrapped := make([]byte, 80)
	key := pbkdf2.Key([]byte(code), wrapped[:32], 2<<16, 32, sha256.New)
	block, _ := aes.NewCipher(key)
	cipher.NewCTR(block, wrapped[32:48]).XORKeyStream(wrapped[48:], publicKey)
	return wrapped
}

func TestPhonePairingReplacedAndExpiredProofsAreIneligible(t *testing.T) {
	for _, mode := range []string{"replaced", "expired"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cli, owner := pairingTestClient(t)
			attempt := beginPairingTestAttempt(t, ctx, owner, "first-ref")
			firstSecret := submitTestPhoneResponse(t, ctx, cli, attempt, "first-ref")
			proof := signedPairingConfirmation(t, cli, firstSecret)
			if mode == "replaced" {
				attempt = beginPairingTestAttempt(t, ctx, owner, "second-ref")
				submitTestPhoneResponse(t, ctx, cli, attempt, "second-ref")
			} else {
				_, err := phonePairingDo(ctx, owner, func(s *phonePairingState) (struct{}, error) {
					s.expires = time.Now().Add(-time.Second)
					return struct{}{}, nil
				})
				if err != nil {
					t.Fatal(err)
				}
			}
			s := usePairingTestStore(cli, nil)
			if err := cli.handlePair(ctx, proof, "stale", "", "", attempt.jid, types.EmptyJID); !errors.Is(err, ErrPairInvalidDeviceIdentityHMAC) {
				t.Fatalf("stale confirmation should be rejected, got %v", err)
			}
			if s.saves.Load() != 0 {
				t.Fatal("stale confirmation saved a device")
			}
		})
	}
}

func TestPhonePairingCommitsOnlyOneConfirmationAndDoesNotBlockAnotherAccount(t *testing.T) {
	ctx, first, firstOwner := pairingTestClient(t)
	secondCtx, second, secondOwner := pairingTestClient(t)
	firstAttempt := beginPairingTestAttempt(t, ctx, firstOwner, "first-account")
	firstSecret := submitTestPhoneResponse(t, ctx, first, firstAttempt, "first-account")
	submitTestPhoneResponse(t, ctx, first, firstAttempt, "first-account")
	secondAttempt := beginPairingTestAttempt(t, secondCtx, secondOwner, "second-account")
	secondSecret := submitTestPhoneResponse(t, secondCtx, second, secondAttempt, "second-account")
	firstProof := signedPairingConfirmation(t, first, firstSecret)
	secondProof := signedPairingConfirmation(t, second, secondSecret)

	saving, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	firstStore := usePairingTestStore(first, func() { close(saving); <-release })
	secondStore := usePairingTestStore(second, nil)
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- first.handlePair(ctx, firstProof, "winner", "", "", firstAttempt.jid, types.EmptyJID)
	}()
	select {
	case <-saving:
	case err := <-firstDone:
		t.Fatalf("first confirmation failed before persistence: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("first confirmation did not reach persistence")
	}
	if err := first.handlePair(ctx, firstProof, "duplicate", "", "", firstAttempt.jid, types.EmptyJID); !errors.Is(err, errPhonePairingFinalizing) {
		t.Fatalf("concurrent duplicate confirmation: %v", err)
	}
	if err := second.handlePair(secondCtx, secondProof, "independent", "", "", secondAttempt.jid, types.EmptyJID); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("second account did not reach the final socket send: %v", err)
	}
	if firstStore.saves.Load() != 1 || !bytes.Equal(firstStore.saved, firstSecret) {
		t.Fatal("first account should save the first reply's secret exactly once")
	}
	if secondStore.saves.Load() != 1 || !bytes.Equal(secondStore.saved, secondSecret) {
		t.Fatal("second account should save its own secret independently")
	}
	checkLivePairingTestDispatch(t)
}

func checkLivePairingTestDispatch(t *testing.T) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	own := types.NewJID("972500000003", types.DefaultUserServer)
	peer := types.NewJID("972500000004", types.DefaultUserServer)
	cli := NewClient(&store.Device{ID: &own}, nil)
	cli.SynchronousAck = true
	messages := make(chan any, 2)
	cli.AddEventHandler(func(event any) { messages <- event })
	queue := make(chan *waBinary.Node, 2)
	done := make(chan struct{})
	go cli.handlerQueueLoop(ctx, ctx, queue, done)
	defer func() { cancel(); <-done }()

	text := "synthetic message"
	payload, err := proto.Marshal(&waE2E.Message{Conversation: &text})
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range []waBinary.Node{
		{
			Tag:     "message",
			Attrs:   waBinary.Attrs{"from": types.NewJID("972500000005", types.NewsletterServer), "id": "message", "t": "1700000000"},
			Content: []waBinary.Node{{Tag: "plaintext", Content: payload}},
		},
		{Tag: "receipt", Attrs: waBinary.Attrs{"from": peer, "id": "message", "t": "1700000000"}},
	} {
		frame, err := waBinary.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		cli.handleFrame(ctx, frame, queue)
	}
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for _, expectedTag := range []string{"message", "receipt"} {
		select {
		case event := <-messages:
			switch evt := event.(type) {
			case *events.Message:
				if expectedTag != "message" || evt.Message.GetConversation() != text {
					t.Fatalf("unexpected message event for %s", expectedTag)
				}
			case *events.Receipt:
				if expectedTag != "receipt" || len(evt.MessageIDs) != 1 || evt.MessageIDs[0] != "message" {
					t.Fatalf("unexpected receipt event for %s", expectedTag)
				}
			default:
				t.Fatalf("unexpected event type %T", event)
			}
		case <-timer.C:
			t.Fatalf("live client did not dispatch its %s while pairing was blocked", expectedTag)
		}
	}
}

func TestQRCodeRetainsIndependentSecretDuringPhonePairing(t *testing.T) {
	ctx, cli, owner := pairingTestClient(t)
	cli.Store.AdvSecretKey = bytes.Repeat([]byte{0x51}, 32)
	attempt := beginPairingTestAttempt(t, ctx, owner, "phone-ref")
	submitTestPhoneResponse(t, ctx, cli, attempt, "phone-ref")
	cli.rotateADVSecret(ctx)
	qrSecret, err := cli.devicePairingSecret(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := usePairingTestStore(cli, nil)
	if err := cli.handlePair(ctx, signedPairingConfirmation(t, cli, qrSecret), "qr", "", "", attempt.jid, types.EmptyJID); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("QR confirmation did not reach final send: %v", err)
	}
	if s.saves.Load() != 1 || !bytes.Equal(s.saved, qrSecret) {
		t.Fatal("QR pairing should persist its own secret")
	}
}

func TestPasskeyHandoffSupersedesPendingPhoneReply(t *testing.T) {
	ctx, cli, owner := pairingTestClient(t)
	attempt := beginPairingTestAttempt(t, ctx, owner, "phone-ref")
	phoneSecret := submitTestPhoneResponse(t, ctx, cli, attempt, "phone-ref")
	var passkeyRequested bool
	cli.AddEventHandler(func(event any) {
		_, passkeyRequested = event.(*events.PairPasskeyRequest)
	})
	cli.handlePasskeyNotification(ctx, &waBinary.Node{
		Tag: "notification", Attrs: waBinary.Attrs{"from": types.ServerJID},
		Content: []waBinary.Node{{Tag: "passkey_request_options", Content: []byte("{}")}},
	})
	handoff := cli.passkeyHandoffKey.Load()
	want := hkdfutil.SHA256(phoneSecret, nil, []byte("shortcake-passkey-handoff-v1"), 32)
	if !passkeyRequested || handoff == nil || !bytes.Equal(handoff.hmac, want) {
		t.Fatal("passkey handoff should use the pending phone secret")
	}
	passkeySecret, err := cli.devicePairingSecret(ctx)
	if err != nil {
		t.Fatal(err)
	}
	s := usePairingTestStore(cli, nil)
	if err := cli.handlePair(ctx, signedPairingConfirmation(t, cli, phoneSecret), "old phone", "", "", attempt.jid, types.EmptyJID); !errors.Is(err, errPhonePairingStaleProof) {
		t.Fatalf("old phone proof remained eligible after passkey handoff: %v", err)
	}
	if err := cli.handlePair(ctx, signedPairingConfirmation(t, cli, passkeySecret), "passkey", "", "", attempt.jid, types.EmptyJID); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("passkey confirmation did not reach final send: %v", err)
	}
	if s.saves.Load() != 1 || !bytes.Equal(s.saved, passkeySecret) {
		t.Fatal("passkey pairing should only persist the passkey secret")
	}
}

func TestPhonePairingRetransmissionPreservesConfirmationSecret(t *testing.T) {
	checkDelayedPhonePairingConfirmation(t, false)
}

func TestPhonePairingDifferentResponsePreservesEarlierConfirmation(t *testing.T) {
	checkDelayedPhonePairingConfirmation(t, true)
}

func checkDelayedPhonePairingConfirmation(t *testing.T, differentResponse bool) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	cli := NewClient(&store.Device{IdentityKey: keys.NewKeyPair()}, nil)
	owner := newPhonePairingOwner(nil)
	go owner.run(ctx.Done())
	cli.phonePairing.Store(owner)
	_, wrappedKey, code := generateCompanionEphemeralKey()
	attempt := &phonePairingAttempt{
		jid:         types.NewJID("972500000001", types.DefaultUserServer),
		keyPair:     keys.NewKeyPair(),
		linkingCode: code,
		ready:       make(chan struct{}),
	}
	if err := owner.begin(ctx, attempt); err != nil {
		t.Fatal(err)
	}
	if err := owner.register(ctx, attempt, "pairing-reference"); err != nil {
		t.Fatal(err)
	}
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
	if err := cli.handleCodePairNotification(ctx, notification); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("first notification: expected disconnected send, got %v", err)
	}
	// This is the HMAC the primary would compute from the first companion finish.
	// Invalid proto data stops the test before account signature checks or storage.
	details := []byte{0xff}
	if cli.Store.AdvSecretKey != nil {
		t.Fatal("preparing a reply persisted an unverified secret to the device")
	}
	firstSecret, err := phonePairingDo(ctx, owner, func(s *phonePairingState) ([]byte, error) {
		return s.replies[0].secret, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, firstSecret)
	mac.Write(details)
	identity := &waAdv.ADVSignedDeviceIdentityHMAC{
		Details: details,
		HMAC:    mac.Sum(nil),
	}
	confirmation, err := proto.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if differentResponse {
		// Wrap a different primary ephemeral public key using the same pairing code.
		notification.GetChildren()[0].GetChildren()[1].Content = wrapPrimaryPairingKey(code, keys.NewKeyPair().Pub[:])
	}
	if err := cli.handleCodePairNotification(ctx, notification); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("retransmission: expected disconnected send, got %v", err)
	}
	identity.HMAC[0] ^= 1
	tampered, err := proto.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.handlePair(ctx, tampered, "pair-success", "", "", types.EmptyJID, types.EmptyJID); !errors.Is(err, ErrPairInvalidDeviceIdentityHMAC) {
		t.Fatalf("tampered confirmation should fail authentication, got %v", err)
	}
	err = cli.handlePair(ctx, confirmation, "pair-success", "", "", types.EmptyJID, types.EmptyJID)
	var protoErr *PairProtoError
	if !errors.As(err, &protoErr) {
		t.Fatalf("pairing confirmation was rejected before device identity parsing: %v", err)
	}
	if cli.Store.AdvSecretKey != nil {
		t.Fatal("a malformed device identity installed a secret")
	}
	if err := cli.handlePair(ctx, confirmation, "pair-success", "", "", types.EmptyJID, types.EmptyJID); !errors.Is(err, errPhonePairingFinalizing) {
		t.Fatalf("duplicate confirmation should be ignored, got %v", err)
	}

	cli.paired.Store(true)
	if err := cli.handleCodePairNotification(ctx, notification); err != nil {
		t.Fatalf("late retransmission should be ignored after pairing, got %v", err)
	}
	if !cli.paired.Load() {
		t.Fatal("late retransmission cleared the completed pairing")
	}
}
