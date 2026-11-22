// Copyright (c) 2023 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"go.mau.fi/util/random"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/pbkdf2"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/hkdfutil"
	"go.mau.fi/whatsmeow/util/keys"
)

// PairClientType is the type of client to use with PairCode.
// The type is automatically filled based on store.DeviceProps.PlatformType (which is what QR login uses).
type PairClientType string

const (
	PairClientUnknown        PairClientType = "0"
	PairClientChrome         PairClientType = "1"
	PairClientEdge           PairClientType = "2"
	PairClientFirefox        PairClientType = "3"
	PairClientIE             PairClientType = "4"
	PairClientOpera          PairClientType = "5"
	PairClientSafari         PairClientType = "6"
	PairClientElectron       PairClientType = "7"
	PairClientUWP            PairClientType = "8"
	PairClientOtherWebClient PairClientType = "9"
	PairClientMacOS          PairClientType = "c"
	PairClientAndroid        PairClientType = "e"
)

var notNumbers = regexp.MustCompile("[^0-9]")
var linkingBase32 = base32.NewEncoding("123456789ABCDEFGHJKLMNPQRSTVWXYZ")

type phonePairFinish struct {
	wrappedPrimaryHash  [sha256.Size]byte
	primaryIdentityHash [sha256.Size]byte
	wrappedKeyBundle    []byte
	secret              []byte
}

func generateCompanionEphemeralKey() (ephemeralKeyPair *keys.KeyPair, ephemeralKey []byte, encodedLinkingCode string) {
	ephemeralKeyPair = keys.NewKeyPair()
	salt := random.Bytes(32)
	iv := random.Bytes(16)
	linkingCode := random.Bytes(5)
	encodedLinkingCode = linkingBase32.EncodeToString(linkingCode)
	linkCodeKey := pbkdf2.Key([]byte(encodedLinkingCode), salt, 2<<16, 32, sha256.New)
	linkCipherBlock, _ := aes.NewCipher(linkCodeKey)
	encryptedPubkey := ephemeralKeyPair.Pub[:]
	cipher.NewCTR(linkCipherBlock, iv).XORKeyStream(encryptedPubkey, encryptedPubkey)
	ephemeralKey = make([]byte, 80)
	copy(ephemeralKey[0:32], salt)
	copy(ephemeralKey[32:48], iv)
	copy(ephemeralKey[48:80], encryptedPubkey)
	return
}

// PairPhone generates a pairing code that can be used to link to a phone without scanning a QR code.
//
// You must connect the client normally before calling this (which means you'll also receive a QR code
// event, but that can be ignored when doing code pairing). You should also wait for `*events.QR` before
// calling this to ensure the connection is fully established. If using [Client.GetQRChannel], wait for
// the first item in the channel. Alternatively, sleeping for a second after calling Connect will probably work too.
//
// The exact expiry of pairing codes is unknown, but QR codes are always generated and the login websocket is closed
// after the QR codes run out, which means there's a 160-second time limit. It is recommended to generate the pairing
// code immediately after connecting to the websocket to have the maximum time.
//
// The clientType parameter must be one of the PairClient* constants, but which one doesn't matter.
// The client display name must be formatted as `Browser (OS)`, and only common browsers/OSes are allowed
// (the server will validate it and return 400 if it's wrong).
//
// See https://faq.whatsapp.com/1324084875126592 for more info
func (cli *Client) PairPhone(ctx context.Context, phone string, showPushNotification bool, clientType PairClientType, clientDisplayName string) (string, error) {
	if cli == nil {
		return "", ErrClientIsNil
	}
	phone = notNumbers.ReplaceAllString(phone, "")
	if len(phone) <= 6 {
		return "", ErrPhoneNumberTooShort
	} else if strings.HasPrefix(phone, "0") {
		return "", ErrPhoneNumberIsNotInternational
	}
	owner := cli.phonePairing.Load()
	if owner == nil {
		return "", ErrNotConnected
	}
	ephemeralKeyPair, ephemeralKey, encodedLinkingCode := generateCompanionEphemeralKey()
	attempt := &phonePairingAttempt{
		jid:         types.NewJID(phone, types.DefaultUserServer),
		keyPair:     ephemeralKeyPair,
		linkingCode: encodedLinkingCode,
		ready:       make(chan struct{}),
	}
	if err := owner.begin(ctx, attempt); err != nil {
		return "", err
	}
	registered := false
	defer func() {
		if !registered {
			owner.abandon(context.WithoutCancel(ctx), attempt)
		}
	}()
	resp, err := cli.sendIQ(ctx, infoQuery{
		Namespace:     "md",
		Type:          iqSet,
		To:            types.ServerJID,
		NoRetry:       true,
		pairingSocket: owner.socket,
		Content: []waBinary.Node{{
			Tag: "link_code_companion_reg",
			Attrs: waBinary.Attrs{
				"jid":   attempt.jid,
				"stage": "companion_hello",

				"should_show_push_notification": strconv.FormatBool(showPushNotification),
			},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_wrapped_companion_ephemeral_pub", Content: ephemeralKey},
				{Tag: "companion_server_auth_key_pub", Content: cli.Store.NoiseKey.Pub[:]},
				{Tag: "companion_platform_id", Content: string(clientType)},
				{Tag: "companion_platform_display", Content: clientDisplayName},
				{Tag: "link_code_pairing_nonce", Content: []byte{0}},
			},
		}},
	})
	if err != nil {
		return "", err
	}
	pairingRefNode, ok := resp.GetOptionalChildByTag("link_code_companion_reg", "link_code_pairing_ref")
	if !ok {
		return "", &ElementMissingError{Tag: "link_code_pairing_ref", In: "code link registration response"}
	}
	pairingRef, ok := pairingRefNode.Content.([]byte)
	if !ok {
		return "", fmt.Errorf("unexpected type %T in content of link_code_pairing_ref tag", pairingRefNode.Content)
	}
	if len(pairingRef) == 0 {
		return "", fmt.Errorf("empty link_code_pairing_ref in code link registration response")
	}
	if err = owner.register(ctx, attempt, string(pairingRef)); err != nil {
		return "", err
	}
	registered = true
	return encodedLinkingCode[0:4] + "-" + encodedLinkingCode[4:], nil
}

func (cli *Client) tryHandleCodePairNotification(ctx context.Context, parentNode *waBinary.Node) {
	err := cli.handleCodePairNotification(ctx, parentNode)
	if err != nil {
		cli.Log.Errorf("Failed to handle code pair notification: %s", err)
	}
}

func (cli *Client) handleCodePairNotification(ctx context.Context, parentNode *waBinary.Node) error {
	node, ok := parentNode.GetOptionalChildByTag("link_code_companion_reg")
	if !ok {
		return &ElementMissingError{
			Tag: "link_code_companion_reg",
			In:  "notification",
		}
	}
	if cli.paired.Load() {
		return nil
	}
	owner := cli.phonePairing.Load()
	if owner == nil {
		return fmt.Errorf("received code pair notification without a pending pairing")
	}
	linkCodePairingRef, _ := node.GetChildByTag("link_code_pairing_ref").Content.([]byte)
	wrappedPrimaryEphemeralPub, ok := node.GetChildByTag("link_code_pairing_wrapped_primary_ephemeral_pub").Content.([]byte)
	if !ok {
		return &ElementMissingError{
			Tag: "link_code_pairing_wrapped_primary_ephemeral_pub",
			In:  "notification",
		}
	} else if len(wrappedPrimaryEphemeralPub) < 80 {
		return fmt.Errorf("unexpected length of link_code_pairing_wrapped_primary_ephemeral_pub: %d", len(wrappedPrimaryEphemeralPub))
	}
	primaryIdentityPub, ok := node.GetChildByTag("primary_identity_pub").Content.([]byte)
	if !ok {
		return &ElementMissingError{
			Tag: "primary_identity_pub",
			In:  "notification",
		}
	}
	if len(primaryIdentityPub) != curve25519.PointSize {
		return fmt.Errorf("unexpected length of primary_identity_pub: %d", len(primaryIdentityPub))
	}

	attempt, err := phonePairingDo(ctx, owner, func(s *phonePairingState) (*phonePairingAttempt, error) {
		if s.finalizing || s.attempt == nil {
			return nil, errPhonePairingReplaced
		}
		if s.ref == "" {
			if s.waiting == maxPhonePairingReplies {
				return nil, fmt.Errorf("too many notifications waiting for phone pairing registration")
			}
			s.waiting++
		}
		return s.attempt, nil
	})
	if err != nil {
		return err
	}
	// The socket can deliver a notification before the PairPhone caller has
	// published the registration response. Wait outside the state owner.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-owner.done:
		return ErrNotConnected
	case <-attempt.ready:
	}
	wrappedKeyBundle, err := phonePairingDo(ctx, owner, func(s *phonePairingState) ([]byte, error) {
		if s.attempt != attempt || s.finalizing {
			return nil, errPhonePairingReplaced
		}
		if string(linkCodePairingRef) != s.ref {
			return nil, fmt.Errorf("pairing ref mismatch in code pair notification")
		}
		return cli.preparePhonePairFinish(s, wrappedPrimaryEphemeralPub, primaryIdentityPub)
	})
	if err != nil {
		return err
	}
	_, err = cli.sendIQ(ctx, infoQuery{
		Namespace:     "md",
		Type:          iqSet,
		To:            types.ServerJID,
		NoRetry:       true,
		pairingSocket: owner.socket,
		Content: []waBinary.Node{{
			Tag: "link_code_companion_reg",
			Attrs: waBinary.Attrs{
				"jid":   attempt.jid,
				"stage": "companion_finish",
			},
			Content: []waBinary.Node{
				{Tag: "link_code_pairing_wrapped_key_bundle", Content: wrappedKeyBundle},
				{Tag: "companion_identity_public", Content: cli.Store.IdentityKey.Pub[:]},
				{Tag: "link_code_pairing_ref", Content: linkCodePairingRef},
			},
		}},
	})
	return err
}

func (cli *Client) preparePhonePairFinish(state *phonePairingState, wrappedPrimaryEphemeralPub, primaryIdentityPub []byte) ([]byte, error) {
	wrappedPrimaryHash := sha256.Sum256(wrappedPrimaryEphemeralPub[:80])
	primaryIdentityHash := sha256.Sum256(primaryIdentityPub)
	for _, reply := range state.replies {
		if reply.wrappedPrimaryHash == wrappedPrimaryHash && reply.primaryIdentityHash == primaryIdentityHash {
			return reply.wrappedKeyBundle, nil
		}
	}
	if len(state.replies) == maxPhonePairingReplies {
		return nil, fmt.Errorf("too many distinct replies for the active phone pairing")
	}
	attempt := state.attempt

	advSecretRandom := random.Bytes(32)
	keyBundleSalt := random.Bytes(32)
	keyBundleNonce := random.Bytes(12)

	// Decrypt the primary device's ephemeral public key, which was encrypted with the 8-character pairing code,
	// then compute the DH shared secret using our ephemeral private key we generated earlier.
	primarySalt := wrappedPrimaryEphemeralPub[0:32]
	primaryIV := wrappedPrimaryEphemeralPub[32:48]
	primaryEncryptedPubkey := wrappedPrimaryEphemeralPub[48:80]
	linkCodeKey := pbkdf2.Key([]byte(attempt.linkingCode), primarySalt, 2<<16, 32, sha256.New)
	linkCipherBlock, err := aes.NewCipher(linkCodeKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create link cipher: %w", err)
	}
	primaryDecryptedPubkey := make([]byte, 32)
	cipher.NewCTR(linkCipherBlock, primaryIV).XORKeyStream(primaryDecryptedPubkey, primaryEncryptedPubkey)
	ephemeralSharedSecret, err := curve25519.X25519(attempt.keyPair.Priv[:], primaryDecryptedPubkey)
	if err != nil {
		return nil, fmt.Errorf("failed to compute ephemeral shared secret: %w", err)
	}

	// Encrypt and wrap key bundle containing our identity key, the primary device's identity key and the randomness used for the adv key.
	keyBundleEncryptionKey := hkdfutil.SHA256(ephemeralSharedSecret, keyBundleSalt, []byte("link_code_pairing_key_bundle_encryption_key"), 32)
	keyBundleCipherBlock, err := aes.NewCipher(keyBundleEncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create key bundle cipher: %w", err)
	}
	keyBundleGCM, err := cipher.NewGCM(keyBundleCipherBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create key bundle GCM: %w", err)
	}
	plaintextKeyBundle := concatBytes(cli.Store.IdentityKey.Pub[:], primaryIdentityPub, advSecretRandom)
	encryptedKeyBundle := keyBundleGCM.Seal(nil, keyBundleNonce, plaintextKeyBundle, nil)
	wrappedKeyBundle := concatBytes(keyBundleSalt, keyBundleNonce, encryptedKeyBundle)

	// Compute the adv secret key (which is used to authenticate the pair-success event later)
	identitySharedKey, err := curve25519.X25519(cli.Store.IdentityKey.Priv[:], primaryIdentityPub)
	if err != nil {
		return nil, fmt.Errorf("failed to compute identity shared key: %w", err)
	}
	advSecretInput := append(append(ephemeralSharedSecret, identitySharedKey...), advSecretRandom...)
	advSecret := hkdfutil.SHA256(advSecretInput, nil, []byte("adv_secret"), 32)
	state.replies = append(state.replies, phonePairFinish{
		wrappedPrimaryHash:  wrappedPrimaryHash,
		primaryIdentityHash: primaryIdentityHash,
		wrappedKeyBundle:    wrappedKeyBundle,
		secret:              advSecret,
	})
	return wrappedKeyBundle, nil
}
