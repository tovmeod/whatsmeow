// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/util/random"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waCompanionReg"
	"go.mau.fi/whatsmeow/proto/waWa6"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
)

var (
	AdvAccountSignaturePrefix = []byte{6, 0}
	AdvDeviceSignaturePrefix  = []byte{6, 1}

	AdvHostedAccountSignaturePrefix = []byte{6, 5}
	AdvHostedDeviceSignaturePrefix  = []byte{6, 6}
)

func (cli *Client) handleIQ(ctx context.Context, node *waBinary.Node) {
	children := node.GetChildren()
	if len(children) != 1 || node.Attrs["from"] != types.ServerJID {
		return
	}
	switch children[0].Tag {
	case "pair-device":
		cli.handlePairDevice(ctx, node)
	case "pair-success":
		cli.handlePairSuccess(ctx, node)
	}
}

func (cli *Client) handlePairDevice(ctx context.Context, node *waBinary.Node) {
	pairDevice := node.GetChildByTag("pair-device")
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   node.Attrs["from"],
			"id":   node.Attrs["id"],
			"type": "result",
		},
	})
	if err != nil {
		cli.Log.Warnf("Failed to send acknowledgement for pair-device request: %v", err)
	}

	evt := &events.QR{Codes: make([]string, 0, len(pairDevice.GetChildren()))}
	for i, child := range pairDevice.GetChildren() {
		if child.Tag != "ref" {
			cli.Log.Warnf("pair-device node contains unexpected child tag %s at index %d", child.Tag, i)
			continue
		}
		content, ok := child.Content.([]byte)
		if !ok {
			cli.Log.Warnf("pair-device node contains unexpected child content type %T at index %d", child, i)
			continue
		}
		if code := cli.makeQRData(content, cli.getQRClientType()); code != "" {
			evt.Codes = append(evt.Codes, code)
		}
	}

	cli.dispatchEvent(evt)
}

func (cli *Client) rotateADVSecret(ctx context.Context) {
	var oldSecret, newSecret []byte
	if !cli.updatePairingSecret(ctx, false, func(current []byte) {
		oldSecret = current
		newSecret = random.Bytes(32)
		cli.Store.AdvSecretKey = newSecret
	}) {
		return
	}
	cli.dispatchEvent(&events.RotateADVSecret{
		OldSecret: base64.StdEncoding.EncodeToString(oldSecret),
		NewSecret: base64.StdEncoding.EncodeToString(newSecret),
	})
}

func (cli *Client) getQRClientType() PairClientType {
	if cli.QRClientType != "" {
		return cli.QRClientType
	}
	switch store.DeviceProps.GetPlatformType() {
	case waCompanionReg.DeviceProps_CHROME:
		return PairClientChrome
	case waCompanionReg.DeviceProps_FIREFOX:
		return PairClientFirefox
	case waCompanionReg.DeviceProps_EDGE:
		return PairClientEdge
	case waCompanionReg.DeviceProps_IE:
		return PairClientIE
	case waCompanionReg.DeviceProps_OPERA:
		return PairClientOpera
	case waCompanionReg.DeviceProps_SAFARI:
		return PairClientSafari
	case waCompanionReg.DeviceProps_UWP:
		return PairClientUWP
	case waCompanionReg.DeviceProps_ANDROID_PHONE:
		return PairClientAndroid
	}
	switch store.BaseClientPayload.UserAgent.GetPlatform() {
	case waWa6.ClientPayload_UserAgent_WEB:
		return PairClientOtherWebClient
	case waWa6.ClientPayload_UserAgent_MACOS:
		return PairClientMacOS
	default:
		return PairClientUnknown
	}
}

func (cli *Client) makeQRData(ref []byte, clientType PairClientType) string {
	secret, err := cli.devicePairingSecret(cli.BackgroundEventCtx)
	if err != nil {
		return ""
	}
	noise := base64.StdEncoding.EncodeToString(cli.Store.NoiseKey.Pub[:])
	identity := base64.StdEncoding.EncodeToString(cli.Store.IdentityKey.Pub[:])
	adv := base64.StdEncoding.EncodeToString(secret)
	return fmt.Sprintf("https://wa.me/settings/linked_devices#%s,%s,%s,%s,%s", ref, noise, identity, adv, clientType)
}

func (cli *Client) handlePairSuccess(ctx context.Context, node *waBinary.Node) {
	cli.serverTimeOffset.Store(int64(node.AttrGetter().UnixTime("t").Sub(time.Now().Round(time.Second))))
	id := node.Attrs["id"].(string)
	pairSuccess := node.GetChildByTag("pair-success")

	deviceIdentityBytes, _ := pairSuccess.GetChildByTag("device-identity").Content.([]byte)
	businessName, _ := pairSuccess.GetChildByTag("biz").Attrs["name"].(string)
	jid, _ := pairSuccess.GetChildByTag("device").Attrs["jid"].(types.JID)
	lid, _ := pairSuccess.GetChildByTag("device").Attrs["lid"].(types.JID)
	platform, _ := pairSuccess.GetChildByTag("platform").Attrs["name"].(string)
	clientPropsBytes, _ := pairSuccess.GetChildByTag("client-props").Content.([]byte)
	var props waCompanionReg.ClientPairingProps
	if err := proto.Unmarshal(clientPropsBytes, &props); err != nil {
		cli.Log.Warnf("Failed to parse client pairing props: %v", err)
	}

	owner := cli.phonePairing.Load()
	// Reserve the reply in receive order before starting a worker. A later
	// passkey handoff or retry must not overtake this confirmation.
	identity, secret, claimErr := cli.authenticatePairConfirmation(ctx, owner, deviceIdentityBytes)
	cli.runAsyncProtocol(func() {
		err := cli.completePair(ctx, owner, identity, secret, claimErr, id, businessName, platform, jid, lid)
		if errors.Is(err, errPhonePairingFinalizing) || errors.Is(err, errPhonePairingStaleProof) || errors.Is(err, ErrNotConnected) {
			return
		}
		if err != nil {
			cli.Log.Errorf("Failed to pair device: %v", err)
			cli.Disconnect()
			cli.dispatchEvent(&events.PairError{ID: jid, LID: lid, BusinessName: businessName, Platform: platform, Props: &props, Error: err})
		} else {
			cli.Log.Infof("Successfully paired %s", cli.Store.ID)
			go cli.sendUnifiedSession()
			cli.dispatchEvent(&events.PairSuccess{ID: jid, LID: lid, BusinessName: businessName, Platform: platform, Props: &props})
		}
	})
}

func (cli *Client) handlePair(ctx context.Context, deviceIdentityBytes []byte, reqID, businessName, platform string, jid, lid types.JID) error {
	owner := cli.phonePairing.Load()
	identity, secret, err := cli.authenticatePairConfirmation(ctx, owner, deviceIdentityBytes)
	return cli.completePair(ctx, owner, identity, secret, err, reqID, businessName, platform, jid, lid)
}

func validPairingHMAC(identity *waAdv.ADVSignedDeviceIdentityHMAC, secret []byte) bool {
	h := hmac.New(sha256.New, secret)
	if identity.GetAccountType() == waAdv.ADVEncryptionType_HOSTED {
		h.Write(AdvHostedAccountSignaturePrefix)
	}
	h.Write(identity.Details)
	return hmac.Equal(h.Sum(nil), identity.HMAC)
}

func (cli *Client) authenticatePairConfirmation(ctx context.Context, owner *phonePairingOwner, data []byte) (*waAdv.ADVSignedDeviceIdentityHMAC, []byte, error) {
	identity := &waAdv.ADVSignedDeviceIdentityHMAC{}
	var parseErr error
	if err := proto.Unmarshal(data, identity); err != nil {
		parseErr = &PairProtoError{"failed to parse device identity container in pair success message", err}
	}
	secret, err := cli.claimPairingSecret(ctx, owner, identity, parseErr)
	return identity, secret, err
}

func (cli *Client) completePair(ctx context.Context, owner *phonePairingOwner, deviceIdentityContainer *waAdv.ADVSignedDeviceIdentityHMAC, secret []byte, claimErr error, reqID, businessName, platform string, jid, lid types.JID) error {
	if claimErr != nil {
		var malformed *PairProtoError
		if errors.Is(claimErr, ErrPairInvalidDeviceIdentityHMAC) {
			cli.Log.Warnf("Invalid HMAC from pair success message")
			cli.sendPairError(ctx, reqID, 401, "hmac-mismatch")
		} else if errors.As(claimErr, &malformed) {
			cli.sendPairError(ctx, reqID, 500, "internal-error")
		}
		return claimErr
	}

	var deviceIdentity waAdv.ADVSignedDeviceIdentity
	err := proto.Unmarshal(deviceIdentityContainer.Details, &deviceIdentity)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to parse signed device identity in pair success message", err}
	}

	var deviceIdentityDetails waAdv.ADVDeviceIdentity
	err = proto.Unmarshal(deviceIdentity.Details, &deviceIdentityDetails)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to parse device identity details in pair success message", err}
	}

	if !verifyAccountSignature(&deviceIdentity, cli.Store.IdentityKey, deviceIdentityDetails.GetDeviceType() == waAdv.ADVEncryptionType_HOSTED) {
		cli.sendPairError(ctx, reqID, 401, "signature-mismatch")
		return ErrPairInvalidDeviceSignature
	}

	deviceIdentity.DeviceSignature = generateDeviceSignature(&deviceIdentity, cli.Store.IdentityKey)[:]

	if cli.PrePairCallback != nil && !cli.PrePairCallback(jid, platform, businessName) {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return ErrPairRejectedLocally
	}

	mainDeviceLID := lid
	mainDeviceLID.Device = 0
	mainDeviceIdentity := *(*[32]byte)(deviceIdentity.AccountSignatureKey)
	deviceIdentity.AccountSignatureKey = nil

	selfSignedDeviceIdentity, err := proto.Marshal(&deviceIdentity)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairProtoError{"failed to marshal self-signed device identity", err}
	}

	if owner != nil {
		_, err = phonePairingDo(ctx, owner, func(s *phonePairingState) (struct{}, error) {
			cli.Store.AdvSecretKey = secret
			s.reset()
			return struct{}{}, nil
		})
		if err != nil {
			return err
		}
	}
	cli.Store.Account = proto.Clone(&deviceIdentity).(*waAdv.ADVSignedDeviceIdentity)
	cli.Store.ID = &jid
	cli.Store.LID = lid
	cli.Store.BusinessName = businessName
	cli.Store.Platform = platform
	err = cli.Store.Save(ctx)
	if err != nil {
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairDatabaseError{"failed to save device store", err}
	}
	cli.StoreLIDPNMapping(ctx, lid, jid)
	err = cli.Store.Identities.PutIdentity(ctx, mainDeviceLID.SignalAddress().String(), mainDeviceIdentity)
	if err != nil {
		_ = cli.Store.Delete(ctx)
		cli.sendPairError(ctx, reqID, 500, "internal-error")
		return &PairDatabaseError{"failed to store main device identity", err}
	}

	// Expect a disconnect after this and don't dispatch the usual Disconnected event
	cli.expectDisconnect()
	cli.paired.Store(true)

	err = cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   types.ServerJID,
			"type": "result",
			"id":   reqID,
		},
		Content: []waBinary.Node{{
			Tag: "pair-device-sign",
			Content: []waBinary.Node{{
				Tag: "device-identity",
				Attrs: waBinary.Attrs{
					"key-index": deviceIdentityDetails.GetKeyIndex(),
				},
				Content: selfSignedDeviceIdentity,
			}},
		}},
	})
	if err != nil {
		_ = cli.Store.Delete(ctx)
		return fmt.Errorf("failed to send pairing confirmation: %w", err)
	}
	return nil
}

func concatBytes(data ...[]byte) []byte {
	length := 0
	for _, item := range data {
		length += len(item)
	}
	output := make([]byte, length)
	ptr := 0
	for _, item := range data {
		ptr += copy(output[ptr:ptr+len(item)], item)
	}
	return output
}

func verifyAccountSignature(deviceIdentity *waAdv.ADVSignedDeviceIdentity, ikp *keys.KeyPair, isHosted bool) bool {
	if len(deviceIdentity.AccountSignatureKey) != 32 || len(deviceIdentity.AccountSignature) != 64 {
		return false
	}

	signatureKey := ecc.NewDjbECPublicKey(*(*[32]byte)(deviceIdentity.AccountSignatureKey))
	signature := *(*[64]byte)(deviceIdentity.AccountSignature)

	prefix := AdvAccountSignaturePrefix
	if isHosted {
		prefix = AdvHostedAccountSignaturePrefix
	}
	message := concatBytes(prefix, deviceIdentity.Details, ikp.Pub[:])

	return ecc.VerifySignature(signatureKey, message, signature)
}

func generateDeviceSignature(deviceIdentity *waAdv.ADVSignedDeviceIdentity, ikp *keys.KeyPair) *[64]byte {
	prefix := AdvDeviceSignaturePrefix
	message := concatBytes(prefix, deviceIdentity.Details, ikp.Pub[:], deviceIdentity.AccountSignatureKey)
	sig := ecc.CalculateSignature(ecc.NewDjbECPrivateKey(*ikp.Priv), message)
	return &sig
}

func (cli *Client) sendPairError(ctx context.Context, id string, code int, text string) {
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "iq",
		Attrs: waBinary.Attrs{
			"to":   types.ServerJID,
			"type": "error",
			"id":   id,
		},
		Content: []waBinary.Node{{
			Tag: "error",
			Attrs: waBinary.Attrs{
				"code": code,
				"text": text,
			},
		}},
	})
	if err != nil {
		cli.Log.Errorf("Failed to send pair error node: %v", err)
	}
}
