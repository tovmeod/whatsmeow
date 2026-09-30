// Copyright (c) 2022 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"

	"go.mau.fi/libsignal/ecc"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/keys/identity"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/state/store"
)

var SignalProtobufSerializer = serialize.NewProtoBufSerializer()

var _ store.SignalProtocol = (*Device)(nil)

func (device *Device) GetIdentityKeyPair() *identity.KeyPair {
	return identity.NewKeyPair(
		identity.NewKey(ecc.NewDjbECPublicKey(*device.IdentityKey.Pub)),
		ecc.NewDjbECPrivateKey(*device.IdentityKey.Priv),
	)
}

func (device *Device) GetLocalRegistrationID() uint32 {
	return device.RegistrationID
}

func (device *Device) SaveIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) error {
	addrString := address.String()
	err := device.Identities.PutIdentity(ctx, addrString, identityKey.PublicKey().PublicKey())
	if err != nil {
		return fmt.Errorf("failed to save identity of %s: %w", addrString, err)
	}
	return nil
}

func (device *Device) IsTrustedIdentity(ctx context.Context, address *protocol.SignalAddress, identityKey *identity.Key) (bool, error) {
	addrString := address.String()
	isTrusted, err := device.Identities.IsTrustedIdentity(ctx, addrString, identityKey.PublicKey().PublicKey())
	if err != nil {
		return false, fmt.Errorf("failed to check if %s's identity is trusted: %w", addrString, err)
	}
	return isTrusted, nil
}

func (device *Device) LoadPreKey(ctx context.Context, id uint32) (*record.PreKey, error) {
	preKey, err := device.PreKeys.GetPreKey(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("failed to load prekey %d: %w", id, err)
	}
	if preKey == nil {
		return nil, nil
	}
	return record.NewPreKey(preKey.KeyID, ecc.NewECKeyPair(
		ecc.NewDjbECPublicKey(*preKey.Pub),
		ecc.NewDjbECPrivateKey(*preKey.Priv),
	), nil), nil
}

func (device *Device) RemovePreKey(ctx context.Context, id uint32) error {
	err := device.PreKeys.RemovePreKey(ctx, id)
	if err != nil {
		return fmt.Errorf("failed to remove prekey %d: %w", id, err)
	}
	return nil
}

func (device *Device) StorePreKey(ctx context.Context, preKeyID uint32, preKeyRecord *record.PreKey) error {
	panic("not implemented")
}

func (device *Device) ContainsPreKey(ctx context.Context, preKeyID uint32) (bool, error) {
	panic("not implemented")
}

func (device *Device) LoadSession(ctx context.Context, address *protocol.SignalAddress) (*record.Session, error) {
	addrString := address.String()
	// Context cache: send-path only (getCachedSession returns nil during decrypts).
	// Preserve this check — it short-circuits the byte-cache lookup for send-path
	// contexts (RESEARCH Pitfall 6).
	if sess := getCachedSession(ctx, addrString); sess != nil {
		return sess, nil
	}

	// Fetch raw bytes from byte-cache (CachedSessionStore LRU or DB).
	// Stage 1: single-tier — no struct cache (D-04a removal).
	rawSess, err := device.Sessions.GetSession(ctx, addrString)
	if err != nil {
		return nil, fmt.Errorf("failed to load session with %s: %w", addrString, err)
	}
	if rawSess == nil {
		return record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State), nil
	}

	// Format detection: byte[0]=0x01 → flat (Stage 3: only valid format).
	// Stage 3: JSON-read path removed after backfill confirmed zero JSON rows.
	// A non-flat blob returns a wrapped error — never panics, never silently drops.
	var structure *record.SessionStructure
	if len(rawSess) > 0 && rawSess[0] == 0x01 {
		structure, err = UnpackFlatSession(rawSess)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize session with %s: %w", addrString, err)
		}
	} else {
		// Non-flat blob: JSON-read path removed in Stage 3. All prod rows confirmed flat.
		var byte0desc string
		if len(rawSess) == 0 {
			byte0desc = "empty blob"
		} else {
			byte0desc = fmt.Sprintf("byte0=0x%02x", rawSess[0])
		}
		return nil, fmt.Errorf("LoadSession: non-flat session blob for %s (%s); JSON read path removed in Stage 3", addrString, byte0desc)
	}
	return record.NewSessionFromStructure(structure, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
}

func (device *Device) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	panic("not implemented")
}

func (device *Device) StoreSession(ctx context.Context, address *protocol.SignalAddress, record *record.Session) error {
	addrString := address.String()

	// Stage 3: write flat bytes via PackFlatSession only. No JSON fallback.
	// If PackFlatSession refuses (codec bug), return a wrapped error — no silent session loss.
	structure := record.Structure()
	flat, ok := PackFlatSession(structure)
	if !ok {
		return fmt.Errorf("PackFlatSession refused to encode session with %s: codec bug", addrString)
	}
	serialized := flat

	if putCachedSession(ctx, addrString, record) {
		return nil
	}
	err := device.Sessions.PutSession(ctx, addrString, serialized)
	if err != nil {
		return fmt.Errorf("failed to store session with %s: %w", addrString, err)
	}
	return nil
}

func (device *Device) ContainsSession(ctx context.Context, remoteAddress *protocol.SignalAddress) (bool, error) {
	addrString := remoteAddress.String()

	// Check cache first - sessions may exist in cache but not yet flushed to DB
	if exists, inCache := hasCachedSession(ctx, addrString); inCache {
		return exists, nil
	}

	// Fall back to database check
	hasSession, err := device.Sessions.HasSession(ctx, addrString)
	if err != nil {
		return false, fmt.Errorf("failed to check if store has session for %s: %w", addrString, err)
	}
	return hasSession, nil
}

func (device *Device) DeleteSession(ctx context.Context, remoteAddress *protocol.SignalAddress) error {
	panic("not implemented")
}

func (device *Device) DeleteAllSessions(ctx context.Context) error {
	panic("not implemented")
}

func (device *Device) LoadSignedPreKey(ctx context.Context, signedPreKeyID uint32) (*record.SignedPreKey, error) {
	if signedPreKeyID == device.SignedPreKey.KeyID {
		return record.NewSignedPreKey(signedPreKeyID, 0, ecc.NewECKeyPair(
			ecc.NewDjbECPublicKey(*device.SignedPreKey.Pub),
			ecc.NewDjbECPrivateKey(*device.SignedPreKey.Priv),
		), *device.SignedPreKey.Signature, nil), nil
	}
	return nil, nil
}

func (device *Device) LoadSignedPreKeys(ctx context.Context) ([]*record.SignedPreKey, error) {
	panic("not implemented")
}

func (device *Device) StoreSignedPreKey(ctx context.Context, signedPreKeyID uint32, record *record.SignedPreKey) error {
	panic("not implemented")
}

func (device *Device) ContainsSignedPreKey(ctx context.Context, signedPreKeyID uint32) (bool, error) {
	panic("not implemented")
}

func (device *Device) RemoveSignedPreKey(ctx context.Context, signedPreKeyID uint32) error {
	panic("not implemented")
}

func (device *Device) StoreSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName, keyRecord *groupRecord.SenderKey) error {
	groupID := senderKeyName.GroupID()
	senderString := senderKeyName.Sender().String()

	// Phase 38.4-03: parsed struct-cache (SKParsed) deleted. The write-through flat
	// c.cache inside CachedSenderKeyStore.PutSenderKeyStructure is the authoritative
	// write path. No StoreStruct call here.

	// Phase 17.9: columnar hot path — no Serialize on the per-message write.
	// Type-assert device.SenderKeys to the fork-local optional interface.
	// Structure() is JSON-free (in-memory only; no Marshal).
	// DESIGN OVERRIDE: the columnar path uses a structure-carrying fork-local
	// interface; whatsmeow's []byte SenderKeyStore is preserved for upstream-merge
	// compatibility (DESIGN line 64 non-veto; line 11 hard goal).
	if csk, ok := device.SenderKeys.(SenderKeyColumnarStore); ok {
		err := csk.PutSenderKeyStructure(ctx, groupID, senderString, keyRecord.Structure())
		if err != nil {
			return fmt.Errorf("failed to store sender key from %s for %s: %w", senderString, groupID, err)
		}
		return nil
	}

	// Fallback: store does not implement SenderKeyColumnarStore (legacy / test stores).
	// This is the ONLY remaining Serialize in StoreSenderKey; fires only for non-columnar stores.
	serialized := keyRecord.Serialize() // ALLOW-JSON-LEGACY-READ (non-columnar store fallback: fires only on legacy/test stores, not production CachedSenderKeyStore)
	err := device.SenderKeys.PutSenderKey(ctx, groupID, senderString, serialized)
	if err != nil {
		return fmt.Errorf("failed to store sender key from %s for %s: %w", senderString, groupID, err)
	}
	return nil
}

func (device *Device) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	groupID := senderKeyName.GroupID()
	senderString := senderKeyName.Sender().String()

	// Phase 38.4-03: parsed struct-cache (SKParsed) deleted. LoadSenderKey now reads
	// the flat []byte cache directly via GetSenderKeyStructure (cache-aware since
	// Plan 02). Decode flat bytes → record per decrypt (transient; GC'd immediately —
	// no pointer-dense graph retained, per the Phase 17.8/17.9 GC decision).

	// 1. Columnar read path (fmt_ver=2 → flat bytes → structure, no JSON).
	// GetSenderKeyStructure is cache-aware (Plan 02): checks c.cache before DB.
	if csk, ok := device.SenderKeys.(SenderKeyColumnarStore); ok {
		structure, err := csk.GetSenderKeyStructure(ctx, groupID, senderString)
		if err != nil {
			return nil, fmt.Errorf("failed to load sender key structure from %s for %s: %w", senderString, groupID, err)
		}
		if structure == nil {
			// Absent row: return empty record (recovery invariant — never cache nil).
			return groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState), nil
		}
		return groupRecord.NewSenderKeyFromStruct(structure, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	}

	// 2. Fallback: store does not implement SenderKeyColumnarStore (legacy / test stores).
	// Use the []byte GetSenderKey + Deserialize path (ALLOW-JSON-LEGACY-READ).
	rawKey, err := device.SenderKeys.GetSenderKey(ctx, groupID, senderString)
	if err != nil {
		return nil, fmt.Errorf("failed to load sender key from %s for %s: %w", senderString, groupID, err)
	}
	if rawKey == nil {
		return groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState), nil
	}
	key, err := groupRecord.NewSenderKeyFromBytes(rawKey, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize sender key from %s for %s: %w", senderString, groupID, err)
	}
	return key, nil
}
