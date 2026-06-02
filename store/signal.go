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
	// Preserve this check — it short-circuits before the struct-cache lookup
	// for send-path contexts (RESEARCH Pitfall 6).
	if sess := getCachedSession(ctx, addrString); sess != nil {
		return sess, nil
	}

	// Phase 17.8: cacheKey includes device JID prefix so the shared struct LRU
	// keeps each device's entries separate.
	if device.ID != nil {
		cacheKey := device.ID.String() + "|" + addrString
		// 1. Check decoded structure cache (decode-once hit: ~375 ns, 20 allocs).
		if device.ParsedSessionCache != nil {
			if s, ok := device.ParsedSessionCache.LoadStruct(cacheKey); ok {
				return record.NewSessionFromStructure(s, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
			}
		}

		// 2. Cache miss: fetch []byte from byte-cache (CachedSessionStore LRU or DB).
		rawSess, err := device.Sessions.GetSession(ctx, addrString)
		if err != nil {
			return nil, fmt.Errorf("failed to load session with %s: %w", addrString, err)
		}
		if rawSess == nil {
			return record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State), nil
		}

		// 3. Deserialize once: JSON → structure.
		structure, err := SignalProtobufSerializer.Session.Deserialize(rawSess)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize session with %s: %w", addrString, err)
		}
		// 4. Populate struct cache (decode-once stored).
		if device.ParsedSessionCache != nil {
			device.ParsedSessionCache.StoreStruct(cacheKey, structure)
		}

		// 5. Build live record from structure.
		return record.NewSessionFromStructure(structure, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
	}

	// Fallback: device.ID is nil (test or pre-init scenarios without a JID).
	rawSess, err := device.Sessions.GetSession(ctx, addrString)
	if err != nil {
		return nil, fmt.Errorf("failed to load session with %s: %w", addrString, err)
	}
	if rawSess == nil {
		return record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State), nil
	}
	sess, err := record.NewSessionFromBytes(rawSess, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize session with %s: %w", addrString, err)
	}
	return sess, nil
}

func (device *Device) GetSubDeviceSessions(ctx context.Context, name string) ([]uint32, error) {
	panic("not implemented")
}

func (device *Device) StoreSession(ctx context.Context, address *protocol.SignalAddress, record *record.Session) error {
	addrString := address.String()

	// Phase 17.8: extract serialized bytes and post-ratchet structure BEFORE
	// the putCachedSession branch so the struct cache is always updated
	// regardless of which path takes the write (RESEARCH Pitfall 6, lines 447-449).
	serialized := record.Serialize()
	newStruct := record.Structure()
	if device.ID != nil && device.ParsedSessionCache != nil {
		cacheKey := device.ID.String() + "|" + addrString
		device.ParsedSessionCache.StoreStruct(cacheKey, newStruct)

		// Context cache: send-path only — preserve existing short-circuit.
		// Struct cache already updated above before this branch.
		if putCachedSession(ctx, addrString, record) {
			return nil
		}

		err := device.Sessions.PutSession(ctx, addrString, serialized)
		if err != nil {
			// Roll back: struct cache advanced past DB; force re-fetch on next Load
			// (session write-through coherence, RESEARCH lines 323-328).
			device.ParsedSessionCache.Invalidate(cacheKey)
			return fmt.Errorf("failed to store session with %s: %w", addrString, err)
		}
		return nil
	}

	// Fallback: device.ID is nil or no parsed cache wired (test or pre-init scenarios).
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

	// ONE serialize call — passed to PutSenderKey; no second serialize downstream (SC-3).
	serialized := keyRecord.Serialize()

	// Phase 17.8: update struct cache with post-ratchet structure.
	// cacheKey includes device JID prefix — required because ParsedSKCache is a
	// shared process-level LRU; device scoping prevents cross-account collisions
	// (matches CachedSenderKeyStore.key format). REPLACE, not invalidate — avoids
	// stale-after-write against async flusher (Pitfall 2).
	if device.ID != nil && device.ParsedSKCache != nil {
		cacheKey := device.ID.String() + "|" + groupID + "|" + senderString
		device.ParsedSKCache.StoreStruct(cacheKey, keyRecord.Structure())
	}

	err := device.SenderKeys.PutSenderKey(ctx, groupID, senderString, serialized)
	if err != nil {
		return fmt.Errorf("failed to store sender key from %s for %s: %w", senderString, groupID, err)
	}
	return nil
}

func (device *Device) LoadSenderKey(ctx context.Context, senderKeyName *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	groupID := senderKeyName.GroupID()
	senderString := senderKeyName.Sender().String()

	// Phase 17.8: struct-cache hit path. cacheKey includes device JID prefix
	// (shared LRU, device scoping required for multi-account correctness).
	if device.ID != nil && device.ParsedSKCache != nil {
		cacheKey := device.ID.String() + "|" + groupID + "|" + senderString

		// 1. Check decoded structure cache (decode-once hit: ~120 ns, 7 allocs).
		if s, ok := device.ParsedSKCache.LoadStruct(cacheKey); ok {
			return groupRecord.NewSenderKeyFromStruct(s, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
		}

		// 2. Cache miss: fetch []byte from byte-cache (CachedSenderKeyStore LRU or DB).
		rawKey, err := device.SenderKeys.GetSenderKey(ctx, groupID, senderString)
		if err != nil {
			return nil, fmt.Errorf("failed to load sender key from %s for %s: %w", senderString, groupID, err)
		}
		if rawKey == nil {
			return groupRecord.NewSenderKey(SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState), nil
		}

		// 3. Deserialize once: JSON → structure.
		structure, err := SignalProtobufSerializer.SenderKeyRecord.Deserialize(rawKey)
		if err != nil {
			return nil, fmt.Errorf("failed to deserialize sender key from %s for %s: %w", senderString, groupID, err)
		}
		// 4. Populate struct cache (decode-once stored).
		device.ParsedSKCache.StoreStruct(cacheKey, structure)

		// 5. Build live record from structure.
		return groupRecord.NewSenderKeyFromStruct(structure, SignalProtobufSerializer.SenderKeyRecord, SignalProtobufSerializer.SenderKeyState)
	}

	// Fallback: no JID or no parsed cache wired (test or pre-init scenarios).
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
