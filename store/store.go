// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package store contains interfaces for storing data needed for WhatsApp multidevice.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type IdentityStore interface {
	PutIdentity(ctx context.Context, address string, key [32]byte) error
	DeleteAllIdentities(ctx context.Context, phone string) error
	DeleteIdentity(ctx context.Context, address string) error
	IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error)
}

type SessionStore interface {
	GetSession(ctx context.Context, address string) ([]byte, error)
	HasSession(ctx context.Context, address string) (bool, error)
	GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error)
	PutSession(ctx context.Context, address string, session []byte) error
	PutManySessions(ctx context.Context, sessions map[string][]byte) error
	DeleteAllSessions(ctx context.Context, phone string) error
	DeleteSession(ctx context.Context, address string) error
	MigratePNToLID(ctx context.Context, pn, lid types.JID) error
}

type PreKeyStore interface {
	GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error)
	GenOnePreKey(ctx context.Context) (*keys.PreKey, error)
	GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error)
	RemovePreKey(ctx context.Context, id uint32) error
	MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error
	UploadedPreKeyCount(ctx context.Context) (int, error)
}

type SenderKeyStore interface {
	PutSenderKey(ctx context.Context, group, user string, session []byte) error
	GetSenderKey(ctx context.Context, group, user string) ([]byte, error)
	// GetSenderKeyDevices is READ-ONLY (a SELECT; no write, merge, or migration).
	// It returns the full device-qualified sender_id strings (e.g. "75811323404294_1:0",
	// "75811323404294_1:5") that exist in (our_jid, group, userBare) so a caller can
	// rebuild a SenderKeyName per device and let the existing cached LoadSenderKey
	// fetch each record. userBare is the device-stripped sender user string
	// (from.SignalAddressUser() form, e.g. "75811323404294_1") — the range query matches
	// rows with sender_id starting with "<userBare>:". The returned strings are
	// device-qualified; an empty/nil slice means no candidates exist. Carries forward D-06:
	// this method never writes, merges, or rewrites any sender_id.
	GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error)
}

type AppStateSyncKey struct {
	Data        []byte
	Fingerprint []byte
	Timestamp   int64
}

type AppStateSyncKeyStore interface {
	PutAppStateSyncKey(ctx context.Context, id []byte, key AppStateSyncKey) error
	GetAppStateSyncKey(ctx context.Context, id []byte) (*AppStateSyncKey, error)
	GetLatestAppStateSyncKeyID(ctx context.Context) ([]byte, error)
	GetAllAppStateSyncKeys(ctx context.Context) ([]*AppStateSyncKey, error)
}

type AppStateMutationMAC struct {
	IndexMAC []byte
	ValueMAC []byte
}

type AppStateStore interface {
	PutAppStateVersion(ctx context.Context, name string, version uint64, hash [128]byte) error
	GetAppStateVersion(ctx context.Context, name string) (uint64, [128]byte, error)
	DeleteAppStateVersion(ctx context.Context, name string) error

	PutAppStateMutationMACs(ctx context.Context, name string, version uint64, mutations []AppStateMutationMAC) error
	DeleteAppStateMutationMACs(ctx context.Context, name string, indexMACs [][]byte) error
	GetAppStateMutationMAC(ctx context.Context, name string, indexMAC []byte) (valueMAC []byte, err error)

	// PutAppStateVersionAndMACs atomically persists the version cursor together with the
	// removed and added mutation MACs for one app state collection (55.1-10, class 14 root
	// cause H1: storeMACs was three independent non-transactional statements). Implementations
	// must make this all-or-nothing: on any error, none of the three writes may have taken
	// effect (no more cursor-ahead-of-ledger states after a crash or error mid-write).
	PutAppStateVersionAndMACs(ctx context.Context, name string, version uint64, hash [128]byte, removedMACs [][]byte, addedMACs []AppStateMutationMAC) error
}

type ContactEntry struct {
	JID       types.JID
	FirstName string
	FullName  string
}

func (ce ContactEntry) GetMassInsertValues() [3]any {
	return [...]any{ce.JID.String(), ce.FirstName, ce.FullName}
}

type RedactedPhoneEntry struct {
	JID           types.JID
	RedactedPhone string
}

func (rpe RedactedPhoneEntry) GetMassInsertValues() [2]any {
	return [...]any{rpe.JID.String(), rpe.RedactedPhone}
}

type ContactStore interface {
	PutPushName(ctx context.Context, user types.JID, pushName string) (bool, string, error)
	PutBusinessName(ctx context.Context, user types.JID, businessName string) (bool, string, error)
	PutContactName(ctx context.Context, user types.JID, fullName, firstName string) error
	PutAllContactNames(ctx context.Context, contacts []ContactEntry) error
	PutManyRedactedPhones(ctx context.Context, entries []RedactedPhoneEntry) error
	GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error)
	GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error)
}

var MutedForever = time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)

type ChatSettingsStore interface {
	PutMutedUntil(ctx context.Context, chat types.JID, mutedUntil time.Time) error
	PutPinned(ctx context.Context, chat types.JID, pinned bool) error
	PutArchived(ctx context.Context, chat types.JID, archived bool) error
	GetChatSettings(ctx context.Context, chat types.JID) (types.LocalChatSettings, error)
}

type DeviceContainer interface {
	PutDevice(ctx context.Context, store *Device) error
	DeleteDevice(ctx context.Context, store *Device) error
}

// SenderKeyInlineRecoverer is the interface for synchronous inline recovery.
// Defined in package store (not sqlstore) so message.go can call it via
// cli.Store.InlineRecoverer without importing sqlstore (package-boundary
// constraint — message.go only imports store, not sqlstore).
// Implemented by *CachedSenderKeyStore (sqlstore). Set on Device by
// attachCachedStores. Nil before wiring and in test environments;
// message.go gates on nil before calling TryInlineRecovery.
type SenderKeyInlineRecoverer interface {
	TryInlineRecovery(ctx context.Context, group, targetSenderID, senderBare string, targetKeyID, targetIter uint32) (donorJID string, ok bool, err error)
}

type MessageSecretInsert struct {
	Chat   types.JID
	Sender types.JID
	ID     types.MessageID
	Secret []byte
}

type MsgSecretStore interface {
	PutMessageSecrets(ctx context.Context, inserts []MessageSecretInsert) error
	PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error
	GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error)
}

type PrivacyToken struct {
	User            types.JID
	Token           []byte
	Timestamp       time.Time
	SenderTimestamp time.Time
}

type PrivacyTokenStore interface {
	PutPrivacyTokens(ctx context.Context, tokens ...PrivacyToken) error
	GetPrivacyToken(ctx context.Context, user types.JID) (*PrivacyToken, error)
	DeleteExpiredPrivacyTokens(ctx context.Context, cutoff time.Time) (int64, error)
}

type NCTSaltStore interface {
	PutNCTSalt(ctx context.Context, salt []byte) error
	GetNCTSalt(ctx context.Context) ([]byte, error)
	DeleteNCTSalt(ctx context.Context) error
}

type BufferedEvent struct {
	Plaintext  []byte
	InsertTime time.Time
	ServerTime time.Time
}

type EventBuffer interface {
	GetBufferedEvent(ctx context.Context, ciphertextHash [32]byte) (*BufferedEvent, error)
	PutBufferedEvent(ctx context.Context, ciphertextHash [32]byte, plaintext []byte, serverTimestamp time.Time) error
	DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error
	ClearBufferedEventPlaintext(ctx context.Context, ciphertextHash [32]byte) error
	DeleteOldBufferedHashes(ctx context.Context) error

	GetOutgoingEvent(ctx context.Context, chatJID, altChatJID types.JID, id types.MessageID) (string, []byte, error)
	// GetOutgoingEventByID looks up a stored outgoing message by ID alone (ignoring chat). Used
	// to serve own-account/DeviceSentMessage retries, which arrive keyed by our own account
	// while the message is stored under its destination chat. See getMessageForRetry.
	GetOutgoingEventByID(ctx context.Context, id types.MessageID) (string, []byte, error)
	AddOutgoingEvent(ctx context.Context, chatJID types.JID, id types.MessageID, format string, plaintext []byte) error
	DeleteOldOutgoingEvents(ctx context.Context) error
}

type LIDMapping struct {
	LID types.JID
	PN  types.JID
}

func (lm LIDMapping) GetMassInsertValues() [2]any {
	return [...]any{lm.LID.User, lm.PN.User}
}

type LIDStore interface {
	PutManyLIDMappings(ctx context.Context, mappings []LIDMapping) error
	PutLIDMapping(ctx context.Context, lid, jid types.JID) error
	GetPNForLID(ctx context.Context, lid types.JID) (types.JID, error)
	GetLIDForPN(ctx context.Context, pn types.JID) (types.JID, error)
	GetManyLIDsForPNs(ctx context.Context, pns []types.JID) (map[types.JID]types.JID, error)
}

type AllSessionSpecificStores interface {
	IdentityStore
	SessionStore
	PreKeyStore
	SenderKeyStore
	AppStateSyncKeyStore
	AppStateStore
	ContactStore
	ChatSettingsStore
	MsgSecretStore
	PrivacyTokenStore
	NCTSaltStore
	EventBuffer
}

type AllGlobalStores interface {
	LIDStore
}

type AllStores interface {
	AllSessionSpecificStores
	AllGlobalStores
}

type Device struct {
	Log waLog.Logger

	NoiseKey       *keys.KeyPair
	IdentityKey    *keys.KeyPair
	SignedPreKey   *keys.PreKey
	RegistrationID uint32
	AdvSecretKey   []byte

	ID  *types.JID
	LID types.JID

	Account      *waAdv.ADVSignedDeviceIdentity
	Platform     string
	BusinessName string
	PushName     string

	LIDMigrationTimestamp int64

	FacebookUUID uuid.UUID

	Initialized bool
	Deleted     bool
	Identities  IdentityStore
	Sessions    SessionStore
	PreKeys     PreKeyStore
	SenderKeys  SenderKeyStore
	// Phase 17.12: inline synchronous cross-account sender-key recovery.
	// Nil before attachCachedStores wires it. message.go gates on nil before
	// calling TryInlineRecovery — no-op when not wired (test environments, pre-init).
	InlineRecoverer SenderKeyInlineRecoverer
	AppStateKeys    AppStateSyncKeyStore
	AppState        AppStateStore
	Contacts        ContactStore
	ChatSettings    ChatSettingsStore
	MsgSecrets      MsgSecretStore
	PrivacyTokens   PrivacyTokenStore
	NCTSalt         NCTSaltStore
	EventBuffer     EventBuffer
	LIDs            LIDStore
	Container       DeviceContainer
}

func (device *Device) GetJID() types.JID {
	if device == nil {
		return types.EmptyJID
	}
	id := device.ID
	if id == nil {
		return types.EmptyJID
	}
	return *id
}

func (device *Device) GetLID() types.JID {
	if device == nil {
		return types.EmptyJID
	}
	return device.LID
}

var ErrDeviceDeleted = errors.New("invalid use of deleted device")

func (device *Device) Save(ctx context.Context) error {
	if device.Deleted {
		return ErrDeviceDeleted
	}
	return device.Container.PutDevice(ctx, device)
}

func (device *Device) Delete(ctx context.Context) error {
	if device.Deleted {
		return nil
	}
	err := device.Container.DeleteDevice(ctx, device)
	if err != nil {
		return err
	}
	device.ID = nil
	device.LID = types.EmptyJID
	device.Deleted = true
	device.SetAllStores(&NoopStore{ErrDeviceDeleted})
	return nil
}

func (device *Device) SetAllStores(store AllSessionSpecificStores) {
	device.Identities = store
	device.Sessions = store
	device.PreKeys = store
	device.SenderKeys = store
	device.AppStateKeys = store
	device.AppState = store
	device.Contacts = store
	device.ChatSettings = store
	device.MsgSecrets = store
	device.PrivacyTokens = store
	device.NCTSalt = store
	device.EventBuffer = store
}

func (device *Device) GetAltJID(ctx context.Context, jid types.JID) (types.JID, error) {
	if device == nil {
		return types.EmptyJID, nil
	} else if jid.Server == types.DefaultUserServer {
		return device.LIDs.GetLIDForPN(ctx, jid)
	} else if jid.Server == types.HiddenUserServer {
		return device.LIDs.GetPNForLID(ctx, jid)
	} else {
		return types.EmptyJID, nil
	}
}
