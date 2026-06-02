// proto_serializer.go — fork-owned protobuf record serializer for Signal
// SessionRecord and SenderKeyRecord (Phase 17.9, Req 2).
//
// Implements the four libsignal record serializer interfaces over the
// generated proto message types in go.mau.fi/libsignal/serialize, using
// the RecordStructure wrapper as the top-level marshal target for sessions
// (required to preserve PreviousStates — a bare SessionStructure drops them).
//
// Interface conformance compile-time assertions are at the bottom of the file.

package sqlstore

import (
	"fmt"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/keys/chain"
	"go.mau.fi/libsignal/keys/message"
	"go.mau.fi/libsignal/groups/ratchet"
	"go.mau.fi/libsignal/serialize"
	librecord "go.mau.fi/libsignal/state/record"
	"go.mau.fi/libsignal/util/optional"
	"google.golang.org/protobuf/proto"
)

// ============================================================================
// ProtoSessionSerializer — implements record.SessionSerializer
// ============================================================================

// ProtoSessionSerializer serializes a *record.SessionStructure (the outer
// wrapper that holds SessionState + PreviousStates) via the proto
// RecordStructure wrapper, then proto.Marshal.
//
// NAMING INVERSION: record.SessionStructure{SessionState, PreviousStates}
// maps to proto RecordStructure{CurrentSession, PreviousSessions}, where
// each Go StateStructure maps to one proto SessionStructure (not the record).
type ProtoSessionSerializer struct{}

// Serialize maps the Go SessionStructure to a proto RecordStructure and
// marshals it to bytes. Returns nil on marshal error (matching JSON idiom).
func (s *ProtoSessionSerializer) Serialize(session *librecord.SessionStructure) []byte {
	if session == nil {
		return nil
	}
	rec := &serialize.RecordStructure{
		CurrentSession: stateToProto(session.SessionState),
	}
	if len(session.PreviousStates) > 0 {
		rec.PreviousSessions = make([]*serialize.SessionStructure, len(session.PreviousStates))
		for i, ps := range session.PreviousStates {
			rec.PreviousSessions[i] = stateToProto(ps)
		}
	}
	b, err := proto.Marshal(rec)
	if err != nil {
		return nil
	}
	return b
}

// Deserialize unmarshals bytes into a proto RecordStructure, then maps back to
// a Go *record.SessionStructure. Returns an error on unmarshal failure.
func (s *ProtoSessionSerializer) Deserialize(serialized []byte) (*librecord.SessionStructure, error) {
	var rec serialize.RecordStructure
	if err := proto.Unmarshal(serialized, &rec); err != nil {
		return nil, fmt.Errorf("proto session deserialize: %w", err)
	}
	sessionStructure := &librecord.SessionStructure{
		SessionState: stateFromProto(rec.CurrentSession),
	}
	if len(rec.PreviousSessions) > 0 {
		sessionStructure.PreviousStates = make([]*librecord.StateStructure, len(rec.PreviousSessions))
		for i, ps := range rec.PreviousSessions {
			sessionStructure.PreviousStates[i] = stateFromProto(ps)
		}
	}
	return sessionStructure, nil
}

// ============================================================================
// ProtoStateSerializer — implements record.StateSerializer
// ============================================================================

// ProtoStateSerializer serializes a *record.StateStructure directly (i.e.
// one session state, used by the graph-rebuild path that calls StateSerializer).
// Marshal target is a proto SessionStructure (not RecordStructure).
type ProtoStateSerializer struct{}

// Serialize maps the Go StateStructure to a proto SessionStructure and
// marshals it to bytes.
func (s *ProtoStateSerializer) Serialize(state *librecord.StateStructure) []byte {
	if state == nil {
		return nil
	}
	b, err := proto.Marshal(stateToProto(state))
	if err != nil {
		return nil
	}
	return b
}

// Deserialize unmarshals bytes into a proto SessionStructure, then maps back
// to a Go *record.StateStructure.
func (s *ProtoStateSerializer) Deserialize(serialized []byte) (*librecord.StateStructure, error) {
	var ss serialize.SessionStructure
	if err := proto.Unmarshal(serialized, &ss); err != nil {
		return nil, fmt.Errorf("proto state deserialize: %w", err)
	}
	return stateFromProto(&ss), nil
}

// ============================================================================
// ProtoSenderKeySerializer — implements groupRecord.SenderKeySerializer
// ============================================================================

// ProtoSenderKeySerializer serializes a *groupRecord.SenderKeyStructure via
// the proto SenderKeyRecordStructure wrapper and proto.Marshal.
type ProtoSenderKeySerializer struct{}

// Serialize maps the Go SenderKeyStructure to a proto SenderKeyRecordStructure
// and marshals it to bytes.
func (s *ProtoSenderKeySerializer) Serialize(sk *groupRecord.SenderKeyStructure) []byte {
	if sk == nil {
		return nil
	}
	rec := &serialize.SenderKeyRecordStructure{}
	if len(sk.SenderKeyStates) > 0 {
		rec.SenderKeyStates = make([]*serialize.SenderKeyStateStructure, len(sk.SenderKeyStates))
		for i, state := range sk.SenderKeyStates {
			rec.SenderKeyStates[i] = senderKeyStateToProto(state)
		}
	}
	b, err := proto.Marshal(rec)
	if err != nil {
		return nil
	}
	return b
}

// Deserialize unmarshals bytes into a proto SenderKeyRecordStructure, then
// maps back to a Go *groupRecord.SenderKeyStructure.
func (s *ProtoSenderKeySerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStructure, error) {
	var rec serialize.SenderKeyRecordStructure
	if err := proto.Unmarshal(serialized, &rec); err != nil {
		return nil, fmt.Errorf("proto sender key deserialize: %w", err)
	}
	result := &groupRecord.SenderKeyStructure{}
	if len(rec.SenderKeyStates) > 0 {
		result.SenderKeyStates = make([]*groupRecord.SenderKeyStateStructure, len(rec.SenderKeyStates))
		for i, ps := range rec.SenderKeyStates {
			result.SenderKeyStates[i] = senderKeyStateFromProto(ps)
		}
	}
	return result, nil
}

// ============================================================================
// ProtoSenderKeyStateSerializer — implements groupRecord.SenderKeyStateSerializer
// ============================================================================

// ProtoSenderKeyStateSerializer serializes a *groupRecord.SenderKeyStateStructure
// directly, using the proto SenderKeyStateStructure as the marshal target.
type ProtoSenderKeyStateSerializer struct{}

// Serialize maps the Go SenderKeyStateStructure to its proto form and marshals it.
func (s *ProtoSenderKeyStateSerializer) Serialize(state *groupRecord.SenderKeyStateStructure) []byte {
	if state == nil {
		return nil
	}
	b, err := proto.Marshal(senderKeyStateToProto(state))
	if err != nil {
		return nil
	}
	return b
}

// Deserialize unmarshals bytes into a proto SenderKeyStateStructure, then maps
// back to a Go *groupRecord.SenderKeyStateStructure.
func (s *ProtoSenderKeyStateSerializer) Deserialize(serialized []byte) (*groupRecord.SenderKeyStateStructure, error) {
	var ss serialize.SenderKeyStateStructure
	if err := proto.Unmarshal(serialized, &ss); err != nil {
		return nil, fmt.Errorf("proto sender key state deserialize: %w", err)
	}
	return senderKeyStateFromProto(&ss), nil
}

// ============================================================================
// Private mapper pairs — Go StateStructure ↔ proto SessionStructure
// ============================================================================

// stateToProto maps a Go record.StateStructure to a proto serialize.SessionStructure.
// Field map from 17.9-PATTERNS.md "Session field map" (load-bearing; copy exactly).
//
// Non-1:1 mappings:
//   - SessionVersion int          ↔ SessionVersion *uint32
//   - NeedsRefresh   bool         ↔ NeedsRefresh *bool
//   - SenderBaseKey  []byte       ↔ AliceBaseKey []byte    (name differs)
//   - PreviousCounter uint32      ↔ PreviousCounter *uint32
//   - RemoteRegistrationID uint32 ↔ RemoteRegistrationId *uint32
//   - LocalRegistrationID  uint32 ↔ LocalRegistrationId *uint32
func stateToProto(s *librecord.StateStructure) *serialize.SessionStructure {
	if s == nil {
		return nil
	}
	sv := uint32(s.SessionVersion)
	pc := s.PreviousCounter
	rrid := s.RemoteRegistrationID
	lrid := s.LocalRegistrationID
	nr := s.NeedsRefresh

	ss := &serialize.SessionStructure{
		SessionVersion:       &sv,
		LocalIdentityPublic:  s.LocalIdentityPublic,
		RemoteIdentityPublic: s.RemoteIdentityPublic,
		RootKey:              s.RootKey,
		PreviousCounter:      &pc,
		RemoteRegistrationId: &rrid,
		LocalRegistrationId:  &lrid,
		NeedsRefresh:         &nr,
		AliceBaseKey:         s.SenderBaseKey, // ⚠ name differs: SenderBaseKey ↔ AliceBaseKey
		SenderChain:          chainToProto(s.SenderChain),
	}
	if len(s.ReceiverChains) > 0 {
		ss.ReceiverChains = make([]*serialize.SessionStructure_Chain, len(s.ReceiverChains))
		for i, c := range s.ReceiverChains {
			ss.ReceiverChains[i] = chainToProto(c)
		}
	}
	if s.PendingKeyExchange != nil {
		ss.PendingKeyExchange = pendingKeyExchangeToProto(s.PendingKeyExchange)
	}
	if s.PendingPreKey != nil {
		ss.PendingPreKey = pendingPreKeyToProto(s.PendingPreKey)
	}
	return ss
}

// stateFromProto maps a proto serialize.SessionStructure back to a Go record.StateStructure.
func stateFromProto(ss *serialize.SessionStructure) *librecord.StateStructure {
	if ss == nil {
		return nil
	}
	s := &librecord.StateStructure{
		LocalIdentityPublic:  ss.LocalIdentityPublic,
		RemoteIdentityPublic: ss.RemoteIdentityPublic,
		RootKey:              ss.RootKey,
		SenderBaseKey:        ss.AliceBaseKey, // ⚠ name differs: AliceBaseKey ↔ SenderBaseKey
		SenderChain:          chainFromProto(ss.SenderChain),
	}
	if ss.SessionVersion != nil {
		s.SessionVersion = int(*ss.SessionVersion)
	}
	if ss.PreviousCounter != nil {
		s.PreviousCounter = *ss.PreviousCounter
	}
	if ss.RemoteRegistrationId != nil {
		s.RemoteRegistrationID = *ss.RemoteRegistrationId
	}
	if ss.LocalRegistrationId != nil {
		s.LocalRegistrationID = *ss.LocalRegistrationId
	}
	if ss.NeedsRefresh != nil {
		s.NeedsRefresh = *ss.NeedsRefresh
	}
	if len(ss.ReceiverChains) > 0 {
		s.ReceiverChains = make([]*librecord.ChainStructure, len(ss.ReceiverChains))
		for i, c := range ss.ReceiverChains {
			s.ReceiverChains[i] = chainFromProto(c)
		}
	}
	if ss.PendingKeyExchange != nil {
		s.PendingKeyExchange = pendingKeyExchangeFromProto(ss.PendingKeyExchange)
	}
	if ss.PendingPreKey != nil {
		s.PendingPreKey = pendingPreKeyFromProto(ss.PendingPreKey)
	}
	return s
}

// chainToProto maps a Go ChainStructure to a proto SessionStructure_Chain.
// Field map:
//   SenderRatchetKeyPublic  []byte ↔ SenderRatchetKey []byte (name differs)
//   SenderRatchetKeyPrivate []byte ↔ SenderRatchetKeyPrivate []byte
//   ChainKey *chain.KeyStructure  ↔ ChainKey *SessionStructure_Chain_ChainKey
//   MessageKeys []*message.KeysStructure ↔ MessageKeys []*SessionStructure_Chain_MessageKey
func chainToProto(c *librecord.ChainStructure) *serialize.SessionStructure_Chain {
	if c == nil {
		return nil
	}
	pc := &serialize.SessionStructure_Chain{
		SenderRatchetKey:        c.SenderRatchetKeyPublic, // name differs
		SenderRatchetKeyPrivate: c.SenderRatchetKeyPrivate,
		ChainKey:                chainKeyToProto(c.ChainKey),
	}
	if len(c.MessageKeys) > 0 {
		pc.MessageKeys = make([]*serialize.SessionStructure_Chain_MessageKey, len(c.MessageKeys))
		for i, mk := range c.MessageKeys {
			pc.MessageKeys[i] = messageKeyToProto(mk)
		}
	}
	return pc
}

// chainFromProto maps a proto SessionStructure_Chain back to a Go ChainStructure.
func chainFromProto(c *serialize.SessionStructure_Chain) *librecord.ChainStructure {
	if c == nil {
		return nil
	}
	cs := &librecord.ChainStructure{
		SenderRatchetKeyPublic:  c.SenderRatchetKey, // name differs
		SenderRatchetKeyPrivate: c.SenderRatchetKeyPrivate,
		ChainKey:                chainKeyFromProto(c.ChainKey),
	}
	if len(c.MessageKeys) > 0 {
		cs.MessageKeys = make([]*message.KeysStructure, len(c.MessageKeys))
		for i, mk := range c.MessageKeys {
			cs.MessageKeys[i] = messageKeyFromProto(mk)
		}
	}
	return cs
}

// chainKeyToProto maps a Go chain.KeyStructure to proto _ChainKey.
// ⚠ Field order differs in proto: Index is field 1, Key is field 2 (reversed
// from Go struct declaration order — proto field numbers don't affect wire
// mapping but noting it here per PATTERNS.md).
func chainKeyToProto(ck *chain.KeyStructure) *serialize.SessionStructure_Chain_ChainKey {
	if ck == nil {
		return nil
	}
	idx := ck.Index
	return &serialize.SessionStructure_Chain_ChainKey{
		Index: &idx,
		Key:   ck.Key,
	}
}

// chainKeyFromProto maps a proto _ChainKey back to a Go chain.KeyStructure.
func chainKeyFromProto(ck *serialize.SessionStructure_Chain_ChainKey) *chain.KeyStructure {
	if ck == nil {
		return nil
	}
	cs := &chain.KeyStructure{
		Key: ck.Key,
	}
	if ck.Index != nil {
		cs.Index = *ck.Index
	}
	return cs
}

// messageKeyToProto maps a Go message.KeysStructure to proto _MessageKey.
// ⚠ Go uses IV []byte; proto uses Iv []byte (name differs).
func messageKeyToProto(mk *message.KeysStructure) *serialize.SessionStructure_Chain_MessageKey {
	if mk == nil {
		return nil
	}
	idx := mk.Index
	return &serialize.SessionStructure_Chain_MessageKey{
		Index:     &idx,
		CipherKey: mk.CipherKey,
		MacKey:    mk.MacKey,
		Iv:        mk.IV, // ⚠ Go IV ↔ proto Iv
	}
}

// messageKeyFromProto maps a proto _MessageKey back to a Go message.KeysStructure.
func messageKeyFromProto(mk *serialize.SessionStructure_Chain_MessageKey) *message.KeysStructure {
	if mk == nil {
		return nil
	}
	ks := &message.KeysStructure{
		CipherKey: mk.CipherKey,
		MacKey:    mk.MacKey,
		IV:        mk.Iv, // ⚠ proto Iv ↔ Go IV
	}
	if mk.Index != nil {
		ks.Index = *mk.Index
	}
	return ks
}

// pendingKeyExchangeToProto maps a Go PendingKeyExchangeStructure to proto
// SessionStructure_PendingKeyExchange.
// Proto fields (from pb.go:611-622):
//   Sequence *uint32, LocalBaseKey []byte, LocalBaseKeyPrivate []byte,
//   LocalRatchetKey []byte, LocalRatchetKeyPrivate []byte,
//   LocalIdentityKey []byte, LocalIdentityKeyPrivate []byte
// Note: proto field numbers skip 6; fields 1-5,7,8 are present.
func pendingKeyExchangeToProto(pke *librecord.PendingKeyExchangeStructure) *serialize.SessionStructure_PendingKeyExchange {
	if pke == nil {
		return nil
	}
	seq := pke.Sequence
	return &serialize.SessionStructure_PendingKeyExchange{
		Sequence:                &seq,
		LocalBaseKey:            pke.LocalBaseKeyPublic,
		LocalBaseKeyPrivate:     pke.LocalBaseKeyPrivate,
		LocalRatchetKey:         pke.LocalRatchetKeyPublic,
		LocalRatchetKeyPrivate:  pke.LocalRatchetKeyPrivate,
		LocalIdentityKey:        pke.LocalIdentityKeyPublic,
		LocalIdentityKeyPrivate: pke.LocalIdentityKeyPrivate,
	}
}

// pendingKeyExchangeFromProto maps a proto SessionStructure_PendingKeyExchange
// back to a Go PendingKeyExchangeStructure.
func pendingKeyExchangeFromProto(pke *serialize.SessionStructure_PendingKeyExchange) *librecord.PendingKeyExchangeStructure {
	if pke == nil {
		return nil
	}
	s := &librecord.PendingKeyExchangeStructure{
		LocalBaseKeyPublic:      pke.LocalBaseKey,
		LocalBaseKeyPrivate:     pke.LocalBaseKeyPrivate,
		LocalRatchetKeyPublic:   pke.LocalRatchetKey,
		LocalRatchetKeyPrivate:  pke.LocalRatchetKeyPrivate,
		LocalIdentityKeyPublic:  pke.LocalIdentityKey,
		LocalIdentityKeyPrivate: pke.LocalIdentityKeyPrivate,
	}
	if pke.Sequence != nil {
		s.Sequence = *pke.Sequence
	}
	return s
}

// pendingPreKeyToProto maps a Go PendingPreKeyStructure to proto
// SessionStructure_PendingPreKey.
// Go PendingPreKeyStructure.PreKeyID is *optional.Uint32 (which is either
// nil/empty or has a Value). Proto PreKeyId is *uint32.
func pendingPreKeyToProto(ppk *librecord.PendingPreKeyStructure) *serialize.SessionStructure_PendingPreKey {
	if ppk == nil {
		return nil
	}
	spk := int32(ppk.SignedPreKeyID)
	result := &serialize.SessionStructure_PendingPreKey{
		BaseKey:        ppk.BaseKey,
		SignedPreKeyId: &spk,
	}
	if ppk.PreKeyID != nil && !ppk.PreKeyID.IsEmpty {
		pkid := ppk.PreKeyID.Value
		result.PreKeyId = &pkid
	}
	return result
}

// pendingPreKeyFromProto maps a proto SessionStructure_PendingPreKey back to
// a Go PendingPreKeyStructure.
func pendingPreKeyFromProto(ppk *serialize.SessionStructure_PendingPreKey) *librecord.PendingPreKeyStructure {
	if ppk == nil {
		return nil
	}
	s := &librecord.PendingPreKeyStructure{
		BaseKey: ppk.BaseKey,
	}
	if ppk.SignedPreKeyId != nil {
		s.SignedPreKeyID = uint32(*ppk.SignedPreKeyId)
	}
	if ppk.PreKeyId != nil {
		s.PreKeyID = optional.NewOptionalUint32(*ppk.PreKeyId)
	} else {
		s.PreKeyID = optional.NewEmptyUint32()
	}
	return s
}

// ============================================================================
// Private mapper pairs — Go SenderKeyStateStructure ↔ proto SenderKeyStateStructure
// ============================================================================

// senderKeyStateToProto maps a Go groupRecord.SenderKeyStateStructure to
// a proto serialize.SenderKeyStateStructure.
// Non-1:1 mappings:
//   KeyID uint32            ↔ SenderKeyId *uint32          (name differs)
//   SigningKeyPublic  []byte \
//   SigningKeyPrivate []byte /  ↔ SenderSigningKey *SenderSigningKey{Public,Private}
//   Keys []*ratchet.SenderMessageKeyStructure ↔ SenderMessageKeys []*SenderMessageKey
//
// The proto SenderMessageKey carries only {Iteration *uint32; Seed []byte}.
// The Go SenderMessageKeyStructure also has IV and CipherKey (derived from Seed
// via kdf.DeriveSecrets). Only Iteration + Seed are round-tripped here; IV and
// CipherKey are re-derived at runtime from Seed on load.
func senderKeyStateToProto(state *groupRecord.SenderKeyStateStructure) *serialize.SenderKeyStateStructure {
	if state == nil {
		return nil
	}
	keyID := state.KeyID
	ss := &serialize.SenderKeyStateStructure{
		SenderKeyId: &keyID,
		SenderSigningKey: &serialize.SenderKeyStateStructure_SenderSigningKey{
			Public:  state.SigningKeyPublic,
			Private: state.SigningKeyPrivate,
		},
	}
	if state.SenderChainKey != nil {
		iter := state.SenderChainKey.Iteration
		ss.SenderChainKey = &serialize.SenderKeyStateStructure_SenderChainKey{
			Iteration: &iter,
			Seed:      state.SenderChainKey.ChainKey,
		}
	}
	if len(state.Keys) > 0 {
		ss.SenderMessageKeys = make([]*serialize.SenderKeyStateStructure_SenderMessageKey, len(state.Keys))
		for i, mk := range state.Keys {
			iter := mk.Iteration
			ss.SenderMessageKeys[i] = &serialize.SenderKeyStateStructure_SenderMessageKey{
				Iteration: &iter,
				Seed:      mk.Seed,
			}
		}
	}
	return ss
}

// senderKeyStateFromProto maps a proto serialize.SenderKeyStateStructure back
// to a Go groupRecord.SenderKeyStateStructure.
func senderKeyStateFromProto(ss *serialize.SenderKeyStateStructure) *groupRecord.SenderKeyStateStructure {
	if ss == nil {
		return nil
	}
	s := &groupRecord.SenderKeyStateStructure{}
	if ss.SenderKeyId != nil {
		s.KeyID = *ss.SenderKeyId
	}
	if ss.SenderSigningKey != nil {
		s.SigningKeyPublic = ss.SenderSigningKey.Public
		s.SigningKeyPrivate = ss.SenderSigningKey.Private
	}
	if ss.SenderChainKey != nil {
		s.SenderChainKey = &ratchet.SenderChainKeyStructure{
			ChainKey: ss.SenderChainKey.Seed,
		}
		if ss.SenderChainKey.Iteration != nil {
			s.SenderChainKey.Iteration = *ss.SenderChainKey.Iteration
		}
	}
	if len(ss.SenderMessageKeys) > 0 {
		s.Keys = make([]*ratchet.SenderMessageKeyStructure, len(ss.SenderMessageKeys))
		for i, mk := range ss.SenderMessageKeys {
			kmk := &ratchet.SenderMessageKeyStructure{}
			if mk.Iteration != nil {
				kmk.Iteration = *mk.Iteration
			}
			kmk.Seed = mk.Seed
			// IV and CipherKey are not in the proto leaf; they are re-derived
			// at runtime from Seed via NewSenderMessageKey(iteration, seed).
			s.Keys[i] = kmk
		}
	}
	return s
}

// ============================================================================
// Compile-time interface conformance assertions
// ============================================================================

var _ librecord.SessionSerializer       = (*ProtoSessionSerializer)(nil)
var _ librecord.StateSerializer         = (*ProtoStateSerializer)(nil)
var _ groupRecord.SenderKeySerializer   = (*ProtoSenderKeySerializer)(nil)
var _ groupRecord.SenderKeyStateSerializer = (*ProtoSenderKeyStateSerializer)(nil)
