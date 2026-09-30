// decode_once_bench_test.go — D-01/D-03 gate benchmark for Phase 17.8/17.9.
//
// Measures these arms for session records:
//   (a) Full parse JSON: NewSessionFromBytes (Deserialize JSON → NewSessionFromStructure)
//   (b) Deserialize only JSON: pbSerializer.Session.Deserialize (JSON→SessionStructure)
//   (c) Graph rebuild only: NewSessionFromStructure (SessionStructure→*Session) [format-independent]
//
// Plus, for sender-key records:
//   (d) Full parse JSON: NewSenderKeyFromBytes
//   (e) SenderKey Deserialize only JSON
//   (f) SenderKey graph rebuild only [format-independent]
//
// "Clone" via structure-cache means caching the *SessionStructure from (b) and
// paying (c) per decrypt hit instead of (a). Only paths (b)+(c) decomposition
// can answer whether structure-caching moves both CPU and allocs.
//
// NOTE: libsignal Session/State/Chain have all-unexported fields; there is no
// Clone() method. The only correct non-aliasing "copy" available from outside
// the libsignal package is NewSessionFromStructure.

package sqlstore

import (
	"encoding/json"
	"testing"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/serialize"
	librecord "go.mau.fi/libsignal/state/record"
)

var pbSerializer = serialize.NewProtoBufSerializer()

// -----------------------------------------------------------------------------
// Session benchmark helpers
// -----------------------------------------------------------------------------

// buildSessionBlob constructs a synthetic session blob with the given number
// of skipped-message-keys in the first receiver chain.
// Structure:
//
//	SessionState.SenderChain with no skipped keys
//	ReceiverChains[0].MessageKeys with numKeys entries (worst-case ratchet lag)
//
// Each skipped MessageKey is represented as a *message.KeysStructure with
// fixed 32-byte arrays; this matches the worst-case in the wild.
func buildSessionBlob(numKeys int) []byte {
	type chainKeyStruct struct {
		Index uint32
		Key   []byte
	}
	type msgKeyStruct struct {
		CipherKey []byte
		MacKey    []byte
		Iv        []byte
		Index     uint32
	}
	type chainStruct struct {
		SenderRatchetKeyPublic  []byte
		SenderRatchetKeyPrivate []byte
		ChainKey                chainKeyStruct
		MessageKeys             []msgKeyStruct
	}
	type stateStruct struct {
		SessionVersion       int
		LocalIdentityPublic  []byte
		RemoteIdentityPublic []byte
		RootKey              []byte
		PreviousCounter      uint32
		SenderBaseKey        []byte
		SenderChain          chainStruct
		ReceiverChains       []chainStruct
		LocalRegistrationID  uint32
		RemoteRegistrationID uint32
	}
	type sessionStruct struct {
		SessionState   stateStruct
		PreviousStates []stateStruct
	}

	// Build synthetic 32-byte keys (must be valid Curve25519 pubkeys: prefix 0x05).
	pub32 := func() []byte {
		b := make([]byte, 33)
		b[0] = 0x05
		for i := 1; i < 33; i++ {
			b[i] = byte(i)
		}
		return b
	}
	priv32 := func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return b
	}
	key32 := func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i + 2)
		}
		return b
	}

	msgKeys := make([]msgKeyStruct, numKeys)
	for i := range msgKeys {
		msgKeys[i] = msgKeyStruct{
			CipherKey: key32(),
			MacKey:    key32(),
			Iv:        key32()[:16],
			Index:     uint32(i),
		}
	}

	senderChain := chainStruct{
		SenderRatchetKeyPublic:  pub32(),
		SenderRatchetKeyPrivate: priv32(),
		ChainKey:                chainKeyStruct{Index: 0, Key: key32()},
		MessageKeys:             nil,
	}
	receiverChain := chainStruct{
		SenderRatchetKeyPublic:  pub32(),
		SenderRatchetKeyPrivate: priv32(),
		ChainKey:                chainKeyStruct{Index: uint32(numKeys), Key: key32()},
		MessageKeys:             msgKeys,
	}

	state := stateStruct{
		SessionVersion:       3,
		LocalIdentityPublic:  pub32(),
		RemoteIdentityPublic: pub32(),
		RootKey:              key32(),
		SenderBaseKey:        pub32(),
		SenderChain:          senderChain,
		ReceiverChains:       []chainStruct{receiverChain},
		LocalRegistrationID:  12345,
		RemoteRegistrationID: 67890,
	}

	sess := sessionStruct{
		SessionState:   state,
		PreviousStates: nil,
	}

	b, err := json.Marshal(sess)
	if err != nil {
		panic("buildSessionBlob: " + err.Error())
	}
	return b
}

// sessionBlob0 is a typical session (no skipped keys — steady state).
var sessionBlob0 = buildSessionBlob(0)

// sessionBlob500 is a moderately lagged session.
var sessionBlob500 = buildSessionBlob(500)

// sessionBlob2000 is the worst-case session (2000 skipped-message-keys).
var sessionBlob2000 = buildSessionBlob(2000)

// deserializeSessionOnly calls JSONSessionSerializer.Deserialize and returns
// the raw *SessionStructure without graph-rebuild. This is arm (b).
func deserializeSessionOnly(blob []byte) (*librecord.SessionStructure, error) {
	return pbSerializer.Session.Deserialize(blob)
}

// graphRebuildSession calls NewSessionFromStructure. This is arm (c).
func graphRebuildSession(s *librecord.SessionStructure) (*librecord.Session, error) {
	return librecord.NewSessionFromStructure(s, pbSerializer.Session, pbSerializer.State)
}

// fullParseSession is arm (a).
func fullParseSession(blob []byte) (*librecord.Session, error) {
	return librecord.NewSessionFromBytes(blob, pbSerializer.Session, pbSerializer.State)
}

// -----------------------------------------------------------------------------
// Session benchmarks
// -----------------------------------------------------------------------------

// ---------------- Session FullParse JSON arms (arm a) ----------------

// BenchmarkSession_FullParse_JSON_0Keys is arm (a) with 0 skipped keys (typical).
func BenchmarkSession_FullParse_JSON_0Keys(b *testing.B) {
	blob := sessionBlob0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSession(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// BenchmarkSession_FullParse_JSON_500Keys is arm (a) with 500 skipped keys.
func BenchmarkSession_FullParse_JSON_500Keys(b *testing.B) {
	blob := sessionBlob500
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSession(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// BenchmarkSession_FullParse_JSON_2000Keys is arm (a) with 2000 skipped keys (worst case).
func BenchmarkSession_FullParse_JSON_2000Keys(b *testing.B) {
	blob := sessionBlob2000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSession(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// ---------------- Session DeserializeOnly JSON arms (arm b) ----------------

// BenchmarkSession_DeserializeOnly_JSON_0Keys is arm (b) with 0 skipped keys.
func BenchmarkSession_DeserializeOnly_JSON_0Keys(b *testing.B) {
	blob := sessionBlob0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSessionOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

// BenchmarkSession_DeserializeOnly_JSON_500Keys is arm (b) with 500 skipped keys.
func BenchmarkSession_DeserializeOnly_JSON_500Keys(b *testing.B) {
	blob := sessionBlob500
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSessionOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

// BenchmarkSession_DeserializeOnly_JSON_2000Keys is arm (b) with 2000 skipped keys.
func BenchmarkSession_DeserializeOnly_JSON_2000Keys(b *testing.B) {
	blob := sessionBlob2000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSessionOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

// BenchmarkSession_GraphRebuild_0Keys is arm (c) with 0 skipped keys.
// This represents "clone cost" when using structure-cache approach: cache
// *SessionStructure, call NewSessionFromStructure per decrypt.
func BenchmarkSession_GraphRebuild_0Keys(b *testing.B) {
	blob := sessionBlob0
	structure, err := deserializeSessionOnly(blob)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graphRebuildSession(structure)
		if err != nil {
			b.Fatalf("graph rebuild failed: %v", err)
		}
	}
}

// BenchmarkSession_GraphRebuild_500Keys is arm (c) with 500 skipped keys.
func BenchmarkSession_GraphRebuild_500Keys(b *testing.B) {
	blob := sessionBlob500
	structure, err := deserializeSessionOnly(blob)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graphRebuildSession(structure)
		if err != nil {
			b.Fatalf("graph rebuild failed: %v", err)
		}
	}
}

// BenchmarkSession_GraphRebuild_2000Keys is arm (c) with 2000 skipped keys (worst case).
func BenchmarkSession_GraphRebuild_2000Keys(b *testing.B) {
	blob := sessionBlob2000
	structure, err := deserializeSessionOnly(blob)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graphRebuildSession(structure)
		if err != nil {
			b.Fatalf("graph rebuild failed: %v", err)
		}
	}
}

// -----------------------------------------------------------------------------
// Sender-key benchmark helpers
// -----------------------------------------------------------------------------

// buildSenderKeyBlob constructs a synthetic sender-key blob with numKeys
// skipped message keys in SenderKeyStates[0].
func buildSenderKeyBlob(numKeys int) []byte {
	// Field names MUST match libsignal's structure JSON keys: the chain key is
	// SenderChainKeyStructure.ChainKey (NOT "Seed"), and a skipped message key is
	// SenderMessageKeyStructure{Iteration,IV,CipherKey,Seed}. Earlier fixtures
	// named the chain field "Seed" and omitted IV/CipherKey, yielding a structure
	// with an empty chain key and empty IV/CipherKey — invalid lengths that the
	// flat-cache length guard correctly refuses. Use real lengths (chainKey=32,
	// iv=16, cipherKey=32, seed=32).
	type senderMsgKeyStruct struct {
		Iteration uint32
		IV        []byte
		CipherKey []byte
		Seed      []byte
	}
	type chainKeyStruct struct {
		Iteration uint32
		ChainKey  []byte
	}
	type senderKeyStateStruct struct {
		SenderKeyStateStructure struct {
			KeyID          uint32
			SenderChainKey chainKeyStruct
			// Keys are the skipped-message-keys (up to 2000 in SenderKeyState)
			Keys              []senderMsgKeyStruct
			SigningKeyPublic  []byte
			SigningKeyPrivate []byte
		}
	}
	type senderKeyRecordStruct struct {
		SenderKeyStates []struct {
			KeyID             uint32
			SenderChainKey    chainKeyStruct
			Keys              []senderMsgKeyStruct
			SigningKeyPublic  []byte
			SigningKeyPrivate []byte
		}
	}

	key32 := func() []byte {
		b := make([]byte, 32)
		for i := range b {
			b[i] = byte(i + 3)
		}
		return b
	}
	pub33 := func() []byte {
		b := make([]byte, 33)
		b[0] = 0x05
		for i := 1; i < 33; i++ {
			b[i] = byte(i)
		}
		return b
	}

	key16 := func() []byte {
		b := make([]byte, 16)
		for i := range b {
			b[i] = byte(i + 7)
		}
		return b
	}
	msgKeys := make([]senderMsgKeyStruct, numKeys)
	for i := range msgKeys {
		msgKeys[i] = senderMsgKeyStruct{
			Iteration: uint32(i),
			IV:        key16(),
			CipherKey: key32(),
			Seed:      key32(),
		}
	}

	record := senderKeyRecordStruct{}
	record.SenderKeyStates = []struct {
		KeyID             uint32
		SenderChainKey    chainKeyStruct
		Keys              []senderMsgKeyStruct
		SigningKeyPublic  []byte
		SigningKeyPrivate []byte
	}{
		{
			KeyID: 1,
			SenderChainKey: chainKeyStruct{
				Iteration: uint32(numKeys),
				ChainKey:  key32(),
			},
			Keys:              msgKeys,
			SigningKeyPublic:  pub33(),
			SigningKeyPrivate: key32(),
		},
	}

	b, err := json.Marshal(record)
	if err != nil {
		panic("buildSenderKeyBlob: " + err.Error())
	}
	return b
}

// senderKeyBlob0 is a typical sender-key (no skipped keys).
var senderKeyBlob0 = buildSenderKeyBlob(0)

// senderKeyBlob500 is a moderately lagged sender-key.
var senderKeyBlob500 = buildSenderKeyBlob(500)

// senderKeyBlob2000 is the worst-case sender-key (2000 skipped message keys).
var senderKeyBlob2000 = buildSenderKeyBlob(2000)

// fullParseSenderKey is arm (d) for sender-key.
func fullParseSenderKey(blob []byte) (*groupRecord.SenderKey, error) {
	return groupRecord.NewSenderKeyFromBytes(blob, pbSerializer.SenderKeyRecord, pbSerializer.SenderKeyState)
}

// deserializeSenderKeyOnly is arm (e): JSON→*SenderKeyStructure only.
func deserializeSenderKeyOnly(blob []byte) (*groupRecord.SenderKeyStructure, error) {
	return pbSerializer.SenderKeyRecord.Deserialize(blob)
}

// graphRebuildSenderKey is arm (f): *SenderKeyStructure→*SenderKey.
func graphRebuildSenderKey(s *groupRecord.SenderKeyStructure) (*groupRecord.SenderKey, error) {
	return groupRecord.NewSenderKeyFromStruct(s, pbSerializer.SenderKeyRecord, pbSerializer.SenderKeyState)
}

// -----------------------------------------------------------------------------
// Sender-key benchmarks
// -----------------------------------------------------------------------------

// ---------------- SenderKey FullParse JSON arms (arm d) ----------------

func BenchmarkSenderKey_FullParse_JSON_0Keys(b *testing.B) {
	blob := senderKeyBlob0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSenderKey(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_FullParse_JSON_500Keys(b *testing.B) {
	blob := senderKeyBlob500
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSenderKey(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_FullParse_JSON_2000Keys(b *testing.B) {
	blob := senderKeyBlob2000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := fullParseSenderKey(blob)
		if err != nil {
			b.Fatalf("parse failed: %v", err)
		}
	}
}

// ---------------- SenderKey DeserializeOnly JSON arms (arm e) ----------------

func BenchmarkSenderKey_DeserializeOnly_JSON_0Keys(b *testing.B) {
	blob := senderKeyBlob0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSenderKeyOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_DeserializeOnly_JSON_500Keys(b *testing.B) {
	blob := senderKeyBlob500
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSenderKeyOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_DeserializeOnly_JSON_2000Keys(b *testing.B) {
	blob := senderKeyBlob2000
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deserializeSenderKeyOnly(blob)
		if err != nil {
			b.Fatalf("deserialize failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_GraphRebuild_0Keys(b *testing.B) {
	blob := senderKeyBlob0
	structure, err := deserializeSenderKeyOnly(blob)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graphRebuildSenderKey(structure)
		if err != nil {
			b.Fatalf("graph rebuild failed: %v", err)
		}
	}
}

func BenchmarkSenderKey_GraphRebuild_2000Keys(b *testing.B) {
	blob := senderKeyBlob2000
	structure, err := deserializeSenderKeyOnly(blob)
	if err != nil {
		b.Fatalf("setup failed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := graphRebuildSenderKey(structure)
		if err != nil {
			b.Fatalf("graph rebuild failed: %v", err)
		}
	}
}
