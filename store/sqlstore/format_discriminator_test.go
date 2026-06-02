// format_discriminator_test.go — [BLOCKING] D-06 first-byte discriminator
// unambiguity proof (Phase 17.9-02, Req 6).
//
// Proves that the marker-free first-byte discriminator `raw[0] == 0x7B` is safe
// for dual-read dispatch:
//
//   TestFormatDiscriminator_JSONStartsBrace
//     Every JSON session/sender-key fixture starts with 0x7B ('{').
//
//   TestFormatDiscriminator_ProtoNeverBrace
//     Every protobuf blob from ProtoSessionSerializer/ProtoSenderKeySerializer
//     does NOT start with 0x7B.
//
//   TestFormatDiscriminator_ProtoUnmarshalRejectsJSON
//     Feeding a JSON session/sender-key blob through the ProtoSessionSerializer
//     / ProtoSenderKeySerializer Deserialize path either errors OR yields a
//     record that is NOT structurally equal to the genuine record — proving
//     that Pitfall-2 (permissive proto.Unmarshal silent success) does not pass
//     through.
//
// D-06 ESCALATION RULE: if ANY assertion fails (a protobuf blob starts 0x7B,
// or a JSON blob decodes to a usable proto record), t.Fatalf immediately.
// The SUMMARY flags this as the D-06 escalation trigger and Plan-04 dual-read
// dispatcher MUST NOT be wired. Escalate to the user for a different
// discriminator.
//
// Run: go test ./store/sqlstore/ -run TestFormatDiscriminator -race -count=1

package sqlstore

import (
	"reflect"
	"testing"
)

// ============================================================================
// Test 1: every JSON fixture starts with 0x7B
// ============================================================================

func TestFormatDiscriminator_JSONStartsBrace(t *testing.T) {
	fixtures := []struct {
		name string
		blob []byte
	}{
		// Session fixtures (produced by buildSessionBlob — same helper as benchmarks)
		{"session-0-keys", buildSessionBlob(0)},
		{"session-5-keys", buildSessionBlob(5)},
		{"session-500-keys", buildSessionBlob(500)},
		{"session-2000-keys-tail", buildSessionBlob(2000)},
		// Sender-key fixtures
		{"senderkey-0-keys", buildSenderKeyBlob(0)},
		{"senderkey-500-keys", buildSenderKeyBlob(500)},
		{"senderkey-2000-keys-tail", buildSenderKeyBlob(2000)},
	}

	for _, fx := range fixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			if len(fx.blob) == 0 {
				t.Fatalf("fixture %q produced empty blob — cannot check first byte", fx.name)
			}
			if fx.blob[0] != 0x7B {
				t.Fatalf("D-06 ESCALATION: JSON fixture %q first byte = 0x%02X, want 0x7B ('{'); "+
					"JSON discriminator assumption violated", fx.name, fx.blob[0])
			}
		})
	}
}

// ============================================================================
// Test 2: every protobuf blob from the Plan-01 serializer does NOT start 0x7B
// ============================================================================

func TestFormatDiscriminator_ProtoNeverBrace(t *testing.T) {
	protoSess := &ProtoSessionSerializer{}
	protoSK := &ProtoSenderKeySerializer{}

	// Session fixtures
	sessFixtures := []struct {
		name    string
		numKeys int
	}{
		{"session-0-keys", 0},
		{"session-5-keys", 5},
		{"session-500-keys", 500},
		{"session-2000-keys-tail", 2000},
	}
	for _, fx := range sessFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			jsonBlob := buildSessionBlob(fx.numKeys)

			// JSON → *SessionStructure → proto blob
			structure, err := pbSerializer.Session.Deserialize(jsonBlob)
			if err != nil {
				t.Fatalf("JSON Deserialize for %q failed: %v", fx.name, err)
			}
			protoBlob := protoSess.Serialize(structure)
			if len(protoBlob) == 0 {
				t.Fatalf("ProtoSessionSerializer.Serialize returned empty bytes for %q", fx.name)
			}
			if protoBlob[0] == 0x7B {
				t.Fatalf("D-06 ESCALATION: protobuf session blob %q first byte = 0x7B ('{'); "+
					"first-byte discriminator is ambiguous — do NOT wire the dual-read dispatcher; "+
					"escalate to user for a different discriminator", fx.name)
			}
		})
	}

	// Sender-key fixtures
	skFixtures := []struct {
		name    string
		numKeys int
	}{
		{"senderkey-0-keys", 0},
		{"senderkey-500-keys", 500},
		{"senderkey-2000-keys-tail", 2000},
	}
	for _, fx := range skFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			jsonBlob := buildSenderKeyBlob(fx.numKeys)

			structure, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob)
			if err != nil {
				t.Fatalf("JSON SenderKey Deserialize for %q failed: %v", fx.name, err)
			}
			protoBlob := protoSK.Serialize(structure)
			if len(protoBlob) == 0 {
				t.Fatalf("ProtoSenderKeySerializer.Serialize returned empty bytes for %q", fx.name)
			}
			if protoBlob[0] == 0x7B {
				t.Fatalf("D-06 ESCALATION: protobuf sender-key blob %q first byte = 0x7B ('{'); "+
					"first-byte discriminator is ambiguous — do NOT wire the dual-read dispatcher; "+
					"escalate to user for a different discriminator", fx.name)
			}
		})
	}

	// Also test a session with non-empty PreviousStates (proves the RecordStructure
	// wrapper path; PreviousSessions maps to proto field 2 / wiretype 2 = 0x12).
	t.Run("session-with-previous-states", func(t *testing.T) {
		// Build two independent session structures and manually combine them into
		// a SessionStructure with PreviousStates populated.
		blob0 := buildSessionBlob(0)
		blob5 := buildSessionBlob(5)

		state0, err := pbSerializer.Session.Deserialize(blob0)
		if err != nil {
			t.Fatalf("JSON Deserialize state0 failed: %v", err)
		}
		state5, err := pbSerializer.Session.Deserialize(blob5)
		if err != nil {
			t.Fatalf("JSON Deserialize state5 failed: %v", err)
		}

		// Attach state5.SessionState as a previous state on state0.
		state0.PreviousStates = append(state0.PreviousStates, state5.SessionState)

		protoBlob := protoSess.Serialize(state0)
		if len(protoBlob) == 0 {
			t.Fatalf("ProtoSessionSerializer.Serialize returned empty for session-with-previous-states")
		}
		if protoBlob[0] == 0x7B {
			t.Fatalf("D-06 ESCALATION: protobuf session-with-previous-states blob first byte = 0x7B ('{'); "+
				"first-byte discriminator is ambiguous")
		}
	})
}

// ============================================================================
// Test 3: feeding a JSON blob to the proto deserialize path does NOT silently
// yield a structurally usable record (Pitfall-2 ambiguity proof)
// ============================================================================

func TestFormatDiscriminator_ProtoUnmarshalRejectsJSON(t *testing.T) {
	protoSess := &ProtoSessionSerializer{}
	protoSK := &ProtoSenderKeySerializer{}

	// Session fixtures
	sessFixtures := []struct {
		name    string
		numKeys int
	}{
		{"session-0-keys", 0},
		{"session-500-keys", 500},
		{"session-2000-keys-tail", 2000},
	}
	for _, fx := range sessFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			jsonBlob := buildSessionBlob(fx.numKeys)

			// Genuine record via JSON path
			genuine, err := pbSerializer.Session.Deserialize(jsonBlob)
			if err != nil {
				t.Fatalf("genuine JSON Deserialize failed: %v", err)
			}

			// Production dual-read path: pass JSON blob through the proto deserializer.
			// This is the exact code path Plan-04 will wire; prove it does not silently
			// accept JSON as a valid proto record equal to the genuine one.
			got, protoErr := protoSess.Deserialize(jsonBlob)

			if protoErr == nil {
				// proto.Unmarshal did not error. Check whether the result is structurally
				// usable (equal to the genuine record). If it is, the discriminator is
				// unsafe — escalate immediately.
				normGenuine := normalizeSession(genuine)
				normGot := normalizeSession(got)
				if reflect.DeepEqual(normGenuine, normGot) {
					t.Fatalf("D-06 ESCALATION: ProtoSessionSerializer.Deserialize accepted JSON "+
						"fixture %q without error AND produced a record structurally equal to the "+
						"genuine record. first-byte discriminator is NOT safe — escalate to user; "+
						"do NOT wire the dual-read dispatcher in Plan-04", fx.name)
				}
				// proto.Unmarshal accepted the blob but the result is garbage/empty —
				// the discriminator is safe (this is the expected outcome for 0x7B blobs
				// that map to proto field 15 / wiretype-3 = start-group, which proto
				// skips as unknown).
				t.Logf("fixture %q: proto.Unmarshal returned nil error but result is structurally "+
					"different from genuine — discriminator safe (got: %+v)", fx.name, normGot)
			}
			// err != nil → proto.Unmarshal rejected the JSON blob outright → safe.
		})
	}

	// Sender-key fixtures
	skFixtures := []struct {
		name    string
		numKeys int
	}{
		{"senderkey-0-keys", 0},
		{"senderkey-2000-keys-tail", 2000},
	}
	for _, fx := range skFixtures {
		fx := fx
		t.Run(fx.name, func(t *testing.T) {
			jsonBlob := buildSenderKeyBlob(fx.numKeys)

			// Genuine record
			genuine, err := pbSerializer.SenderKeyRecord.Deserialize(jsonBlob)
			if err != nil {
				t.Fatalf("genuine JSON SenderKey Deserialize failed: %v", err)
			}

			// Proto path on JSON blob
			got, protoErr := protoSK.Deserialize(jsonBlob)

			if protoErr == nil {
				normGenuine := normalizeSenderKey(genuine)
				normGot := normalizeSenderKey(got)
				if reflect.DeepEqual(normGenuine, normGot) {
					t.Fatalf("D-06 ESCALATION: ProtoSenderKeySerializer.Deserialize accepted JSON "+
						"fixture %q without error AND produced a record structurally equal to the "+
						"genuine record. first-byte discriminator is NOT safe — escalate to user; "+
						"do NOT wire the dual-read dispatcher in Plan-04", fx.name)
				}
				t.Logf("fixture %q: proto.Unmarshal returned nil error but result is structurally "+
					"different from genuine — discriminator safe (got: %+v)", fx.name, normGot)
			}
		})
	}
}
