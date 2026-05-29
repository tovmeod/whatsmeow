// kavtov-fork: Phase 26 regression -- guards the bare-JID normalization of the
// two inbound group sender-key sites in message.go against accidental revert
// during a future tulir/whatsmeow rebase. A reverter who restores
// `from.SignalAddress()` (device-qualified) at EITHER decryptGroupMsg (lookup)
// or handleSenderKeyDistributionMessage (store) breaks this test: the store
// record lands under one device address and the lookup misses it, yielding
// `no sender key` (signalerror.ErrNoSenderKeyForUser).
//
// WhatsApp delivers the SKDM-bearing stanza and the group skmsg stanza with
// inconsistent device qualification for the same sender. The fix keys both
// paths by the device-stripped (bare) address so they converge on one record;
// the keyID inside the message disambiguates devices.

package whatsmeow

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"go.mau.fi/libsignal/groups"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/signalerror"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// seedDeviceQualifiedRecord seeds a sender-key record directly under a
// device-qualified SenderKeyName via a receiver-side builder.Process. This
// bypasses handleSenderKeyDistributionMessage (which post-26-01 always stores
// bare :0 and cannot create a :N record for N != 0). Used by Plan 03 fallback
// tests to reproduce the legacy device-qualified state that the production
// fix targets.
//
// sender must have the desired Device set (e.g. Device=5 for ":5", Device=0
// for bare ":0"). The raw SKDM bytes are parsed and processed into cli.Store
// under the device-qualified SenderKeyName.
func seedDeviceQualifiedRecord(ctx context.Context, t *testing.T, cli *Client, chat types.JID, sender types.JID, skdmBytes []byte) {
	t.Helper()
	skdmName := protocol.NewSenderKeyName(chat.String(), sender.SignalAddress())
	sdkMsg, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, store.SignalProtobufSerializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("seedDeviceQualifiedRecord: parse SKDM: %v", err)
	}
	builder := groups.NewGroupSessionBuilder(cli.Store, store.SignalProtobufSerializer)
	if err := builder.Process(ctx, skdmName, sdkMsg); err != nil {
		t.Fatalf("seedDeviceQualifiedRecord: builder.Process: %v", err)
	}
}

// bare0User returns the SenderKeyName user string that the bare :0 fast path
// would use for the given sender (i.e. what decryptGroupMsg builds as
// senderKeyName.Sender().String()). Used to assert the bare :0 slot is absent.
func bare0User(chat types.JID, sender types.JID) string {
	return protocol.NewSenderKeyName(chat.String(), sender.ToNonAD().SignalAddress()).Sender().String()
}

// fakeSenderKeyStore is a string-keyed in-memory store.SenderKeyStore. It MUST
// mirror production's (group, user) string derivation (store/signal.go uses
// senderKeyName.Sender().String() as the user key) so that a device-qualified
// vs bare address actually changes the storage slot -- the whole point of the
// regression. libsignal's InMemorySenderKey is pointer-keyed and cannot
// reproduce the bug; the fork's store/noop.go discards writes.
//
// getDevicesCalls is an invocation counter added in Plan 03 for the
// self-extinguishing recovery assertion (TestGroupSenderKeySelfExtinguishingRecovery).
type fakeSenderKeyStore struct {
	keys            map[string][]byte
	getDevicesCalls int
}

func newFakeSenderKeyStore() *fakeSenderKeyStore {
	return &fakeSenderKeyStore{keys: make(map[string][]byte)}
}

func (f *fakeSenderKeyStore) slot(group, user string) string { return group + "|" + user }

func (f *fakeSenderKeyStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	f.keys[f.slot(group, user)] = session
	return nil
}

func (f *fakeSenderKeyStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	return f.keys[f.slot(group, user)], nil
}

// GetSenderKeyDevices is the real prefix-scan over f.keys — the in-memory
// mirror of SQLStore.GetSenderKeyDevices. It scans for slot keys equal to
// group + "|" + userBare + ":" + <dev> and returns the <userBare>:<dev>
// portion (the slot key with the group+"|" prefix removed). This ships in
// Plan 02 so the root whatsmeow test binary compiles against the enlarged
// interface; the fallback loop that calls it lands in Plan 03. Plan 03 adds
// an invocation counter (getDevicesCalls) for the self-extinguishing recovery
// assertion.
func (f *fakeSenderKeyStore) GetSenderKeyDevices(_ context.Context, group, userBare string) ([]string, error) {
	f.getDevicesCalls++ // Plan 03: invocation counter for recovery assertion
	prefix := group + "|" + userBare + ":"
	var devices []string
	for k := range f.keys {
		if strings.HasPrefix(k, prefix) {
			// slot = group + "|" + user; return the user part (after group+"|")
			devices = append(devices, k[len(group)+1:])
		}
	}
	return devices, nil
}

// aliceSenderKeyStore is Alice's own libsignal sender-key store, used ONLY to
// generate the SKDM + skmsg bytes. Pointer-keyed is fine here: Alice uses one
// consistent senderKeyName for both Create and Encrypt. It is fully
// independent of cli.Store -- only the serialized bytes cross into the fork.
type aliceSenderKeyStore struct {
	keys map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func newAliceSenderKeyStore() *aliceSenderKeyStore {
	return &aliceSenderKeyStore{keys: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey)}
}

func (a *aliceSenderKeyStore) StoreSenderKey(ctx context.Context, name *protocol.SenderKeyName, rec *groupRecord.SenderKey) error {
	a.keys[name] = rec
	return nil
}

func (a *aliceSenderKeyStore) LoadSenderKey(ctx context.Context, name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	if rec, ok := a.keys[name]; ok {
		return rec, nil
	}
	return groupRecord.NewSenderKey(store.SignalProtobufSerializer.SenderKeyRecord, store.SignalProtobufSerializer.SenderKeyState), nil
}

// newTestClient builds a minimal *Client that drives the real unexported
// decrypt machinery. EnableDecryptedEventBuffer stays at its false default so
// bufferedDecrypt short-circuits to decrypt(ctx) -- no server I/O / EventBuffer.
func newTestClient(sk store.SenderKeyStore) *Client {
	return &Client{
		Store: &store.Device{SenderKeys: sk, Log: waLog.Noop},
		Log:   waLog.Noop,
	}
}

// aliceCrypto produces the SKDM bytes and an encrypted skmsg, using
// store.SignalProtobufSerializer EXPLICITLY (the fork parse paths at
// message.go are hardcoded to pbSerializer = store.SignalProtobufSerializer).
// Alice's own libsignal sender-key store is independent of cli.Store -- only
// the serialized bytes cross into the fork methods.
func aliceCrypto(ctx context.Context, t *testing.T, group string, plaintext []byte) (skdmBytes, skmsgBytes []byte) {
	t.Helper()
	aliceStore := newAliceSenderKeyStore()
	aliceAddr := protocol.NewSignalAddress("alice", 0)
	aliceName := protocol.NewSenderKeyName(group, aliceAddr)
	builder := groups.NewGroupSessionBuilder(aliceStore, store.SignalProtobufSerializer)

	skdm, err := builder.Create(ctx, aliceName)
	if err != nil {
		t.Fatalf("alice builder.Create: %v", err)
	}
	cipher := groups.NewGroupCipher(builder, aliceName, aliceStore)
	enc, err := cipher.Encrypt(ctx, plaintext)
	if err != nil {
		t.Fatalf("alice cipher.Encrypt: %v", err)
	}
	// SignedSerialize() is the on-the-wire format (carries the signature that
	// the decrypt path's verifySignature needs); plain Serialize() omits it
	// and fails to parse.
	skm, ok := enc.(*protocol.SenderKeyMessage)
	if !ok {
		t.Fatalf("alice cipher.Encrypt returned %T, want *protocol.SenderKeyMessage", enc)
	}
	return skdm.Serialize(), skm.SignedSerialize()
}

func TestGroupSenderKeyBareJIDDeviceMismatch(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000000", Server: types.GroupServer}

	// Two LID fixtures differing ONLY in Device. SignalAddressUser() returns
	// "75811323404294_1" for both (the _1 is LIDDomain, device-independent);
	// only the Sender().String() device suffix differs (:1 store vs :2 lookup).
	// Two DISTINCT NON-ZERO devices make each per-site revert individually
	// catchable -- a Device=0 lookup would make a site-1 revert a no-op.
	senderStore := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}
	senderLookup := senderStore
	senderLookup.Device = 2

	// Asymmetry proof (SUPPORTING check, not the binding gate -- it holds for
	// both the broken and fixed fixtures): device-qualified addresses DIFFER,
	// bare (ToNonAD) addresses are IDENTICAL.
	qualStore := protocol.NewSenderKeyName(chat.String(), senderStore.SignalAddress()).Sender().String()
	qualLookup := protocol.NewSenderKeyName(chat.String(), senderLookup.SignalAddress()).Sender().String()
	if qualStore == qualLookup {
		t.Fatalf("fixture sanity: device-qualified addresses should differ, both = %q", qualStore)
	}
	bareStore := protocol.NewSenderKeyName(chat.String(), senderStore.ToNonAD().SignalAddress()).Sender().String()
	bareLookup := protocol.NewSenderKeyName(chat.String(), senderLookup.ToNonAD().SignalAddress()).Sender().String()
	if bareStore != bareLookup {
		t.Fatalf("fixture sanity: bare addresses should be identical, got %q vs %q", bareStore, bareLookup)
	}
	t.Logf("asymmetry: qualified %q != %q ; bare %q == %q", qualStore, qualLookup, bareStore, bareLookup)

	plaintext := []byte("hello bare-keyed group")
	skdmBytes, skmsgBytes := aliceCrypto(ctx, t, chat.String(), plaintext)

	cli := newTestClient(newFakeSenderKeyStore())

	// STORE via the real method under Device=1.
	cli.handleSenderKeyDistributionMessage(ctx, chat, senderStore, skdmBytes)

	// LOOKUP via the real method under Device=2 (same bare user). The "v":"3"
	// attr is REQUIRED so unpadMessage hits its version==3 early-return
	// (libsignal's GroupCipher.Encrypt applies no padMessage padding).
	skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}
	pt, _, err := cli.decryptGroupMsg(ctx, skmsgNode, senderLookup, chat, time.Now())
	if err != nil {
		// If either site is reverted to from.SignalAddress(), this is where the
		// test fails: the lookup misses the bare-stored record ->
		// signalerror.ErrNoSenderKeyForUser.
		if errors.Is(err, signalerror.ErrNoSenderKeyForUser) {
			t.Fatalf("decrypt failed with %v -- a sender-key site is device-qualified (reverted); both must use from.ToNonAD().SignalAddress()", err)
		}
		t.Fatalf("decrypt failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

// TestGroupSenderKeySameDeviceControl is a harness-soundness control: store and
// lookup under the SAME device qualification succeed regardless of the fix.
// Proves the libsignal crypto + fake-store wiring is correct, so a failure in
// the mismatch test above is attributable to the keying, not the harness.
func TestGroupSenderKeySameDeviceControl(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000001", Server: types.GroupServer}
	sender := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}

	plaintext := []byte("control same-device path")
	skdmBytes, skmsgBytes := aliceCrypto(ctx, t, chat.String(), plaintext)

	cli := newTestClient(newFakeSenderKeyStore())
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdmBytes)

	skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}
	pt, _, err := cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if err != nil {
		t.Fatalf("control decrypt failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("control plaintext mismatch: got %q want %q", pt, plaintext)
	}
}

// TestGroupSenderKeyDeviceDisregardFallback proves the DEVICE-DISREGARD
// property: a skmsg whose `from` device qualifies as :0 or :2 (bare or
// mismatched) decrypts successfully when the sender-key record exists under a
// device-qualified :5 slot — via the fallback enumerate path.
//
// This is precisely the case that 2026.05.64 (bare-only lookup) fails: the
// live :N records are orphaned, producing a sustained `no sender key` storm.
//
// The test also asserts the READ-ONLY invariant: after a fallback decrypt, the
// bare :0 slot is still absent (the fallback never creates a :0 row).
//
// RED (against unmodified message.go): decryptGroupMsg returns an error
// wrapping ErrNoSenderKeyForUser — the bare-only fast path misses the :5
// record. Task 2 adds the fallback to turn this GREEN.
func TestGroupSenderKeyDeviceDisregardFallback(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000002", Server: types.GroupServer}
	// The sender stored its key under device :5.
	senderStore := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 5}
	plaintext := []byte("device disregard fallback test")

	for _, lookupDev := range []uint8{0, 2} {
		lookupDev := lookupDev
		t.Run(strings.Join([]string{"lookupDev", string(rune('0'+lookupDev))}, ""), func(t *testing.T) {
			fake := newFakeSenderKeyStore()
			cli := newTestClient(fake)

			skdmBytes, skmsgBytes := aliceCrypto(ctx, t, chat.String(), plaintext)

			// Seed the :5 record directly (NOT via handleSenderKeyDistributionMessage,
			// which post-26-01 always stores bare :0).
			seedDeviceQualifiedRecord(ctx, t, cli, chat, senderStore, skdmBytes)

			// Deliver skmsg with from.Device = lookupDev (:0 or :2).
			senderLookup := senderStore
			senderLookup.Device = uint16(lookupDev)
			skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}
			pt, _, err := cli.decryptGroupMsg(ctx, skmsgNode, senderLookup, chat, time.Now())
			if err != nil {
				// RED (before Task 2 fallback): expect ErrNoSenderKeyForUser.
				// GREEN (after Task 2 fallback): this should not be reached.
				if errors.Is(err, signalerror.ErrNoSenderKeyForUser) {
					t.Fatalf("decrypt failed with no-sender-key — fallback not yet implemented (Task 2); err: %v", err)
				}
				t.Fatalf("decrypt failed: %v", err)
			}
			if string(pt) != string(plaintext) {
				t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
			}

			// READ-ONLY INVARIANT: after a fallback decrypt, the bare :0 slot
			// must still be absent — the fallback never creates a :0 row and
			// never merges states.
			bare0 := bare0User(chat, senderStore)
			gotBytes, _ := cli.Store.SenderKeys.GetSenderKey(ctx, chat.String(), bare0)
			if gotBytes != nil {
				t.Fatalf("read-only invariant violated: bare :0 slot %q was created by the fallback (expected absent)", bare0)
			}
		})
	}
}

// TestGroupSenderKeyFallbackAbsentSender asserts there is no false positive:
// a genuinely-absent sender (no record at any device) still returns an error
// wrapping ErrNoSenderKeyForUser.
func TestGroupSenderKeyFallbackAbsentSender(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000003", Server: types.GroupServer}
	sender := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 0}

	cli := newTestClient(newFakeSenderKeyStore())
	// No seeding — sender has no record at any device.
	_, skmsgBytes := aliceCrypto(ctx, t, chat.String(), []byte("absent sender"))

	skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}
	_, _, err := cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if err == nil {
		t.Fatal("expected error for absent sender, got nil")
	}
	if !errors.Is(err, signalerror.ErrNoSenderKeyForUser) {
		t.Fatalf("expected ErrNoSenderKeyForUser for absent sender, got: %v", err)
	}
}

// TestGroupSenderKeySelfExtinguishingRecovery proves the SELF-EXTINGUISHING
// property: once a fresh SKDM stores bare :0, the fast path hits and the
// fallback is no longer entered.
//
// This is grounded in 26-02 <cache_interaction> FACT 2: the production
// CachedSenderKeyStore never caches a :0 miss, so the fast path is
// re-evaluated on every call; once bare :0 exists, it hits and the fallback
// branch (which calls GetSenderKeyDevices) is never reached.
//
// The root test uses the in-memory fakeSenderKeyStore (no LRU), so the
// recovery is asserted via the getDevicesCalls invocation counter on the fake.
func TestGroupSenderKeySelfExtinguishingRecovery(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000004", Server: types.GroupServer}
	senderDev5 := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 5}
	senderBare := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 0}
	plaintext1 := []byte("first skmsg via fallback")

	fake := newFakeSenderKeyStore()
	cli := newTestClient(fake)

	// Step 1: seed :5 record directly and deliver first skmsg via fallback.
	skdmBytes1, skmsgBytes1 := aliceCrypto(ctx, t, chat.String(), plaintext1)
	seedDeviceQualifiedRecord(ctx, t, cli, chat, senderDev5, skdmBytes1)

	skmsgNode1 := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes1}
	pt1, _, err := cli.decryptGroupMsg(ctx, skmsgNode1, senderBare, chat, time.Now())
	if err != nil {
		// RED: before Task 2, this fails with ErrNoSenderKeyForUser.
		if errors.Is(err, signalerror.ErrNoSenderKeyForUser) {
			t.Fatalf("first decrypt (via fallback) failed with no-sender-key — fallback not yet implemented (Task 2); err: %v", err)
		}
		t.Fatalf("first decrypt failed: %v", err)
	}
	if string(pt1) != string(plaintext1) {
		t.Fatalf("first decrypt plaintext mismatch: got %q want %q", pt1, plaintext1)
	}
	// Fallback WAS entered for the first decrypt.
	if fake.getDevicesCalls < 1 {
		t.Fatalf("expected fallback to be entered on first decrypt (getDevicesCalls >= 1), got %d", fake.getDevicesCalls)
	}

	// Step 2: seed a fresh bare :0 record directly, simulating the sender's
	// next SKDM. This is NOT done via the fallback — it is done via
	// seedDeviceQualifiedRecord with Device=0 (i.e., a direct :0 Put, the
	// same path as builder.Process under the bare SenderKeyName).
	plaintext2 := []byte("second skmsg via fast path")
	skdmBytes2, skmsgBytes2 := aliceCrypto(ctx, t, chat.String(), plaintext2)
	seedDeviceQualifiedRecord(ctx, t, cli, chat, senderBare, skdmBytes2)

	// Step 3: deliver second skmsg — should hit the bare :0 fast path.
	before := fake.getDevicesCalls
	skmsgNode2 := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes2}
	pt2, _, err := cli.decryptGroupMsg(ctx, skmsgNode2, senderBare, chat, time.Now())
	if err != nil {
		t.Fatalf("second decrypt (via fast path) failed: %v", err)
	}
	if string(pt2) != string(plaintext2) {
		t.Fatalf("second decrypt plaintext mismatch: got %q want %q", pt2, plaintext2)
	}
	// Fallback was NOT entered — the fast path hit bare :0.
	if fake.getDevicesCalls != before {
		t.Fatalf("self-extinguishing invariant violated: getDevicesCalls changed from %d to %d during fast-path decrypt (fallback was entered when it should not be)", before, fake.getDevicesCalls)
	}
}
