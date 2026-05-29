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

// fakeSenderKeyStore is a string-keyed in-memory store.SenderKeyStore. It MUST
// mirror production's (group, user) string derivation (store/signal.go uses
// senderKeyName.Sender().String() as the user key) so that a device-qualified
// vs bare address actually changes the storage slot -- the whole point of the
// regression. libsignal's InMemorySenderKey is pointer-keyed and cannot
// reproduce the bug; the fork's store/noop.go discards writes.
type fakeSenderKeyStore struct {
	keys map[string][]byte
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
// interface; the fallback loop that calls it lands in Plan 03. The two
// existing 26-01 tests pass unchanged (they don't invoke this method).
// Plan 03 will add an invocation counter — this method is intentionally
// easy to instrument (no counter here).
func (f *fakeSenderKeyStore) GetSenderKeyDevices(_ context.Context, group, userBare string) ([]string, error) {
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
