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
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.mau.fi/libsignal/groups"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/signalerror"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
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

// TestGroupSenderKeyDeviceMatchedRecovery proves Phase-27 recovery: a message
// whose sender key was first reachable only under a non-labeled device (:5)
// still decrypts via the device-tolerant loop, AND once the sender's key is
// stored under the message's labeled device (:0) the message decrypts with the
// labeled device tried first.
//
// Phase-27 note (supersedes the Phase-26 "self-extinguishing" invariant): the
// device-tolerant lookup ALWAYS enumerates the sender's device set — there is no
// fast-path/fallback split — so GetSenderKeyDevices is consulted once per
// decrypt. In production that enumerate is cache-served by CachedSenderKeyStore
// (0 DB queries warm — see the sqlstore cache tests); the in-memory
// fakeSenderKeyStore here has no LRU, so getDevicesCalls increments by exactly
// one per decrypt. The behavioral guarantee is that the decrypt SUCCEEDS.
func TestGroupSenderKeyDeviceMatchedRecovery(t *testing.T) {
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

	// Step 3: deliver second skmsg (labeled :0). The device-tolerant loop tries
	// the labeled device (:0) first and decrypts. Phase 27: the loop always
	// enumerates once (no fast-path skip), so getDevicesCalls increments by 1.
	before := fake.getDevicesCalls
	skmsgNode2 := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes2}
	pt2, _, err := cli.decryptGroupMsg(ctx, skmsgNode2, senderBare, chat, time.Now())
	if err != nil {
		t.Fatalf("second decrypt (labeled-device match) failed: %v", err)
	}
	if string(pt2) != string(plaintext2) {
		t.Fatalf("second decrypt plaintext mismatch: got %q want %q", pt2, plaintext2)
	}
	// Phase 27: the unified loop enumerates exactly once per decrypt (cache-served
	// in prod). The recovery guarantee is decrypt success, asserted above.
	if fake.getDevicesCalls != before+1 {
		t.Fatalf("expected one enumerate per decrypt (Phase 27 device-tolerant loop): getDevicesCalls %d → %d, want +1", before, fake.getDevicesCalls)
	}
}

// inlineTestDSN returns the test Postgres DSN (same convention as batchTestDSN
// in sqlstore_test, but replicated here since that function is in a separate
// package that cannot be imported from package whatsmeow).
func inlineTestDSN() string {
	if dsn := os.Getenv("TEST_DSN"); dsn != "" {
		return dsn
	}
	if dsn := os.Getenv("KAVTOV_TEST_DSN"); dsn != "" {
		return dsn
	}
	return "postgresql://kavtov_test:kavtov_test@localhost:5433/kavtov_test"
}

// insertInlineTestDevice inserts a minimal whatsmeow_device row so that
// whatsmeow_sender_keys.our_jid FK constraints are satisfied.
// Returns a cleanup function that removes the device row.
func insertInlineTestDevice(t *testing.T, db *sql.DB, jid string) func() {
	t.Helper()
	const insertQ = `
		INSERT INTO whatsmeow_device (jid, registration_id, noise_key, identity_key,
									  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
									  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (jid) DO NOTHING
	`
	thirtyTwo := bytes.Repeat([]byte{0x11}, 32)
	sixtyFour := bytes.Repeat([]byte{0x22}, 64)
	_, err := db.ExecContext(context.Background(), insertQ,
		jid, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	)
	if err != nil {
		t.Fatalf("insertInlineTestDevice %s: %v", jid, err)
	}
	return func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM whatsmeow_device WHERE jid=$1`, jid)
	}
}

// TestInlineDecryptEquivalence is the BLOCKING gate for Phase 17.12 plan 01.
//
// It proves that:
//  1. TryInlineRecovery finds a cross-account donor (B) and installs the key
//     via PutSenderKeyStructure, firing parsedReplace on C's store.
//  2. A direct-cipher retry (no GetSenderKeyDevices — warm parsedReplace hit)
//     decrypts the original plaintext.
//
// 3-account scenario: Alice (sender), B (donor account — processed Alice's SKDM),
// C (recovering account — no Alice key, calls TryInlineRecovery).
//
// Single shared *sql.DB: B and C rows differ only by our_jid; findSenderKeyDonor
// finds B's row because it has no our_jid filter. This is the production path.
//
// BLOCKING: the test DB is reachable (confirmed UP). Any SKIP means the
// harness is wrong (DSN / driver / device-row missing) — fix it; do not accept.
func TestInlineDecryptEquivalence(t *testing.T) {
	ctx := context.Background()

	// Open the test DB.
	db, err := sql.Open("pgx", inlineTestDSN())
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("test Postgres not reachable: %v", err)
	}

	// Separate JIDs to avoid collision with recovery_sender_key_test.go JIDs.
	const (
		inlineTestJIDB = "17799990031@s.whatsapp.net" // donor account (has Alice key)
		inlineTestJIDC = "17799990032@s.whatsapp.net" // recovering account (no Alice key)
	)

	cleanupB := insertInlineTestDevice(t, db, inlineTestJIDB)
	cleanupC := insertInlineTestDevice(t, db, inlineTestJIDC)
	t.Cleanup(func() {
		cleanupB()
		cleanupC()
		db.Close()
	})

	const (
		group     = "inlinedecrypt_test_group@g.us"
		plaintext = "inline recovery decrypt equivalence proof"
	)

	// Step 1: Alice generates real SKDM + skmsg.
	skdmBytes, skmsgBytes := aliceCrypto(ctx, t, group, []byte(plaintext))

	// Step 2: B processes Alice's SKDM. B needs a real *CachedSenderKeyStore
	// backed by *SQLStore (no flusher — write-through fallback writes to DB
	// immediately so findSenderKeyDonor sees the row).
	jidBParsed, err := types.ParseJID(inlineTestJIDB)
	if err != nil {
		t.Fatalf("ParseJID B: %v", err)
	}
	containerB := sqlstore.NewWithDB(db, "postgres", nil)
	innerB := sqlstore.NewSQLStore(containerB, jidBParsed)
	byteB, _ := lru.New[string, []byte](256)
	devB, _ := lru.New[string, []string](256)
	csBStore := sqlstore.NewCachedSenderKeyStore(innerB, inlineTestJIDB, byteB, devB, nil)

	// Phase 38.4-03: the parsed struct cache is deleted. The flat c.cache
	// write-through inside PutSenderKeyStructure is the single sender-key cache;
	// no parsed-cache wiring is needed.

	// Build a Device for B so builder.Process routes writes through csBStore.
	// aliceAddr is "alice:0", so the key is stored under sender_id="alice:0".
	deviceB := &store.Device{
		SenderKeys: csBStore,
		Log:        waLog.Noop,
		ID:         &jidBParsed,
	}

	// Clean up leftover rows from previous test runs.
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		inlineTestJIDB, inlineTestJIDC, group)

	// Process Alice's SKDM into B's store (same path as handleSenderKeyDistributionMessage).
	aliceAddr := protocol.NewSignalAddress("alice", 0)
	aliceSKName := protocol.NewSenderKeyName(group, aliceAddr)
	sdkMsg, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, store.SignalProtobufSerializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("parse SKDM: %v", err)
	}
	builderB := groups.NewGroupSessionBuilder(deviceB, store.SignalProtobufSerializer)
	if err := builderB.Process(ctx, aliceSKName, sdkMsg); err != nil {
		t.Fatalf("B builder.Process: %v", err)
	}
	t.Logf("B processed Alice SKDM — key stored under our_jid=%s", inlineTestJIDB)

	// Step 3: Build C's CachedSenderKeyStore on the SAME shared DB.
	// C has NO Alice key. After TryInlineRecovery's PutSenderKeyStructure write-
	// through populates the flat c.cache, the warm-cache hit in LoadSenderKey
	// during the cipher.Decrypt retry succeeds — no parsed-cache wiring needed
	// (Phase 38.4-03: parsed struct cache deleted).
	jidCParsed, err := types.ParseJID(inlineTestJIDC)
	if err != nil {
		t.Fatalf("ParseJID C: %v", err)
	}
	containerC := sqlstore.NewWithDB(db, "postgres", nil)
	innerC := sqlstore.NewSQLStore(containerC, jidCParsed)
	byteC, _ := lru.New[string, []byte](256)
	devC, _ := lru.New[string, []string](256)
	csC := sqlstore.NewCachedSenderKeyStore(innerC, inlineTestJIDC, byteC, devC, nil)

	deviceC := &store.Device{
		SenderKeys:      csC,
		InlineRecoverer: csC,
		Log:             waLog.Noop,
		ID:              &jidCParsed,
	}

	// Step 4: Call TryInlineRecovery on C.
	// labeled = Alice's signal address string ("alice:0")
	// senderBare = "alice" (from SignalAddressUser, device-stripped)
	// keyID and iter come from the SKDM (parsed from skmsg).
	parsedSKDM, err := protocol.NewSenderKeyDistributionMessageFromBytes(skdmBytes, store.SignalProtobufSerializer.SenderKeyDistributionMessage)
	if err != nil {
		t.Fatalf("re-parse SKDM for keyID: %v", err)
	}
	aliceKeyID := parsedSKDM.ID()

	labeled := aliceSKName.Sender().String() // "alice:0"
	senderBare := "alice"

	donorJID, ok, recErr := deviceC.InlineRecoverer.TryInlineRecovery(
		ctx, group, labeled, senderBare, aliceKeyID, 0)
	if recErr != nil {
		t.Fatalf("TryInlineRecovery: %v", recErr)
	}
	if !ok {
		t.Fatal("TryInlineRecovery returned ok=false — donor not found; B's key should be in shared DB")
	}
	if donorJID == "" {
		t.Fatal("TryInlineRecovery returned empty donorJID on success")
	}
	t.Logf("TryInlineRecovery succeeded: donorJID=%s", donorJID)

	// Step 5: Direct-cipher retry — construct cipher under labeled, Decrypt skmsg.
	// This validates the warm flat c.cache hit (D-04 safe: no DB round-trip).
	sep := strings.LastIndex(labeled, ":")
	devIDStr := labeled[sep+1:]
	devIDVal, err := strconv.ParseUint(devIDStr, 10, 32)
	if err != nil {
		t.Fatalf("parse device id from labeled %q: %v", labeled, err)
	}
	retryName := protocol.NewSenderKeyName(group, protocol.NewSignalAddress(labeled[:sep], uint32(devIDVal)))
	retryCipher := groups.NewGroupCipher(groups.NewGroupSessionBuilder(deviceC, store.SignalProtobufSerializer), retryName, deviceC)

	skmsg, err := protocol.NewSenderKeyMessageFromBytes(skmsgBytes, store.SignalProtobufSerializer.SenderKeyMessage)
	if err != nil {
		t.Fatalf("parse skmsg: %v", err)
	}
	decrypted, decErr := retryCipher.Decrypt(ctx, skmsg)
	if decErr != nil {
		t.Fatalf("cipher.Decrypt after TryInlineRecovery: %v", decErr)
	}
	if string(decrypted) != plaintext {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", decrypted, plaintext)
	}
	t.Logf("PASS: TestInlineDecryptEquivalence — donor=%s, decrypted=%q", donorJID, decrypted)
}
