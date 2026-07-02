// kavtov-fork (55.1-08): SKDM parse-fail visibility + per-(sender,group) dedup tests (D-11
// corrected per 55.1-INVESTIGATION-skdm.md). The 32-byte payloads captured in prod are proven
// external-format garbage (two @lid devices, not a fixable libsignal-version gap) -- there is no
// valid parse to recover. Correct handling: the FIRST parse failure per (sender,group) pair emits
// the full Error diagnostic (unchanged level, unchanged byte0/verNibble/hex fields); every repeat
// from the SAME pair only counts (skdmParseFailTotal) without re-emitting; a second distinct pair
// still gets its own first-occurrence Error; and no install/recovery write is ever attempted on a
// parse failure (mirrors the write-count-proof style of skdm_dedup_test.go).

package whatsmeow

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/libsignal/serialize"
	"go.mau.fi/libsignal/signalerror"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waAdv"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/keys"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// errCapture records Errorf calls so tests can assert exact first-occurrence-only emission.
// Implements waLog.Logger; Sub returns itself. Mirrors warnCapture in bot_resend_blacklist_test.go.
type errCapture struct {
	mu     sync.Mutex
	errors []string
}

func (l *errCapture) Infof(string, ...interface{})  {}
func (l *errCapture) Warnf(string, ...interface{})  {}
func (l *errCapture) Debugf(string, ...interface{}) {}
func (l *errCapture) Sub(string) waLog.Logger       { return l }
func (l *errCapture) Errorf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errors = append(l.errors, msg)
}
func (l *errCapture) errCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, e := range l.errors {
		if strings.Contains(e, substr) {
			n++
		}
	}
	return n
}

// nonConformantSKDMBytes is a real captured 32-byte SKDM_PARSE_FAIL_BYTES sample
// (55.1-INVESTIGATION-skdm.md §3, sample 0) -- proven too short and version-byte-less to be any
// valid or truncated whatsmeow SenderKeyDistributionMessage (min 35 bytes, fixed 0x33 version
// byte). Decoding fails immediately in proto.Unmarshal on the 31 bytes after the stripped version
// nibble.
func nonConformantSKDMBytes(t *testing.T) []byte {
	t.Helper()
	b, err := hex.DecodeString("01d7e68975509f6be5871050e2bc280839ec27a9669bc2c60c2eefe39ac99dd2")
	if err != nil {
		t.Fatalf("bad test fixture hex: %v", err)
	}
	if len(b) != 32 {
		t.Fatalf("test fixture is %d bytes, want 32 (matching the documented failing shape)", len(b))
	}
	return b
}

// TestSKDMParseFail_FirstOccurrencePerPairEmitsError verifies the first parse failure for a
// (sender,group) pair emits both existing Error lines, every repeat from the SAME pair emits
// neither (only Debugf), every occurrence still advances skdmParseFailTotal, and no
// install/recovery write is ever attempted.
func TestSKDMParseFail_FirstOccurrencePerPairEmitsError(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000090", Server: types.GroupServer}
	from := types.JID{User: "249439369334987", Server: types.HiddenUserServer, Device: 46}
	badBytes := nonConformantSKDMBytes(t)

	log := &errCapture{}
	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)
	cli.Log = log

	startTotal := skdmParseFailTotal.Load()

	for i := 0; i < 5; i++ {
		cli.handleSenderKeyDistributionMessage(ctx, chat, from, badBytes)
	}

	if n := log.errCount("Failed to parse sender key distribution message"); n != 1 {
		t.Errorf("first-line Error emitted %d times across 5 repeats of the SAME pair, want exactly 1", n)
	}
	if n := log.errCount("SKDM_PARSE_FAIL_BYTES"); n != 1 {
		t.Errorf("SKDM_PARSE_FAIL_BYTES emitted %d times across 5 repeats of the SAME pair, want exactly 1", n)
	}
	if got := skdmParseFailTotal.Load() - startTotal; got != 5 {
		t.Errorf("skdmParseFailTotal advanced by %d across 5 calls, want 5 (every occurrence must count)", got)
	}
	if sk.putCalls != 0 {
		t.Errorf("PutSenderKey called %d times on parse failures, want 0 (no install/recovery attempt -- "+
			"a parse-fail SKDM installs no key and must never retry)", sk.putCalls)
	}
}

// TestSKDMParseFail_SecondDistinctPairGetsOwnFirstOccurrence verifies a second (sender,group)
// pair still gets its own first-occurrence Error even though a different pair already fired.
func TestSKDMParseFail_SecondDistinctPairGetsOwnFirstOccurrence(t *testing.T) {
	ctx := context.Background()
	chatA := types.JID{User: "120363000000000091", Server: types.GroupServer}
	chatB := types.JID{User: "120363000000000092", Server: types.GroupServer}
	fromA := types.JID{User: "249439369334987", Server: types.HiddenUserServer, Device: 46}
	fromB := types.JID{User: "275204576162033", Server: types.HiddenUserServer, Device: 25}
	badBytes := nonConformantSKDMBytes(t)

	log := &errCapture{}
	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)
	cli.Log = log

	cli.handleSenderKeyDistributionMessage(ctx, chatA, fromA, badBytes)
	cli.handleSenderKeyDistributionMessage(ctx, chatA, fromA, badBytes) // repeat of pair A: no new Error
	cli.handleSenderKeyDistributionMessage(ctx, chatB, fromB, badBytes) // distinct pair B: own first-occurrence

	if n := log.errCount("Failed to parse sender key distribution message"); n != 2 {
		t.Errorf("two distinct pairs (one repeated) produced %d Error lines, want 2 (one per distinct pair)", n)
	}
}

// TestSKDMParseFailShouldEmit_BareClientNoNilPanic verifies a bare &Client{} does not nil-panic
// on the parse-fail dedup registry (lazy-init, mirroring markSKDMProcessed's bare-Client safety),
// and that the underlying method itself returns true-then-false for a repeated pair.
func TestSKDMParseFailShouldEmit_BareClientNoNilPanic(t *testing.T) {
	bare := &Client{}
	if !bare.skdmParseFailShouldEmit("249439369334987", "120363000000000093") {
		t.Fatal("first call on bare &Client{}: want true (first occurrence), got false")
	}
	if bare.skdmParseFailShouldEmit("249439369334987", "120363000000000093") {
		t.Fatal("second call for same pair: want false (repeat), got true")
	}
}

// TestSKDMParseFailShouldEmit_BoundedOverflowCountsWithoutOwnFirstEmit verifies the registry is
// bounded at skdmParseFailPairsSize: once full, a brand-new distinct pair is counted but does not
// get its own first-occurrence Error (D-11's future-storm guard; today's shape is two senders).
func TestSKDMParseFailShouldEmit_BoundedOverflowCountsWithoutOwnFirstEmit(t *testing.T) {
	bare := &Client{}
	for i := 0; i < skdmParseFailPairsSize; i++ {
		key := "sender" + strconv.Itoa(i)
		if !bare.skdmParseFailShouldEmit(key, "group") {
			t.Fatalf("pair %d: want first-occurrence true (registry not yet full)", i)
		}
	}
	if bare.skdmParseFailShouldEmit("overflow-sender", "group") {
		t.Fatal("pair beyond skdmParseFailPairsSize: want false (overflow counts only, no own first-occurrence Error)")
	}
	if bare.skdmParseFailOverflow != 1 {
		t.Errorf("skdmParseFailOverflow = %d, want 1", bare.skdmParseFailOverflow)
	}
}

// --- 55.1-06 Task 1: D-06 Option B unavailable-message WARN collapse (classes 3/9) -------------
//
// unavailableMessageTestSetup wires a bare &Client{} with SynchronousAck=true (so
// backgroundIfAsyncAck runs the ack inline instead of racing a goroutine), a sendNodeFunc hook to
// observe the outbound <ack>, and an event handler to capture the dispatched
// events.UndecryptableMessage -- no socket, no PG.
func unavailableMessageTestSetup(t *testing.T) (cli *Client, log *warnCapture, ackSent *bool, dispatched **events.UndecryptableMessage) {
	t.Helper()
	log = &warnCapture{}
	cli = &Client{Log: log, SynchronousAck: true}
	var sent bool
	ackSent = &sent
	cli.sendNodeFunc = func(_ context.Context, node waBinary.Node) error {
		if node.Tag == "ack" {
			*ackSent = true
		}
		return nil
	}
	var got *events.UndecryptableMessage
	dispatched = &got
	cli.AddEventHandler(func(evt any) {
		if um, ok := evt.(*events.UndecryptableMessage); ok {
			*dispatched = um
		}
	})
	return
}

// TestUnavailableMessage_NoWarnAckAndEventUnchanged verifies, for both unavailable-message type
// variants ("" and "view_once"), that the ack still fires, no Warn-level log is emitted (D-06
// Option B demotes it to Debug), the dispatched events.UndecryptableMessage carries the same
// IsUnavailable/UnavailableType fields as before, and AutomaticMessageRerequestFromPhone (left at
// its zero value, false) is never flipped into a phone-fetch call.
func TestUnavailableMessage_NoWarnAckAndEventUnchanged(t *testing.T) {
	for _, uType := range []string{"", "view_once"} {
		t.Run("type="+uType, func(t *testing.T) {
			cli, log, ackSent, dispatched := unavailableMessageTestSetup(t)

			info := &types.MessageInfo{
				MessageSource: types.MessageSource{
					Chat:   types.JID{User: "120363000000000099", Server: types.GroupServer},
					Sender: types.JID{User: "15550009999", Server: types.DefaultUserServer},
				},
				ID: "UNAVAIL-TEST-ID",
			}
			node := &waBinary.Node{
				Tag:   "message",
				Attrs: waBinary.Attrs{"id": string(info.ID), "from": info.Chat},
				Content: []waBinary.Node{
					{Tag: "unavailable", Attrs: waBinary.Attrs{"type": uType}},
				},
			}

			cli.decryptMessages(context.Background(), info, node)

			if !*ackSent {
				t.Error("want sendAck to fire for an unavailable-message placeholder, but no <ack> was sent")
			}
			if n := log.warnCount("Unavailable message"); n != 0 {
				t.Errorf("Warn-level log fired %d times for unavailable message (type %q), want 0 (D-06 Option B demotes to Debug)", n, uType)
			}
			if *dispatched == nil {
				t.Fatal("events.UndecryptableMessage was not dispatched")
			}
			if !(*dispatched).IsUnavailable {
				t.Error("dispatched event IsUnavailable = false, want true")
			}
			if (*dispatched).UnavailableType != events.UnavailableType(uType) {
				t.Errorf("dispatched event UnavailableType = %q, want %q", (*dispatched).UnavailableType, uType)
			}
		})
	}
}

// --- 55.1-06 Task 2: newsletter body-less plaintext (class 6) -----------------------------------

// TestHandlePlaintextMessage_NewsletterEmptyPlaintext verifies a <plaintext> node with no byte
// content from a @newsletter sender (one of the five spec'd byte-free newsletter sub-types --
// reaction / reaction-revoke / revoke / poll-vote / WAMOEmpty, per
// 55.1-INVESTIGATION-message-classes.md §2) is recognized and counted, not warned.
func TestHandlePlaintextMessage_NewsletterEmptyPlaintext(t *testing.T) {
	log := &warnCapture{}
	cli := &Client{Log: log}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Sender: types.JID{User: "120363000000000098", Server: types.NewsletterServer},
			Chat:   types.JID{User: "120363000000000098", Server: types.NewsletterServer},
		},
	}
	node := &waBinary.Node{
		Tag: "message",
		Content: []waBinary.Node{
			{Tag: "plaintext", Content: nil},
		},
	}
	startCount := newsletterControlEmpty.Load()

	handlerFailed := cli.handlePlaintextMessage(context.Background(), info, node)

	if handlerFailed {
		t.Error("handlerFailed = true, want false for a recognized newsletter control event")
	}
	if n := log.warnCount("doesn't have byte content"); n != 0 {
		t.Errorf("Warn-level log fired %d times for body-less newsletter plaintext, want 0 (recognized newsletter control event)", n)
	}
	if got := newsletterControlEmpty.Load() - startCount; got != 1 {
		t.Errorf("newsletterControlEmpty advanced by %d, want 1", got)
	}
}

// TestHandlePlaintextMessage_NonNewsletterEmptyPlaintextStillWarns verifies the same node shape
// from a non-newsletter sender has no legitimate byte-free shape and still warns (regression guard
// against over-broadening the newsletter early-return).
func TestHandlePlaintextMessage_NonNewsletterEmptyPlaintextStillWarns(t *testing.T) {
	log := &warnCapture{}
	cli := &Client{Log: log}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Sender: types.JID{User: "15550001234", Server: types.DefaultUserServer},
			Chat:   types.JID{User: "15550001234", Server: types.DefaultUserServer},
		},
	}
	node := &waBinary.Node{
		Tag: "message",
		Content: []waBinary.Node{
			{Tag: "plaintext", Content: nil},
		},
	}

	cli.handlePlaintextMessage(context.Background(), info, node)

	if n := log.warnCount("doesn't have byte content"); n != 1 {
		t.Errorf("Warn-level log fired %d times for non-newsletter body-less plaintext, want 1 (genuine anomaly, no legitimate byte-free shape)", n)
	}
}

// --- 55.1-07 Task 1/2/3: old-counter / old-message-version / status-broadcast-no-valid-sessions /
// STALE_PREKEY dedup ------------------------------------------------------------------------------
//
// handleDecryptError (message.go) is a pure extraction of decryptMessages' decrypt-error
// classification chain -- decryptMessages calls it with exactly these arguments, so calling it
// directly with a sentinel-wrapped error exercises the real production branch-routing code (log
// level, ack, retry-receipt, event dispatch). Reproducing the exact libsignal session/ciphertext
// state that PRODUCES ErrOldCounter/ErrNoValidSessions in prod (an established Signal session with
// specific ratchet state) is out of this plan's scope -- libsignal's own test suite already covers
// that error-derivation logic; errors.Is classification behaves identically for a
// directly-constructed sentinel-wrapped error and a real one, since Go error identity is
// location-independent. ErrOldMessageVersion is the one exception: it fires purely from parsing raw
// ciphertext bytes with no session involved, so it gets a real end-to-end test through
// cli.decryptMessages with crafted bytes below.

// decryptErrorCapture records Warnf/Debugf/Infof calls so tests can assert exact log-level routing.
// Implements waLog.Logger; Sub returns itself.
type decryptErrorCapture struct {
	mu     sync.Mutex
	warns  []string
	debugs []string
}

func (l *decryptErrorCapture) Errorf(string, ...interface{}) {}
func (l *decryptErrorCapture) Infof(string, ...interface{})  {}
func (l *decryptErrorCapture) Sub(string) waLog.Logger       { return l }
func (l *decryptErrorCapture) Warnf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}
func (l *decryptErrorCapture) Debugf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, msg)
}
func countSubstr(lines []string, substr string) int {
	n := 0
	for _, s := range lines {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}
func (l *decryptErrorCapture) warnCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return countSubstr(l.warns, substr)
}
func (l *decryptErrorCapture) debugCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return countSubstr(l.debugs, substr)
}

// fakeGenOnePreKeyStore implements store.PreKeyStore just enough for sendRetryReceipt's
// forceIncludeIdentity path (GenOnePreKey) -- the rest of the interface is unused by that path.
// calls counts GenOnePreKey invocations so tests can prove forceIncludeIdentity actually took the
// keys-inclusion branch (sendRetryReceipt itself sends over the real cli.sendNode, which is NOT
// covered by cli.sendNodeFunc -- see sendNodeOrHook's doc -- so the outbound wire node is not
// observable from a bare &Client{} test; GenOnePreKey invocation is the reliable proxy).
type fakeGenOnePreKeyStore struct {
	mu     sync.Mutex
	nextID uint32
	calls  int
}

func (f *fakeGenOnePreKeyStore) GetOrGenPreKeys(context.Context, uint32) ([]*keys.PreKey, error) {
	return nil, nil
}
func (f *fakeGenOnePreKeyStore) GenOnePreKey(context.Context) (*keys.PreKey, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.nextID++
	return keys.NewPreKey(f.nextID), nil
}
func (f *fakeGenOnePreKeyStore) GetPreKey(context.Context, uint32) (*keys.PreKey, error) {
	return nil, nil
}
func (f *fakeGenOnePreKeyStore) RemovePreKey(context.Context, uint32) error          { return nil }
func (f *fakeGenOnePreKeyStore) MarkPreKeysAsUploaded(context.Context, uint32) error { return nil }
func (f *fakeGenOnePreKeyStore) UploadedPreKeyCount(context.Context) (int, error)    { return 0, nil }
func (f *fakeGenOnePreKeyStore) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// decryptErrorTestSetup wires a bare &Client{} with SynchronousAck=true (so sendRetryReceipt/sendAck
// run inline instead of racing a goroutine), a minimal real Store (sendRetryReceipt always reads
// Store.RegistrationID, and reads Store.PreKeys/IdentityKey/SignedPreKey/Account when
// forceIncludeIdentity fires), a sendNodeFunc hook that records every outbound ack node (sendAck
// goes through sendNodeOrHook, so it IS observable), and an event handler that captures the last
// dispatched events.UndecryptableMessage -- no socket, no PG. Mirrors unavailableMessageTestSetup's
// style. The returned *fakeGenOnePreKeyStore lets tests prove sendRetryReceipt's forceIncludeIdentity
// branch fired (see the type doc -- the outbound retry-receipt node itself is not observable).
func decryptErrorTestSetup(t *testing.T) (cli *Client, log *decryptErrorCapture, sentNodes *[]waBinary.Node, dispatched **events.UndecryptableMessage, preKeys *fakeGenOnePreKeyStore) {
	t.Helper()
	log = &decryptErrorCapture{}
	identityKey := keys.NewKeyPair()
	preKeys = &fakeGenOnePreKeyStore{}
	cli = &Client{
		Log:            log,
		SynchronousAck: true,
		Store: &store.Device{
			Log:            waLog.Noop,
			RegistrationID: 12345,
			IdentityKey:    identityKey,
			SignedPreKey:   identityKey.CreateSignedPreKey(1),
			PreKeys:        preKeys,
			Account:        &waAdv.ADVSignedDeviceIdentity{},
		},
	}
	var nodes []waBinary.Node
	sentNodes = &nodes
	cli.sendNodeFunc = func(_ context.Context, node waBinary.Node) error {
		*sentNodes = append(*sentNodes, node)
		return nil
	}
	var got *events.UndecryptableMessage
	dispatched = &got
	cli.AddEventHandler(func(evt any) {
		if um, ok := evt.(*events.UndecryptableMessage); ok {
			*dispatched = um
		}
	})
	return
}

// retryAttemptCount reads cli.retryAttempts directly (same package) to prove sendRetryReceipt's
// registerRetryAttempt ran for (msgID, sender) -- registerRetryAttempt executes before the actual
// wire send, so this is unaffected by sendRetryReceipt's real cli.sendNode failing with
// ErrNotConnected (no socket in these tests).
func retryAttemptCount(cli *Client, msgID, sender string) int {
	cli.messageRetriesLock.Lock()
	defer cli.messageRetriesLock.Unlock()
	return cli.retryAttempts[retryAttemptKey{MsgID: msgID, Sender: sender}].Count
}

// decryptErrorTestInfoAndNode builds a minimal MessageInfo/Node/AttrUtility triple matching the
// exact arguments decryptMessages passes to handleDecryptError.
func decryptErrorTestInfoAndNode(chatServer string) (*types.MessageInfo, *waBinary.Node, *waBinary.AttrUtility) {
	chatUser := "120363000000000200"
	if chatServer == types.BroadcastServer {
		chatUser = "status"
	}
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:   types.JID{User: chatUser, Server: chatServer},
			Sender: types.JID{User: "15550002000", Server: types.HiddenUserServer},
		},
		ID: "DECRYPT-ERR-TEST-ID",
	}
	node := &waBinary.Node{
		Tag:   "message",
		Attrs: waBinary.Attrs{"id": string(info.ID), "from": info.Chat},
	}
	return info, node, node.AttrGetter()
}

// sentNodeCount counts outbound nodes matching tag (and, if typeAttr is non-empty, an exact
// Attrs["type"] match).
func sentNodeCount(nodes []waBinary.Node, tag, typeAttr string) int {
	n := 0
	for _, nd := range nodes {
		if nd.Tag != tag {
			continue
		}
		if typeAttr == "" {
			n++
			continue
		}
		if v, ok := nd.Attrs["type"].(string); ok && v == typeAttr {
			n++
		}
	}
	return n
}

// TestOldCounter_DebugContinueNoRetryNoDispatch verifies ErrOldCounter routes through the
// already-processed handling: Debug-only (no Warn), shouldContinue=true, no retry receipt sent, and
// no UndecryptableMessage dispatched (a known duplicate is not a loss).
func TestOldCounter_DebugContinueNoRetryNoDispatch(t *testing.T) {
	cli, log, _, dispatched, _ := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	err := fmt.Errorf("%w (index: 5, count: 3)", signalerror.ErrOldCounter)

	shouldContinue := cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)

	if !shouldContinue {
		t.Error("shouldContinue = false, want true (ErrOldCounter routes through the already-processed path)")
	}
	if n := log.warnCount("Ignoring message"); n != 0 {
		t.Errorf("Warn-level log fired %d times for ErrOldCounter, want 0", n)
	}
	if n := log.debugCount("Ignoring message"); n != 1 {
		t.Errorf("Debug-level log fired %d times for ErrOldCounter, want 1", n)
	}
	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 0 {
		t.Errorf("retry receipt sent %d times for ErrOldCounter, want 0 (known duplicate, no retry)", n)
	}
	if *dispatched != nil {
		t.Error("UndecryptableMessage dispatched for ErrOldCounter, want none (a duplicate is not a loss)")
	}
}

// oldVersionPreKeyBytes builds real wire bytes for a version-0 prekey message: a leading byte whose
// high nibble is 0 (UnsupportedVersion=1, so version 0 is "too old") followed by a validly-marshaled
// (but otherwise arbitrary) serialize.PreKeySignalMessage body. The version check
// (protocol.NewPreKeySignalMessageFromStruct) fires before any session/store lookup, so this
// triggers signalerror.ErrOldMessageVersion with no signal session needed at all -- unlike
// ErrOldCounter/ErrNoValidSessions/ErrNoOneTimeKeyFound below.
func oldVersionPreKeyBytes(t *testing.T) []byte {
	t.Helper()
	msg := &serialize.PreKeySignalMessage{
		RegistrationId: proto.Uint32(1),
		BaseKey:        []byte{1, 2, 3, 4},
		IdentityKey:    []byte{5, 6, 7, 8},
		Message:        []byte{9, 10, 11, 12},
	}
	body, err := proto.Marshal(msg)
	if err != nil {
		t.Fatalf("marshal test PreKeySignalMessage: %v", err)
	}
	return append([]byte{0x00}, body...)
}

// TestOldMessageVersion_RealBytesThroughDecryptMessages verifies a real version-0 prekey message,
// fed through the actual cli.decryptMessages loop (decryptDM -> protocol.NewPreKeySignalMessageFromBytes
// -> signalerror.ErrOldMessageVersion, no session lookup reached), acks, dispatches
// UndecryptableMessage, advances staleMessageVersionTotal, logs Debug-only, and sends no retry
// receipt.
func TestOldMessageVersion_RealBytesThroughDecryptMessages(t *testing.T) {
	log := &warnCapture{}
	cli := &Client{Log: log, SynchronousAck: true}
	var sentNodes []waBinary.Node
	cli.sendNodeFunc = func(_ context.Context, node waBinary.Node) error {
		sentNodes = append(sentNodes, node)
		return nil
	}
	var dispatched *events.UndecryptableMessage
	cli.AddEventHandler(func(evt any) {
		if um, ok := evt.(*events.UndecryptableMessage); ok {
			dispatched = um
		}
	})
	info := &types.MessageInfo{
		MessageSource: types.MessageSource{
			Chat:   types.JID{User: "120363000000000201", Server: types.GroupServer},
			Sender: types.JID{User: "15550002001", Server: types.HiddenUserServer},
		},
		ID: "OLD-VERSION-TEST-ID",
	}
	node := &waBinary.Node{
		Tag:   "message",
		Attrs: waBinary.Attrs{"id": string(info.ID), "from": info.Chat},
		Content: []waBinary.Node{
			{Tag: "enc", Attrs: waBinary.Attrs{"type": "pkmsg", "v": "2"}, Content: oldVersionPreKeyBytes(t)},
		},
	}
	startTotal := staleMessageVersionTotal.Load()

	cli.decryptMessages(context.Background(), info, node)

	if n := log.warnCount("Error decrypting message"); n != 0 {
		t.Errorf("generic decrypt Warnf fired %d times for a version-0 prekey message, want 0", n)
	}
	if got := staleMessageVersionTotal.Load() - startTotal; got != 1 {
		t.Errorf("staleMessageVersionTotal advanced by %d, want 1", got)
	}
	if n := sentNodeCount(sentNodes, "ack", ""); n != 1 {
		t.Errorf("ack sent %d times, want 1 (ack so WhatsApp stops redelivering)", n)
	}
	if n := sentNodeCount(sentNodes, "receipt", "retry"); n != 0 {
		t.Errorf("retry receipt sent %d times, want 0 (a malformed version can never parse via retry)", n)
	}
	if dispatched == nil {
		t.Fatal("UndecryptableMessage was not dispatched")
	}
	if dispatched.IsUnavailable {
		t.Error("dispatched IsUnavailable = true, want false")
	}
}

// TestGenericDecryptError_StillWarnsAndRetries is the regression guard: an unrelated decrypt error
// (not EventAlreadyProcessed/ErrOldCounter/ErrOldMessageVersion) still takes the generic Warnf +
// retry-receipt + ack + UndecryptableMessage-dispatch path, unchanged by this plan's new branches.
func TestGenericDecryptError_StillWarnsAndRetries(t *testing.T) {
	cli, log, sentNodes, dispatched, _ := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	err := fmt.Errorf("boom: unrelated decrypt failure")

	shouldContinue := cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)

	if shouldContinue {
		t.Error("shouldContinue = true, want false (an unrelated decrypt error must still return from decryptMessages)")
	}
	if n := log.warnCount("Error decrypting message"); n != 1 {
		t.Errorf("Warn-level log fired %d times for an unrelated decrypt error, want 1 (generic path unchanged)", n)
	}
	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 1 {
		t.Errorf("retry receipt sent %d times, want 1 (generic decrypt errors still retry)", n)
	}
	if n := sentNodeCount(*sentNodes, "ack", ""); n != 1 {
		t.Errorf("ack sent %d times, want 1", n)
	}
	if *dispatched == nil {
		t.Fatal("UndecryptableMessage was not dispatched for a genuine decrypt failure")
	}
}

// TestNoValidSessions_StatusBroadcastDebugRetryUnchanged verifies status@broadcast +
// ErrNoValidSessions logs Debug (not the generic Warnf) while the retry-with-identity recovery path
// (isUnavailable=true forcing forceIncludeIdentity) fires exactly as it does today.
func TestNoValidSessions_StatusBroadcastDebugRetryUnchanged(t *testing.T) {
	cli, log, _, dispatched, preKeys := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.BroadcastServer)
	if info.Chat != types.StatusBroadcastJID {
		t.Fatalf("test setup bug: info.Chat = %v, want types.StatusBroadcastJID", info.Chat)
	}
	err := fmt.Errorf("%w: pairwise status delivery", signalerror.ErrNoValidSessions)

	shouldContinue := cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)

	if shouldContinue {
		t.Error("shouldContinue = true, want false (a genuine decrypt failure returns from decryptMessages)")
	}
	if n := log.warnCount("Error decrypting message"); n != 0 {
		t.Errorf("Warn-level log fired %d times for status@broadcast ErrNoValidSessions, want 0", n)
	}
	if n := log.debugCount("Error decrypting message"); n != 1 {
		t.Errorf("Debug-level log fired %d times for status@broadcast ErrNoValidSessions, want 1", n)
	}
	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 1 {
		t.Errorf("retry receipt sent %d times, want 1 (retry-with-identity recovery is unchanged)", n)
	}
	// GenOnePreKey is only called when sendRetryReceipt's forceIncludeIdentity branch fires
	// (retry.go: "if retryCount > 1 || forceIncludeIdentity") -- on this first attempt
	// (retryCount==1), only isUnavailable=true (forceIncludeIdentity) reaches it, so this proves
	// the retry-with-identity recovery fired, without depending on the outbound wire node (not
	// observable -- see fakeGenOnePreKeyStore's doc).
	if n := preKeys.callCount(); n != 1 {
		t.Errorf("GenOnePreKey called %d times, want 1 (forceIncludeIdentity=true from isUnavailable must include fresh identity/prekeys)", n)
	}
	if *dispatched == nil {
		t.Fatal("UndecryptableMessage was not dispatched")
	}
	if !(*dispatched).IsUnavailable {
		t.Error("dispatched IsUnavailable = false, want true (ErrNoValidSessions is in the isUnavailable set)")
	}
}

// TestNoValidSessions_NonBroadcastStillWarns is the D-03 boundary regression guard: the identical
// ErrNoValidSessions error on a non-broadcast chat still warns -- the Debug demotion is scoped
// exclusively to status@broadcast, not broadened to every ErrNoValidSessions occurrence.
func TestNoValidSessions_NonBroadcastStillWarns(t *testing.T) {
	cli, log, _, _, _ := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	err := fmt.Errorf("%w: pairwise group delivery", signalerror.ErrNoValidSessions)

	cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)

	if n := log.warnCount("Error decrypting message"); n != 1 {
		t.Errorf("Warn-level log fired %d times for non-broadcast ErrNoValidSessions, want 1 (D-03 boundary: only status@broadcast demotes)", n)
	}
	if n := log.debugCount("Error decrypting message"); n != 0 {
		t.Errorf("Debug-level log fired %d times for non-broadcast ErrNoValidSessions, want 0", n)
	}
}

// TestStalePrekey_FirstOccurrenceWarnsRepeatOnlyCounts verifies the fresh-prekey retry fires on
// every occurrence (recovery unchanged), but the WARN emits only on the first occurrence per sender
// -- a repeat from the SAME sender advances stalePrekeyTotal without re-warning.
func TestStalePrekey_FirstOccurrenceWarnsRepeatOnlyCounts(t *testing.T) {
	cli, log, _, _, _ := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	err := fmt.Errorf("%w with ID 7", signalerror.ErrNoOneTimeKeyFound)
	startTotal := stalePrekeyTotal.Load()

	cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)
	cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, true, info.Sender, err)

	if n := log.warnCount("STALE_PREKEY"); n != 1 {
		t.Errorf("STALE_PREKEY warned %d times across 2 occurrences from the SAME sender, want exactly 1 (first occurrence only)", n)
	}
	if got := stalePrekeyTotal.Load() - startTotal; got != 2 {
		t.Errorf("stalePrekeyTotal advanced by %d across 2 occurrences, want 2 (every occurrence counts)", got)
	}
	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 2 {
		t.Errorf("retry receipt sent %d times across 2 occurrences, want 2 (the fresh-prekey retry recovery fires every time, unaffected by WARN dedup)", n)
	}
}

// TestStalePrekey_DifferentSenderGetsOwnWarn verifies a second, distinct sender still gets its own
// first-occurrence WARN even though a different sender already fired one.
func TestStalePrekey_DifferentSenderGetsOwnWarn(t *testing.T) {
	cli, log, _, _, _ := decryptErrorTestSetup(t)
	infoA, nodeA, agA := decryptErrorTestInfoAndNode(types.GroupServer)
	infoB, nodeB, agB := decryptErrorTestInfoAndNode(types.GroupServer)
	infoB.Sender = types.JID{User: "15550002099", Server: types.HiddenUserServer}
	err := fmt.Errorf("%w with ID 9", signalerror.ErrNoOneTimeKeyFound)

	cli.handleDecryptError(context.Background(), infoA, nodeA, agA, "msg", []string{"msg"}, true, infoA.Sender, err)
	cli.handleDecryptError(context.Background(), infoA, nodeA, agA, "msg", []string{"msg"}, true, infoA.Sender, err) // repeat: no new WARN
	cli.handleDecryptError(context.Background(), infoB, nodeB, agB, "msg", []string{"msg"}, true, infoB.Sender, err) // distinct sender: own first-occurrence

	if n := log.warnCount("STALE_PREKEY"); n != 2 {
		t.Errorf("two distinct senders (one repeated) produced %d STALE_PREKEY WARNs, want 2 (one per distinct sender)", n)
	}
}

// --- 55.1-09 Task 1/2: history-sync media delete (class 10) + placeholder-resend empty item
// (class 15) -----------------------------------------------------------------------------------

// outcomeCapture records Warnf/Infof/Debugf calls so a test can assert the WA-conformant
// fire-and-forget media-delete and folded placeholder-resend paths never emit a per-event Warn
// while still producing the periodic aggregate Infof line.
type outcomeCapture struct {
	mu     sync.Mutex
	warns  []string
	infos  []string
	debugs []string
}

func (l *outcomeCapture) Warnf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}
func (l *outcomeCapture) Infof(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.infos = append(l.infos, msg)
}
func (l *outcomeCapture) Debugf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, msg)
}
func (l *outcomeCapture) Errorf(string, ...interface{}) {}
func (l *outcomeCapture) Sub(string) waLog.Logger       { return l }

func outcomeCaptureCount(bucket []string, substr string) int {
	n := 0
	for _, s := range bucket {
		if strings.Contains(s, substr) {
			n++
		}
	}
	return n
}
func (l *outcomeCapture) warnCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return outcomeCaptureCount(l.warns, substr)
}
func (l *outcomeCapture) infoCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return outcomeCaptureCount(l.infos, substr)
}
func (l *outcomeCapture) debugCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return outcomeCaptureCount(l.debugs, substr)
}

// newMediaDeleteClient builds a bare Client whose DeleteMedia call is routed to a fake
// RoundTripper returning the given status code, with a pre-populated mediaConnCache so
// refreshMediaConn never hits the network (mirrors newHostFailoverClient in
// download_hostfailover_test.go).
func newMediaDeleteClient(log waLog.Logger, status int) *Client {
	cli := &Client{
		Log: log,
		mediaHTTP: &http.Client{Transport: &multiHostTransport{byHost: map[string]hostRoundTripFunc{
			"media.example.test": func(req *http.Request) (*http.Response, error) {
				return errorResponse(status), nil
			},
		}}},
	}
	cli.mediaConnCache = &MediaConn{
		Hosts:     []MediaConnHost{{Hostname: "media.example.test"}},
		FetchedAt: time.Now(),
		TTL:       3600,
	}
	return cli
}

// TestHistorySyncMediaDelete_FailureCountedDebugNoWarn verifies a failed DeleteMedia call
// (400 response) is a single best-effort attempt (no retry, no status-code branching, matching
// WAWebMmsClientMmsDeleteMdHistorySyncBlob.js) whose outcome is counted and logged at Debug,
// never Warn.
func TestHistorySyncMediaDelete_FailureCountedDebugNoWarn(t *testing.T) {
	log := &outcomeCapture{}
	cli := newMediaDeleteClient(log, http.StatusBadRequest)

	beforeFail := mediaDeleteFail.Load()
	beforeOk := mediaDeleteOk.Load()

	err := cli.DeleteMedia(context.Background(), MediaHistory, "/v/t/abc", []byte("hash"), "")
	if err == nil {
		t.Fatal("expected DeleteMedia to return an error for a 400 response")
	}
	cli.recordMediaDeleteOutcome(err)

	if n := log.warnCount("delete history sync media"); n != 0 {
		t.Errorf("Warn-level log fired %d times for a media-delete failure, want 0 (WA-conformant fire-and-forget)", n)
	}
	if n := log.debugCount("delete history sync media"); n == 0 {
		t.Error("expected a Debugf call carrying the delete error")
	}
	if got := mediaDeleteFail.Load(); got != beforeFail+1 {
		t.Errorf("mediaDeleteFail = %d, want %d", got, beforeFail+1)
	}
	if got := mediaDeleteOk.Load(); got != beforeOk {
		t.Errorf("mediaDeleteOk = %d, want unchanged %d", got, beforeOk)
	}
}

// TestHistorySyncMediaDelete_SuccessCounted verifies a successful DeleteMedia call (200
// response) increments the success counter with no Warn.
func TestHistorySyncMediaDelete_SuccessCounted(t *testing.T) {
	log := &outcomeCapture{}
	cli := newMediaDeleteClient(log, http.StatusOK)

	beforeOk := mediaDeleteOk.Load()

	err := cli.DeleteMedia(context.Background(), MediaHistory, "/v/t/abc", []byte("hash"), "")
	if err != nil {
		t.Fatalf("expected DeleteMedia to succeed for a 200 response, got %v", err)
	}
	cli.recordMediaDeleteOutcome(err)

	if n := log.warnCount("delete history sync media"); n != 0 {
		t.Errorf("Warn-level log fired %d times for a successful media delete, want 0", n)
	}
	if got := mediaDeleteOk.Load(); got != beforeOk+1 {
		t.Errorf("mediaDeleteOk = %d, want %d", got, beforeOk+1)
	}
}

// TestHistorySyncMediaDelete_PeriodicInfoStillFires verifies the aggregate
// HISTORY_SYNC_MEDIA_DELETE Infof line fires when a counter crosses the mediaDeleteLogEvery
// threshold, so a persistent anomaly stays observable without per-event WARN spam.
func TestHistorySyncMediaDelete_PeriodicInfoStillFires(t *testing.T) {
	log := &outcomeCapture{}
	cli := &Client{Log: log}

	for mediaDeleteFail.Load()%mediaDeleteLogEvery != mediaDeleteLogEvery-1 {
		mediaDeleteFail.Add(1)
	}
	cli.recordMediaDeleteOutcome(fmt.Errorf("simulated delete failure"))

	if n := log.infoCount("HISTORY_SYNC_MEDIA_DELETE"); n != 1 {
		t.Errorf("HISTORY_SYNC_MEDIA_DELETE Infof fired %d times crossing the threshold, want 1", n)
	}
}

// placeholderResendFixtureWebMessageBytes builds a minimal, marshalable WebMessageInfo whose
// key resolves to a real chat/sender via ParseWebMessage without needing cli.Store (chatJID
// empty -> parsed from Key.RemoteJID; DefaultUserServer chat -> sender = chat, no participant
// needed).
func placeholderResendFixtureWebMessageBytes(t *testing.T, msgID string) []byte {
	t.Helper()
	webMsg := &waWeb.WebMessageInfo{
		Key: &waCommon.MessageKey{
			RemoteJID: proto.String("15550001111@s.whatsapp.net"),
			FromMe:    proto.Bool(false),
			ID:        proto.String(msgID),
		},
		MessageTimestamp: proto.Uint64(1700000000),
	}
	b, err := proto.Marshal(webMsg)
	if err != nil {
		t.Fatalf("marshal fixture WebMessageInfo: %v", err)
	}
	return b
}

// TestPlaceholderResendResponse_EmptyItemNoWarn verifies a mix of nil (phone genuinely lacks
// the message) and populated placeholder-resend response items: nil items advance
// placeholderResendEmpty with NO per-item Warnf, while populated items still recover normally
// (placeholderResendOk advances, recordRecoveredMsgID is called, the batch stays ok).
func TestPlaceholderResendResponse_EmptyItemNoWarn(t *testing.T) {
	log := &outcomeCapture{}
	cli := &Client{Log: log}

	webMsgBytes := placeholderResendFixtureWebMessageBytes(t, "PLACEHOLDER-RECOVERED-1")

	beforeEmpty := placeholderResendEmpty.Load()
	beforeOk := placeholderResendOk.Load()

	msg := &waE2E.PeerDataOperationRequestResponseMessage{
		StanzaID: proto.String("REQ-1"),
		PeerDataOperationResult: []*waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult{
			{}, // empty item -- phone genuinely lacks the message
			{
				PlaceholderMessageResendResponse: &waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult_PlaceholderMessageResendResponse{
					WebMessageInfoBytes: webMsgBytes,
				},
			},
			{}, // second empty item
		},
	}

	ok := cli.handlePlaceholderResendResponse(msg)

	if !ok {
		t.Error("handlePlaceholderResendResponse returned ok=false, want true")
	}
	if n := log.warnCount("Missing response in item"); n != 0 {
		t.Errorf("Warn-level log fired %d times for empty placeholder-resend items, want 0", n)
	}
	if got := placeholderResendEmpty.Load(); got != beforeEmpty+2 {
		t.Errorf("placeholderResendEmpty = %d, want %d (2 empty items)", got, beforeEmpty+2)
	}
	if got := placeholderResendOk.Load(); got != beforeOk+1 {
		t.Errorf("placeholderResendOk = %d, want %d (1 populated item recovered)", got, beforeOk+1)
	}
	if !cli.isRecoveredMsgID("PLACEHOLDER-RECOVERED-1") {
		t.Error("recordRecoveredMsgID was not called for the populated item")
	}
}

// TestPlaceholderResendResponse_PeriodicInfoStillFires verifies the existing PLACEHOLDER_RESEND
// aggregate Infof line still fires when placeholderResendEmpty crosses the placeholderLogEvery
// threshold, even though the per-item Warnf is gone.
func TestPlaceholderResendResponse_PeriodicInfoStillFires(t *testing.T) {
	log := &outcomeCapture{}
	cli := &Client{Log: log}

	for placeholderResendEmpty.Load()%placeholderLogEvery != placeholderLogEvery-1 {
		placeholderResendEmpty.Add(1)
	}

	msg := &waE2E.PeerDataOperationRequestResponseMessage{
		StanzaID:                proto.String("REQ-2"),
		PeerDataOperationResult: []*waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult{{}},
	}
	cli.handlePlaceholderResendResponse(msg)

	if n := log.infoCount("PLACEHOLDER_RESEND"); n != 1 {
		t.Errorf("PLACEHOLDER_RESEND Infof fired %d times crossing the threshold, want 1", n)
	}
}

// TestPlaceholderResendResponse_UnmarshalAndParseFailureWarnsUnchanged verifies the two
// unrelated Warnf branches (a genuinely malformed non-empty item) are untouched by the class-15
// fix -- only the "resp == nil" per-item WARN was removed.
func TestPlaceholderResendResponse_UnmarshalAndParseFailureWarnsUnchanged(t *testing.T) {
	log := &outcomeCapture{}
	cli := &Client{Log: log}

	msg := &waE2E.PeerDataOperationRequestResponseMessage{
		StanzaID: proto.String("REQ-3"),
		PeerDataOperationResult: []*waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult{
			{
				PlaceholderMessageResendResponse: &waE2E.PeerDataOperationRequestResponseMessage_PeerDataOperationResult_PlaceholderMessageResendResponse{
					WebMessageInfoBytes: []byte("not a valid protobuf"),
				},
			},
		},
	}
	cli.handlePlaceholderResendResponse(msg)

	if n := log.warnCount("Failed to unmarshal protobuf web message"); n != 1 {
		t.Errorf("unmarshal-failure Warnf fired %d times, want 1 (unchanged by class 15 fix)", n)
	}
}
