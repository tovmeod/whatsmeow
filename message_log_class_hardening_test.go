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
	"strconv"
	"strings"
	"sync"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
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
