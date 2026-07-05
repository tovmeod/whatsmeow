// kavtov-fork (quick-260705-ill): three-case regression guard for the skmsg retry-receipt prekey
// gate. WA Web (WAWebSendRetryReceiptJob.js:6 constant d = 2, gate at :110 `e >= d`) attaches the
// <keys> identity+prekey bundle only at retryCount>=2. This suite pins the conformant behavior:
// group (skmsg) attempt-1 receipts carry NO keys even with forceIncludeIdentity, attempt-2 receipts
// carry keys via the retryCount>1 leg, and the pairwise (non-skmsg) forceIncludeIdentity attempt-1
// path is deliberately preserved (genuine session-establishment recovery, low volume).
//
// Assertion strategy: sendRetryReceipt sends via the REAL cli.sendNode (not the sendNodeFunc hook
// -- see fakeGenOnePreKeyStore's doc in message_log_class_hardening_test.go), so the outbound
// <receipt> node is not observable from a bare &Client{}. GenOnePreKey fires if-and-only-if the
// <keys>-attach branch is entered, so preKeys.callCount() is the documented proxy -- same pattern
// as TestNoValidSessions_StatusBroadcastDebugRetryUnchanged.

package whatsmeow

import (
	"context"
	"fmt"
	"testing"

	"go.mau.fi/libsignal/signalerror"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

// TestRetryPrekeyGate_SKMsgAttempt1NoKeys: a group (skmsg) no-sender-key miss at attempt 1 must NOT
// enter the <keys>-attach branch even though isUnavailable=true forces forceIncludeIdentity=true.
func TestRetryPrekeyGate_SKMsgAttempt1NoKeys(t *testing.T) {
	cli, _, _, _, preKeys := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	// skmsg enc child so classifyRetryEnc yields isSKMsg=true. No "count" attr: a count attr would
	// seed registerRetryAttempt to count+1 (Pitfall 6) and skip attempt 1.
	node.Content = []waBinary.Node{{Tag: "enc", Attrs: waBinary.Attrs{"type": "skmsg"}}}
	err := fmt.Errorf("%w: test", signalerror.ErrNoSenderKeyForUser)

	cli.handleDecryptError(context.Background(), info, node, ag, "skmsg", []string{"skmsg"}, false, info.Sender, err)

	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 1 {
		t.Errorf("retryAttemptCount = %d, want 1 (retry receipt path must run for attempt 1)", n)
	}
	if n := preKeys.callCount(); n != 0 {
		t.Errorf("GenOnePreKey called %d times, want 0 (skmsg attempt 1 must NOT attach <keys> -- WA Web gates keys to retryCount>=2)", n)
	}
}

// TestRetryPrekeyGate_SKMsgAttempt2IncludesKeys: attempt 2 of the same skmsg miss must attach the
// <keys> bundle via the retryCount>1 leg (unchanged conformant behavior).
func TestRetryPrekeyGate_SKMsgAttempt2IncludesKeys(t *testing.T) {
	cli, _, _, _, preKeys := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	node.Content = []waBinary.Node{{Tag: "enc", Attrs: waBinary.Attrs{"type": "skmsg"}}}
	err := fmt.Errorf("%w: test", signalerror.ErrNoSenderKeyForUser)

	cli.handleDecryptError(context.Background(), info, node, ag, "skmsg", []string{"skmsg"}, false, info.Sender, err)
	cli.handleDecryptError(context.Background(), info, node, ag, "skmsg", []string{"skmsg"}, false, info.Sender, err)

	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 2 {
		t.Errorf("retryAttemptCount = %d, want 2 (both attempts must register; skmsg cap is 3)", n)
	}
	if n := preKeys.callCount(); n != 1 {
		t.Errorf("GenOnePreKey called %d times, want 1 (0 from attempt 1, 1 from attempt 2 via the retryCount>1 leg)", n)
	}
}

// TestRetryPrekeyGate_PairwiseForceIncludeIdentityAttempt1Keys: the pairwise (non-skmsg)
// forceIncludeIdentity path still attaches <keys> on attempt 1 -- deliberate preserved deviation
// from strict WA Web conformance (genuine session-establishment recovery need, low volume).
func TestRetryPrekeyGate_PairwiseForceIncludeIdentityAttempt1Keys(t *testing.T) {
	cli, _, _, _, preKeys := decryptErrorTestSetup(t)
	info, node, ag := decryptErrorTestInfoAndNode(types.GroupServer)
	// pkmsg enc child for explicitness: classifyRetryEnc still yields isSKMsg=false.
	node.Content = []waBinary.Node{{Tag: "enc", Attrs: waBinary.Attrs{"type": "pkmsg"}}}
	err := fmt.Errorf("%w: pairwise delivery", signalerror.ErrNoValidSessions)

	cli.handleDecryptError(context.Background(), info, node, ag, "msg", []string{"msg"}, false, info.Sender, err)

	if n := retryAttemptCount(cli, string(info.ID), info.Sender.User); n != 1 {
		t.Errorf("retryAttemptCount = %d, want 1", n)
	}
	if n := preKeys.callCount(); n != 1 {
		t.Errorf("GenOnePreKey called %d times, want 1 (pairwise forceIncludeIdentity recovery must be preserved)", n)
	}
}
