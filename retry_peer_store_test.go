// kavtov-fork (D-08): Regression tests for peer-message retry storage and framing.
//
// Root cause (debug session retry-store-miss-never-stored): peer-protocol sends
// (req.Peer, e.g. PLACEHOLDER_MESSAGE_RESEND) were excluded from the retry buffer by
// `if !req.Peer` gates, so their retry receipts hit RETRY_STORE_MISS and were never
// re-served. Fix: store peer messages in the in-memory ring only (skip the write-bound
// DB), and re-send a served peer message with PEER framing (category=peer, no
// DeviceSentMessage wrap) instead of the DeviceSentMessage re-wrap used for normal
// own-device DM retries.
//
// These tests assert the two load-bearing decisions directly:
//   1. addRecentMessage with isPeer=true populates the ring but does NOT write the DB.
//   2. A stored peer message resends with PEER framing (category=peer, type=text, no
//      device_fanout) and is NOT wrapped as DeviceSentMessage.

package whatsmeow

import (
	"context"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// recordingEventBuffer implements store.EventBuffer and records AddOutgoingEvent calls so a
// test can assert whether the DB retry-buffer write happened. All other methods are no-ops.
type recordingEventBuffer struct {
	addOutgoingCalls int
}

func (r *recordingEventBuffer) GetBufferedEvent(context.Context, [32]byte) (*store.BufferedEvent, error) {
	return nil, nil
}
func (r *recordingEventBuffer) PutBufferedEvent(context.Context, [32]byte, []byte, time.Time) error {
	return nil
}
func (r *recordingEventBuffer) DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error {
	return fn(ctx)
}
func (r *recordingEventBuffer) ClearBufferedEventPlaintext(context.Context, [32]byte) error {
	return nil
}
func (r *recordingEventBuffer) DeleteOldBufferedHashes(context.Context) error { return nil }
func (r *recordingEventBuffer) GetOutgoingEvent(context.Context, types.JID, types.JID, types.MessageID) (string, []byte, error) {
	return "", nil, nil
}
func (r *recordingEventBuffer) GetOutgoingEventByID(context.Context, types.MessageID) (string, []byte, error) {
	return "", nil, nil
}
func (r *recordingEventBuffer) AddOutgoingEvent(context.Context, types.JID, types.MessageID, string, []byte) error {
	r.addOutgoingCalls++
	return nil
}
func (r *recordingEventBuffer) DeleteOldOutgoingEvents(context.Context) error { return nil }

func newRetryStoreTestClient(buf store.EventBuffer) *Client {
	return &Client{
		Store:                &store.Device{Log: waLog.Noop, EventBuffer: buf},
		Log:                  waLog.Noop,
		UseRetryMessageStore: true,
		recentMessagesMap:    make(map[recentMessageKey]RecentMessage, recentMessagesSize),
		lastRetryStoreClear:  time.Now(), // avoid the 12h DeleteOldOutgoingEvents branch
	}
}

// TestAddRecentMessage_PeerSkipsDBWrite asserts that a peer send populates the in-memory
// ring (so getRecentMessage finds it) but does NOT write the write-bound DB retry buffer,
// while a non-peer send DOES write the DB.
func TestAddRecentMessage_PeerSkipsDBWrite(t *testing.T) {
	to := types.NewJID("12345", types.DefaultUserServer)
	wa := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
		Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
		PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
			PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_PLACEHOLDER_MESSAGE_RESEND.Enum(),
		},
	}}

	t.Run("peer: ring populated, DB write skipped", func(t *testing.T) {
		buf := &recordingEventBuffer{}
		cli := newRetryStoreTestClient(buf)
		if err := cli.addRecentMessage(context.Background(), to, "peerID1", wa, nil, true); err != nil {
			t.Fatalf("addRecentMessage returned error: %v", err)
		}
		if buf.addOutgoingCalls != 0 {
			t.Errorf("peer message wrote DB retry buffer %d time(s); want 0", buf.addOutgoingCalls)
		}
		got := cli.getRecentMessage(to, "peerID1")
		if got.IsEmpty() {
			t.Fatal("peer message not found in in-memory ring")
		}
		if !got.isPeer {
			t.Error("ring entry isPeer=false; want true")
		}
	})

	t.Run("non-peer: ring populated AND DB written", func(t *testing.T) {
		buf := &recordingEventBuffer{}
		cli := newRetryStoreTestClient(buf)
		if err := cli.addRecentMessage(context.Background(), to, "dmID1", wa, nil, false); err != nil {
			t.Fatalf("addRecentMessage returned error: %v", err)
		}
		if buf.addOutgoingCalls != 1 {
			t.Errorf("non-peer message wrote DB retry buffer %d time(s); want 1", buf.addOutgoingCalls)
		}
		got := cli.getRecentMessage(to, "dmID1")
		if got.IsEmpty() {
			t.Fatal("non-peer message not found in in-memory ring")
		}
		if got.isPeer {
			t.Error("ring entry isPeer=true; want false")
		}
	})
}

// TestShouldWrapDeviceSentRetry asserts the framing decision: own-account (IsFromMe) DM
// retries are wrapped as DeviceSentMessage, but peer messages are NOT (they get PEER
// framing instead). This is the guard that prevents the malformed peer resend.
func TestShouldWrapDeviceSentRetry(t *testing.T) {
	tests := []struct {
		name     string
		isFromMe bool
		isPeer   bool
		want     bool
	}{
		{"own-device DM retry wraps DeviceSent", true, false, true},
		{"peer message must NOT wrap DeviceSent", true, true, false},
		{"not-from-me never wraps", false, false, false},
		{"not-from-me peer never wraps", false, true, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			receipt := &events.Receipt{}
			receipt.IsFromMe = tc.isFromMe
			msg := &RecentMessage{isPeer: tc.isPeer}
			if got := shouldWrapDeviceSentRetry(receipt, msg); got != tc.want {
				t.Errorf("shouldWrapDeviceSentRetry(isFromMe=%v, isPeer=%v) = %v; want %v",
					tc.isFromMe, tc.isPeer, got, tc.want)
			}
		})
	}
}

// TestApplyPeerRetryAttrs asserts a stored peer message resends with PEER framing:
// category=peer, type=text, and crucially NO device_fanout (peer sends never set it).
// The dominant PLACEHOLDER_MESSAGE_RESEND request gets no push_priority; the two special
// peer request types get their documented priorities.
func TestApplyPeerRetryAttrs(t *testing.T) {
	baseAttrs := func() waBinary.Attrs {
		return waBinary.Attrs{"to": "x", "type": "media", "id": "id1", "t": int64(1)}
	}

	t.Run("placeholder-resend: peer framing, no device_fanout, no push_priority", func(t *testing.T) {
		attrs := baseAttrs()
		wa := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
			PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
				PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_PLACEHOLDER_MESSAGE_RESEND.Enum(),
			},
		}}
		applyPeerRetryAttrs(attrs, wa)
		if attrs["category"] != "peer" {
			t.Errorf("category = %v; want peer", attrs["category"])
		}
		if attrs["type"] != "text" {
			t.Errorf("type = %v; want text", attrs["type"])
		}
		if _, ok := attrs["device_fanout"]; ok {
			t.Error("device_fanout set on peer retry; peer sends must NOT set it")
		}
		if _, ok := attrs["push_priority"]; ok {
			t.Error("push_priority set for PLACEHOLDER_MESSAGE_RESEND; want none")
		}
	})

	t.Run("app-state-sync-key-request: push_priority high", func(t *testing.T) {
		attrs := baseAttrs()
		wa := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST.Enum(),
		}}
		applyPeerRetryAttrs(attrs, wa)
		if attrs["push_priority"] != "high" {
			t.Errorf("push_priority = %v; want high", attrs["push_priority"])
		}
	})

	t.Run("history-sync-on-demand: high_force + privacy_sensitive", func(t *testing.T) {
		attrs := baseAttrs()
		wa := &waE2E.Message{ProtocolMessage: &waE2E.ProtocolMessage{
			Type: waE2E.ProtocolMessage_PEER_DATA_OPERATION_REQUEST_MESSAGE.Enum(),
			PeerDataOperationRequestMessage: &waE2E.PeerDataOperationRequestMessage{
				PeerDataOperationRequestType: waE2E.PeerDataOperationRequestType_HISTORY_SYNC_ON_DEMAND.Enum(),
			},
		}}
		applyPeerRetryAttrs(attrs, wa)
		if attrs["push_priority"] != "high_force" {
			t.Errorf("push_priority = %v; want high_force", attrs["push_priority"])
		}
		if attrs["privacy_sensitive"] != "1" {
			t.Errorf("privacy_sensitive = %v; want 1", attrs["privacy_sensitive"])
		}
	})
}
