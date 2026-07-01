// kavtov-fork (55.1-02 Task 1): unit tests for the reconnect-durable pending ack/receipt
// queue.
//
//   - sendAck with no socket (ErrNotConnected) queues instead of warning.
//   - replayPendingStanzas re-sends queued nodes in FIFO order.
//   - replayPendingStanzas re-queues the remainder (order preserved) if a replay send hits
//     ErrNotConnected again.
//   - the queue is deduplicated by (tag,id,to).
//   - the queue is capped, discards the oldest entry, and logs a throttled overflow ERROR
//     (not one Errorf per discard).
//   - a non-ErrNotConnected send error (sendAck and sendMessageReceipt) does not enqueue and
//     still warns, exactly like before this plan.
//
// Test style: bare &Client{} with a captured waLog.Logger; cli.sendNodeFunc stands in for a
// real socket (see the sendNodeFunc field doc in client.go) — no socket, no PG.

package whatsmeow

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// replayLogCapture records all four log levels so tests can assert exact warn/error counts.
type replayLogCapture struct {
	mu     sync.Mutex
	warns  []string
	errs   []string
	debugs []string
}

func (l *replayLogCapture) Infof(string, ...any) {}
func (l *replayLogCapture) Debugf(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.debugs = append(l.debugs, fmt.Sprintf(msg, args...))
}
func (l *replayLogCapture) Warnf(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, fmt.Sprintf(msg, args...))
}
func (l *replayLogCapture) Errorf(msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.errs = append(l.errs, fmt.Sprintf(msg, args...))
}
func (l *replayLogCapture) Sub(string) waLog.Logger { return l }

func (l *replayLogCapture) warnCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.warns)
}
func (l *replayLogCapture) errorCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.errs)
}

func newReplayClient() (*Client, *replayLogCapture) {
	log := &replayLogCapture{}
	return &Client{Log: log}, log
}

// --- Task 1: sendAck / sendMessageReceipt on ErrNotConnected -----------------------------

func TestPendingStanza_SendAckQueuesOnDisconnect(t *testing.T) {
	cli, log := newReplayClient()
	node := &waBinary.Node{
		Tag: "message",
		Attrs: waBinary.Attrs{
			"id":   "MSG1",
			"from": types.JID{User: "15550001001", Server: types.DefaultUserServer},
		},
	}

	cli.sendAck(context.Background(), node, 0)

	if log.warnCount() != 0 {
		t.Fatalf("want no Warnf on ErrNotConnected, got %d: %v", log.warnCount(), log.warns)
	}
	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 1 {
		t.Fatalf("want 1 queued stanza, got %d", n)
	}
}

func TestPendingStanza_NonDisconnectErrorWarnsAndDoesNotEnqueue(t *testing.T) {
	cli, log := newReplayClient()
	boom := errors.New("boom: marshal failed")
	cli.sendNodeFunc = func(context.Context, waBinary.Node) error {
		return boom
	}
	node := &waBinary.Node{
		Tag: "message",
		Attrs: waBinary.Attrs{
			"id":   "MSG2",
			"from": types.JID{User: "15550001002", Server: types.DefaultUserServer},
		},
	}

	cli.sendAck(context.Background(), node, 0)

	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 0 {
		t.Fatalf("want no stanza queued for a non-ErrNotConnected error, got %d", n)
	}
	if log.warnCount() != 1 {
		t.Fatalf("want exactly 1 Warnf for a non-ErrNotConnected send error, got %d: %v", log.warnCount(), log.warns)
	}
}

func TestPendingStanza_SendMessageReceiptNonDisconnectErrorWarns(t *testing.T) {
	cli, log := newReplayClient()
	boom := errors.New("boom: marshal failed")
	cli.sendNodeFunc = func(context.Context, waBinary.Node) error {
		return boom
	}
	info := &types.MessageInfo{}
	info.ID = "MSG3"
	node := &waBinary.Node{Attrs: waBinary.Attrs{"from": types.JID{User: "15550001003", Server: types.DefaultUserServer}}}

	cli.sendMessageReceipt(context.Background(), info, node)

	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 0 {
		t.Fatalf("want no stanza queued for a non-ErrNotConnected error, got %d", n)
	}
	if log.warnCount() != 1 {
		t.Fatalf("want exactly 1 Warnf for a non-ErrNotConnected send error, got %d: %v", log.warnCount(), log.warns)
	}
}

// --- Task 1: queue mechanics ---------------------------------------------------------------

func TestPendingStanza_DedupByTagIDTo(t *testing.T) {
	cli, _ := newReplayClient()
	node := waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A1", "to": "u1"}}

	cli.enqueuePendingStanza(node)
	cli.enqueuePendingStanza(node)
	cli.enqueuePendingStanza(node)

	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 1 {
		t.Fatalf("want 1 entry after 3 enqueues of the same (tag,id,to), got %d", n)
	}
}

func TestPendingStanza_CapDiscardsOldestAndThrottlesOverflowLog(t *testing.T) {
	cli, log := newReplayClient()

	for i := 0; i < pendingStanzaCap+5; i++ {
		cli.enqueuePendingStanza(waBinary.Node{
			Tag:   "ack",
			Attrs: waBinary.Attrs{"id": fmt.Sprintf("A%d", i), "to": "u1"},
		})
	}

	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	oldestRemaining := cli.pendingStanzas[0].key.ID
	overflow := cli.pendingStanzasOverflowCount
	cli.pendingStanzasLock.Unlock()

	if n != pendingStanzaCap {
		t.Fatalf("want queue capped at %d, got %d", pendingStanzaCap, n)
	}
	if oldestRemaining != "A5" {
		t.Fatalf("want oldest-discard to leave A5 as the first entry, got %s", oldestRemaining)
	}
	// 5 discards total; the first one logs immediately (throttle window starts empty) and
	// resets the counter, so 4 remain uncounted-for-logging and the Errorf call count is 1,
	// not 5 (steady state must not log per-event).
	if log.errorCount() != 1 {
		t.Fatalf("want exactly 1 throttled overflow ERROR for 5 discards in one burst, got %d: %v", log.errorCount(), log.errs)
	}
	if overflow != 4 {
		t.Fatalf("want overflow counter at 4 (discards after the throttled log), got %d", overflow)
	}
}

// --- Task 1: replay -------------------------------------------------------------------------

func TestReceiptReplay_ResendsInOrder(t *testing.T) {
	cli, _ := newReplayClient()
	cli.enqueuePendingStanza(waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A1", "to": "u1"}})
	cli.enqueuePendingStanza(waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A2", "to": "u1"}})

	var mu sync.Mutex
	var sentIDs []string
	cli.sendNodeFunc = func(_ context.Context, node waBinary.Node) error {
		mu.Lock()
		sentIDs = append(sentIDs, fmt.Sprintf("%v", node.Attrs["id"]))
		mu.Unlock()
		return nil
	}

	cli.replayPendingStanzas(context.Background())

	if len(sentIDs) != 2 || sentIDs[0] != "A1" || sentIDs[1] != "A2" {
		t.Fatalf("want [A1 A2] resent in order, got %v", sentIDs)
	}
	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 0 {
		t.Fatalf("want queue drained after a successful replay, got %d remaining", n)
	}
}

func TestReceiptReplay_ReEnqueuesRemainderOnErrNotConnectedAgain(t *testing.T) {
	cli, _ := newReplayClient()
	cli.enqueuePendingStanza(waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A1", "to": "u1"}})
	cli.enqueuePendingStanza(waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A2", "to": "u1"}})

	var calls int
	cli.sendNodeFunc = func(context.Context, waBinary.Node) error {
		calls++
		return ErrNotConnected
	}

	cli.replayPendingStanzas(context.Background())

	if calls != 1 {
		t.Fatalf("want replay to stop after the first ErrNotConnected, got %d send attempts", calls)
	}
	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 2 {
		t.Fatalf("want both entries re-queued (order preserved) after a mid-replay ErrNotConnected, got %d", n)
	}
}

func TestReceiptReplay_DiscardsOnNonDisconnectErrorAndWarns(t *testing.T) {
	cli, log := newReplayClient()
	cli.enqueuePendingStanza(waBinary.Node{Tag: "ack", Attrs: waBinary.Attrs{"id": "A1", "to": "u1"}})
	boom := errors.New("boom: transport error")
	cli.sendNodeFunc = func(context.Context, waBinary.Node) error {
		return boom
	}

	cli.replayPendingStanzas(context.Background())

	if log.warnCount() != 1 {
		t.Fatalf("want exactly 1 Warnf for a non-ErrNotConnected replay error, got %d: %v", log.warnCount(), log.warns)
	}
	cli.pendingStanzasLock.Lock()
	n := len(cli.pendingStanzas)
	cli.pendingStanzasLock.Unlock()
	if n != 0 {
		t.Fatalf("want the entry discarded (not re-queued) on a non-ErrNotConnected replay error, got %d remaining", n)
	}
}
