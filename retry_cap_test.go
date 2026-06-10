// kavtov-fork (35.2-02): Unit tests for bounded (msgID,sender)-keyed retry store.
//
// Coverage:
//   D-05: skmsg-class entries stop being eligible after count reaches 3 (cap).
//   D-08: non-skmsg (session-class) entries stay eligible until count reaches 5.
//   D-09: store is bounded — cap+1 distinct keys evict the oldest.
//         restart seeding: first observation with retryCountInMsg=3 seeds count to 4.
//         clearing on decrypt success removes the entry.
//         same msgID from two different senders tracks two independent counts.
//         bare &Client{} does not nil-panic on first use (lazy-init).
//
// Test style: bare &Client{}, no socket, no PG — fake-store style of
// retry_peer_store_test.go.

package whatsmeow

import (
	"testing"
)

// --- helpers ------------------------------------------------------------------

// newRetryCap makes a minimal &Client{} for retry-cap tests.
// The ring fields are zero-valued (nil map + zero ptr) to exercise lazy-init.
func newRetryCap() *Client {
	return &Client{}
}

// --- Task 1 tests: cap / class scoping / restart seeding / clearing / bound ---

// TestRetryCap_SKMsg_StopsAt3 asserts that for an skmsg-class message the verdict
// transitions from "proceed" to "stop" exactly at count 3 (D-05, cap=3).
func TestRetryCap_SKMsg_StopsAt3(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-skm-1"
	const sender = "15550001001"

	for attempt := 1; attempt <= 3; attempt++ {
		count, proceed := cli.registerRetryAttempt(msgID, sender, 0, true)
		if !proceed {
			t.Errorf("attempt %d: want proceed=true, got false (count=%d)", attempt, count)
		}
		if count != attempt {
			t.Errorf("attempt %d: want count=%d, got %d", attempt, attempt, count)
		}
	}

	// Attempt 4 must be stopped.
	count, proceed := cli.registerRetryAttempt(msgID, sender, 0, true)
	if proceed {
		t.Errorf("attempt 4 (past skmsg cap 3): want proceed=false, got true (count=%d)", count)
	}
}

// TestRetryCap_Session_StopsAt5 asserts that for a session-class (non-skmsg) message
// the verdict stays "proceed" through attempt 4 and stops at 5 (D-08, existing cap >= 5).
func TestRetryCap_Session_StopsAt5(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-ses-1"
	const sender = "15550001002"

	for attempt := 1; attempt <= 4; attempt++ {
		count, proceed := cli.registerRetryAttempt(msgID, sender, 0, false)
		if !proceed {
			t.Errorf("session attempt %d: want proceed=true, got false (count=%d)", attempt, count)
		}
		if count != attempt {
			t.Errorf("session attempt %d: want count=%d, got %d", attempt, attempt, count)
		}
	}

	// Attempt 5 must be stopped.
	count, proceed := cli.registerRetryAttempt(msgID, sender, 0, false)
	if proceed {
		t.Errorf("session attempt 5 (at cap): want proceed=false, got true (count=%d)", count)
	}
}

// TestRetryCap_RestartSeeding asserts that when retryCountInMsg=3 on the first
// observation the count is seeded to 4 (retryCountInMsg+1) per Pitfall 6.
func TestRetryCap_RestartSeeding(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-seed-1"
	const sender = "15550001003"

	count, _ := cli.registerRetryAttempt(msgID, sender, 3, true)
	if count != 4 {
		t.Errorf("restart seeding retryCountInMsg=3: want count=4, got %d", count)
	}

	// Already seeded to 4 — next call should yield 5 and stop (past cap 3 for skmsg).
	count2, proceed := cli.registerRetryAttempt(msgID, sender, 0, true)
	if proceed {
		t.Errorf("after seed-to-4 on skmsg: want proceed=false, got true (count=%d)", count2)
	}
}

// TestRetryCap_ClearRemovesEntry asserts that clearing by (msgID, sender) after a
// decrypt success removes the entry so a fresh retry starts from count 1.
func TestRetryCap_ClearRemovesEntry(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-clear-1"
	const sender = "15550001004"

	cli.registerRetryAttempt(msgID, sender, 0, true)
	cli.registerRetryAttempt(msgID, sender, 0, true)

	cli.clearMessageRetrySender(msgID, sender)

	// After clear the entry must be gone; count must restart at 1.
	count, proceed := cli.registerRetryAttempt(msgID, sender, 0, true)
	if count != 1 {
		t.Errorf("after clear: want count=1, got %d", count)
	}
	if !proceed {
		t.Errorf("after clear: want proceed=true, got false")
	}
}

// TestRetryCap_TwoSendersIndependent asserts that the same msgID from two different
// senders maintains two independent counts (keying is (msgID, sender), not msgID alone).
func TestRetryCap_TwoSendersIndependent(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-twosend-1"
	const senderA = "15550001005"
	const senderB = "15550001006"

	// Advance sender A twice.
	cli.registerRetryAttempt(msgID, senderA, 0, true)
	countA, _ := cli.registerRetryAttempt(msgID, senderA, 0, true)

	// Sender B must still be at 1 (independent count).
	countB, _ := cli.registerRetryAttempt(msgID, senderB, 0, true)

	if countA != 2 {
		t.Errorf("senderA count: want 2, got %d", countA)
	}
	if countB != 1 {
		t.Errorf("senderB count after first call: want 1, got %d", countB)
	}
}

// TestRetryCap_Bounded asserts that inserting retryStoreSKMsgSize+1 distinct keys
// evicts the oldest entry so total held entries never exceeds the configured size.
func TestRetryCap_Bounded(t *testing.T) {
	cli := newRetryCap()

	// Save and restore the cap for this test so it doesn't depend on the
	// production size (which is large).
	origCap := retryStoreSKMsgSize
	retryStoreSKMsgSize = 4
	defer func() { retryStoreSKMsgSize = origCap }()

	const msgIDPrefix = "msg-bound-"
	const sender = "15550001007"

	// Fill the ring exactly to capacity.
	for i := 0; i < 4; i++ {
		id := msgIDPrefix + string(rune('a'+i))
		cli.registerRetryAttempt(id, sender, 0, true)
	}

	// Insert one more distinct key — must evict the oldest.
	cli.registerRetryAttempt(msgIDPrefix+"e", sender, 0, true)

	// The ring holds exactly retryStoreSKMsgSize entries.
	cli.messageRetriesLock.Lock()
	n := len(cli.retryAttempts)
	cli.messageRetriesLock.Unlock()

	if n > 4 {
		t.Errorf("after cap+1 inserts: store holds %d entries; want <= %d", n, 4)
	}
}

// TestRetryCap_LazyInit asserts that a bare &Client{} does not nil-panic when
// registerRetryAttempt is called before any production constructor runs.
func TestRetryCap_LazyInit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil-panic on bare &Client{}: %v", r)
		}
	}()
	cli := &Client{}
	cli.registerRetryAttempt("any-id", "any-sender", 0, true)
}
