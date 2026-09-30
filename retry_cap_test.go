// kavtov-fork (35.2-02): Unit tests for bounded (msgID,sender)-keyed retry store,
// content-recovered short-circuit, and SENDERKEY_TERMINAL exactly-once logging.
//
// Coverage:
//   Task 1 (D-05/D-08/D-09):
//     skmsg-class entries stop being eligible after count reaches 3 (cap).
//     non-skmsg (session-class) entries stay eligible until count reaches 5.
//     restart seeding: first observation with retryCountInMsg=3 seeds count to 4.
//     clearing on decrypt success removes the entry.
//     store is bounded — cap+1 distinct keys evict the oldest.
//     same msgID from two different senders tracks two independent counts.
//     bare &Client{} does not nil-panic on first use (lazy-init).
//
//   Task 2 (D-06/D-07):
//     msgID recorded as recovered -> attempt #2+ verdict is stop + logTerminal=true with contentRecovered=true.
//     first retry attempt is NEVER short-circuited (phone-fetch rides attempt #1 per D-06).
//     cap reached without recovery -> logTerminal=true with contentRecovered=false exactly once.
//     terminal log fires exactly once per (msgID, sender) — subsequent attempt does not re-log.
//     recovered-set is bounded (eviction at cap) and lazy-init safe on bare &Client{}.
//
// Test style: bare &Client{}, no socket, no PG — fake-store style of
// retry_peer_store_test.go.

package whatsmeow

import (
	"testing"

	waBinary "go.mau.fi/whatsmeow/binary"
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
	const group = "120363000000000001@g.us"

	for attempt := 1; attempt <= 3; attempt++ {
		count, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, true)
		if !proceed {
			t.Errorf("attempt %d: want proceed=true, got false (count=%d)", attempt, count)
		}
		if count != attempt {
			t.Errorf("attempt %d: want count=%d, got %d", attempt, attempt, count)
		}
	}

	// Attempt 4 must be stopped.
	count, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, true)
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
	const group = ""

	for attempt := 1; attempt <= 4; attempt++ {
		count, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, false)
		if !proceed {
			t.Errorf("session attempt %d: want proceed=true, got false (count=%d)", attempt, count)
		}
		if count != attempt {
			t.Errorf("session attempt %d: want count=%d, got %d", attempt, attempt, count)
		}
	}

	// Attempt 5 must be stopped.
	count, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, false)
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
	const group = "120363000000000002@g.us"

	count, _, _ := cli.registerRetryAttempt(msgID, sender, group, 3, true)
	if count != 4 {
		t.Errorf("restart seeding retryCountInMsg=3: want count=4, got %d", count)
	}

	// Already seeded to 4 — next call should yield 5 and stop (past cap 3 for skmsg).
	count2, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, true)
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
	const group = "120363000000000003@g.us"

	cli.registerRetryAttempt(msgID, sender, group, 0, true)
	cli.registerRetryAttempt(msgID, sender, group, 0, true)

	cli.clearMessageRetrySender(msgID, sender)

	// After clear the entry must be gone; count must restart at 1.
	count, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, true)
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
	const group = "120363000000000004@g.us"

	// Advance sender A twice.
	cli.registerRetryAttempt(msgID, senderA, group, 0, true)
	countA, _, _ := cli.registerRetryAttempt(msgID, senderA, group, 0, true)

	// Sender B must still be at 1 (independent count).
	countB, _, _ := cli.registerRetryAttempt(msgID, senderB, group, 0, true)

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
	const group = "120363000000000005@g.us"

	// Fill the ring exactly to capacity.
	for i := 0; i < 4; i++ {
		id := msgIDPrefix + string(rune('a'+i))
		cli.registerRetryAttempt(id, sender, group, 0, true)
	}

	// Insert one more distinct key — must evict the oldest.
	cli.registerRetryAttempt(msgIDPrefix+"e", sender, group, 0, true)

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
	cli.registerRetryAttempt("any-id", "any-sender", "any-group", 0, true)
}

// --- Task 2 tests: content-recovered short-circuit + SENDERKEY_TERMINAL ---

// TestSenderKeyTerminal_RecoveredShortCircuit asserts that once a msgID is recorded as
// recovered, attempt #2+ returns proceed=false AND logTerminal=true with contentRecovered=true.
func TestSenderKeyTerminal_RecoveredShortCircuit(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-rec-1"
	const sender = "15550002001"
	const group = "120363000000000010@g.us"

	// Attempt 1 must NEVER be short-circuited (phone-fetch rides attempt #1 per D-06).
	cli.recordRecoveredMsgID(msgID) // recovered BEFORE attempt 1 (edge case: must still proceed)
	_, proceed1, logTerminal1 := cli.registerRetryAttempt(msgID, sender, group, 0, true)
	if !proceed1 {
		t.Error("attempt 1: must never be short-circuited even after recovery recorded")
	}
	if logTerminal1 {
		t.Error("attempt 1: logTerminal must be false even when recovered")
	}

	// Attempt 2: recovered → short-circuit, logTerminal=true, contentRecovered=true.
	_, proceed2, logTerminal2 := cli.registerRetryAttempt(msgID, sender, group, 0, true)
	if proceed2 {
		t.Error("attempt 2 after recovery: want proceed=false (short-circuit)")
	}
	if !logTerminal2 {
		t.Error("attempt 2 after recovery: want logTerminal=true (first terminal fire)")
	}

	// Verify contentRecovered flag from isRecoveredMsgID.
	if !cli.isRecoveredMsgID(msgID) {
		t.Error("isRecoveredMsgID: want true after recordRecoveredMsgID")
	}
}

// TestSenderKeyTerminal_CapWithoutRecovery asserts that reaching the cap without recovery
// fires logTerminal=true with contentRecovered=false exactly once.
func TestSenderKeyTerminal_CapWithoutRecovery(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-norecov-1"
	const sender = "15550002002"
	const group = "120363000000000011@g.us"

	// Exhaust the cap.
	for attempt := 1; attempt <= 3; attempt++ {
		_, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, 0, true)
		if !proceed {
			t.Errorf("attempt %d: want proceed=true before cap reached", attempt)
		}
	}

	// Attempt 4: cap exceeded → proceed=false, logTerminal=true, contentRecovered=false.
	_, proceed4, logTerminal4 := cli.registerRetryAttempt(msgID, sender, group, 0, true)
	if proceed4 {
		t.Error("attempt 4 (past cap): want proceed=false")
	}
	if !logTerminal4 {
		t.Error("attempt 4 (first cap-exceeded): want logTerminal=true")
	}
	if cli.isRecoveredMsgID(msgID) {
		t.Error("isRecoveredMsgID: want false (no recovery recorded)")
	}
}

// TestSenderKeyTerminal_TerminalOnce asserts that the terminal log fires exactly once
// per (msgID, sender) — a 5th or 6th attempt after the terminal does not re-log.
func TestSenderKeyTerminal_TerminalOnce(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-termonce-1"
	const sender = "15550002003"
	const group = "120363000000000012@g.us"

	// Reach cap: 3 proceed + 1 terminal (attempt 4).
	for i := 0; i < 3; i++ {
		cli.registerRetryAttempt(msgID, sender, group, 0, true)
	}
	_, _, firstTerminal := cli.registerRetryAttempt(msgID, sender, group, 0, true)
	if !firstTerminal {
		t.Error("4th attempt: want logTerminal=true (first give-up)")
	}

	// 5th attempt: terminal flag already set → logTerminal must be false.
	_, _, secondTerminal := cli.registerRetryAttempt(msgID, sender, group, 0, true)
	if secondTerminal {
		t.Error("5th attempt: want logTerminal=false (already logged)")
	}
}

// TestSenderKeyTerminal_RecoveredSetBounded asserts the recovered-msgID set evicts at cap.
func TestSenderKeyTerminal_RecoveredSetBounded(t *testing.T) {
	cli := newRetryCap()

	origCap := recoveredMsgIDsSize
	recoveredMsgIDsSize = 4
	defer func() { recoveredMsgIDsSize = origCap }()

	for i := 0; i < 5; i++ {
		id := "msg-rb-" + string(rune('a'+i))
		cli.recordRecoveredMsgID(id)
	}

	cli.recoveredMsgIDsLock.Lock()
	n := len(cli.recoveredMsgIDs)
	cli.recoveredMsgIDsLock.Unlock()

	if n > 4 {
		t.Errorf("recovered set holds %d entries after 5 inserts into cap-4 ring; want <= 4", n)
	}
}

// --- WR-03 test: cleared-then-re-added keys must not occupy two ring slots ---

// TestRetryCap_ClearThenReAddSurvivesRingWrap asserts the WR-03 lockstep
// invariant: after clear + re-register, the old ring slot is a zeroed sentinel,
// so a ring wrap over it does NOT evict the live re-registered entry — the cap
// does not reset and SENDERKEY_TERMINAL fires exactly once.
//
// Against the pre-fix code (map delete only, stale slot left in the ring), the
// re-registration inserts a SECOND slot; the wrap reaches the stale first slot
// and delete(retryAttempts, old) evicts the LIVE entry — count restarts at 1
// and the terminal can fire a second time.
func TestRetryCap_ClearThenReAddSurvivesRingWrap(t *testing.T) {
	cli := newRetryCap()

	origCap := retryStoreSKMsgSize
	retryStoreSKMsgSize = 4
	defer func() { retryStoreSKMsgSize = origCap }()

	const msgA = "msg-wr03-a"
	const sender = "15550003002"
	const group = "120363000000000021@g.us"

	// Register A (occupies slot 0) and advance its count to 3.
	for i := 0; i < 3; i++ {
		cli.registerRetryAttempt(msgA, sender, group, 0, true)
	}

	// Decrypt success: clear A. Slot 0 must become a zeroed sentinel.
	cli.clearMessageRetrySender(msgA, sender)

	// A re-enters (late duplicate retry): fresh entry at slot 1, count back to 3.
	for i := 0; i < 3; i++ {
		_, proceed, _ := cli.registerRetryAttempt(msgA, sender, group, 0, true)
		if !proceed {
			t.Fatalf("re-registered A attempt %d: want proceed=true", i+1)
		}
	}

	// Fill the remaining slots (2, 3) and wrap the pointer over the old
	// (now-zeroed) slot 0. Pre-fix: slot 0 still held A → live A evicted here.
	cli.registerRetryAttempt("msg-wr03-b", sender, group, 0, true) // slot 2
	cli.registerRetryAttempt("msg-wr03-c", sender, group, 0, true) // slot 3
	cli.registerRetryAttempt("msg-wr03-d", sender, group, 0, true) // wraps to slot 0

	// A's live entry must have survived the wrap: 4th attempt is past the cap
	// and fires the terminal exactly once.
	_, proceed, logTerminal := cli.registerRetryAttempt(msgA, sender, group, 0, true)
	if proceed {
		t.Error("A attempt 4 after ring wrap: want proceed=false (cap intact); " +
			"proceed=true means the live entry was evicted via the stale slot (WR-03)")
	}
	if !logTerminal {
		t.Error("A attempt 4 after ring wrap: want logTerminal=true (first give-up)")
	}

	// 5th attempt: terminal already fired — must not re-log (D-07 exactly-once).
	_, _, secondTerminal := cli.registerRetryAttempt(msgA, sender, group, 0, true)
	if secondTerminal {
		t.Error("A attempt 5: want logTerminal=false (terminal must fire exactly once)")
	}
}

// --- WR-01 tests: enc-node classification on multi-child message nodes ---

// TestClassifyRetryEnc_MetaPlusSKMsg asserts that a full message node carrying a
// non-enc sibling (meta) plus an enc(type=skmsg) child is classified skmsg-class
// with the embedded count read from the enc child. Against the pre-WR-01 code
// (len(children)==1 requirement) this returns isSKMsg=false (session-class
// misclassification: cap 5, no SENDERKEY_TERMINAL, seeding lost).
func TestClassifyRetryEnc_MetaPlusSKMsg(t *testing.T) {
	children := []waBinary.Node{
		{Tag: "meta", Attrs: waBinary.Attrs{"target_id": "x"}},
		{Tag: "enc", Attrs: waBinary.Attrs{"type": "skmsg", "count": "2", "v": "2"}},
	}
	count, isSK := classifyRetryEnc(children)
	if !isSK {
		t.Error("meta+enc(skmsg): want isSKMsg=true, got false (WR-01 misclassification)")
	}
	if count != 2 {
		t.Errorf("meta+enc(skmsg): want retryCountInMsg=2, got %d", count)
	}
}

// TestClassifyRetryEnc_PKMsgPlusSKMsg asserts the mixed pkmsg+skmsg node (group
// send with attached SKDM — the SENDER_KEY_MISMATCH class) classifies skmsg,
// with the count taken from the skmsg child.
func TestClassifyRetryEnc_PKMsgPlusSKMsg(t *testing.T) {
	children := []waBinary.Node{
		{Tag: "enc", Attrs: waBinary.Attrs{"type": "pkmsg", "count": "1", "v": "2"}},
		{Tag: "enc", Attrs: waBinary.Attrs{"type": "skmsg", "count": "3", "v": "2"}},
	}
	count, isSK := classifyRetryEnc(children)
	if !isSK {
		t.Error("pkmsg+skmsg: want isSKMsg=true (skmsg leg drives the retry loop)")
	}
	if count != 3 {
		t.Errorf("pkmsg+skmsg: want retryCountInMsg=3 (from the skmsg child), got %d", count)
	}
}

// TestClassifyRetryEnc_SessionOnly asserts a single session-class enc node keeps
// the previous behavior: isSKMsg=false, count read from the enc child.
func TestClassifyRetryEnc_SessionOnly(t *testing.T) {
	children := []waBinary.Node{
		{Tag: "enc", Attrs: waBinary.Attrs{"type": "msg", "count": "4", "v": "2"}},
	}
	count, isSK := classifyRetryEnc(children)
	if isSK {
		t.Error("session-only: want isSKMsg=false")
	}
	if count != 4 {
		t.Errorf("session-only: want retryCountInMsg=4, got %d", count)
	}
}

// TestClassifyRetryEnc_SKMsgCapAndTerminal asserts the WR-01 end-to-end contract:
// a meta-bearing skmsg node feeds isSKMsg=true into registerRetryAttempt, so the
// skmsg cap (3) applies and SENDERKEY_TERMINAL fires on the 4th attempt.
func TestClassifyRetryEnc_SKMsgCapAndTerminal(t *testing.T) {
	cli := newRetryCap()
	const msgID = "msg-wr01-1"
	const sender = "15550003001"
	const group = "120363000000000020@g.us"

	children := []waBinary.Node{
		{Tag: "meta"},
		{Tag: "enc", Attrs: waBinary.Attrs{"type": "skmsg", "v": "2"}},
	}
	count, isSK := classifyRetryEnc(children)
	if !isSK || count != 0 {
		t.Fatalf("classify: want (0, true), got (%d, %v)", count, isSK)
	}

	for attempt := 1; attempt <= 3; attempt++ {
		_, proceed, _ := cli.registerRetryAttempt(msgID, sender, group, count, isSK)
		if !proceed {
			t.Fatalf("attempt %d: want proceed=true under skmsg cap 3", attempt)
		}
	}
	_, proceed, logTerminal := cli.registerRetryAttempt(msgID, sender, group, count, isSK)
	if proceed {
		t.Error("attempt 4 (past skmsg cap 3): want proceed=false")
	}
	if !logTerminal {
		t.Error("attempt 4: want logTerminal=true (SENDERKEY_TERMINAL fires for skmsg class)")
	}
}

// TestSenderKeyTerminal_RecoveredSetLazyInit asserts bare &Client{} doesn't nil-panic
// on recordRecoveredMsgID/isRecoveredMsgID calls.
func TestSenderKeyTerminal_RecoveredSetLazyInit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil-panic on bare &Client{} recovered-set: %v", r)
		}
	}()
	cli := &Client{}
	cli.recordRecoveredMsgID("any-msg")
	_ = cli.isRecoveredMsgID("any-msg")
}
