// kavtov-fork (38.5): unit tests for bot-resend blacklist and ask-once phone-request claims.
//
// Task 1 — bot-resend blacklist:
//   - 10th miss flips blacklisted; 9th does not.
//   - counter is per (group, sender); different groups / senders are independent.
//   - on a blacklisted sender, isBotResendBlacklisted returns true; below threshold false.
//   - counter is per-Client (two bare clients share no state).
//   - counter never resets (cumulative).
//   - bare &Client{} does not nil-panic (lazy-init in incrementBotResendBlacklist).
//   - log line is emitted exactly once (at the 10th miss), not on subsequent misses.
//
// Task 2 — PhoneRequestClaims:
//   - TryClaim returns true for a fresh key.
//   - TryClaim returns false for a repeat within 5s.
//   - TryClaim returns true again after the TTL expires.
//   - Two clients sharing one PhoneRequestClaims: first claims+asks, second skips.
//   - After TTL a later miss re-asks (no loss).
//
// Test style: bare &Client{} and/or &PhoneRequestClaims{} — no socket, no PG.

package whatsmeow

import (
	"strings"
	"sync"
	"testing"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// --- helpers ------------------------------------------------------------------

// newBlacklist returns a bare &Client{} for blacklist tests.
func newBlacklist() *Client {
	return &Client{}
}

// warnCapture records Warnf calls so tests can assert exact log-once behavior.
// Implements waLog.Logger; Sub returns itself.
type warnCapture struct {
	mu    sync.Mutex
	warns []string
}

func (l *warnCapture) Infof(string, ...interface{})      {}
func (l *warnCapture) Errorf(string, ...interface{})     {}
func (l *warnCapture) Debugf(string, ...interface{})     {}
func (l *warnCapture) Sub(string) waLog.Logger           { return l }
func (l *warnCapture) Warnf(msg string, _ ...interface{}) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.warns = append(l.warns, msg)
}
func (l *warnCapture) warnCount(substr string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := 0
	for _, w := range l.warns {
		if strings.Contains(w, substr) {
			n++
		}
	}
	return n
}

// --- Task 1: blacklist --------------------------------------------------------

// TestBotResendBlacklist_ThresholdAt10 verifies that the 9th miss does NOT flip
// the blacklist but the 10th does.
func TestBotResendBlacklist_ThresholdAt10(t *testing.T) {
	cli := newBlacklist()
	const group = "120363000000000001@g.us"
	const sender = "15550001001"

	for i := 1; i < botResendBlacklistThreshold; i++ {
		cli.incrementBotResendBlacklist(group, sender)
		if cli.isBotResendBlacklisted(group, sender) {
			t.Errorf("miss %d: want not-yet-blacklisted, got blacklisted", i)
		}
	}
	// 10th miss flips it.
	cli.incrementBotResendBlacklist(group, sender)
	if !cli.isBotResendBlacklisted(group, sender) {
		t.Error("10th miss: want blacklisted, got not-blacklisted")
	}
}

// TestBotResendBlacklist_IndependentPerSender verifies that two distinct senders
// accumulate independent counts.
func TestBotResendBlacklist_IndependentPerSender(t *testing.T) {
	cli := newBlacklist()
	const group = "120363000000000002@g.us"
	const senderA = "15550001002"
	const senderB = "15550001003"

	// Blacklist senderA.
	for i := 0; i < botResendBlacklistThreshold; i++ {
		cli.incrementBotResendBlacklist(group, senderA)
	}
	if !cli.isBotResendBlacklisted(group, senderA) {
		t.Error("senderA should be blacklisted")
	}
	// senderB must not be affected.
	if cli.isBotResendBlacklisted(group, senderB) {
		t.Error("senderB must not be blacklisted (independent count)")
	}
}

// TestBotResendBlacklist_IndependentPerGroup verifies that the same sender in two
// different groups has independent counts.
func TestBotResendBlacklist_IndependentPerGroup(t *testing.T) {
	cli := newBlacklist()
	const groupA = "120363000000000003@g.us"
	const groupB = "120363000000000004@g.us"
	const sender = "15550001004"

	// Blacklist in groupA only.
	for i := 0; i < botResendBlacklistThreshold; i++ {
		cli.incrementBotResendBlacklist(groupA, sender)
	}
	if !cli.isBotResendBlacklisted(groupA, sender) {
		t.Error("sender in groupA should be blacklisted")
	}
	if cli.isBotResendBlacklisted(groupB, sender) {
		t.Error("sender in groupB must not be blacklisted (different group key)")
	}
}

// TestBotResendBlacklist_PerClient verifies that two separate Client instances
// share no state.
func TestBotResendBlacklist_PerClient(t *testing.T) {
	cli1 := newBlacklist()
	cli2 := newBlacklist()
	const group = "120363000000000005@g.us"
	const sender = "15550001005"

	for i := 0; i < botResendBlacklistThreshold; i++ {
		cli1.incrementBotResendBlacklist(group, sender)
	}
	if !cli1.isBotResendBlacklisted(group, sender) {
		t.Error("cli1: should be blacklisted")
	}
	// cli2 must have its own zero-count.
	if cli2.isBotResendBlacklisted(group, sender) {
		t.Error("cli2: must not be blacklisted (separate Client)")
	}
}

// TestBotResendBlacklist_NeverResets verifies that the count is cumulative and
// never decremented (past threshold stays there after further increments).
func TestBotResendBlacklist_NeverResets(t *testing.T) {
	cli := newBlacklist()
	const group = "120363000000000006@g.us"
	const sender = "15550001006"

	for i := 0; i < botResendBlacklistThreshold+5; i++ {
		cli.incrementBotResendBlacklist(group, sender)
	}
	if !cli.isBotResendBlacklisted(group, sender) {
		t.Error("should remain blacklisted after excess increments")
	}
}

// TestBotResendBlacklist_LazyInit verifies that a bare &Client{} does not
// nil-panic on incrementBotResendBlacklist or isBotResendBlacklisted.
func TestBotResendBlacklist_LazyInit(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil-panic on bare &Client{}: %v", r)
		}
	}()
	cli := &Client{}
	cli.incrementBotResendBlacklist("120363000000000007@g.us", "15550001007")
	_ = cli.isBotResendBlacklisted("120363000000000007@g.us", "15550001007")
}

// TestBotResendBlacklist_LogExactlyOnce verifies that BOT_RESEND_BLACKLISTED is
// logged exactly once — at the 10th miss — and not on subsequent misses.
func TestBotResendBlacklist_LogExactlyOnce(t *testing.T) {
	log := &warnCapture{}
	cli := &Client{Log: log}
	const group = "120363000000000008@g.us"
	const sender = "15550001008"

	for i := 0; i < botResendBlacklistThreshold+3; i++ {
		cli.incrementBotResendBlacklist(group, sender)
	}
	n := log.warnCount("BOT_RESEND_BLACKLISTED")
	if n != 1 {
		t.Errorf("BOT_RESEND_BLACKLISTED logged %d times; want exactly 1", n)
	}
}

// --- Task 2: PhoneRequestClaims -----------------------------------------------

// TestPhoneRequestClaims_FreshKeyReturnsTrue verifies TryClaim returns true for
// a key that has never been claimed.
func TestPhoneRequestClaims_FreshKeyReturnsTrue(t *testing.T) {
	p := NewPhoneRequestClaims()
	if !p.TryClaim("120363000000000010@g.us", "msgid-1") {
		t.Error("fresh key: want TryClaim=true")
	}
}

// TestPhoneRequestClaims_RepeatWithinTTLReturnsFalse verifies that a second
// TryClaim within the TTL window returns false.
func TestPhoneRequestClaims_RepeatWithinTTLReturnsFalse(t *testing.T) {
	p := NewPhoneRequestClaims()
	const group = "120363000000000011@g.us"
	const msgID = "msgid-2"

	if !p.TryClaim(group, msgID) {
		t.Fatal("first claim: want true")
	}
	if p.TryClaim(group, msgID) {
		t.Error("second claim within TTL: want false, got true")
	}
}

// TestPhoneRequestClaims_ExpiredClaimReturnsTrueAgain verifies that TryClaim
// returns true after the TTL has elapsed.
func TestPhoneRequestClaims_ExpiredClaimReturnsTrueAgain(t *testing.T) {
	p := NewPhoneRequestClaims()
	const group = "120363000000000012@g.us"
	const msgID = "msgid-3"

	p.TryClaim(group, msgID)

	// Back-date the claim so it appears expired.
	p.mu.Lock()
	k := claimKey{Group: group, MsgID: msgID}
	p.claims[k] = time.Now().Add(-(phoneRequestClaimTTL + time.Millisecond))
	p.mu.Unlock()

	if !p.TryClaim(group, msgID) {
		t.Error("after TTL: want TryClaim=true (claim expired)")
	}
}

// TestPhoneRequestClaims_TwoClientsSharedInstance verifies the ask-once contract:
// with two clients sharing one PhoneRequestClaims, the first client claims and
// the second is skipped; after TTL a later miss re-asks.
func TestPhoneRequestClaims_TwoClientsSharedInstance(t *testing.T) {
	shared := NewPhoneRequestClaims()
	const group = "120363000000000013@g.us"
	const msgID = "msgid-4"

	// Simulate two clients both receiving the same (group, message) miss.
	cli1 := &Client{PhoneRequestClaims: shared}
	cli2 := &Client{PhoneRequestClaims: shared}

	got1 := cli1.PhoneRequestClaims.TryClaim(group, msgID)
	got2 := cli2.PhoneRequestClaims.TryClaim(group, msgID)

	if !got1 {
		t.Error("cli1 (first): want TryClaim=true")
	}
	if got2 {
		t.Error("cli2 (second within TTL): want TryClaim=false")
	}

	// After TTL, a later miss re-asks (no loss).
	shared.mu.Lock()
	k := claimKey{Group: group, MsgID: msgID}
	shared.claims[k] = time.Now().Add(-(phoneRequestClaimTTL + time.Millisecond))
	shared.mu.Unlock()

	got3 := cli2.PhoneRequestClaims.TryClaim(group, msgID)
	if !got3 {
		t.Error("after TTL: want TryClaim=true for cli2 (no loss)")
	}
}

// TestPhoneRequestClaims_IndependentKeys verifies that different (group, msgID)
// pairs are independent claims.
func TestPhoneRequestClaims_IndependentKeys(t *testing.T) {
	p := NewPhoneRequestClaims()
	const group = "120363000000000014@g.us"

	p.TryClaim(group, "msg-a")
	// msg-b must be claimable independently.
	if !p.TryClaim(group, "msg-b") {
		t.Error("independent key msg-b: want TryClaim=true")
	}
	// msg-a within TTL must be false.
	if p.TryClaim(group, "msg-a") {
		t.Error("msg-a within TTL: want TryClaim=false")
	}
}
