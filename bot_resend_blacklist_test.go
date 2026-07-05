// kavtov-fork (q6h): unit tests for the shared, DB-agnostic bot-resend blacklist
// and the ask-once phone-request claims.
//
// Task 1 — BotResendBlacklist (fleet-wide, threshold 3, 7d TTL re-probe):
//   - 2 misses do NOT blacklist; the 3rd does (threshold=3, code default).
//   - keying is per (group, sender); different groups / senders are independent.
//   - fleet-wide: misses to ONE shared instance from what would be different
//     accounts accumulate under one (group,sender) key — 3 total blacklist.
//   - persistFunc is called EXACTLY once, at the threshold-cross (not misses 1-2,
//     not misses 4+).
//   - IsBlacklisted TTL expiry re-probes: a back-dated (>7d) entry returns false,
//     drops from the blacklisted set, and resets its count so a single subsequent
//     miss does NOT immediately re-blacklist (it takes the full threshold again).
//   - LoadBlacklisted installs within-7d entries and skips older ones.
//   - BOT_RESEND_BLACKLISTED is logged exactly once at the threshold-cross.
//   - a bare &Client{} (nil BotResendBL) does not nil-panic (no-op / false).
//
// Task 2 — PhoneRequestClaims:
//   - TryClaim returns true for a fresh key.
//   - TryClaim returns false for a repeat within 5s.
//   - TryClaim returns true again after the TTL expires.
//   - Two clients sharing one PhoneRequestClaims: first claims+asks, second skips.
//   - After TTL a later miss re-asks (no loss).
//
// Test style: bare &Client{} and/or shared instances — no socket, no PG.

package whatsmeow

import (
	"strings"
	"sync"
	"testing"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

// --- helpers ------------------------------------------------------------------

// newBlacklist returns a &Client{} wired to a fresh shared BotResendBlacklist
// (persistFunc off) for the delegating-method tests.
func newBlacklist() *Client {
	return &Client{BotResendBL: NewBotResendBlacklist(nil)}
}

// warnCapture records Warnf calls so tests can assert exact log-once behavior.
// Implements waLog.Logger; Sub returns itself.
type warnCapture struct {
	mu    sync.Mutex
	warns []string
}

func (l *warnCapture) Infof(string, ...interface{})  {}
func (l *warnCapture) Errorf(string, ...interface{}) {}
func (l *warnCapture) Debugf(string, ...interface{}) {}
func (l *warnCapture) Sub(string) waLog.Logger       { return l }
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

// persistCall records a single persistFunc invocation.
type persistCall struct {
	group  string
	sender string
	at     time.Time
}

// --- Task 1: BotResendBlacklist -----------------------------------------------

// TestBotResendBlacklist_ThresholdAt3 verifies the code-default threshold is 3:
// the 2nd miss does NOT flip the blacklist but the 3rd does.
func TestBotResendBlacklist_ThresholdAt3(t *testing.T) {
	if botResendBlacklistThreshold != 3 {
		t.Fatalf("threshold must be the code default 3; got %d", botResendBlacklistThreshold)
	}
	cli := newBlacklist()
	const group = "120363000000000001@g.us"
	const sender = "15550001001"

	for i := 1; i < botResendBlacklistThreshold; i++ {
		cli.incrementBotResendBlacklist(group, sender)
		if cli.isBotResendBlacklisted(group, sender) {
			t.Errorf("miss %d: want not-yet-blacklisted, got blacklisted", i)
		}
	}
	// 3rd miss flips it.
	cli.incrementBotResendBlacklist(group, sender)
	if !cli.isBotResendBlacklisted(group, sender) {
		t.Error("3rd miss: want blacklisted, got not-blacklisted")
	}
}

// TestBotResendBlacklist_IndependentPerSender verifies that two distinct senders
// accumulate independent counts.
func TestBotResendBlacklist_IndependentPerSender(t *testing.T) {
	cli := newBlacklist()
	const group = "120363000000000002@g.us"
	const senderA = "15550001002"
	const senderB = "15550001003"

	for i := 0; i < botResendBlacklistThreshold; i++ {
		cli.incrementBotResendBlacklist(group, senderA)
	}
	if !cli.isBotResendBlacklisted(group, senderA) {
		t.Error("senderA should be blacklisted")
	}
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

// TestBotResendBlacklist_FleetWideAggregation verifies the fleet-wide contract:
// misses routed through two Clients that share ONE BotResendBlacklist accumulate
// under a single (group,sender) key, so 3 total misses across accounts blacklist.
func TestBotResendBlacklist_FleetWideAggregation(t *testing.T) {
	shared := NewBotResendBlacklist(nil)
	const group = "120363000000000005@g.us"
	const sender = "15550001005"

	cli1 := &Client{BotResendBL: shared}
	cli2 := &Client{BotResendBL: shared}

	cli1.incrementBotResendBlacklist(group, sender) // 1 (account A)
	cli2.incrementBotResendBlacklist(group, sender) // 2 (account B)
	if cli1.isBotResendBlacklisted(group, sender) {
		t.Error("2 aggregated misses: must not yet be blacklisted")
	}
	cli1.incrementBotResendBlacklist(group, sender) // 3 (account A)
	if !cli2.isBotResendBlacklisted(group, sender) {
		t.Error("3 aggregated misses across accounts: want blacklisted (fleet-wide)")
	}
}

// TestBotResendBlacklist_PersistFuncOnce verifies persistFunc fires exactly once,
// at the threshold-cross — not on misses 1-2 and not on misses 4+.
func TestBotResendBlacklist_PersistFuncOnce(t *testing.T) {
	calls := make(chan persistCall, 8)
	b := NewBotResendBlacklist(func(group, sender string, at time.Time) {
		calls <- persistCall{group: group, sender: sender, at: at}
	})
	const group = "120363000000000006@g.us"
	const sender = "15550001006"

	// Misses 1-2 must NOT persist.
	b.Increment(group, sender)
	b.Increment(group, sender)
	select {
	case <-calls:
		t.Fatal("persistFunc called before threshold-cross")
	case <-time.After(50 * time.Millisecond):
	}

	// 3rd miss crosses the threshold -> exactly one persist.
	b.Increment(group, sender)
	select {
	case c := <-calls:
		if c.group != group || c.sender != sender {
			t.Errorf("persist got (%s,%s); want (%s,%s)", c.group, c.sender, group, sender)
		}
		if c.at.IsZero() {
			t.Error("persist blacklisted_at must be non-zero")
		}
	case <-time.After(time.Second):
		t.Fatal("persistFunc not called at threshold-cross")
	}

	// Misses 4-5 must NOT persist again.
	b.Increment(group, sender)
	b.Increment(group, sender)
	select {
	case <-calls:
		t.Error("persistFunc called again after threshold-cross")
	case <-time.After(50 * time.Millisecond):
	}
}

// TestBotResendBlacklist_TTLReprobe verifies the data-loss guard: a blacklisted
// entry back-dated beyond the 7-day TTL is re-probed — IsBlacklisted returns
// false, the entry drops from the blacklisted set, and its count resets so a
// single subsequent miss does NOT immediately re-blacklist.
func TestBotResendBlacklist_TTLReprobe(t *testing.T) {
	b := NewBotResendBlacklist(nil)
	const group = "120363000000000007@g.us"
	const sender = "15550001007"

	for i := 0; i < botResendBlacklistThreshold; i++ {
		b.Increment(group, sender)
	}
	if !b.IsBlacklisted(group, sender) {
		t.Fatal("want blacklisted after reaching threshold")
	}

	// Back-date blacklisted_at beyond the TTL.
	k := botResendKey{Group: group, Sender: sender}
	b.mu.Lock()
	b.blacklisted[k] = time.Now().Add(-(botResendBlacklistTTL + time.Minute))
	b.mu.Unlock()

	// IsBlacklisted must re-probe: return false AND remove the entry AND reset count.
	if b.IsBlacklisted(group, sender) {
		t.Error("expired entry: want IsBlacklisted=false (re-probe)")
	}
	b.mu.Lock()
	_, stillListed := b.blacklisted[k]
	cnt := b.counts[k]
	b.mu.Unlock()
	if stillListed {
		t.Error("expired entry must be dropped from the blacklisted set")
	}
	if cnt != 0 {
		t.Errorf("counts must reset on re-probe; got %d", cnt)
	}

	// One miss after re-probe must NOT immediately re-blacklist (needs full threshold).
	b.Increment(group, sender)
	if b.IsBlacklisted(group, sender) {
		t.Error("one miss after re-probe must not re-blacklist (needs the full threshold again)")
	}
}

// TestBotResendBlacklist_LoadBlacklisted verifies startup seeding: within-7d
// entries install as blacklisted and >7d entries are skipped.
func TestBotResendBlacklist_LoadBlacklisted(t *testing.T) {
	b := NewBotResendBlacklist(nil)
	fresh := BotResendBlacklistEntry{Group: "120363000000000008@g.us", Sender: "15550001008", At: time.Now().Add(-time.Hour)}
	stale := BotResendBlacklistEntry{Group: "120363000000000009@g.us", Sender: "15550001009", At: time.Now().Add(-(botResendBlacklistTTL + time.Hour))}

	b.LoadBlacklisted([]BotResendBlacklistEntry{fresh, stale})

	if !b.IsBlacklisted(fresh.Group, fresh.Sender) {
		t.Error("within-7d entry should be installed as blacklisted")
	}
	if b.IsBlacklisted(stale.Group, stale.Sender) {
		t.Error(">7d entry must be skipped, not installed")
	}
}

// TestBotResendBlacklist_LogExactlyOnce verifies BOT_RESEND_BLACKLISTED is logged
// exactly once — at the threshold-cross — and not on subsequent misses.
func TestBotResendBlacklist_LogExactlyOnce(t *testing.T) {
	log := &warnCapture{}
	cli := &Client{Log: log, BotResendBL: NewBotResendBlacklist(nil)}
	const group = "120363000000000010@g.us"
	const sender = "15550001010"

	for i := 0; i < botResendBlacklistThreshold+3; i++ {
		cli.incrementBotResendBlacklist(group, sender)
	}
	n := log.warnCount("BOT_RESEND_BLACKLISTED")
	if n != 1 {
		t.Errorf("BOT_RESEND_BLACKLISTED logged %d times; want exactly 1", n)
	}
}

// TestBotResendBlacklist_NilSafe verifies a bare &Client{} (nil BotResendBL) does
// not nil-panic: increment is a no-op and isBotResendBlacklisted returns false.
func TestBotResendBlacklist_NilSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("nil-panic on bare &Client{}: %v", r)
		}
	}()
	cli := &Client{}
	cli.incrementBotResendBlacklist("120363000000000011@g.us", "15550001011")
	if cli.isBotResendBlacklisted("120363000000000011@g.us", "15550001011") {
		t.Error("nil BotResendBL: isBotResendBlacklisted must return false")
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
