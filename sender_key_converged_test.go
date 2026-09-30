// kavtov-fork: P2a SENDER_KEY_CONVERGED convergence-instrument safety tests.
//
// The P2a instrument (commit a1ce682) is the load-bearing signal we will trust,
// after deploy, to decide whether the skmsg establish-session fix (a, e66dfae)
// actually helped: we read POSITIVE per-(sender,device,group) SENDER_KEY_CONVERGED
// lines, never a raw log-rate drop. If the instrument's bookkeeping were buggy and
// silently never fired, we would deploy, see zero CONVERGED lines, and wrongly
// conclude the fix failed. So the bookkeeping MUST be proven correct BEFORE deploy.
//
// These tests cover two layers:
//   1. The bookkeeping methods in isolation (recordFailedSenderKeyTuple /
//      clearFailedSenderKeyTuple): fire-once, device granularity, dedup-on-add,
//      ring eviction, lazy-init. Each behavioral case is constructed so that
//      removing the behavior under test (the dedup early-return, the eviction
//      delete) makes the test go RED -- a green that still passes when the
//      behavior is broken would be exactly the false confidence we must avoid.
//   2. The WIRING (end-to-end): a real group skmsg that first misses (records the
//      tuple) then, after the sender key is stored, decrypts via the KEY path and
//      emits the SENDER_KEY_CONVERGED INFO. This proves message.go actually calls
//      the bookkeeping on the live decrypt path -- "silently never fires" is a
//      wiring failure the isolated method tests cannot catch.

package whatsmeow

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Reflection lets the RED test exercise the existing real decrypt path before
// the diagnostic method exists, failing on its missing aggregate contract.
func outcomeSnapshot(t *testing.T, cli *Client) map[string]any {
	t.Helper()
	method := reflect.ValueOf(cli).MethodByName("SenderKeyRecoverySnapshot")
	if !method.IsValid() {
		t.Fatal("sender-key recovery aggregate is missing; original failure and exact-ID recovery must be observable")
	}
	data, err := json.Marshal(method.Call(nil)[0].Interface())
	if err != nil {
		t.Fatal(err)
	}
	var snapshot map[string]any
	if err = json.Unmarshal(data, &snapshot); err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSenderKeyOutcomeOriginalLater(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "outcome-group", Server: types.GroupServer}
	sender := types.JID{User: "outcome-sender", Server: types.HiddenUserServer, Device: 1}
	skdm, ciphertext := aliceCrypto(ctx, t, chat.String(), []byte("exact original"))
	cli := newTestClient(newFakeSenderKeyStore())
	node := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: ciphertext}
	if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now()); err == nil {
		t.Fatal("original must fail before its sender key arrives")
	}
	if snapshot := outcomeSnapshot(t, cli); snapshot["original_failures"] != float64(1) {
		t.Fatalf("expected one terminal original failure, got %v", snapshot)
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdm)
	if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now()); err != nil {
		t.Fatal(err)
	}
	if snapshot := outcomeSnapshot(t, cli); snapshot["original_recovered"] != float64(1) || snapshot["later_success"] != float64(0) {
		t.Fatalf("exact original retry must recover only the original, got %v", snapshot)
	}
}

// --- capturing logger -------------------------------------------------------

// captureLogger records every Infof message so a test can assert that the
// SENDER_KEY_CONVERGED line was emitted on the real decrypt path. It implements
// the full waLog.Logger interface. Concurrency-safe because the decrypt path may
// log from goroutines, though the wiring test below drives it synchronously.
type captureLogger struct {
	mu   sync.Mutex
	info []string
}

func (c *captureLogger) Infof(msg string, args ...interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.info = append(c.info, fmt.Sprintf(msg, args...))
}
func (c *captureLogger) Warnf(string, ...interface{})  {}
func (c *captureLogger) Errorf(string, ...interface{}) {}
func (c *captureLogger) Debugf(string, ...interface{}) {}
func (c *captureLogger) Sub(string) waLog.Logger       { return c }

func (c *captureLogger) infoContaining(substr string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.info {
		if strings.Contains(m, substr) {
			n++
		}
	}
	return n
}

// infoMatchingAll counts INFO lines that contain ALL of the given substrings.
// Used to scope an assertion to a specific log line (e.g. the SENDER_KEY_CONVERGED
// line) rather than counting a substring (like "device=1") across every INFO line,
// which would conflate it with other instruments that share the field (e.g. the
// STEP 1 SKDM_FOR_FAILED_TUPLE line).
func (c *captureLogger) infoMatchingAll(substrs ...string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, m := range c.info {
		all := true
		for _, s := range substrs {
			if !strings.Contains(m, s) {
				all = false
				break
			}
		}
		if all {
			n++
		}
	}
	return n
}

// --- core bookkeeping tests -------------------------------------------------

// Case 1: clear returns FALSE for a tuple that was never recorded. No
// false-positive convergence: a SENDER_KEY_CONVERGED line must never fire for a
// tuple that never failed.
func TestConvergeClearUnrecordedReturnsFalse(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	if cli.clearFailedSenderKeyTuple("75811323404294_1:1", "120363000000000000@g.us") {
		t.Fatal("clear of a never-recorded tuple returned true; would emit a false-positive CONVERGED")
	}
}

// Case 2: fire-once. After recording, the first clear returns TRUE (convergence
// fires) and a second clear returns FALSE (does not re-fire). The INFO line is
// gated on this bool, so this proves at most one CONVERGED per converged tuple.
func TestConvergeFiresExactlyOnce(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const sender, group = "75811323404294_1:1", "120363000000000000@g.us"

	cli.recordFailedSenderKeyTuple(sender, group)
	if !cli.clearFailedSenderKeyTuple(sender, group) {
		t.Fatal("first clear after record returned false; convergence would never fire")
	}
	if cli.clearFailedSenderKeyTuple(sender, group) {
		t.Fatal("second clear returned true; convergence would fire more than once per tuple")
	}
}

// Case 3: device granularity. Recording (sender_1:1, group) and clearing
// (sender_1:2, group) returns FALSE -- a different inbound device is a different
// tuple. Proves the key includes the inbound device, so convergence is proven
// per (sender, device, group), not just per (sender, group). (Mirrors the
// message.go keying: labeled = from.SignalAddress().String(), device-qualified.)
func TestConvergeDeviceGranularity(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const group = "120363000000000000@g.us"

	cli.recordFailedSenderKeyTuple("75811323404294_1:1", group)
	if cli.clearFailedSenderKeyTuple("75811323404294_1:2", group) {
		t.Fatal("clear of a different-device tuple returned true; key is not device-qualified")
	}
	// And the originally-recorded device still converges exactly once.
	if !cli.clearFailedSenderKeyTuple("75811323404294_1:1", group) {
		t.Fatal("clear of the recorded device returned false")
	}
}

// Case 4: dedup-on-add. Recording the SAME tuple more than once must consume only
// ONE ring slot, so heavy repeat failure load cannot evict a still-unconverged
// distinct tuple prematurely.
//
// Discriminating construction (a non-discriminating "duplicate then fill" would
// pass with or without dedup): record canary C first, then record D TWICE, then
// record (size-2) more distinct tuples. That is exactly `size` DISTINCT tuples
// but `size+1` record CALLS. With dedup-on-add the duplicate D consumes no slot,
// so C survives and clear(C)==true. Without dedup the duplicate D consumes a slot,
// the ring wraps one step further, and C is evicted -> clear(C)==false. Asserting
// clear(C)==true therefore goes RED if the dedup early-return is removed.
func TestConvergeDedupOnAddPreservesCanary(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const group = "120363000000000000@g.us"
	canary := "canary_1:1"
	dup := "dup_1:1"

	cli.recordFailedSenderKeyTuple(canary, group) // slot 0
	cli.recordFailedSenderKeyTuple(dup, group)    // slot 1
	cli.recordFailedSenderKeyTuple(dup, group)    // dedup: consumes NO slot (the property under test)

	// Add (size-2) more DISTINCT tuples. Total distinct = canary + dup + (size-2) = size.
	for i := 0; i < failedSenderKeyTuplesSize-2; i++ {
		cli.recordFailedSenderKeyTuple(fmt.Sprintf("filler_1:%d", i), group)
	}

	if !cli.clearFailedSenderKeyTuple(canary, group) {
		t.Fatal("canary was evicted: a duplicate record consumed a ring slot (dedup-on-add broken); " +
			"heavy repeat load would evict still-unconverged tuples and undercount convergence")
	}
}

// Case 5: ring eviction. Recording size+1 DISTINCT tuples evicts the OLDEST (its
// clear returns false) while the newest remain (their clears return true).
// Asserting the oldest is gone goes RED if the eviction delete is removed (the
// map would grow unbounded and retain it).
func TestConvergeEvictsOldestWhenFull(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const group = "120363000000000000@g.us"

	oldest := "tuple_1:0"
	cli.recordFailedSenderKeyTuple(oldest, group) // slot 0, will be overwritten by the (size)th add

	// Fill the remaining size-1 slots, then one more to wrap and evict slot 0.
	for i := 1; i <= failedSenderKeyTuplesSize; i++ {
		cli.recordFailedSenderKeyTuple(fmt.Sprintf("tuple_1:%d", i), group)
	}

	if cli.clearFailedSenderKeyTuple(oldest, group) {
		t.Fatal("oldest tuple was NOT evicted after size+1 distinct records; ring eviction broken")
	}
	// The newest tuple (the last one recorded) must still be present.
	newest := fmt.Sprintf("tuple_1:%d", failedSenderKeyTuplesSize)
	if !cli.clearFailedSenderKeyTuple(newest, group) {
		t.Fatal("newest tuple was missing; eviction dropped the wrong entry")
	}
}

// Case 6: lazy-init. A bare &Client{} (no NewClient constructor) must not
// nil-panic on either bookkeeping method. record lazy-inits the map under the
// lock; clear only reads a possibly-nil map (Go returns the zero value for a
// nil-map read, never panics) and returns false. The production hot decrypt path
// runs on a fully-constructed client, but the test harness builds bare clients,
// so both methods must survive it.
func TestConvergeBareClientNoNilPanic(t *testing.T) {
	bare := &Client{}
	const sender, group = "75811323404294_1:1", "120363000000000000@g.us"

	// clear on a bare client (nil map) must return false without panicking.
	if bare.clearFailedSenderKeyTuple(sender, group) {
		t.Fatal("clear on a bare &Client{} returned true; expected false on an empty set")
	}
	// record on a bare client must lazy-init and then be clearable.
	bare.recordFailedSenderKeyTuple(sender, group)
	if !bare.clearFailedSenderKeyTuple(sender, group) {
		t.Fatal("record on a bare &Client{} did not lazy-init; clear could not find the tuple")
	}
}

// --- end-to-end wiring test -------------------------------------------------

// Case (preferred): WIRING. Proves message.go actually calls the bookkeeping on
// the real decrypt path and emits the INFO -- the isolated method tests above
// cannot catch a missing/wrong call site (the "silently never fires" risk the
// instrument exists to guard against).
//
// Flow on one client with a real group skmsg:
//  1. decryptGroupMsg with an EMPTY store -> total miss (ErrNoSenderKeyForUser);
//     decryptGroupSenderKey records the inbound tuple.
//  2. handleSenderKeyDistributionMessage stores the sender's key for the group.
//  3. decryptGroupMsg again with the SAME skmsg -> KEY-path decrypt success;
//     decryptGroupSenderKey clears the previously-failing tuple and logs
//     SENDER_KEY_CONVERGED.
//
// The iteration-0 skmsg decrypts on the second pass because the first total-miss
// touched no key state (mirrors TestGroupSenderKeySameDeviceControl plus a leading
// miss). Using a capturing logger sidesteps reverse-engineering the exact bare-vs-
// device-qualified `labeled` string; we assert on the emitted INFO directly.
func TestConvergeEndToEndKeyPathEmitsConverged(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000099", Server: types.GroupServer}
	sender := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}

	plaintext := []byte("converged via key path")
	skdmBytes, skmsgBytes := aliceCrypto(ctx, t, chat.String(), plaintext)

	log := &captureLogger{}
	cli := newTestClient(newFakeSenderKeyStore())
	cli.Log = log
	cli.Store.Log = log

	skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}

	// Pass 1: empty store -> total miss. Records the failing tuple. (We do not
	// assert the error class here; the point is that the miss path ran and that no
	// CONVERGED fired on a first-ever miss.)
	_, _, _ = cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if n := log.infoContaining("SENDER_KEY_CONVERGED"); n != 0 {
		t.Fatalf("CONVERGED fired on the first miss (n=%d); it must fire only on a later success", n)
	}

	// Store the sender key for the group.
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdmBytes)
	// STEP 1 instrument: the SKDM arrives for a tuple that pass 1 recorded as a total
	// miss, so handleSenderKeyDistributionMessage must emit exactly one
	// SKDM_FOR_FAILED_TUPLE line with installed=y carrying the inbound device (=1).
	// This positively exercises the new instrument on the live receive path.
	if n := log.infoMatchingAll("SKDM_FOR_FAILED_TUPLE", "installed=y", "device=1"); n != 1 {
		t.Fatalf("expected exactly one SKDM_FOR_FAILED_TUPLE installed=y device=1 line for the "+
			"stuck tuple, got %d; the STEP 1 instrument is NOT wired to handleSenderKeyDistributionMessage", n)
	}

	// Pass 2: same skmsg now decrypts via the KEY path -> CONVERGED.
	pt, _, err := cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if err != nil {
		t.Fatalf("second decrypt (key path) failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
	}
	if n := log.infoContaining("SENDER_KEY_CONVERGED"); n != 1 {
		t.Fatalf("expected exactly one SENDER_KEY_CONVERGED line after key-path recovery, got %d; "+
			"the instrument is NOT wired to the live decrypt path", n)
	}
	// The live path must preserve the INBOUND device (Device=1), NOT collapse it
	// to :0. decryptGroupMsg passes `from` verbatim to decryptGroupSenderKey
	// (message.go: "No :0 normalization" -- Phase 27 removed the bare-:0 collapse),
	// so labeled := from.SignalAddress().String() and the logged device must be 1.
	// If a future change re-introduced ToNonAD()/:0 normalization on the sender
	// before this call, every inbound device would collapse to :0 and the set would
	// degrade to per-(sender,group) -- breaking the per-(sender,device,group) claim.
	// Asserting device=1 on the CONVERGED line specifically locks that in (scoped to
	// the CONVERGED line so the SKDM_FOR_FAILED_TUPLE line, which also carries
	// device=1, does not inflate the count).
	if log.infoMatchingAll("SENDER_KEY_CONVERGED", "device=1") != 1 {
		t.Fatalf("CONVERGED line did not carry the inbound device (device=1); " +
			"the sender device was normalized (e.g. to :0) before decryptGroupSenderKey, " +
			"degrading the set to per-(sender,group)")
	}
	if log.infoMatchingAll("SENDER_KEY_CONVERGED", "device=0") != 0 {
		t.Fatal("CONVERGED logged device=0 for a Device=1 inbound; :0 normalization regressed")
	}
}
