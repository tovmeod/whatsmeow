// Failed tuples force SKDM recovery past stale dedup state; successful decrypts clear them.

package whatsmeow

import (
	"context"
	"fmt"
	"testing"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
)

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

func TestFailedSenderKeyTupleClearedAfterKeyPathRecovery(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000099", Server: types.GroupServer}
	sender := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}

	plaintext := []byte("converged via key path")
	skdmBytes, skmsgBytes := aliceCrypto(ctx, t, chat.String(), plaintext)

	cli := newTestClient(newFakeSenderKeyStore())

	skmsgNode := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: skmsgBytes}

	// Pass 1: empty store -> total miss. Records the failing tuple. (We do not
	// assert the error class here; the point is that the miss path ran and that no
	// CONVERGED fired on a first-ever miss.)
	_, _, _ = cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if !cli.isFailedSenderKeyTuple(sender.SignalAddress().String(), chat.String()) {
		t.Fatal("terminal failure did not activate the inbound-device SKDM recovery bypass")
	}

	// Store the sender key for the group.
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdmBytes)
	// STEP 1 instrument: the SKDM arrives for a tuple that pass 1 recorded as a total
	// miss, so handleSenderKeyDistributionMessage must emit exactly one
	// SKDM_FOR_FAILED_TUPLE line with installed=y carrying the inbound device (=1).
	// This positively exercises the new instrument on the live receive path.

	// Pass 2: same skmsg now decrypts via the KEY path -> CONVERGED.
	pt, _, err := cli.decryptGroupMsg(ctx, skmsgNode, sender, chat, time.Now())
	if err != nil {
		t.Fatalf("second decrypt (key path) failed: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("decrypted plaintext mismatch: got %q want %q", pt, plaintext)
	}
	if cli.isFailedSenderKeyTuple(sender.SignalAddress().String(), chat.String()) {
		t.Fatal("successful key-path decrypt left the inbound failed-tuple recovery bypass active")
	}
}
