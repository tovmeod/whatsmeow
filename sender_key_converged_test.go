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
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/protocol"
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
	account := types.JID{User: "outcome-account", Server: types.DefaultUserServer, Device: 3}
	cli.Store.ID = &account
	if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now(), "original"); err == nil {
		t.Fatal("original must fail before its sender key arrives")
	}
	if snapshot := outcomeSnapshot(t, cli); snapshot["original_failures"] != float64(1) {
		t.Fatalf("expected one terminal original failure, got %v", snapshot)
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdm)
	if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now(), "original"); err != nil {
		t.Fatal(err)
	}
	if snapshot := outcomeSnapshot(t, cli); snapshot["original_recovered"] != float64(1) || snapshot["later_success"] != float64(0) {
		t.Fatalf("exact original retry must recover only the original, got %v", snapshot)
	}
}

func outcomeFixture() (*Client, types.JID, types.JID) {
	cli := newTestClient(newFakeSenderKeyStore())
	account := types.JID{User: "private-account", Server: types.DefaultUserServer, Device: 3}
	cli.Store.ID = &account
	return cli, types.JID{User: "private-group", Server: types.GroupServer}, types.JID{User: "private-sender", Server: types.HiddenUserServer, Device: 2}
}

func TestSenderKeyOutcomeOriginalLaterDistinctCiphertext(t *testing.T) {
	ctx := context.Background()
	cli, chat, sender := outcomeFixture()
	alice := newAliceSenderKeyStore()
	name := protocol.NewSenderKeyName(chat.String(), protocol.NewSignalAddress("alice", 0))
	builder := groups.NewGroupSessionBuilder(alice, pbSerializer)
	skdm, err := builder.Create(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	cipher := groups.NewGroupCipher(builder, name, alice)
	encrypt := func(text string) *waBinary.Node {
		message, err := cipher.Encrypt(ctx, []byte(text))
		if err != nil {
			t.Fatal(err)
		}
		return &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: message.(*protocol.SenderKeyMessage).SignedSerialize()}
	}
	original, later := encrypt("failed original"), encrypt("different later ciphertext")
	if _, _, err = cli.decryptGroupMsg(ctx, original, sender, chat, time.Now(), "original"); err == nil {
		t.Fatal("expected miss")
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, sender, skdm.Serialize())
	if _, _, err = cli.decryptGroupMsg(ctx, later, sender, chat, time.Now(), "later"); err != nil {
		t.Fatal(err)
	}
	snapshot := cli.SenderKeyRecoverySnapshot()
	if snapshot.OriginalRecovered != 0 || snapshot.LaterSuccess != 1 || snapshot.PendingOriginals != 1 {
		t.Fatalf("later ciphertext falsely resolved original: %+v", snapshot)
	}
	// The skipped key still supports the existing explicit-original retry.
	if _, _, err = cli.decryptGroupMsg(ctx, original, sender, chat, time.Now(), "original"); err != nil {
		t.Fatal(err)
	}
	snapshot = cli.SenderKeyRecoverySnapshot()
	if snapshot.OriginalRecovered != 1 || snapshot.LaterSuccess != 1 || snapshot.PendingOriginals != 0 {
		t.Fatalf("original/later classifications merged: %+v", snapshot)
	}
}

func TestSenderKeyOutcomeCorrelation(t *testing.T) {
	now := time.Unix(1000, 0)
	for _, dimension := range []string{"nonce", "account", "device", "group", "unicode", "delimiter"} {
		t.Run(dimension, func(t *testing.T) {
			cli, chat, sender := outcomeFixture()
			id := types.MessageID("exact\x00é|raw")
			cli.recordSenderKeyOutcome(chat, sender, id, senderKeyTerminalFailure, now)
			originalNonce, originalAccount := cli.senderKeyOutcomeNonce, *cli.Store.ID
			successChat, successSender, successID := chat, sender, id
			switch dimension {
			case "nonce":
				cli.senderKeyOutcomeNonce = newSenderKeyOutcomeNonce()
			case "account":
				other := originalAccount
				other.User += "other"
				cli.Store.ID = &other
			case "device":
				successSender.Device++
			case "group":
				successChat.User += "other"
			case "unicode":
				successID = "exact\x00e\u0301|raw"
			case "delimiter":
				successID = "exact|\x00éraw"
			}
			cli.recordSenderKeyOutcome(successChat, successSender, successID, senderKeyKeySuccess, now.Add(time.Second))
			snapshot := cli.senderKeyRecoverySnapshotAt(now.Add(time.Second))
			if snapshot.OriginalRecovered != 0 || snapshot.PendingOriginals != 1 {
				t.Fatalf("cross-lineage original match: %+v", snapshot)
			}
			cli.senderKeyOutcomeNonce, cli.Store.ID = originalNonce, &originalAccount
			cli.recordSenderKeyOutcome(chat, sender, id, senderKeyKeySuccess, now.Add(2*time.Second))
			if got := cli.senderKeyRecoverySnapshotAt(now.Add(2 * time.Second)); got.OriginalRecovered != 1 {
				t.Fatalf("exact ID did not recover: %+v", got)
			}
		})
	}
	if senderKeyOutcomeToken([]string{"ab", "c"}) == senderKeyOutcomeToken([]string{"a", "bc"}) {
		t.Fatal("length-prefix encoding is ambiguous")
	}
	cli, _, _ := outcomeFixture()
	other, _, _ := outcomeFixture()
	_ = cli.SenderKeyRecoverySnapshot()
	_ = other.SenderKeyRecoverySnapshot()
	if cli.senderKeyOutcomeNonce == other.senderKeyOutcomeNonce {
		t.Fatal("client/store lifetimes share a nonce")
	}
	data, _ := json.Marshal(cli.SenderKeyRecoverySnapshot())
	for _, raw := range []string{"private-account", "private-group", "private-sender", "exact", "nonce", "token"} {
		if strings.Contains(string(data), raw) {
			t.Fatalf("snapshot leaks %q: %s", raw, data)
		}
	}
}

func TestSenderKeyOutcomeCorrelationEpoch(t *testing.T) {
	if os.Getenv("SENDER_KEY_EPOCH_CHILD") == "1" {
		fmt.Println(senderKeyOutcomeEpoch)
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(self, "-test.run=^TestSenderKeyOutcomeCorrelationEpoch$")
	command.Env = append(os.Environ(), "SENDER_KEY_EPOCH_CHILD=1")
	data, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), senderKeyOutcomeEpoch) {
		t.Fatal("new process reused the old process_epoch")
	}
}

type outcomeInlineRecoverer struct {
	cli          *Client
	chat, sender types.JID
	skdm         []byte
}

func (recoverer *outcomeInlineRecoverer) TryInlineRecovery(ctx context.Context, _, _, _ string, _, _ uint32) (string, bool, error) {
	recoverer.cli.handleSenderKeyDistributionMessage(ctx, recoverer.chat, recoverer.sender, recoverer.skdm)
	return "test-donor", true, nil
}

func TestSenderKeyOutcomeOriginalLaterInline(t *testing.T) {
	cli, chat, sender := outcomeFixture()
	ctx := context.Background()
	skdm, ciphertext := aliceCrypto(ctx, t, chat.String(), []byte("inline rescue"))
	cli.Store.InlineRecoverer = &outcomeInlineRecoverer{cli: cli, chat: chat, sender: sender, skdm: skdm}
	node := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: ciphertext}
	if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now(), "inline"); err != nil {
		t.Fatal(err)
	}
	snapshot := cli.SenderKeyRecoverySnapshot()
	if snapshot.SameAttemptInlineSuccess != 1 || snapshot.OriginalFailures != 0 || snapshot.OriginalRecovered != 0 || snapshot.LaterSuccess != 0 {
		t.Fatalf("same-attempt donor success classified as terminal/later: %+v", snapshot)
	}
}

func TestSenderKeyOutcomeRetention(t *testing.T) {
	cli, chat, sender := outcomeFixture()
	start := time.Unix(1000, 0)
	cli.recordSenderKeyOutcome(chat, sender, "start", senderKeyTerminalFailure, start)
	cli.recordSenderKeyOutcome(chat, sender, "end-minus-one", senderKeyTerminalFailure, start.Add(299*time.Second))
	cli.recordSenderKeyOutcome(chat, sender, "end", senderKeyTerminalFailure, start.Add(300*time.Second))
	snapshot := cli.senderKeyRecoverySnapshotAt(start.Add(900 * time.Second))
	selected := uint64(0)
	for _, cohort := range snapshot.Cohorts {
		if cohort.FailureSecond >= start.Unix() && cohort.FailureSecond < start.Unix()+300 {
			selected += cohort.OriginalFailures
		}
	}
	if selected != 2 || snapshot.PendingOriginals != 3 || snapshot.Expiries != 0 {
		t.Fatalf("300s/900s adjacency failed: %+v", snapshot)
	}
	cli.recordSenderKeyOutcome(chat, sender, "start", senderKeyKeySuccess, start.Add(900*time.Second))
	snapshot = cli.senderKeyRecoverySnapshotAt(start.Add(900*time.Second + time.Nanosecond))
	if snapshot.OriginalRecovered != 1 || snapshot.Expiries != 1 || snapshot.UnknownUntraced != 0 {
		t.Fatalf("inclusive follow-up lost recovery: %+v", snapshot)
	}
	snapshot = cli.senderKeyRecoverySnapshotAt(start.Add(1201 * time.Second))
	if snapshot.Occupancy != 0 || snapshot.PendingOriginals != 0 || snapshot.UnknownUntraced != 2 || len(snapshot.Cohorts) != 0 {
		t.Fatalf("expiry claims loss or retains stale cohorts: %+v", snapshot)
	}
	cli, chat, sender = outcomeFixture()
	for i := 0; i <= senderKeyOutcomeCapacity; i++ {
		cli.recordSenderKeyOutcome(chat, sender, types.MessageID(fmt.Sprint(i)), senderKeyTerminalFailure, start)
	}
	snapshot = cli.senderKeyRecoverySnapshotAt(start)
	if snapshot.Occupancy != senderKeyOutcomeCapacity || snapshot.Evictions != 1 || snapshot.UnknownUntraced != 1 || snapshot.PendingOriginals != senderKeyOutcomeCapacity {
		t.Fatalf("capacity eviction not bounded/unknown: %+v", snapshot)
	}
}

func TestSenderKeyOutcomeDuplicate(t *testing.T) {
	cli, chat, sender := outcomeFixture()
	now := time.Unix(1000, 0)
	for i := 0; i < 2; i++ {
		cli.recordSenderKeyOutcome(chat, sender, "original", senderKeyTerminalFailure, now)
	}
	for i := 0; i < 2; i++ {
		cli.recordSenderKeyOutcome(chat, sender, "later", senderKeyKeySuccess, now.Add(time.Second))
	}
	for i := 0; i < 2; i++ {
		cli.recordSenderKeyOutcome(chat, sender, "original", senderKeyInlineSuccess, now.Add(time.Second))
	}
	snapshot := cli.senderKeyRecoverySnapshotAt(now.Add(time.Second))
	if snapshot.OriginalFailures != 1 || snapshot.OriginalRecovered != 1 || snapshot.LaterSuccess != 1 || snapshot.Duplicates != 3 || snapshot.SameAttemptInlineSuccess != 0 {
		t.Fatalf("duplicate/inline retry classified incorrectly: %+v", snapshot)
	}
	cli.recordSenderKeyOutcome(chat, sender, "new-inline", senderKeyInlineSuccess, now.Add(2*time.Second))
	snapshot = cli.senderKeyRecoverySnapshotAt(now.Add(2 * time.Second))
	if snapshot.OriginalFailures != 1 || snapshot.SameAttemptInlineSuccess != 1 || snapshot.LaterSuccess != 1 {
		t.Fatalf("initial inline rescue creates terminal failure: %+v", snapshot)
	}
}

func TestSenderKeyOutcomeConcurrent(t *testing.T) {
	cli, chat, sender := outcomeFixture()
	now := time.Unix(1000, 0)
	cli.recordSenderKeyOutcome(chat, sender, "original", senderKeyTerminalFailure, now)
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cli.recordSenderKeyOutcome(chat, sender, "later", senderKeyKeySuccess, now.Add(time.Second))
			cli.recordSenderKeyOutcome(chat, sender, "original", senderKeyKeySuccess, now.Add(time.Second))
			_ = cli.senderKeyRecoverySnapshotAt(now.Add(time.Second))
		}()
	}
	wg.Wait()
	snapshot := cli.senderKeyRecoverySnapshotAt(now.Add(time.Second))
	if snapshot.OriginalRecovered != 1 || snapshot.LaterSuccess != 1 || snapshot.Duplicates != 198 || snapshot.PendingOriginals != 0 {
		t.Fatalf("parallel exact-ID classification not deterministic: %+v", snapshot)
	}
}

type outcomeLockedStore struct {
	mu sync.Mutex
	*fakeSenderKeyStore
}

func (store *outcomeLockedStore) GetSenderKeyDevices(ctx context.Context, group, sender string) ([]string, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	return store.fakeSenderKeyStore.GetSenderKeyDevices(ctx, group, sender)
}

func TestSenderKeyOutcomeConcurrentDecrypts(t *testing.T) {
	cli, chat, sender := outcomeFixture()
	cli.Store.SenderKeys = &outcomeLockedStore{fakeSenderKeyStore: newFakeSenderKeyStore()}
	ctx := context.Background()
	_, ciphertext := aliceCrypto(ctx, t, chat.String(), []byte("parallel terminal miss"))
	node := &waBinary.Node{Attrs: waBinary.Attrs{"v": "3"}, Content: ciphertext}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := cli.decryptGroupMsg(ctx, node, sender, chat, time.Now(), "same-original"); err == nil {
				t.Error("unexpected decrypt without a key")
			}
		}()
	}
	wg.Wait()
	snapshot := cli.SenderKeyRecoverySnapshot()
	if snapshot.OriginalFailures != 1 || snapshot.Duplicates != 63 || snapshot.PendingOriginals != 1 {
		t.Fatalf("parallel decrypt callbacks double-count: %+v", snapshot)
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
