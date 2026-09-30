// kavtov-fork (perf 260602): SKDM redundancy-dedup safety tests.
//
// handleSenderKeyDistributionMessage skips builder.Process (a LoadSenderKey +
// StoreSenderKey write) when an SKDM for (sender,group,keyID) is at an iteration
// at-or-below one already processed. The risk if the bookkeeping is wrong is
// twofold and opposite: (a) under-skip = no write reduction (perf only, safe),
// (b) OVER-skip = a needed install is suppressed and a stuck tuple never
// recovers — a correctness regression in the load-bearing no-sender-key path.
//
// The dedup is ITERATION-AWARE precisely because SKDM.Create emits the sender's
// LIVE SenderChainKey iteration (verified: GroupCipher.Encrypt advances it), so a
// re-bundled SKDM from an active sender can carry a HIGHER iteration — a forward
// checkpoint that rescues a recipient who fell >2000 behind (ErrTooFarIntoFuture).
// Skipping that would silently drop a message. These tests pin all three edges:
// equal-iteration re-broadcast is skipped (perf), a HIGHER-iteration SKDM still
// processes (rescue preserved), and a failing tuple always re-processes (recovery
// never blocked). Write-count assertions go through countingPutSenderKeyStore so
// they prove the actual DB-write call count, not just an in-memory flag.

package whatsmeow

import (
	"context"
	"testing"

	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// countingPutSenderKeyStore wraps a fakeSenderKeyStore and counts PutSenderKey
// calls — the write the dedup exists to elide. Get/Devices delegate unchanged.
type countingPutSenderKeyStore struct {
	inner    *fakeSenderKeyStore
	putCalls int
}

func (c *countingPutSenderKeyStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	c.putCalls++
	return c.inner.PutSenderKey(ctx, group, user, session)
}
func (c *countingPutSenderKeyStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	return c.inner.GetSenderKey(ctx, group, user)
}
func (c *countingPutSenderKeyStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	return c.inner.GetSenderKeyDevices(ctx, group, userBare)
}

var _ store.SenderKeyStore = (*countingPutSenderKeyStore)(nil)

// aliceRisingSKDMs produces TWO SKDMs for the SAME keyID: one at iteration 0 and
// one at iteration `advance`, by Create-ing once, Encrypt-ing `advance` times to
// move Alice's sending chain forward (GroupCipher.Encrypt calls SetSenderChainKey
// .Next()), then Create-ing again from the now-advanced live chain. This is the
// real "re-bundled SKDM carries a higher iteration" case the dedup must not skip.
func aliceRisingSKDMs(ctx context.Context, t *testing.T, group string, advance int) (skdm0, skdmN []byte, iterN uint32) {
	t.Helper()
	aliceStore := newAliceSenderKeyStore()
	aliceName := protocol.NewSenderKeyName(group, protocol.NewSignalAddress("alice", 0))
	builder := groups.NewGroupSessionBuilder(aliceStore, store.SignalProtobufSerializer)

	first, err := builder.Create(ctx, aliceName)
	if err != nil {
		t.Fatalf("alice Create (iter 0): %v", err)
	}
	cipher := groups.NewGroupCipher(builder, aliceName, aliceStore)
	for i := 0; i < advance; i++ {
		if _, err := cipher.Encrypt(ctx, []byte("advance")); err != nil {
			t.Fatalf("alice Encrypt #%d: %v", i, err)
		}
	}
	second, err := builder.Create(ctx, aliceName) // same keyID, iteration == advance
	if err != nil {
		t.Fatalf("alice Create (iter %d): %v", advance, err)
	}
	if first.ID() != second.ID() {
		t.Fatalf("expected identical keyID across re-Create, got %d then %d", first.ID(), second.ID())
	}
	if second.Iteration() <= first.Iteration() {
		t.Fatalf("re-Create did not advance iteration: first=%d second=%d (test premise broken)", first.Iteration(), second.Iteration())
	}
	return first.Serialize(), second.Serialize(), second.Iteration()
}

// --- end-to-end wiring: the write-skip ---------------------------------------

// A re-bundled IDENTICAL SKDM (same keyID, same iteration) for a keyID already
// processed must be skipped: the second handleSenderKeyDistributionMessage
// performs NO second PutSenderKey. Goes RED if the skip early-return is removed.
func TestSKDMDedupSkipsRedundantReprocess(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000077", Server: types.GroupServer}
	from := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}
	skdmBytes, _ := aliceCrypto(ctx, t, chat.String(), []byte("x"))

	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)

	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmBytes)
	if sk.putCalls != 1 {
		t.Fatalf("first SKDM: PutSenderKey calls = %d, want 1 (the install)", sk.putCalls)
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmBytes)
	if sk.putCalls != 1 {
		t.Fatalf("re-bundled identical SKDM: PutSenderKey calls = %d, want 1 (dedup must skip the "+
			"second write); the iteration-aware skip is not wired", sk.putCalls)
	}
}

// THE CRITICAL CASE: a re-bundled SKDM for the SAME keyID at a HIGHER iteration is
// a forward checkpoint (the >2000-gap rescue) and MUST process — a second write.
// A subsequent LOWER (stale) SKDM for that keyID is then skipped. Goes RED if the
// skip were keyID-only (iteration-blind): it would wrongly skip the higher SKDM
// and silently drop the rescue — the exact no-sender-key data-loss class.
func TestSKDMDedupHigherIterationStillProcesses(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000080", Server: types.GroupServer}
	from := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}
	skdm0, skdmN, iterN := aliceRisingSKDMs(ctx, t, chat.String(), 50)
	if iterN == 0 {
		t.Fatal("rising SKDM iteration is 0; test premise broken")
	}

	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)

	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdm0) // install @ iter 0
	if sk.putCalls != 1 {
		t.Fatalf("install: PutSenderKey calls = %d, want 1", sk.putCalls)
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmN) // higher iter -> MUST process (rescue)
	if sk.putCalls != 2 {
		t.Fatalf("higher-iteration SKDM: PutSenderKey calls = %d, want 2 (a forward checkpoint must "+
			"process, not dedup); iteration-blind skip would drop the >2000-gap rescue", sk.putCalls)
	}
	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdm0) // stale lower iter -> skip
	if sk.putCalls != 2 {
		t.Fatalf("stale lower-iteration SKDM: PutSenderKey calls = %d, want 2 (at-or-below the processed "+
			"iteration is redundant and must skip)", sk.putCalls)
	}
}

// Two distinct keyIDs for the same (sender,group) are distinct generations and
// must each install. Goes RED if the dedup key omitted KeyID.
func TestSKDMDedupDistinctKeyIDStillInstalls(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000078", Server: types.GroupServer}
	from := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}
	skdmA, _ := aliceCrypto(ctx, t, chat.String(), []byte("a"))
	skdmB, _ := aliceCrypto(ctx, t, chat.String(), []byte("b")) // fresh store -> fresh keyID

	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)

	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmA)
	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmB)
	if sk.putCalls != 2 {
		t.Fatalf("two distinct keyIDs: PutSenderKey calls = %d, want 2 (a different generation must "+
			"install, not dedup); the dedup key is missing KeyID", sk.putCalls)
	}
}

// --- end-to-end wiring: the recovery guard -----------------------------------

// A tuple currently in the failed-set must ALWAYS re-process, even an identical
// re-broadcast — the guarantee that the dedup can never block recovery of a
// deleted/lost key. Goes RED if the `!wasFailed` guard is dropped.
func TestSKDMDedupRecoveryGuardForcesReprocessForFailedTuple(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000079", Server: types.GroupServer}
	from := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 1}
	skdmBytes, _ := aliceCrypto(ctx, t, chat.String(), []byte("y"))

	sk := &countingPutSenderKeyStore{inner: newFakeSenderKeyStore()}
	cli := newTestClient(sk)
	cli.recordFailedSenderKeyTuple(from.SignalAddress().String(), chat.String())

	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmBytes)
	cli.handleSenderKeyDistributionMessage(ctx, chat, from, skdmBytes)
	if sk.putCalls != 2 {
		t.Fatalf("failing tuple: PutSenderKey calls = %d, want 2 (a failing tuple must re-process every "+
			"SKDM so a lost key recovers); the failed-set bypass is broken — dedup is blocking recovery", sk.putCalls)
	}
}

// --- isolated bookkeeping ----------------------------------------------------

// keyID is part of the dedup key: processing keyID 1 must not mark keyID 2.
func TestSKDMProcessedKeyIDGranularity(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const s, g = "75811323404294_1:1", "120363000000000000@g.us"
	cli.markSKDMProcessed(s, g, 1, 0)
	if _, ok := cli.skdmProcessedIteration(s, g, 2); ok {
		t.Fatal("keyID 2 reported processed after only keyID 1 was marked; key is not keyID-qualified")
	}
	if _, ok := cli.skdmProcessedIteration(s, g, 1); !ok {
		t.Fatal("keyID 1 not reported processed after marking")
	}
}

// markSKDMProcessed keeps the MAX iteration: a later stale (lower) mark must not
// lower the recorded bar, or a stale re-broadcast could un-skip future dups.
func TestSKDMProcessedKeepsMaxIteration(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const s, g = "75811323404294_1:1", "120363000000000000@g.us"
	cli.markSKDMProcessed(s, g, 7, 100)
	cli.markSKDMProcessed(s, g, 7, 5) // stale, lower
	if got, _ := cli.skdmProcessedIteration(s, g, 7); got != 100 {
		t.Fatalf("recorded iteration = %d, want 100 (max must not be lowered by a stale mark)", got)
	}
	cli.markSKDMProcessed(s, g, 7, 250) // forward
	if got, _ := cli.skdmProcessedIteration(s, g, 7); got != 250 {
		t.Fatalf("recorded iteration = %d, want 250 (a forward mark must raise the bar)", got)
	}
}

// dedup-on-add: marking the SAME (sender,group,keyID) twice consumes only ONE
// ring slot, so a canary recorded first survives exactly `size` distinct marks.
func TestSKDMProcessedDedupOnAddPreservesCanary(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const g = "120363000000000000@g.us"
	cli.markSKDMProcessed("canary_1:1", g, 1, 0)
	cli.markSKDMProcessed("dup_1:1", g, 1, 0)
	cli.markSKDMProcessed("dup_1:1", g, 1, 1) // dedup: updates iteration, consumes NO slot
	for i := 0; i < skdmInstalledSize-2; i++ {
		cli.markSKDMProcessed("filler_1:1", g, uint32(100+i), 0) // distinct keyIDs
	}
	if _, ok := cli.skdmProcessedIteration("canary_1:1", g, 1); !ok {
		t.Fatal("canary evicted: a duplicate mark consumed a ring slot (dedup-on-add broken)")
	}
}

// ring eviction: size+1 DISTINCT marks evict the oldest.
func TestSKDMProcessedEvictsOldestWhenFull(t *testing.T) {
	cli := newTestClient(newFakeSenderKeyStore())
	const g, s = "120363000000000000@g.us", "75811323404294_1:1"
	cli.markSKDMProcessed(s, g, 0, 0) // oldest
	for i := 1; i <= skdmInstalledSize; i++ {
		cli.markSKDMProcessed(s, g, uint32(i), 0)
	}
	if _, ok := cli.skdmProcessedIteration(s, g, 0); ok {
		t.Fatal("oldest keyID not evicted after size+1 distinct marks; ring eviction broken")
	}
	if _, ok := cli.skdmProcessedIteration(s, g, uint32(skdmInstalledSize)); !ok {
		t.Fatal("newest keyID missing; eviction dropped the wrong entry")
	}
}

// bare &Client{}: neither method nil-panics (the prod constructor seeds the map).
func TestSKDMProcessedBareClientNoNilPanic(t *testing.T) {
	bare := &Client{}
	const s, g = "75811323404294_1:1", "120363000000000000@g.us"
	if _, ok := bare.skdmProcessedIteration(s, g, 1); ok {
		t.Fatal("skdmProcessedIteration on a bare &Client{} returned ok; expected not-present on empty set")
	}
	bare.markSKDMProcessed(s, g, 1, 0) // must lazy-init, not panic
	if _, ok := bare.skdmProcessedIteration(s, g, 1); !ok {
		t.Fatal("markSKDMProcessed on a bare &Client{} did not lazy-init")
	}
}
