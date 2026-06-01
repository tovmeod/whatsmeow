// kavtov-fork: perf 260601-uuy — SENDERKEY_MISS have= sampling.
//
// The have= diagnostic in decryptGroupSenderKey costs one GetSenderKey +
// record deserialize per candidate device and previously ran on EVERY group
// decrypt failure. perf 260601-uuy extracts it into extractSenderKeyHave and
// gates it behind senderKeyMissShouldSample (1-in-N, env-configurable, default
// on, disable via KAVTOV_SENDERKEY_MISS_HAVE=0).
//
// These symbols are unexported, so this test MUST be package whatsmeow
// (internal), not package whatsmeow_test.

package whatsmeow

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// countingSenderKeyStore wraps an inner store.SenderKeyStore and counts
// GetSenderKey calls, so the sampler-gating test can assert extractSenderKeyHave
// is never reached (zero store reads) when senderKeyMissShouldSample is false.
type countingSenderKeyStore struct {
	inner    store.SenderKeyStore
	getCalls atomic.Int64
}

func (c *countingSenderKeyStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	return c.inner.PutSenderKey(ctx, group, user, session)
}

func (c *countingSenderKeyStore) GetSenderKey(ctx context.Context, group, user string) ([]byte, error) {
	c.getCalls.Add(1)
	return c.inner.GetSenderKey(ctx, group, user)
}

func (c *countingSenderKeyStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	return c.inner.GetSenderKeyDevices(ctx, group, userBare)
}

var _ store.SenderKeyStore = (*countingSenderKeyStore)(nil)

// Test A: extractSenderKeyHave with an empty devices slice returns "none"
// without calling the store.
func TestExtractSenderKeyHave_EmptyDevicesReturnsNoneWithoutStoreCalls(t *testing.T) {
	ctx := context.Background()
	sk := &countingSenderKeyStore{inner: newFakeSenderKeyStore()}

	got := extractSenderKeyHave(ctx, sk, "120363000000000000@g.us", nil, 7)
	if got != "none" {
		t.Errorf("extractSenderKeyHave(empty) = %q, want %q", got, "none")
	}
	if n := sk.getCalls.Load(); n != 0 {
		t.Errorf("GetSenderKey calls = %d, want 0 (empty devices must short-circuit)", n)
	}
}

// Test B: extractSenderKeyHave against a populated store returns a non-empty
// formatted string carrying the stored record's keyid and iter for the
// candidate device. Uses the real libsignal builder.Process path to seed a
// genuine serialized SenderKey record (via the package's seedDeviceQualifiedRecord).
func TestExtractSenderKeyHave_PopulatedStoreFormatsKeyidIter(t *testing.T) {
	ctx := context.Background()
	chat := types.JID{User: "120363000000000000", Server: types.GroupServer}
	sender := types.JID{User: "75811323404294", Server: types.HiddenUserServer, Device: 0}

	cli := newTestClient(newFakeSenderKeyStore())
	skdmBytes, _ := aliceCrypto(ctx, t, chat.String(), []byte("seed"))
	seedDeviceQualifiedRecord(ctx, t, cli, chat, sender, skdmBytes)

	// Mirror decryptGroupSenderKey: candidate device id is the bare sender
	// address (the fix keys both store and lookup by ToNonAD().SignalAddress()).
	sid := sender.ToNonAD().SignalAddress().String()
	devices := []string{sid}

	// targetKeyID=0 forces the "no match" branch (the seeded keyID is random),
	// which still formats keyid=/iter= via SenderKeyState() — the cheap path we
	// want to confirm produces a non-empty diagnostic.
	got := extractSenderKeyHave(ctx, cli.Store.SenderKeys, chat.String(), devices, 0)
	if got == "none" || got == "" {
		t.Fatalf("extractSenderKeyHave(populated) = %q, want a non-empty formatted string", got)
	}
	if !strings.Contains(got, "keyid=") || !strings.Contains(got, "iter=") {
		t.Errorf("extractSenderKeyHave = %q, want keyid= and iter= present", got)
	}
	if !strings.Contains(got, sid) {
		t.Errorf("extractSenderKeyHave = %q, want it to name the candidate device %q", got, sid)
	}
}

// Test C: with senderKeyMissHaveRate == 0, senderKeyMissShouldSample always
// returns false. Saves/restores the package var to avoid cross-test pollution.
func TestSenderKeyMissShouldSample_DisabledRateNeverSamples(t *testing.T) {
	saved := senderKeyMissHaveRate
	t.Cleanup(func() { senderKeyMissHaveRate = saved })

	senderKeyMissHaveRate = 0
	for i := 0; i < 1000; i++ {
		if senderKeyMissShouldSample() {
			t.Fatalf("senderKeyMissShouldSample returned true at i=%d with rate=0", i)
		}
	}
}

// Test D-proxy: when senderKeyMissShouldSample is false (rate=0), the have=
// path issues zero GetSenderKey calls — extractSenderKeyHave is never reached.
// (need_keyid/need_iter live on the always-on path and require no store reads.)
func TestSenderKeyMissSampling_RateZeroSkipsStoreReads(t *testing.T) {
	ctx := context.Background()
	saved := senderKeyMissHaveRate
	t.Cleanup(func() { senderKeyMissHaveRate = saved })
	senderKeyMissHaveRate = 0

	sk := &countingSenderKeyStore{inner: newFakeSenderKeyStore()}
	devices := []string{"75811323404294_1:0", "75811323404294_1:5"}

	// Simulate the gated have= computation at the SENDERKEY_MISS site for many
	// failures. With rate=0 the sampler never fires, so extractSenderKeyHave is
	// never invoked and the store is never read.
	for i := 0; i < 1000; i++ {
		if senderKeyMissShouldSample() {
			_ = extractSenderKeyHave(ctx, sk, "120363000000000000@g.us", devices, 7)
		}
	}
	if n := sk.getCalls.Load(); n != 0 {
		t.Errorf("GetSenderKey calls = %d, want 0 (rate=0 must skip the have= store reads)", n)
	}
}

// senderKeyMissShouldSample fires exactly 1-in-N at a positive rate. Confirms
// the sampler still computes have= on the sampled fraction (the diagnostic is
// not silently disabled at the default rate).
func TestSenderKeyMissShouldSample_PositiveRateFiresOneInN(t *testing.T) {
	saved := senderKeyMissHaveRate
	savedCounter := senderKeyMissCounter.Load()
	t.Cleanup(func() {
		senderKeyMissHaveRate = saved
		senderKeyMissCounter.Store(savedCounter)
	})

	senderKeyMissHaveRate = 10
	senderKeyMissCounter.Store(0)
	fires := 0
	for i := 0; i < 100; i++ {
		if senderKeyMissShouldSample() {
			fires++
		}
	}
	if fires != 10 {
		t.Errorf("sampler fired %d times in 100 calls at rate=10, want 10", fires)
	}
}
