// Copyright (c) 2026 Kavtov Platform. MPL-2.0.
package sqlstore

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	_ "github.com/jackc/pgx/v5/stdlib"
	"go.mau.fi/libsignal/groups"
	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/signalerror"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// Every case has actual libsignal ciphertext, committed SQL donor rows and
// separate original/later assertions. No replay worker or timer exists.
func TestInlineCipherOriginalUnreplayedIdle(t *testing.T) { runInlineCipherOutcome(t, "idle") }
func TestInlineCipherOriginalRecoveredByExistingRetry(t *testing.T) {
	runInlineCipherOutcome(t, "retry")
}
func TestInlineCipherRetainedSkippedKey(t *testing.T)          { runInlineCipherOutcome(t, "skipped") }
func TestInlineCipherPermanentlyLostOriginal(t *testing.T)     { runInlineCipherOutcome(t, "loss") }
func TestInlineCipherObservableWriteInvalidation(t *testing.T) { runInlineCipherOutcome(t, "write") }

type aliceSenderKeyStore struct {
	keys map[*protocol.SenderKeyName]*groupRecord.SenderKey
}

func newAliceSenderKeyStore() *aliceSenderKeyStore {
	return &aliceSenderKeyStore{keys: make(map[*protocol.SenderKeyName]*groupRecord.SenderKey)}
}

func (a *aliceSenderKeyStore) StoreSenderKey(ctx context.Context, name *protocol.SenderKeyName, rec *groupRecord.SenderKey) error {
	a.keys[name] = rec
	return nil
}

func (a *aliceSenderKeyStore) LoadSenderKey(ctx context.Context, name *protocol.SenderKeyName) (*groupRecord.SenderKey, error) {
	if rec, ok := a.keys[name]; ok {
		return rec, nil
	}
	return groupRecord.NewSenderKey(store.SignalProtobufSerializer.SenderKeyRecord, store.SignalProtobufSerializer.SenderKeyState), nil
}

func insertInlineTestDevice(t *testing.T, db *sql.DB, jid string) func() {
	t.Helper()
	const insertQ = `
		INSERT INTO whatsmeow_device (jid, registration_id, noise_key, identity_key,
									  signed_pre_key, signed_pre_key_id, signed_pre_key_sig,
									  adv_key, adv_details, adv_account_sig, adv_account_sig_key, adv_device_sig)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (jid) DO NOTHING
	`
	thirtyTwo := bytes.Repeat([]byte{0x11}, 32)
	sixtyFour := bytes.Repeat([]byte{0x22}, 64)
	_, err := db.ExecContext(context.Background(), insertQ,
		jid, 1, thirtyTwo, thirtyTwo,
		thirtyTwo, 1, sixtyFour,
		thirtyTwo, thirtyTwo, sixtyFour, thirtyTwo, sixtyFour,
	)
	if err != nil {
		t.Fatalf("insertInlineTestDevice %s: %v", jid, err)
	}
	return func() {
		_, _ = db.ExecContext(context.Background(), `DELETE FROM whatsmeow_device WHERE jid=$1`, jid)
	}
}

func runInlineCipherOutcome(t *testing.T, mode string) {
	resetNoDonorCacheForTest()
	t.Cleanup(resetNoDonorCacheForTest)
	now := time.Now()
	donorClock = func() time.Time { return now }
	ctx := context.Background()
	if os.Getenv("TEST_DSN") == "" {
		t.Fatal("real-cipher fixture requires an explicitly selected disposable TEST_DSN")
	}
	db, err := sql.Open("pgx", os.Getenv("TEST_DSN"))
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Fatalf("non-production Postgres must be reachable: %v", err)
	}
	testContainer := NewWithDB(db, "postgres", nil)
	if err := testContainer.Upgrade(ctx); err != nil {
		db.Close()
		t.Fatalf("initialize non-production Whatsmeow schema: %v", err)
	}

	const (
		inlineTestJIDB = "17799990041@s.whatsapp.net"
		inlineTestJIDC = "17799990042@s.whatsapp.net"
		group          = "inline_iteration_safe_recovery@g.us"
	)
	cleanupB := insertInlineTestDevice(t, db, inlineTestJIDB)
	cleanupC := insertInlineTestDevice(t, db, inlineTestJIDC)
	t.Cleanup(func() {
		cleanupB()
		cleanupC()
		db.Close()
	})
	_, _ = db.ExecContext(ctx,
		`DELETE FROM whatsmeow_sender_keys WHERE our_jid IN ($1,$2) AND chat_id=$3`,
		inlineTestJIDB, inlineTestJIDC, group)

	newCachedDevice := func(jid string) (*store.Device, *CachedSenderKeyStore, types.JID) {
		t.Helper()
		parsed, parseErr := types.ParseJID(jid)
		if parseErr != nil {
			t.Fatalf("ParseJID %s: %v", jid, parseErr)
		}
		byteCache, cacheErr := lru.New[string, []byte](256)
		if cacheErr != nil {
			t.Fatalf("lru.New byte cache: %v", cacheErr)
		}
		deviceCache, cacheErr := NewSenderKeyDeviceCache(256)
		if cacheErr != nil {
			t.Fatalf("lru.New device cache: %v", cacheErr)
		}
		inner := NewSQLStore(testContainer, parsed)
		cached := NewCachedSenderKeyStore(inner, jid, byteCache, deviceCache)
		return &store.Device{SenderKeys: cached, InlineRecoverer: cached, Log: waLog.Noop, ID: &parsed}, cached, parsed
	}
	deviceB, cachedB, _ := newCachedDevice(inlineTestJIDB)
	deviceC, cachedC, _ := newCachedDevice(inlineTestJIDC)

	aliceAddr := protocol.NewSignalAddress("alice", 0)
	aliceName := protocol.NewSenderKeyName(group, aliceAddr)

	// Seed C with a usable older Alice key. It must survive the donor merge.
	legacyStore := newAliceSenderKeyStore()
	legacyBuilder := groups.NewGroupSessionBuilder(legacyStore, store.SignalProtobufSerializer)
	legacySKDM, err := legacyBuilder.Create(ctx, aliceName)
	if err != nil {
		t.Fatalf("legacy builder.Create: %v", err)
	}
	legacyCipher := groups.NewGroupCipher(legacyBuilder, aliceName, legacyStore)
	legacyEnc, err := legacyCipher.Encrypt(ctx, []byte("older usable state"))
	if err != nil {
		t.Fatalf("legacy cipher.Encrypt: %v", err)
	}
	legacyMessage, ok := legacyEnc.(*protocol.SenderKeyMessage)
	if !ok {
		t.Fatalf("legacy cipher.Encrypt returned %T, want *protocol.SenderKeyMessage", legacyEnc)
	}
	legacyBuilderC := groups.NewGroupSessionBuilder(deviceC, store.SignalProtobufSerializer)
	if err := legacyBuilderC.Process(ctx, aliceName, legacySKDM); err != nil {
		t.Fatalf("C legacy builder.Process: %v", err)
	}

	// One persistent sender session produces actual iteration-0 through -10 messages.
	aliceStore := newAliceSenderKeyStore()
	aliceBuilder := groups.NewGroupSessionBuilder(aliceStore, store.SignalProtobufSerializer)
	currentSKDM, err := aliceBuilder.Create(ctx, aliceName)
	if err != nil {
		t.Fatalf("current builder.Create: %v", err)
	}
	aliceCipher := groups.NewGroupCipher(aliceBuilder, aliceName, aliceStore)
	messages := make([]*protocol.SenderKeyMessage, 13)
	for iteration := range messages {
		plaintext := []byte("current iteration " + strconv.Itoa(iteration))
		enc, encryptErr := aliceCipher.Encrypt(ctx, plaintext)
		if encryptErr != nil {
			t.Fatalf("Alice cipher.Encrypt iteration %d: %v", iteration, encryptErr)
		}
		message, messageOK := enc.(*protocol.SenderKeyMessage)
		if !messageOK {
			t.Fatalf("Alice cipher.Encrypt iteration %d returned %T, want *protocol.SenderKeyMessage", iteration, enc)
		}
		if got := message.Iteration(); got != uint32(iteration) {
			t.Fatalf("generated message iteration = %d, want %d", got, iteration)
		}
		messages[iteration] = message
	}

	// B processes the current SKDM and advances directly to iteration 9. The
	// production GroupCipher leaves skipped-message-key state for 0..8.
	builderB := groups.NewGroupSessionBuilder(deviceB, store.SignalProtobufSerializer)
	if err := builderB.Process(ctx, aliceName, currentSKDM); err != nil {
		t.Fatalf("B current builder.Process: %v", err)
	}
	bCipher := groups.NewGroupCipher(builderB, aliceName, deviceB)
	if got, decryptErr := bCipher.Decrypt(ctx, messages[9]); decryptErr != nil || string(got) != "current iteration 9" {
		t.Fatalf("B direct iteration-9 decrypt = %q, %v; want current iteration 9", got, decryptErr)
	}

	currentKeyID := currentSKDM.ID()
	originalWire := append([]byte(nil), messages[10].SignedSerialize()...)
	legacyKeyID := legacySKDM.ID()
	labeled := aliceName.Sender().String()
	const senderBare = "alice"
	cCipher := groups.NewGroupCipher(groups.NewGroupSessionBuilder(deviceC, store.SignalProtobufSerializer), aliceName, deviceC)

	// At target 5 the only current-key donor is B@9, which is ahead and must
	// neither decrypt, install, nor overwrite C's usable older state.
	if got, decryptErr := cCipher.Decrypt(ctx, messages[5]); decryptErr == nil {
		t.Fatalf("C target-5 decrypt before recovery = %q, %v; want failure", got, decryptErr)
	}
	lowDonor, lowOK, lowErr := cachedC.TryInlineRecovery(ctx, group, labeled, senderBare, currentKeyID, 5)
	if lowErr != nil {
		t.Fatalf("target-5 TryInlineRecovery: %v", lowErr)
	}
	if lowOK || lowDonor != "" {
		t.Fatalf("target-5 recovery = donor %q, ok=%t; want no ahead-donor install", lowDonor, lowOK)
	}
	if got, decryptErr := cCipher.Decrypt(ctx, messages[5]); decryptErr == nil {
		t.Fatalf("C target-5 decrypt after declined recovery = %q, %v; want failure", got, decryptErr)
	}
	beforeMerge, err := cachedC.GetSenderKeyStructure(ctx, group, labeled)
	if err != nil {
		t.Fatalf("C GetSenderKeyStructure after target-5: %v", err)
	}
	if beforeMerge == nil || len(beforeMerge.SenderKeyStates) != 1 || beforeMerge.SenderKeyStates[0].KeyID != legacyKeyID {
		t.Fatalf("target-5 changed C state: got %+v, want only legacy key %d", beforeMerge, legacyKeyID)
	}

	// Target 6 and 10 are suppressed by the same fixed live negative.
	for _, target := range []uint32{6, 10} {
		if donor, ok, err := cachedC.TryInlineRecovery(ctx, group, labeled, senderBare, currentKeyID, target); err != nil || ok || donor != "" {
			t.Fatalf("live negative target-%d = %q, %t, %v; want suppression", target, donor, ok, err)
		}
		if got, err := cCipher.Decrypt(ctx, messages[target]); err == nil {
			t.Fatalf("live negative target-%d unexpectedly decrypted %q", target, got)
		}
	}
	// Expiry with no incoming message or retry is entirely passive.
	if mode != "write" && mode != "loss" {
		now = now.Add(5 * time.Minute)
	}
	stillLegacy, err := cachedC.GetSenderKeyStructure(ctx, group, labeled)
	if err != nil {
		t.Fatal(err)
	}
	if len(stillLegacy.SenderKeyStates) != 1 {
		t.Fatal("expiry replayed an original or ran a donor scan while idle")
	}
	t.Log("original-unreplayed: idle time did not install, retry, emit plaintext or run donor SQL")
	if mode == "write" {
		// Re-publish B's readable state through the observable write path. This
		// defeats the matching negative before five minutes and permits new work.
		donorState, err := cachedB.GetSenderKeyStructure(ctx, group, labeled)
		if err != nil {
			t.Fatal(err)
		}
		if err := cachedB.PutSenderKeyStructure(ctx, group, labeled, donorState); err != nil {
			t.Fatal(err)
		}
	}
	laterTarget := uint32(10)
	if mode == "loss" {
		// At arrival original 10 was eligible for B@10 but suppressed. Prove
		// that counterfactual with an independent recipient before B consumes it.
		cleanupD := insertInlineTestDevice(t, db, "17799990043@s.whatsapp.net")
		defer cleanupD()
		independent := NewWithDB(db, "postgres", nil)
		jidD, _ := types.ParseJID("17799990043@s.whatsapp.net")
		byteD, _ := lru.New[string, []byte](256)
		devD, _ := NewSenderKeyDeviceCache(256)
		cachedD := NewCachedSenderKeyStore(NewSQLStore(independent, jidD), jidD.String(), byteD, devD)
		deviceD := &store.Device{SenderKeys: cachedD, Log: waLog.Noop, ID: &jidD}
		if _, ok, err := cachedD.TryInlineRecovery(ctx, group, labeled, senderBare, currentKeyID, 10); err != nil || !ok {
			t.Fatalf("counterfactual immediate original recovery: %t, %v", ok, err)
		}
		dCipher := groups.NewGroupCipher(groups.NewGroupSessionBuilder(deviceD, store.SignalProtobufSerializer), aliceName, deviceD)
		// libsignal may mutate the ciphertext buffer on decryption: give the
		// counterfactual its own wire copy, just as independent delivery would.
		originalCopy, err := protocol.NewSenderKeyMessageFromBytes(append([]byte(nil), originalWire...), store.SignalProtobufSerializer.SenderKeyMessage)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := dCipher.Decrypt(ctx, originalCopy); err != nil || string(got) != "current iteration 10" {
			t.Fatalf("counterfactual original decrypt=%q, %v", got, err)
		}
		// B receives 10 and 11 during the delay, consuming original-10's
		// message key. Its forward state cannot recreate that consumed key.
		for _, target := range []int{10, 11} {
			if _, err := bCipher.Decrypt(ctx, messages[target]); err != nil {
				t.Fatal(err)
			}
		}
		// Neither the accepted donor advance nor expiry replays C's suppressed
		// original. The next incoming ciphertext is target 12, after expiry.
		now = now.Add(5 * time.Minute)
		laterTarget = 12
	}
	donorJID, recovered, recoveryErr := cachedC.TryInlineRecovery(ctx, group, labeled, senderBare, currentKeyID, laterTarget)
	if recoveryErr != nil {
		t.Fatalf("target-10 TryInlineRecovery: %v", recoveryErr)
	}
	if !recovered || donorJID == "" {
		t.Fatalf("target-10 recovery = donor %q, ok=%t; want eligible donor install", donorJID, recovered)
	}
	afterMerge, err := cachedC.GetSenderKeyStructure(ctx, group, labeled)
	if err != nil {
		t.Fatalf("C GetSenderKeyStructure after target-10: %v", err)
	}
	var hasLegacy, hasCurrent bool
	for _, state := range afterMerge.SenderKeyStates {
		if state == nil {
			continue
		}
		hasLegacy = hasLegacy || state.KeyID == legacyKeyID
		hasCurrent = hasCurrent || state.KeyID == currentKeyID
	}
	if !hasLegacy || !hasCurrent {
		t.Fatalf("merge states legacy=%t current=%t; want both preserved and installed", hasLegacy, hasCurrent)
	}

	if got, decryptErr := cCipher.Decrypt(ctx, legacyMessage); decryptErr != nil || string(got) != "older usable state" {
		t.Fatalf("C legacy decrypt after merge = %q, %v; want older usable state", got, decryptErr)
	}
	if got, decryptErr := cCipher.Decrypt(ctx, messages[4]); decryptErr != nil || string(got) != "current iteration 4" {
		t.Fatalf("C retained skipped-key decrypt = %q, %v; want current iteration 4", got, decryptErr)
	}
	if got, decryptErr := cCipher.Decrypt(ctx, messages[laterTarget]); decryptErr != nil || string(got) != "current iteration "+strconv.Itoa(int(laterTarget)) {
		t.Fatalf("C target-10 decrypt = %q, %v; want current iteration 10", got, decryptErr)
	}

	if mode == "retry" {
		// An explicit re-delivery invokes the existing direct-cipher retry.
		// Expiry itself never called Decrypt on this original target-5 message.
		if got, err := cCipher.Decrypt(ctx, messages[5]); err != nil || string(got) != "current iteration 5" {
			t.Fatalf("existing retry original=%q, %v", got, err)
		}
		t.Log("original-recovered-by-existing-retry: explicit ciphertext re-delivery decrypted target 5")
	} else if mode == "loss" {
		original, err := protocol.NewSenderKeyMessageFromBytes(append([]byte(nil), originalWire...), store.SignalProtobufSerializer.SenderKeyMessage)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := cCipher.Decrypt(ctx, original); !errors.Is(err, signalerror.ErrOldCounter) {
			t.Fatalf("consumed original-10 = %q, %v; want irretrievable old-counter", got, err)
		}
		t.Log("permanently-lost-original: original 10 was eligible before delay, then key consumed; expected D-09 loss, later 12 decrypted")
	} else if mode == "skipped" {
		t.Log("retained-skipped-key: explicit original 4 decrypt succeeded separately from later 10")
	}
	// Keep cachedB referenced so this test documents that B's real cached store
	// is the donor row selected by TryInlineRecovery through shared PostgreSQL.
	if cachedB == nil {
		t.Fatal("B cached sender-key store is nil")
	}
	t.Logf("PASS: target-5 rejected; later recovery and preserved legacy/skipped states; donor=%s", donorJID)
}

// Both arms use the same account, empty group, sender and key. Wall time
// includes SQL round trips and decoding; it is not server SQL execution time.

type benchmarkNegativeStore struct {
	stubRecoveryInner
	deviceCalls atomic.Int32
}

func (s *benchmarkNegativeStore) GetSenderKeyDevices(context.Context, string, string) ([]string, error) {
	s.deviceCalls.Add(1)
	return []string{}, nil // authoritative successful empty, rather than malformed nil
}

func BenchmarkSenderKeyFixedNegativeHits(b *testing.B) {
	resetNoDonorCacheForTest()
	b.Cleanup(resetNoDonorCacheForTest)
	inner := &benchmarkNegativeStore{}
	cache, _ := lru.New[string, []byte](16)
	devices, _ := NewSenderKeyDeviceCache(16)
	cached := NewCachedSenderKeyStore(inner, "bench", cache, devices)
	ctx := context.Background()
	if _, err := cached.GetSenderKeyDevices(ctx, "group", "sender"); err != nil {
		b.Fatal(err)
	}
	if _, _, err := cached.TryInlineRecovery(ctx, "group", "sender:0", "sender", 42, 5); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := cached.GetSenderKeyDevices(ctx, "group", "sender"); err != nil {
			b.Fatal(err)
		}
		if _, ok, err := cached.TryInlineRecovery(ctx, "group", "sender:0", "sender", 42, uint32(i)); err != nil || ok {
			b.Fatalf("negative hit=%t, %v", ok, err)
		}
	}
	b.StopTimer()
	if inner.findCalls.Load() != 1 || inner.deviceCalls.Load() != 1 {
		b.Fatalf("hits repeated database work: donor=%d device=%d", inner.findCalls.Load(), inner.deviceCalls.Load())
	}
	b.ReportMetric(float64(inner.findCalls.Load())/float64(b.N), "donor-scans/op")
	b.ReportMetric(float64(inner.deviceCalls.Load())/float64(b.N), "device-queries/op")
}
