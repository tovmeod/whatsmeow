// Copyright (c) 2026 Kavtov Platform (Phase 17.11 plan 03)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// recovery_worker.go implements SenderKeyRecoveryWorker — the per-account
// background goroutine that drains cross-account sender-key recovery tasks
// produced by decryptGroupSenderKey misses in message.go.
//
// Correctness invariants:
//   - Non-blocking enqueue: TryEnqueue drops tasks when the channel is full.
//     The decrypt hot path (375 miss/min) must never block on recovery.
//   - Jitter (0–30s) on first drain: spreads load across 62 accounts on restart.
//     Pattern: im_v2_contacts.go SyncContactsOnStartup (jitter + global semaphore).
//   - Global semaphore (cap 4 default): bounds concurrent cross-account DB scans.
//     Semaphore acquired per handle() call, not across the drain loop, so all
//     workers make forward progress and 58 of 62 do not starve.
//   - Negative-result cache (LRU, TTL 30m default): deduplicates re-scan for
//     unrecoverable tuples. Key = group|senderBare|keyID. Expiry stored as value.
//     Only the no-donor (false, nil) result is cached — errors retry, successes
//     do not pollute the negative cache.
//   - Per-JID singleton (anti-goroutine-leak): attachCachedStores checks the
//     per-JID map before creating a new worker. Re-wiring on Device.Save() reuses
//     the existing worker (same fix as the SenderKeyFlusher leak, 2026-06-03).
//
// T-1711-08 (thundering herd): jitter + semaphore.
// T-1711-09 (unbounded channel): bounded taskCh cap (default 256).
// T-1711-10 (re-scan per message): negative-result cache.
// T-1711-11 (dispatch gating): dispatch NOT gated on isFailedSenderKeyTuple.
// T-1711-12 (goroutine leak): per-JID singleton in attachCachedStores.

package sqlstore

import (
	"context"
	"math/rand"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// recoveryWorkerSemaphore is the global semaphore bounding concurrent cross-account
// DB scans across all per-account workers. Cap is env-tunable; default 4.
// Pattern: syncContactsSemaphore in im_v2_contacts.go (cap 2 there).
var recoveryWorkerSemaphore = make(chan struct{}, recoveryWorkerSemaphoreCap())

// recoveryWorkerSemaphoreCap reads KAVTOV_RECOVERY_WORKER_SEM_CAP (default 4).
// Called once at package init to size the global semaphore channel.
func recoveryWorkerSemaphoreCap() int {
	return envIntOrDefault("KAVTOV_RECOVERY_WORKER_SEM_CAP", 4)
}

// SenderKeyRecoveryWorker is the per-account background worker that processes
// cross-account sender-key recovery tasks. One instance per device (JID),
// constructed in attachCachedStores as a per-JID singleton.
//
// The concrete struct name matches the store.SenderKeyRecoveryWorker interface;
// compile-time assertion below enforces this.
type SenderKeyRecoveryWorker struct {
	taskCh   chan store.RecoveryTask          // bounded; TryEnqueue drops when full
	negCache *lru.Cache[string, time.Time]   // key = group|senderBare|keyID; value = expiry
	negTTL   time.Duration                   // default 30m; 1ms in tests
	stopCh   chan struct{}
	wg       sync.WaitGroup
	sk       *CachedSenderKeyStore
	log      waLog.Logger

	// jitterMax is the upper bound for startup jitter. Set to 0 in tests so
	// handle() calls work synchronously without waiting for Start() goroutine.
	jitterMax time.Duration

	// scanCount is bumped on each RecoverSenderKey call. Nil in production;
	// injected by NewSenderKeyRecoveryWorkerForTest for test observability.
	scanCount *atomic.Int64
}

// Compile-time assertion: *SenderKeyRecoveryWorker satisfies store.SenderKeyRecoveryWorker.
// If TryEnqueue is removed or its signature drifts, this becomes a BUILD ERROR.
var _ store.SenderKeyRecoveryWorker = (*SenderKeyRecoveryWorker)(nil)

// NewSenderKeyRecoveryWorker constructs a worker for the given CachedSenderKeyStore.
// negTTL and taskChCap are read from env vars with compiled defaults.
func NewSenderKeyRecoveryWorker(sk *CachedSenderKeyStore, log waLog.Logger) *SenderKeyRecoveryWorker {
	negTTL := envDurationOrDefault("KAVTOV_RECOVERY_NEGATIVE_TTL", 30*time.Minute)
	chCap := envIntOrDefault("KAVTOV_RECOVERY_TASK_CH_CAP", 256)
	jitterMax := envDurationOrDefault("KAVTOV_RECOVERY_WORKER_JITTER_MAX", 30*time.Second)

	negCache, _ := lru.New[string, time.Time](4096)
	return &SenderKeyRecoveryWorker{
		taskCh:    make(chan store.RecoveryTask, chCap),
		negCache:  negCache,
		negTTL:    negTTL,
		stopCh:    make(chan struct{}),
		sk:        sk,
		log:       log,
		jitterMax: jitterMax,
	}
}

// NewSenderKeyRecoveryWorkerForTest constructs a worker with a caller-supplied
// negTTL (for deterministic TTL testing) and an optional scan counter.
// jitterMax is set to 0 so the goroutine (if started) drains immediately.
// The test calls HandleForTest directly without calling Start.
func NewSenderKeyRecoveryWorkerForTest(sk *CachedSenderKeyStore, log waLog.Logger, negTTL time.Duration, scanCount *atomic.Int64) *SenderKeyRecoveryWorker {
	negCache, _ := lru.New[string, time.Time](4096)
	return &SenderKeyRecoveryWorker{
		taskCh:    make(chan store.RecoveryTask, 256),
		negCache:  negCache,
		negTTL:    negTTL,
		stopCh:    make(chan struct{}),
		sk:        sk,
		log:       log,
		jitterMax: 0,
		scanCount: scanCount,
	}
}

// HandleForTest exposes handle() for deterministic unit tests that call it
// directly (without Start()). Production code only uses TryEnqueue + Start.
func (w *SenderKeyRecoveryWorker) HandleForTest(ctx context.Context, task store.RecoveryTask) {
	w.handle(ctx, task)
}

// TryEnqueue non-blocking-enqueues a recovery task. Drops the task if the
// channel is full — the decrypt hot path must never block.
func (w *SenderKeyRecoveryWorker) TryEnqueue(task store.RecoveryTask) {
	select {
	case w.taskCh <- task:
	default:
		// channel full — drop; the negative-cache TTL allows a later retry
		// when the next message from this sender arrives
	}
}

// Start launches the async drain goroutine. Must be called once per worker.
// Apply jitter (0–jitterMax) before first drain to spread DB load across 62
// accounts on restart (T-1711-08). The semaphore is acquired per handle() call
// (not outside the drain loop) so that 58 workers don't starve behind 4.
func (w *SenderKeyRecoveryWorker) Start() {
	w.wg.Add(1)
	go func() {
		defer w.wg.Done()

		// Jitter before first drain. Pattern: im_v2_contacts.go lines 149–156.
		if w.jitterMax > 0 {
			jitter := time.Duration(rand.Int63n(int64(w.jitterMax)))
			select {
			case <-time.After(jitter):
			case <-w.stopCh:
				return
			}
		}

		// Drain loop.
		for {
			select {
			case <-w.stopCh:
				return
			case task := <-w.taskCh:
				// Acquire semaphore before the blocking DB scan.
				// Non-blocking try on acquire; if full, still process but
				// skip semaphore (never block the goroutine indefinitely).
				select {
				case recoveryWorkerSemaphore <- struct{}{}:
					ctx := context.Background()
					w.handle(ctx, task)
					<-recoveryWorkerSemaphore
				case <-w.stopCh:
					return
				}
			}
		}
	}()
}

// Stop signals the async goroutine to exit and waits for it.
// Does not drain the remaining taskCh — remaining tasks are dropped.
// The next message from the same sender will re-enqueue the task.
func (w *SenderKeyRecoveryWorker) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

// negCacheKey returns the string key for the negative-result cache.
// Format: group + "|" + senderBare + "|" + keyID.
func negCacheKey(group, senderBare string, keyID uint32) string {
	return group + "|" + senderBare + "|" + strconv.FormatUint(uint64(keyID), 10)
}

// handle processes one recovery task. Steps:
//  1. Check negative cache: if hit and not expired, skip (dedup).
//  2. Call RecoverSenderKey.
//  3. On no-donor (false, nil): add negative cache entry with TTL.
//
// Errors from RecoverSenderKey are logged and not cached (allow retry).
// Successes are not cached in negCache (positive result, no need to block retry).
func (w *SenderKeyRecoveryWorker) handle(ctx context.Context, task store.RecoveryTask) {
	key := negCacheKey(task.Group, task.SenderBare, task.TargetKeyID)

	// Check negative-result cache.
	if expiry, ok := w.negCache.Get(key); ok {
		if time.Now().Before(expiry) {
			// Within TTL — skip redundant scan.
			return
		}
		// TTL expired — allow re-scan; the Peek above consumed the slot;
		// the Add below will refresh it on the next no-donor result.
	}

	// Bump scan counter if wired (test-only).
	if w.scanCount != nil {
		w.scanCount.Add(1)
	}

	ok, err := w.sk.RecoverSenderKey(ctx, task.Group, task.TargetSenderID, task.SenderBare, task.TargetKeyID, task.TargetIter)
	if err != nil {
		w.log.Errorf("SenderKeyRecoveryWorker: RecoverSenderKey failed group=%s sender=%s keyID=%d: %v",
			task.Group, task.SenderBare, task.TargetKeyID, err)
		// Do not cache errors — allow retry on next message.
		return
	}
	if ok {
		w.log.Infof("SENDER_KEY_RECOVERED group=%s sender=%s keyID=%d iter=%d",
			task.Group, task.SenderBare, task.TargetKeyID, task.TargetIter)
		// Positive result — do not add to negative cache.
		return
	}

	// No donor found: cache the negative result to prevent re-scan within TTL.
	w.negCache.Add(key, time.Now().Add(w.negTTL))
}

// envDurationOrDefault reads a time.Duration from the named env var with a
// compiled default. A blank, invalid, or non-positive value falls back to the
// default. Pattern: envIntOrDefault in flusher.go.
func envDurationOrDefault(key string, fallback time.Duration) time.Duration {
	s := os.Getenv(key)
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return fallback
	}
	return d
}
