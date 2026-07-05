// kavtov-fork (q6h): process-wide, fleet-shared bot-resend blacklist.
//
// This type is DB-AGNOSTIC: it imports only sync + time. All persistence flows
// through the injected persistFunc (persist-on-add) and LoadBlacklisted
// (load-on-start); the driver owns every DB detail. One BotResendBlacklist
// instance is created by the driver and injected into every per-account Client
// (Client.BotResendBL), so a known-bad dispatch bot is suppressed fleet-wide.
//
// Semantics:
//   - counts is in-memory transient: it accumulates skmsg-decrypt misses toward
//     the threshold and is NOT persisted (reset-on-restart is fine — the
//     persisted decision is what matters).
//   - blacklisted holds blacklisted_at, the persisted decision. A (group,sender)
//     is blacklisted after botResendBlacklistThreshold cumulative misses.
//   - Fleet-wide rationale (intentional): counts aggregate across ALL accounts
//     sharing the one injected instance, so a known-bad bot blacklists after the
//     threshold of TOTAL misses; the botResendBlacklistTTL 7-day re-probe guards
//     false positives so a recovered bot is re-probed (no silent permanent loss).

package whatsmeow

import (
	"sync"
	"time"
)

// BotResendBlacklistEntry is one persisted blacklist decision, used by
// LoadBlacklisted to seed the in-memory set on driver startup.
type BotResendBlacklistEntry struct {
	Group  string
	Sender string
	At     time.Time
}

// BotResendBlacklist is a process-wide, concurrency-safe suppression set for
// group skmsg-decrypt misses. Shared across all per-account Clients; injected by
// the driver. Mirrors the PhoneRequestClaims style (mutex-guarded, injected).
type BotResendBlacklist struct {
	mu          sync.Mutex
	counts      map[botResendKey]int       // transient miss counters (not persisted)
	blacklisted map[botResendKey]time.Time // persisted decision: blacklisted_at
	// persistFunc is the driver-injected persist-on-add callback. It is fired once,
	// at the threshold-cross. nil disables persistence (safe: in-memory only).
	persistFunc func(group, sender string, at time.Time)
}

// NewBotResendBlacklist creates a shared BotResendBlacklist. persistFunc may be
// nil (persistence disabled — the blacklist is then in-memory only).
func NewBotResendBlacklist(persistFunc func(group, sender string, at time.Time)) *BotResendBlacklist {
	return &BotResendBlacklist{
		counts:      make(map[botResendKey]int),
		blacklisted: make(map[botResendKey]time.Time),
		persistFunc: persistFunc,
	}
}

// Increment records one skmsg-decrypt miss for (group, sender) and reports
// whether THIS call crossed the blacklist threshold (justBlacklisted). The caller
// logs BOT_RESEND_BLACKLISTED exactly once when this returns true. On the
// crossing it records blacklisted_at and fires persistFunc asynchronously.
func (b *BotResendBlacklist) Increment(group, sender string) (justBlacklisted bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := botResendKey{Group: group, Sender: sender}
	b.counts[k]++
	if b.counts[k] != botResendBlacklistThreshold {
		return false
	}
	if _, already := b.blacklisted[k]; already {
		return false
	}
	now := time.Now()
	b.blacklisted[k] = now
	if b.persistFunc != nil {
		go b.persistFunc(group, sender, now)
	}
	return true
}

// IsBlacklisted reports whether (group, sender) is currently suppressed. A
// blacklisted entry older than botResendBlacklistTTL is re-probed: it is dropped
// from the blacklisted set AND its count is reset, so a recovered bot is not
// permanently suppressed — it must accumulate the full threshold again.
func (b *BotResendBlacklist) IsBlacklisted(group, sender string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	k := botResendKey{Group: group, Sender: sender}
	at, ok := b.blacklisted[k]
	if !ok {
		return false
	}
	if time.Since(at) < botResendBlacklistTTL {
		return true
	}
	// TTL expired -> re-probe (data-loss guard).
	delete(b.blacklisted, k)
	delete(b.counts, k)
	return false
}

// LoadBlacklisted seeds the in-memory blacklisted set from persisted entries on
// driver startup. Entries older than botResendBlacklistTTL are skipped (they
// will be re-probed rather than re-suppressed).
func (b *BotResendBlacklist) LoadBlacklisted(entries []BotResendBlacklistEntry) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, e := range entries {
		if time.Since(e.At) < botResendBlacklistTTL {
			b.blacklisted[botResendKey{Group: e.Group, Sender: e.Sender}] = e.At
		}
	}
}
