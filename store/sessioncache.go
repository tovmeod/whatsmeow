// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"
	"os"

	"go.mau.fi/libsignal/state/record"

	"go.mau.fi/util/exsync"
)

// lazySessionDecode gates the Phase 38.4 send-path optimization: decode only the
// current state on the encrypt prefetch and carry the archived states as raw bytes,
// instead of parsing all ~40 archived states + thousands of message keys per send.
// Read once at package load; enable with KAVTOV_LAZY_SESSION_DECODE=1. Flipping it
// off (and restarting) instantly reverts to full-decode behavior — no code rollback.
var lazySessionDecode = os.Getenv("KAVTOV_LAZY_SESSION_DECODE") == "1"

// sendTimingDebug emits a one-line diagnostic from WithCachedSessions so the
// send-size attribution can be debugged (addresses queried, sessions loaded, max
// bytes, whether the byte tracker reached this ctx). Gated by the same flag.
var sendTimingDebug = os.Getenv("KAVTOV_SEND_TIMING_LOG") == "1"

type contextKey int

const (
	contextKeySessionCache contextKey = iota
	contextKeySessionByteTracker
)

// ContextWithSessionByteTracker installs a shared tracker that WithCachedSessions
// updates with the largest raw session blob it loads on this ctx OR any descendant
// ctx (it's a pointer, so it survives the inner ctx reassignment that a value would
// not). Returns the new ctx and the pointer to read after the send completes — used
// by the send-timing log to attribute latency to fat sessions directly. Caller must
// not share the tracker across goroutines (one per send).
func ContextWithSessionByteTracker(ctx context.Context) (context.Context, *int) {
	tracker := new(int)
	return context.WithValue(ctx, contextKeySessionByteTracker, tracker), tracker
}

func recordSessionBytes(ctx context.Context, n int) {
	if t, ok := ctx.Value(contextKeySessionByteTracker).(*int); ok && n > *t {
		*t = n
	}
}

// MaxCachedSessionBytes returns the largest raw session blob recorded by the byte
// tracker on this ctx (0 if no tracker or nothing loaded).
func MaxCachedSessionBytes(ctx context.Context) int {
	if t, ok := ctx.Value(contextKeySessionByteTracker).(*int); ok {
		return *t
	}
	return 0
}

type sessionCacheEntry struct {
	Dirty  bool
	Found  bool
	Record *record.Session

	// Lazy send-path fields (set only when lazySessionDecode and the blob had
	// archived states). LazyTail is the raw, unparsed archived-states suffix of the
	// original flat blob; LazyNPrev is its archived-state count. On write-back the
	// (encrypt-mutated) live states are packed and LazyTail is appended verbatim, so
	// no archived state is lost. See UnpackFlatSessionCurrentOnly.
	Lazy      bool
	LazyTail  []byte
	LazyNPrev int
}

type sessionCache = exsync.Map[string, sessionCacheEntry]

func getSessionCache(ctx context.Context) *sessionCache {
	if ctx == nil {
		return nil
	}
	val := ctx.Value(contextKeySessionCache)
	if val == nil {
		return nil
	}
	if cache, ok := val.(*sessionCache); ok {
		return cache
	}
	return nil
}

func getCachedSession(ctx context.Context, addr string) *record.Session {
	cache := getSessionCache(ctx)
	if cache == nil {
		return nil
	}
	sess, ok := cache.Get(addr)
	if !ok {
		return nil
	}
	return sess.Record
}

func putCachedSession(ctx context.Context, addr string, record *record.Session) bool {
	cache := getSessionCache(ctx)
	if cache == nil {
		return false
	}
	entry := sessionCacheEntry{
		Dirty:  true,
		Found:  true,
		Record: record,
	}
	// Phase 38.4 CORRECTNESS-CRITICAL: the cipher calls StoreSession (→ here) after
	// mutating the current state on encrypt. If this entry was loaded current-only,
	// the original archived tail MUST survive into the new entry, or PutCachedSessions
	// would write the current-only record and silently drop every archived state.
	if prev, ok := cache.Get(addr); ok && prev.Lazy {
		entry.Lazy = true
		entry.LazyTail = prev.LazyTail
		entry.LazyNPrev = prev.LazyNPrev
	}
	cache.Set(addr, entry)
	return true
}

// hasCachedSession checks if a session exists in the cache.
// Returns (exists bool, inCache bool) - inCache indicates if cache was checked.
func hasCachedSession(ctx context.Context, addr string) (exists bool, inCache bool) {
	cache := getSessionCache(ctx)
	if cache == nil {
		return false, false
	}
	entry, ok := cache.Get(addr)
	if !ok {
		return false, true // Cache exists but no entry for this address
	}
	return entry.Found, true
}

func (device *Device) WithCachedSessions(ctx context.Context, addresses []string) (map[string]bool, context.Context, error) {
	if len(addresses) == 0 {
		return nil, ctx, nil
	}

	sessions, err := device.Sessions.GetManySessions(ctx, addresses)
	if err != nil {
		return nil, ctx, fmt.Errorf("failed to prefetch sessions: %w", err)
	}
	wrapped := make(map[string]sessionCacheEntry, len(sessions))
	existingSessions := make(map[string]bool, len(sessions))
	maxSessionBytes := 0
	for addr, rawSess := range sessions {
		if len(rawSess) > maxSessionBytes {
			maxSessionBytes = len(rawSess)
		}
		var sessionRecord *record.Session
		var found bool
		var lazy bool
		var lazyTail []byte
		var lazyNPrev int
		if rawSess == nil {
			sessionRecord = record.NewSession(SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
		} else {
			found = true
			// Phase 17.13 Stage 3: whatsmeow_sessions is flat-bytea (byte0=0x01).
			// This send-path prefetch MUST decode with the same flat codec as the
			// single-read path LoadSession (signal.go) and the write path
			// PutCachedSessions — not the old record.NewSessionFromBytes (JSON).
			// All prod rows are confirmed flat; a non-flat blob or a decode failure
			// returns a wrapped error. NEVER silently drop the address: dropping it
			// leaves the cache entry absent, hasCachedSession reports Found=false,
			// ContainsSession short-circuits to false, and the send aborts with
			// ErrNoSession → WhatsApp 479 (the exact bug this read-gap caused).
			if len(rawSess) == 0 || rawSess[0] != 0x01 {
				var byte0desc string
				if len(rawSess) == 0 {
					byte0desc = "empty blob"
				} else {
					byte0desc = fmt.Sprintf("byte0=0x%02x", rawSess[0])
				}
				return nil, ctx, fmt.Errorf("WithCachedSessions: non-flat session blob for %s (%s); JSON read path removed in Stage 3", addr, byte0desc)
			}
			var structure *record.SessionStructure
			if lazySessionDecode {
				// Phase 38.4: decode only the current state; carry the archived
				// states as a raw tail re-emitted unchanged on write-back. The
				// encrypt path never reads previousSessions, and an existing
				// session is never ProcessBundle'd in the send path (it has no
				// bundle), so previousSessions stays empty through the encrypt and
				// the tail is the complete, untouched archived set.
				structure, lazyTail, lazyNPrev, err = UnpackFlatSessionCurrentOnly(rawSess)
				if err != nil {
					return nil, ctx, fmt.Errorf("WithCachedSessions: failed to deserialize flat session (current-only) with %s: %w", addr, err)
				}
				lazy = true
			} else {
				structure, err = UnpackFlatSession(rawSess)
				if err != nil {
					return nil, ctx, fmt.Errorf("WithCachedSessions: failed to deserialize flat session with %s: %w", addr, err)
				}
			}
			sessionRecord, err = record.NewSessionFromStructure(structure, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
			if err != nil {
				return nil, ctx, fmt.Errorf("WithCachedSessions: failed to build session record for %s: %w", addr, err)
			}
		}
		existingSessions[addr] = found
		wrapped[addr] = sessionCacheEntry{Record: sessionRecord, Found: found, Lazy: lazy, LazyTail: lazyTail, LazyNPrev: lazyNPrev}
	}

	recordSessionBytes(ctx, maxSessionBytes)
	if sendTimingDebug && device.Log != nil {
		_, trackerFound := ctx.Value(contextKeySessionByteTracker).(*int)
		device.Log.Warnf("WCS_DEBUG addrs=%d loaded=%d maxBytes=%d trackerFound=%t", len(addresses), len(sessions), maxSessionBytes, trackerFound)
	}
	ctx = context.WithValue(ctx, contextKeySessionCache, (*sessionCache)(exsync.NewMapWithData(wrapped)))
	return existingSessions, ctx, nil
}

func (device *Device) PutCachedSessions(ctx context.Context) error {
	cache := getSessionCache(ctx)
	if cache == nil {
		return nil
	}
	dirtySessions := make(map[string][]byte)
	for addr, item := range cache.Iter() {
		if !item.Dirty {
			continue
		}
		// Stage 3: write flat only (mirror StoreSession — D-04a). No JSON fallback.
		// This batched send-path flush (send.go/sendfb.go) MUST use the same flat
		// codec as the single-write StoreSession. On refuse (codec bug), return error.
		structure := item.Record.Structure()
		flat, ok := PackFlatSession(structure)
		if !ok {
			return fmt.Errorf("PutCachedSessions: PackFlatSession refused for %s: codec bug", addr)
		}
		if item.Lazy {
			// Phase 38.4: this entry was loaded current-only. Re-attach the raw
			// archived tail verbatim so no archived state is lost. `flat` holds
			// [magic][len(livePrev)][current][livePrev...]; the live previous states
			// are normally empty (pure encrypt) but may be non-empty if the record
			// archived during the op — either way append the original tail and set
			// the count to live+original. Lossless in both cases.
			total := len(structure.PreviousStates) + item.LazyNPrev
			if total > 255 {
				return fmt.Errorf("PutCachedSessions: %s archived-state count %d exceeds 255 after lazy re-attach", addr, total)
			}
			merged := make([]byte, 0, len(flat)+len(item.LazyTail))
			merged = append(merged, flat...)
			merged = append(merged, item.LazyTail...)
			merged[1] = byte(total)
			flat = merged
		}
		dirtySessions[addr] = flat
	}
	if len(dirtySessions) > 0 {
		err := device.Sessions.PutManySessions(ctx, dirtySessions)
		if err != nil {
			return fmt.Errorf("failed to store cached sessions: %w", err)
		}
	}
	cache.Clear()
	return nil
}
