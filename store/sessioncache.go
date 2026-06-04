// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"context"
	"fmt"

	"go.mau.fi/libsignal/state/record"

	"go.mau.fi/util/exsync"
)

type contextKey int

const (
	contextKeySessionCache contextKey = iota
)

type sessionCacheEntry struct {
	Dirty  bool
	Found  bool
	Record *record.Session
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
	cache.Set(addr, sessionCacheEntry{
		Dirty:  true,
		Found:  true,
		Record: record,
	})
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
	for addr, rawSess := range sessions {
		var sessionRecord *record.Session
		var found bool
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
			var structure *record.SessionStructure
			if len(rawSess) > 0 && rawSess[0] == 0x01 {
				structure, err = UnpackFlatSession(rawSess)
				if err != nil {
					return nil, ctx, fmt.Errorf("WithCachedSessions: failed to deserialize flat session with %s: %w", addr, err)
				}
			} else {
				var byte0desc string
				if len(rawSess) == 0 {
					byte0desc = "empty blob"
				} else {
					byte0desc = fmt.Sprintf("byte0=0x%02x", rawSess[0])
				}
				return nil, ctx, fmt.Errorf("WithCachedSessions: non-flat session blob for %s (%s); JSON read path removed in Stage 3", addr, byte0desc)
			}
			sessionRecord, err = record.NewSessionFromStructure(structure, SignalProtobufSerializer.Session, SignalProtobufSerializer.State)
			if err != nil {
				return nil, ctx, fmt.Errorf("WithCachedSessions: failed to build session record for %s: %w", addr, err)
			}
		}
		existingSessions[addr] = found
		wrapped[addr] = sessionCacheEntry{Record: sessionRecord, Found: found}
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
