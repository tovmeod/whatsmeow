// Copyright (c) 2026 Kavtov Platform (Phase 17.5)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// In-memory fake Store implementations for use by Phase 17.5 Wave 1
// cached_*_store_test.go files. Lives in `package sqlstore` (same package
// as production code) so wrappers can reference these helpers without
// exporting them. All call counters are atomic.Int64 so race tests can
// read them via .Load() without locks; the backing maps are protected
// by sync.Mutex.
//
// No reflection, no type assertions: any missing-method drift surfaces as
// a compile error against the `var _ store.XxxStore = (*fakeXxx)(nil)`
// conformance assertions at the bottom of this file.

// ---------------------------------------------------------------------------
// fakeSessionStore implements store.SessionStore (store/store.go:30-39).
// ---------------------------------------------------------------------------

type fakeSessionStore struct {
	mu       sync.Mutex
	sessions map[string][]byte

	getCalls       atomic.Int64
	hasCalls       atomic.Int64
	getManyCalls   atomic.Int64
	putCalls       atomic.Int64
	putManyCalls   atomic.Int64
	deleteAllCalls atomic.Int64
	deleteCalls    atomic.Int64
	migrateCalls   atomic.Int64

	// lastGetManyBatchBuf retains a copy of the addresses argument from the
	// most recent GetManySessions call so cache tests can assert the wrapper
	// passes only the misses to the inner store.
	lastGetManyBatchBuf []string

	// Error-injection fields (Phase 17.5 FIX). When set to non-nil, the
	// corresponding method returns the error WITHOUT mutating the backing
	// map — letting wrapper tests assert that a failed inner call leaves
	// the cache untouched. Setters are not synchronized; tests should set
	// these fields before exercising the wrapper.
	putErr     error
	putManyErr error
	migrateErr error
}

// lastGetManyBatch returns a copy of the addresses passed to the most recent
// GetManySessions call.
func (f *fakeSessionStore) lastGetManyBatch() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.lastGetManyBatchBuf))
	copy(out, f.lastGetManyBatchBuf)
	return out
}

func newFakeSessionStore() *fakeSessionStore {
	return &fakeSessionStore{
		sessions: make(map[string][]byte),
	}
}

func (f *fakeSessionStore) GetSession(_ context.Context, address string) ([]byte, error) {
	f.getCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.sessions[address]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

func (f *fakeSessionStore) HasSession(_ context.Context, address string) (bool, error) {
	f.hasCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.sessions[address]
	return ok, nil
}

func (f *fakeSessionStore) GetManySessions(_ context.Context, addresses []string) (map[string][]byte, error) {
	f.getManyCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastGetManyBatchBuf = append(f.lastGetManyBatchBuf[:0], addresses...)
	result := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		if v, ok := f.sessions[addr]; ok {
			out := make([]byte, len(v))
			copy(out, v)
			result[addr] = out
		}
	}
	return result, nil
}

func (f *fakeSessionStore) PutSession(_ context.Context, address string, session []byte) error {
	f.putCalls.Add(1)
	if f.putErr != nil {
		return f.putErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := make([]byte, len(session))
	copy(stored, session)
	f.sessions[address] = stored
	return nil
}

func (f *fakeSessionStore) PutManySessions(_ context.Context, sessions map[string][]byte) error {
	f.putManyCalls.Add(1)
	if f.putManyErr != nil {
		return f.putManyErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	for addr, session := range sessions {
		stored := make([]byte, len(session))
		copy(stored, session)
		f.sessions[addr] = stored
	}
	return nil
}

func (f *fakeSessionStore) DeleteAllSessions(_ context.Context, phone string) error {
	f.deleteAllCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	pfx := phone + ":"
	for addr := range f.sessions {
		// Mirror SQLStore.DeleteAllSessions semantics: their_id >=
		// phone||':' AND their_id < phone||';'. Canonical form is
		// "address starts with phone+':'" — same predicate the wrapper
		// uses on its cache walk.
		if len(addr) >= len(pfx) && addr[:len(pfx)] == pfx {
			delete(f.sessions, addr)
		}
	}
	return nil
}

func (f *fakeSessionStore) DeleteSession(_ context.Context, address string) error {
	f.deleteCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, address)
	return nil
}

func (f *fakeSessionStore) MigratePNToLID(_ context.Context, pn, lid types.JID) error {
	f.migrateCalls.Add(1)
	if f.migrateErr != nil {
		return f.migrateErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	// Mirror SQLStore.MigratePNToLID semantics (store.go:264-303 and
	// migratePNToLIDSessionsQuery): match addresses whose libsignal user
	// prefix equals pn.SignalAddressUser() followed by ':'. The previous
	// matcher used pn.String() (full JID form) which never matched the
	// production address format and concealed Phase 17.5 FIX2 BL-01 in
	// wrapper tests by silently failing to migrate the inner-side rows
	// either.
	pnPfx := pn.SignalAddressUser() + ":"
	lidUser := lid.SignalAddressUser()
	// Two-pass: collect victims first (Go disallows mutating a map during
	// `for ... range`).
	var victims []string
	for addr := range f.sessions {
		if len(addr) >= len(pnPfx) && addr[:len(pnPfx)] == pnPfx {
			victims = append(victims, addr)
		}
	}
	for _, addr := range victims {
		session := f.sessions[addr]
		newAddr := lidUser + addr[len(pn.SignalAddressUser()):]
		f.sessions[newAddr] = session
		delete(f.sessions, addr)
	}
	return nil
}

// IsPNMigrated: the fake has no once-per-process gate, so every migration is a
// real one (consumed). Phase 47.3 F4 interface widening — fakeSessionStore is
// used as the writer-store backing in cached-store flusher tests.
func (f *fakeSessionStore) IsPNMigrated(string) bool { return false }

// ---------------------------------------------------------------------------
// fakeIdentityStore implements store.IdentityStore (store/store.go:23-28).
// ---------------------------------------------------------------------------

type fakeIdentityStore struct {
	mu         sync.Mutex
	identities map[string][32]byte

	putCalls              atomic.Int64
	deleteAllCalls        atomic.Int64
	deleteCalls           atomic.Int64
	isTrustedCalls        atomic.Int64
	getIdentityBytesCalls atomic.Int64
}

func newFakeIdentityStore() *fakeIdentityStore {
	return &fakeIdentityStore{
		identities: make(map[string][32]byte),
	}
}

func (f *fakeIdentityStore) PutIdentity(_ context.Context, address string, key [32]byte) error {
	f.putCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.identities[address] = key
	return nil
}

func (f *fakeIdentityStore) DeleteAllIdentities(_ context.Context, phone string) error {
	f.deleteAllCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	for addr := range f.identities {
		if len(addr) >= len(phone) && addr[:len(phone)] == phone {
			delete(f.identities, addr)
		}
	}
	return nil
}

func (f *fakeIdentityStore) DeleteIdentity(_ context.Context, address string) error {
	f.deleteCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.identities, address)
	return nil
}

func (f *fakeIdentityStore) IsTrustedIdentity(_ context.Context, address string, key [32]byte) (bool, error) {
	f.isTrustedCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.identities[address]
	if !ok {
		// Mirror SQLStore.IsTrustedIdentity (store.go:97-109): ErrNoRows
		// collapses to (true, nil) — trust on first sight.
		return true, nil
	}
	return existing == key, nil
}

// getIdentityBytes mirrors the private SQLStore.getIdentityBytes signature
// (Phase 17.5-03 Task 1). CachedIdentityStore type-asserts inner against
// `interface{ getIdentityBytes(context.Context, string) (*[32]byte, error) }`
// to populate the cache on miss; the fake satisfies the assertion so wrapper
// tests can exercise the populate-on-miss path without a live SQL backend.
func (f *fakeIdentityStore) getIdentityBytes(_ context.Context, address string) (*[32]byte, error) {
	f.getIdentityBytesCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	existing, ok := f.identities[address]
	if !ok {
		return nil, nil
	}
	out := existing
	return &out, nil
}

// ---------------------------------------------------------------------------
// fakeSenderKeyStore implements store.SenderKeyStore (store/store.go:50-53).
// ---------------------------------------------------------------------------

type fakeSenderKeyStore struct {
	mu   sync.Mutex
	keys map[string][]byte

	getCalls     atomic.Int64
	putCalls     atomic.Int64
	devicesCalls atomic.Int64
}

func newFakeSenderKeyStore() *fakeSenderKeyStore {
	return &fakeSenderKeyStore{
		keys: make(map[string][]byte),
	}
}

func (f *fakeSenderKeyStore) PutSenderKey(_ context.Context, group, user string, session []byte) error {
	f.putCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := make([]byte, len(session))
	copy(stored, session)
	f.keys[group+"|"+user] = stored
	return nil
}

func (f *fakeSenderKeyStore) GetSenderKey(_ context.Context, group, user string) ([]byte, error) {
	f.getCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	v, ok := f.keys[group+"|"+user]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(v))
	copy(out, v)
	return out, nil
}

// GetSenderKeyDevices is the real prefix-scan over f.keys — mirrors
// SQLStore.GetSenderKeyDevices semantics for test coverage. It records
// calls so the cached-store passthrough test can assert that the LRU
// was not touched.
func (f *fakeSenderKeyStore) GetSenderKeyDevices(_ context.Context, group, userBare string) ([]string, error) {
	f.devicesCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	prefix := group + "|" + userBare + ":"
	var devices []string
	for k := range f.keys {
		if strings.HasPrefix(k, prefix) {
			devices = append(devices, k[len(group)+1:])
		}
	}
	return devices, nil
}

// ---------------------------------------------------------------------------
// fakeMessageSecretStore implements store.MsgSecretStore (store/store.go:143).
// ---------------------------------------------------------------------------

type fakeMessageSecretStore struct {
	mu      sync.Mutex
	secrets map[string]msgSecretEntry // key: chat|sender|id (all ToNonAD)

	getCalls  atomic.Int64
	putCalls  atomic.Int64
	bulkCalls atomic.Int64
}

func newFakeMessageSecretStore() *fakeMessageSecretStore {
	return &fakeMessageSecretStore{
		secrets: make(map[string]msgSecretEntry),
	}
}

func (f *fakeMessageSecretStore) fakeKey(chat, sender types.JID, id types.MessageID) string {
	return chat.ToNonAD().String() + "|" + sender.ToNonAD().String() + "|" + string(id)
}

// GetMessageSecret mirrors SQLStore.GetMessageSecret: an unknown key collapses
// to (nil, types.EmptyJID, nil) — the same sentinel ErrNoRows produces.
func (f *fakeMessageSecretStore) GetMessageSecret(_ context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error) {
	f.getCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	entry, ok := f.secrets[f.fakeKey(chat, sender, id)]
	if !ok {
		return nil, types.EmptyJID, nil
	}
	out := make([]byte, len(entry.Secret))
	copy(out, entry.Secret)
	return out, entry.RealSender, nil
}

func (f *fakeMessageSecretStore) PutMessageSecret(_ context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	f.putCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	stored := make([]byte, len(secret))
	copy(stored, secret)
	f.secrets[f.fakeKey(chat, sender, id)] = msgSecretEntry{Secret: stored, RealSender: sender.ToNonAD()}
	return nil
}

func (f *fakeMessageSecretStore) PutMessageSecrets(_ context.Context, inserts []store.MessageSecretInsert) error {
	f.bulkCalls.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, insert := range inserts {
		stored := make([]byte, len(insert.Secret))
		copy(stored, insert.Secret)
		f.secrets[f.fakeKey(insert.Chat, insert.Sender, insert.ID)] = msgSecretEntry{Secret: stored, RealSender: insert.Sender.ToNonAD()}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Interface-conformance assertions: any drift in the Store interfaces
// surfaces as a compile error here, not at runtime. Avoids the need for
// reflection-based conformance probing (forbidden per CLAUDE.md
// "no hasattr/getattr" rule and its Go equivalent).
// ---------------------------------------------------------------------------

var _ store.SessionStore = (*fakeSessionStore)(nil)
var _ store.IdentityStore = (*fakeIdentityStore)(nil)
var _ store.SenderKeyStore = (*fakeSenderKeyStore)(nil)
var _ store.MsgSecretStore = (*fakeMessageSecretStore)(nil)
