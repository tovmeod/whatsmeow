// Copyright (c) 2026 Kavtov Platform (Phase 35.2-09)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// session_flusher_leak_test.go is the reuse regression guard for the
// per-JID session flusher lifecycle. It mirrors flusher_leak_test.go (the
// SenderKeyFlusher goroutine-leak guard) for the SessionFlusher.
//
// Regression context: attachCachedStores is re-invoked on every
// Device.Save() (PutDevice -> initializeDevice). Before the Phase 17.7
// per-JID singleton fix, a new flusher was Start()ed on every re-attach,
// leaking the prior flusher's goroutine. The session flusher MUST use the
// same per-(Container,JID) singleton pattern.
package sqlstore

import (
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// TestAttachCachedStores_SessionFlusherReusedNotLeaked asserts that looping
// attachCachedStores for the same JID yields the same *SessionFlusher
// pointer and len(sessionFlusherMap)==1 (no second goroutine spawned).
func TestAttachCachedStores_SessionFlusherReusedNotLeaked(t *testing.T) {
	log := waLog.Noop
	c := &Container{log: log}
	wireSignalCaches(c, log)
	t.Cleanup(func() { closeSignalCaches(c) })

	jid := types.JID{User: "98765432100", Server: types.DefaultUserServer}
	dev := &store.Device{ID: &jid}
	inner := &SQLStore{JID: dev.ID.String()}

	var first *SessionFlusher
	for i := 0; i < 5; i++ {
		attachCachedStores(c, dev, inner)

		c.caches.sessionFlushersMu.Lock()
		f := c.caches.sessionFlusherMap[dev.ID.String()]
		n := len(c.caches.sessionFlusherMap)
		c.caches.sessionFlushersMu.Unlock()

		if f == nil {
			t.Fatalf("attach %d: no session flusher registered for jid", i)
		}
		if i == 0 {
			first = f
		} else if f != first {
			t.Fatalf("attach %d: session flusher was replaced (leak) — got %p, want the reused %p", i, f, first)
		}
		if n != 1 {
			t.Errorf("attach %d: sessionFlusherMap has %d entries, want 1 (a new flusher per attach = the leak)", i, n)
		}
	}
}
