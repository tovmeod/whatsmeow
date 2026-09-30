// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// TestAttachCachedStores_FlusherReusedNotLeaked is the regression guard for the
// 2026-06-03 prod goroutine leak: attachCachedStores is re-invoked on every
// Device.Save() (PutDevice -> initializeDevice), and the pre-fix code created +
// Start()ed a fresh SenderKeyFlusher each time, overwriting the per-JID map
// entry and orphaning the previous flusher's still-ticking goroutine (~6963
// leaked in prod, heap past GOMEMLIMIT). The flusher must be a per-(Container,
// JID) singleton: re-attach reuses the existing one.
func TestAttachCachedStores_FlusherReusedNotLeaked(t *testing.T) {
	log := waLog.Noop
	c := &Container{log: log}
	wireSignalCaches(c, log)
	t.Cleanup(func() { closeSignalCaches(c) }) // stops the single flusher + metrics loop

	jid := types.JID{User: "12345678901", Server: types.DefaultUserServer}
	dev := &store.Device{ID: &jid}
	inner := &SQLStore{JID: dev.ID.String()}

	var first *SenderKeyFlusher
	for i := 0; i < 5; i++ {
		attachCachedStores(c, dev, inner)

		c.caches.senderKeyFlushersMu.Lock()
		f := c.caches.senderKeyFlusherMap[dev.ID.String()]
		n := len(c.caches.senderKeyFlusherMap)
		c.caches.senderKeyFlushersMu.Unlock()

		if f == nil {
			t.Fatalf("attach %d: no flusher registered for jid", i)
		}
		if i == 0 {
			first = f
		} else if f != first {
			t.Fatalf("attach %d: flusher was replaced (leak) — got %p, want the reused %p", i, f, first)
		}
		if n != 1 {
			t.Errorf("attach %d: senderKeyFlusherMap has %d entries, want 1 (a new flusher per attach = the leak)", i, n)
		}
	}
}
