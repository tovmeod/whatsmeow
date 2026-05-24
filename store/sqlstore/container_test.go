// Copyright (c) 2026 Kavtov Platform (Phase 17.5.1)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"testing"
	"time"
)

// TestContainer_Close_CancelsMetricsLoop asserts WR-01 is closed: the
// metrics-loop ctx (now on c.caches per plan 17.5.1-03) is wired through to
// the emitMetricsLoop goroutine and Container.Close() cancels it so the
// loop returns deterministically.
//
// The test bypasses NewWithWrappedDB to avoid pulling in a real
// *dbutil.Database — the goal is to exercise the metricsCtx/metricsCancel
// handshake, not the full Container lifecycle. The select arm in
// emitMetricsLoop (`<-ctx.Done()`) fires before any c.log / c.caches.Session
// access, so a bare Container{} with only the two ctx fields populated
// will not panic before exit.
func TestContainer_Close_CancelsMetricsLoop(t *testing.T) {
	c := &Container{}
	c.caches.metricsCtx, c.caches.metricsCancel = context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.emitMetricsLoop(c.caches.metricsCtx)
		close(done)
	}()

	if err := c.Close(); err != nil {
		t.Fatalf("Close returned unexpected error: %v", err)
	}

	select {
	case <-done:
		// emitMetricsLoop returned within the timeout — WR-01 closed.
	case <-time.After(time.Second):
		t.Fatal("emitMetricsLoop did not exit within 1s after Close()")
	}
}
