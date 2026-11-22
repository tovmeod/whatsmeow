// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"math/rand/v2"
	"sync/atomic"
	"time"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

var (
	// KeepAliveResponseDeadline specifies the duration to wait for a response to websocket keepalive pings.
	// 55.1-12: raised from 10s to 20s to match WA Web's own deadSocketTime
	// (55.1-INVESTIGATION-websocket.md §2, WAWebCommsConfig.js:29); the ping interval below is
	// unchanged, it was already in WA's 15-30s band.
	KeepAliveResponseDeadline = 20 * time.Second
	// KeepAliveIntervalMin specifies the minimum interval for websocket keepalive pings.
	KeepAliveIntervalMin = 20 * time.Second
	// KeepAliveIntervalMax specifies the maximum interval for websocket keepalive pings.
	KeepAliveIntervalMax = 30 * time.Second
)

// keepAliveForcedReconnects counts WA-cadence forced reconnects triggered by a keepalive miss
// (55.1-12) -- periodically visible, mirrors the newsletterControlEmpty/hostFailover* counters
// elsewhere in this fork.
var keepAliveForcedReconnects atomic.Uint64

const keepAliveForcedReconnectsLogEvery = 20

func (cli *Client) keepAliveLoop(_ context.Context, connCtx context.Context) {
	lastSuccess := time.Now()
	var errorCount int
	for {
		interval := rand.Int64N(KeepAliveIntervalMax.Milliseconds()-KeepAliveIntervalMin.Milliseconds()) + KeepAliveIntervalMin.Milliseconds()
		select {
		case <-time.After(time.Duration(interval) * time.Millisecond):
			isSuccess, shouldContinue := cli.sendKeepAlive(connCtx)
			if !shouldContinue {
				return
			} else if !isSuccess {
				errorCount++
				go cli.dispatchEvent(&events.KeepAliveTimeout{
					ErrorCount:  errorCount,
					LastSuccess: lastSuccess,
				})
				if cli.EnableAutoReconnect {
					cli.forceKeepAliveReconnect(connCtx)
				}
			} else {
				if errorCount > 0 {
					errorCount = 0
					go cli.dispatchEvent(&events.KeepAliveRestored{})
				}
				lastSuccess = time.Now()
			}
		case <-connCtx.Done():
			return
		}
	}
}

// forceKeepAliveReconnect tears down and reconnects the socket on a keepalive miss (55.1-12).
// WA Web closes the socket after the FIRST unanswered ping (deadSocketTime ~20s,
// 55.1-INVESTIGATION-websocket.md §2) rather than tolerating minutes of silence on a
// silently-dead connection (no FIN/RST -- the case conn.Read never errors on); the fork
// previously waited up to KeepAliveMaxFailTime (3 minutes) of continuous ping failure before
// forcing a reconnect -- that tolerance is deleted, this now fires on every miss.
func (cli *Client) forceKeepAliveReconnect(connCtx context.Context) {
	if !cli.resetConnection(connCtx) {
		return
	}
	if n := keepAliveForcedReconnects.Add(1); n%keepAliveForcedReconnectsLogEvery == 0 {
		cli.Log.Infof("KEEPALIVE_FORCED_RECONNECT count=%d", n)
	}
	cli.Log.Debugf("Forcing reconnect due to keepalive failure")
}

func (cli *Client) sendKeepAlive(ctx context.Context) (isSuccess, shouldContinue bool) {
	id := cli.generateRequestID()
	cli.lastKeepAliveID.Store(&id)
	respCh, err := cli.sendIQAsync(ctx, infoQuery{
		Namespace: "w:p",
		Type:      "get",
		To:        types.ServerJID,
		ID:        id,
	})
	if ctx.Err() != nil {
		return false, false
	} else if err != nil {
		cli.Log.Warnf("Failed to send keepalive: %v", err)
		return false, true
	}
	select {
	case <-respCh:
		return true, true
	case <-time.After(KeepAliveResponseDeadline):
		cli.Log.Warnf("Keepalive timed out")
		return false, true
	case <-ctx.Done():
		return false, false
	}
}

func (cli *Client) isKeepAliveNode(node *waBinary.Node) bool {
	if node.Tag != "iq" || node.Content != nil {
		return false
	}
	id := cli.lastKeepAliveID.Load()
	return id != nil && node.Attrs["id"] == *id
}
