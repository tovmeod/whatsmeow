// Copyright (c) 2026 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/json"
	"fmt"

	"go.mau.fi/whatsmeow/types/events"
)

const queryFetchReachoutTimelock = "23983697327930364"

type respFetchReachoutTimelock struct {
	Timelock *events.NotifyAccountReachoutTimelock `json:"xwa2_fetch_account_reachout_timelock"`
}

// FetchReachoutTimelock fetches the account's current reachout-timelock enforcement state
// (is_active / enforcement_type / time_enforcement_ends) directly from WhatsApp, mirroring
// the fetchReachoutTimelock() call WA Web makes on every connect. Unlike the push notification
// path (which only fires if WhatsApp decides to send it), this pull always returns the current
// server-side state, or an explicit error.
func (cli *Client) FetchReachoutTimelock(ctx context.Context) (*events.NotifyAccountReachoutTimelock, error) {
	data, err := cli.sendMexIQ(ctx, queryFetchReachoutTimelock, map[string]any{})
	var respData respFetchReachoutTimelock
	if data != nil {
		jsonErr := json.Unmarshal(data, &respData)
		if err == nil && jsonErr != nil {
			err = jsonErr
		}
	}
	if err != nil {
		return nil, err
	}
	if respData.Timelock == nil {
		return nil, fmt.Errorf("reachout timelock: xwa2_fetch_account_reachout_timelock missing in mex response")
	}
	return respData.Timelock, nil
}
