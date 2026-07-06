// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package store

import (
	"testing"

	"go.mau.fi/whatsmeow/proto/waWa6"
	"go.mau.fi/whatsmeow/types"
)

// testDeviceForConnectReason builds a minimal *Device with a non-nil ID -- getLoginPayload
// dereferences device.ID (UserInt/Device), so a bare &Device{} would panic.
func testDeviceForConnectReason() *Device {
	id := types.NewJID("15550001234", types.DefaultUserServer)
	return &Device{ID: &id}
}

// TestConnectReasonOverride_DefaultsNilFallsBackToBase: with no override set on a fresh Device,
// getLoginPayload() falls back to BaseClientPayload.ConnectReason (USER_ACTIVATED).
func TestConnectReasonOverride_DefaultsNilFallsBackToBase(t *testing.T) {
	device := testDeviceForConnectReason()
	payload := device.getLoginPayload()
	if payload.GetConnectReason() != waWa6.ClientPayload_USER_ACTIVATED {
		t.Errorf("ConnectReason = %v, want USER_ACTIVATED", payload.GetConnectReason())
	}
}

// TestConnectReasonOverride_SetAppliesToNextPayload: after SetConnectReasonOverride, the next
// getLoginPayload() call reflects the override.
func TestConnectReasonOverride_SetAppliesToNextPayload(t *testing.T) {
	device := testDeviceForConnectReason()
	device.SetConnectReasonOverride(waWa6.ClientPayload_ERROR_RECONNECT.Enum())
	payload := device.getLoginPayload()
	if payload.GetConnectReason() != waWa6.ClientPayload_ERROR_RECONNECT {
		t.Errorf("ConnectReason = %v, want ERROR_RECONNECT", payload.GetConnectReason())
	}
}

// TestConnectReasonOverride_ClearResetsToBase: setting the override then clearing it with nil
// reverts to BaseClientPayload.ConnectReason (USER_ACTIVATED).
func TestConnectReasonOverride_ClearResetsToBase(t *testing.T) {
	device := testDeviceForConnectReason()
	device.SetConnectReasonOverride(waWa6.ClientPayload_ERROR_RECONNECT.Enum())
	device.SetConnectReasonOverride(nil)
	payload := device.getLoginPayload()
	if payload.GetConnectReason() != waWa6.ClientPayload_USER_ACTIVATED {
		t.Errorf("ConnectReason = %v, want USER_ACTIVATED after clearing override", payload.GetConnectReason())
	}
}

// TestConnectReasonOverride_PerDeviceIsolation: the override is scoped to *Device, not
// process-global -- setting it on one Device must never leak to another Device. Regression test
// for the cross-account race the checker flagged (D-08 #5, 60-CONTEXT.md): the kavtov driver runs
// ~60 accounts in one process, each with its own *store.Device.
func TestConnectReasonOverride_PerDeviceIsolation(t *testing.T) {
	deviceA := testDeviceForConnectReason()
	deviceB := testDeviceForConnectReason()
	deviceA.SetConnectReasonOverride(waWa6.ClientPayload_ERROR_RECONNECT.Enum())

	if got := deviceA.getLoginPayload().GetConnectReason(); got != waWa6.ClientPayload_ERROR_RECONNECT {
		t.Errorf("deviceA ConnectReason = %v, want ERROR_RECONNECT", got)
	}
	if got := deviceB.getLoginPayload().GetConnectReason(); got != waWa6.ClientPayload_USER_ACTIVATED {
		t.Errorf("deviceB ConnectReason = %v, want USER_ACTIVATED (must not be affected by deviceA's override)", got)
	}
}
