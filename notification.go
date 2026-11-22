// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"

	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// appStateSyncFailureThreshold is the number of consecutive ErrMismatchingLTHash errors
// for the same app-state collection that triggers an automatic full resync.
const appStateSyncFailureThreshold = 3

// maxAppStateFullSyncFailures bounds how many times a fullSync may itself fail with
// ErrMismatchingLTHash before we give up on auto-healing a collection. A permanently
// diverged collection (server snapshot itself fails LTHash verification, e.g. a stuck
// patch version) cannot be healed by re-fetching, so without a cap the auto-resync
// degenerates into an unbounded fullSync loop hammering the server (D-12 prod loop on
// 972527147052, patch v67292). After this many failed fullSyncs we stop triggering and
// leave the collection diverged; any later successful sync re-arms auto-heal.
const maxAppStateFullSyncFailures = 3

func (cli *Client) handleEncryptNotification(ctx context.Context, node *waBinary.Node) {
	from := node.AttrGetter().JID("from")
	if from == types.ServerJID {
		count := node.GetChildByTag("count")
		ag := count.AttrGetter()
		otksLeft := ag.Int("value")
		if !ag.OK() {
			cli.Log.Warnf("Didn't get number of OTKs left in encryption notification %s", node)
			return
		}
		cli.Log.Infof("Got prekey count from server: %s", node)
		if otksLeft < MinPreKeyCount {
			cli.uploadPreKeys(ctx, false)
		}
	} else if _, ok := node.GetOptionalChildByTag("identity"); ok {
		cli.Log.Debugf("Got identity change for %s: %s, deleting all identities/sessions for that number", from, node)
		err := cli.Store.Identities.DeleteAllIdentities(ctx, from.User)
		if err != nil {
			cli.Log.Warnf("Failed to delete all identities of %s from store after identity change: %v", from, err)
		}
		err = cli.Store.Sessions.DeleteAllSessions(ctx, from.User)
		if err != nil {
			cli.Log.Warnf("Failed to delete all sessions of %s from store after identity change: %v", from, err)
		}
		ts := node.AttrGetter().UnixTime("t")
		storageLID := cli.resolveTCTokenStorageLID(ctx, from)
		pt, err := cli.Store.PrivacyTokens.GetPrivacyToken(ctx, storageLID)
		if err != nil {
			cli.Log.Debugf("Failed to load tctoken for identity change re-issue %s: %v", storageLID, err)
		}
		storedSenderTS := time.Time{}
		if pt != nil {
			storedSenderTS = pt.SenderTimestamp
		}
		if cli.validateAndSetTCTokenSenderTS(storageLID, storedSenderTS) {
			senderTS := cli.getTCTokenSenderTS(storageLID)
			if !senderTS.IsZero() {
				cli.Log.Debugf("Identity changed for %s, re-issuing tctoken", from)
				go cli.issuePrivacyTokenAndSave(storageLID, senderTS)
			}
		}
		cli.dispatchEvent(&events.IdentityChange{JID: from, Timestamp: ts})
	} else {
		cli.Log.Debugf("Got unknown encryption notification from server: %s", node)
	}
}

func (cli *Client) handleAppStateNotification(ctx context.Context, node *waBinary.Node) {
	for _, collection := range node.GetChildrenByTag("collection") {
		ag := collection.AttrGetter()
		name := appstate.WAPatchName(ag.String("name"))
		version := ag.Uint64("version")
		cli.Log.Debugf("Got server sync notification that app state %s has updated to version %d", name, version)
		err := cli.fetchAppStateFunc(ctx, name, false, false)
		if errors.Is(err, ErrIQDisconnected) || errors.Is(err, ErrNotConnected) {
			// There are some app state changes right before a remote logout, so stop syncing if we're disconnected.
			cli.Log.Debugf("Failed to sync app state after notification: %v, not trying to sync other states", err)
			return
		} else if errors.Is(err, appstate.ErrMismatchingLTHash) {
			cli.appStateSyncFailuresLock.Lock()
			cli.appStateSyncFailures[name]++
			count := cli.appStateSyncFailures[name]
			gaveUp := cli.appStateFullSyncFailures[name] >= maxAppStateFullSyncFailures
			cli.appStateSyncFailuresLock.Unlock()
			cli.Log.Errorf("Failed to sync app state after notification: %v", err)
			if count >= appStateSyncFailureThreshold && !gaveUp {
				cli.Log.Warnf("APP_STATE_AUTO_RESYNC: %d consecutive ErrMismatchingLTHash for %s — triggering fullSync", count, name)
				err2 := cli.fetchAppStateFunc(ctx, name, true, false)
				cli.appStateSyncFailuresLock.Lock()
				// Reset the consecutive-error counter after EVERY fullSync attempt so a
				// failed fullSync backs off to one attempt per appStateSyncFailureThreshold
				// errors instead of re-firing on every subsequent notification (D-12 loop fix).
				cli.appStateSyncFailures[name] = 0
				if err2 == nil {
					cli.appStateFullSyncFailures[name] = 0
				} else {
					cli.appStateFullSyncFailures[name]++
				}
				fullSyncFails := cli.appStateFullSyncFailures[name]
				cli.appStateSyncFailuresLock.Unlock()
				if err2 != nil {
					cli.Log.Errorf("APP_STATE_AUTO_RESYNC fullSync also failed for %s (attempt %d/%d): %v", name, fullSyncFails, maxAppStateFullSyncFailures, err2)
					if fullSyncFails >= maxAppStateFullSyncFailures {
						cli.Log.Errorf("APP_STATE_AUTO_RESYNC giving up on %s after %d failed fullSync attempts — collection left diverged; manual intervention required", name, fullSyncFails)
					}
				}
			}
		} else if err != nil {
			cli.Log.Errorf("Failed to sync app state after notification: %v", err)
		} else {
			// Success: reset both failure counters for this collection (re-arms auto-heal).
			cli.appStateSyncFailuresLock.Lock()
			cli.appStateSyncFailures[name] = 0
			cli.appStateFullSyncFailures[name] = 0
			cli.appStateSyncFailuresLock.Unlock()
		}
	}
}

func (cli *Client) handlePictureNotification(ctx context.Context, node *waBinary.Node) {
	ts := node.AttrGetter().UnixTime("t")
	for _, child := range node.GetChildren() {
		ag := child.AttrGetter()
		var evt events.Picture
		evt.Timestamp = ts
		evt.JID = ag.JID("jid")
		evt.Author = ag.OptionalJIDOrEmpty("author")
		if child.Tag == "delete" {
			evt.Remove = true
		} else if child.Tag == "add" {
			evt.PictureID = ag.String("id")
		} else if child.Tag == "set" {
			// TODO sometimes there's a hash and no ID?
			evt.PictureID = ag.String("id")
		} else {
			continue
		}
		if !ag.OK() {
			cli.Log.Debugf("Ignoring picture change notification with unexpected attributes: %v", ag.Error())
			continue
		}
		cli.dispatchEvent(&evt)
	}
}

func (cli *Client) handleDeviceNotification(ctx context.Context, node *waBinary.Node) {
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	ag := node.AttrGetter()
	from := ag.JID("from")
	fromLID := ag.OptionalJID("lid")
	if fromLID != nil {
		cli.StoreLIDPNMapping(ctx, *fromLID, from)
	}
	cached, ok := cli.userDevicesCache[from]
	if !ok {
		cli.Log.Debugf("No device list cached for %s, ignoring device list notification", from)
		return
	}
	var cachedLID deviceCache
	var cachedLIDHash string
	if fromLID != nil {
		cachedLID = cli.userDevicesCache[*fromLID]
		cachedLIDHash = participantListHashV2(cachedLID.devices)
	}
	cachedParticipantHash := participantListHashV2(cached.devices)
	var removedDevices []types.JID
	for _, child := range node.GetChildren() {
		cag := child.AttrGetter()
		deviceHash := cag.String("device_hash")
		deviceLIDHash := cag.OptionalString("device_lid_hash")
		deviceChild, _ := child.GetOptionalChildByTag("device")
		changedDeviceJID := deviceChild.AttrGetter().JID("jid")
		changedDeviceLID := deviceChild.AttrGetter().OptionalJID("lid")
		switch child.Tag {
		case "add":
			cached.devices = append(cached.devices, changedDeviceJID)
			if changedDeviceLID != nil {
				cachedLID.devices = append(cachedLID.devices, *changedDeviceLID)
			}
		case "remove":
			cached.devices = slices.DeleteFunc(cached.devices, func(existing types.JID) bool {
				return existing == changedDeviceJID
			})
			if changedDeviceLID != nil {
				cachedLID.devices = slices.DeleteFunc(cachedLID.devices, func(existing types.JID) bool {
					return existing == *changedDeviceLID
				})
			}
			// A removed device's pairwise session/identity are cryptographically
			// dead; retaining them only accumulates stale rows. Delete them
			// (matches WA Web's deleteRemoteInfo on device removal). Both the PN
			// and LID address forms are deleted since sessions may be keyed either way.
			removedDevices = append(removedDevices, changedDeviceJID)
			if changedDeviceLID != nil {
				removedDevices = append(removedDevices, *changedDeviceLID)
			}
		case "update":
			// Exact meaning of "update" is unknown, clear device list cache to be safe
			cli.Log.Debugf("%s's device list updated, dropping cached devices", from)
			delete(cli.userDevicesCache, from)
			continue
		default:
			cli.Log.Debugf("Unknown device list change tag %s", child.Tag)
			continue
		}
		newParticipantHash := participantListHashV2(cached.devices)
		if newParticipantHash == deviceHash {
			cli.Log.Debugf("%s's device list hash changed from %s to %s (%s). New hash matches", from, cachedParticipantHash, deviceHash, child.Tag)
			cli.userDevicesCache[from] = cached
		} else {
			cli.Log.Warnf("%s's device list hash changed from %s to %s (%s). New hash doesn't match (%s)", from, cachedParticipantHash, deviceHash, child.Tag, newParticipantHash)
			delete(cli.userDevicesCache, from)
		}
		if fromLID != nil && changedDeviceLID != nil && deviceLIDHash != "" {
			newLIDParticipantHash := participantListHashV2(cachedLID.devices)
			if newLIDParticipantHash == deviceLIDHash {
				cli.Log.Debugf("%s's device list hash changed from %s to %s (%s). New hash matches", fromLID, cachedLIDHash, deviceLIDHash, child.Tag)
				cli.userDevicesCache[*fromLID] = cachedLID
			} else {
				cli.Log.Warnf("%s's device list hash changed from %s to %s (%s). New hash doesn't match (%s)", fromLID, cachedLIDHash, deviceLIDHash, child.Tag, newLIDParticipantHash)
				delete(cli.userDevicesCache, *fromLID)
			}
		}
	}
	if len(removedDevices) > 0 {
		// Run the store deletes off the userDevicesCacheLock and detached from the
		// notification ctx (WithoutCancel + goroutine, so the cache lock isn't held
		// during store I/O).
		go cli.deleteRemovedDeviceData(context.WithoutCancel(ctx), removedDevices)
	}
}

// deleteRemovedDeviceData deletes the pairwise session + identity for devices that
// were removed from a peer's device list (<notification type="devices"><remove>).
// WA Web does this (deleteRemoteInfo): a removed device is cryptographically dead,
// so keeping its session only accumulates stale whatsmeow_sessions rows — the
// primary 1:1-session disk-bloat source for peers that cycle devices (dispatch bots).
// Per-device failures are logged and skipped, not fatal.
func (cli *Client) deleteRemovedDeviceData(ctx context.Context, devices []types.JID) {
	for _, device := range devices {
		addr := device.SignalAddress().String()
		if err := cli.Store.Sessions.DeleteSession(ctx, addr); err != nil {
			cli.Log.Warnf("DEVICE_REMOVED: failed to delete session for %s: %v", addr, err)
		}
		if err := cli.Store.Identities.DeleteIdentity(ctx, addr); err != nil {
			cli.Log.Warnf("DEVICE_REMOVED: failed to delete identity for %s: %v", addr, err)
		}
	}
	cli.Log.Infof("DEVICE_REMOVED: cleaned session+identity for %d removed device(s)", len(devices))
}

func (cli *Client) handleFBDeviceNotification(ctx context.Context, node *waBinary.Node) {
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	jid := node.AttrGetter().JID("from")
	userDevices := parseFBDeviceList(jid, node.GetChildByTag("devices"))
	cli.userDevicesCache[jid] = userDevices
}

func (cli *Client) handleOwnDevicesNotification(ctx context.Context, node *waBinary.Node, fromJID types.JID) {
	cli.userDevicesCacheLock.Lock()
	defer cli.userDevicesCacheLock.Unlock()
	ownLID := cli.getOwnLID().ToNonAD()
	ownID := cli.getOwnID().ToNonAD()
	if ownID.IsEmpty() {
		cli.Log.Debugf("Ignoring own device change notification, session was deleted")
		return
	}
	fromJIDPlain := fromJID.ToNonAD()
	var altJID types.JID
	switch fromJIDPlain {
	case ownID:
		altJID = ownLID
	case ownLID:
		altJID = ownID
	default:
		cli.Log.Warnf("Unexpected own device notification sender %s", fromJID)
		return
	}
	var oldHash string
	if cached, ok := cli.userDevicesCache[fromJIDPlain]; ok {
		oldHash = participantListHashV2(cached.devices)
	}
	expectedNewHash := node.AttrGetter().String("dhash")
	var newDeviceList, altDeviceList []types.JID
	for _, child := range node.GetChildren() {
		jid := child.AttrGetter().JID("jid")
		if child.Tag == "device" && !jid.IsEmpty() {
			newDeviceList = append(newDeviceList, jid)
			altDeviceJID := altJID
			altDeviceJID.Device = jid.Device
			altDeviceList = append(altDeviceList, altDeviceJID)
		}
	}
	newHash := participantListHashV2(newDeviceList)
	if newHash != expectedNewHash {
		cli.Log.Debugf("Received own device list change notification %s -> %s from %s, but expected hash was %s", oldHash, newHash, fromJID, expectedNewHash)
		delete(cli.userDevicesCache, ownID)
		delete(cli.userDevicesCache, ownLID)
	} else {
		cli.Log.Debugf("Received own device list change notification %s -> %s from %s", oldHash, newHash, fromJID)
		cli.userDevicesCache[fromJIDPlain] = deviceCache{devices: newDeviceList, dhash: expectedNewHash}
		cli.userDevicesCache[altJID] = deviceCache{devices: altDeviceList, dhash: participantListHashV2(altDeviceList)}
	}
}

func (cli *Client) handleBlocklist(ctx context.Context, node *waBinary.Node) {
	ag := node.AttrGetter()
	evt := events.Blocklist{
		Action:    events.BlocklistAction(ag.OptionalString("action")),
		DHash:     ag.String("dhash"),
		PrevDHash: ag.OptionalString("prev_dhash"),
	}
	for _, child := range node.GetChildren() {
		ag := child.AttrGetter()
		change := events.BlocklistChange{
			JID:    ag.JID("jid"),
			Action: events.BlocklistChangeAction(ag.String("action")),
		}
		if !ag.OK() {
			cli.Log.Warnf("Unexpected data in blocklist event child %s: %v", &child, ag.Error())
			continue
		}
		evt.Changes = append(evt.Changes, change)
	}
	cli.dispatchEvent(&evt)
}

func (cli *Client) handleAccountSyncNotification(ctx context.Context, node *waBinary.Node) {
	for _, child := range node.GetChildren() {
		switch child.Tag {
		case "privacy":
			cli.handlePrivacySettingsNotification(ctx, &child)
		case "devices":
			cli.handleOwnDevicesNotification(ctx, &child, node.AttrGetter().JID("from"))
		case "picture":
			cli.dispatchEvent(&events.Picture{
				Timestamp: node.AttrGetter().UnixTime("t"),
				JID:       cli.getOwnID().ToNonAD(),
			})
		case "blocklist":
			cli.handleBlocklist(ctx, &child)
		default:
			cli.Log.Debugf("Unhandled account sync item %s", child.Tag)
		}
	}
}

func (cli *Client) handlePrivacyTokenNotification(ctx context.Context, node *waBinary.Node) {
	if cli.getOwnID().IsEmpty() {
		cli.Log.Debugf("Ignoring privacy token notification, session was deleted")
		return
	}
	tokens := node.GetChildByTag("tokens")
	if tokens.Tag != "tokens" {
		cli.Log.Warnf("privacy_token notification didn't contain <tokens> tag")
		return
	}
	parentAG := node.AttrGetter()
	sender := parentAG.JID("from").ToNonAD()
	senderLID := parentAG.OptionalJIDOrEmpty("sender_lid").ToNonAD()
	if senderLID.IsEmpty() {
		senderLID = cli.resolveTCTokenStorageLID(ctx, sender)
	}
	if !parentAG.OK() {
		cli.Log.Warnf("privacy_token notification didn't have a sender (%v)", parentAG.Error())
		return
	}
	for _, child := range tokens.GetChildren() {
		ag := child.AttrGetter()
		if child.Tag != "token" {
			cli.Log.Warnf("privacy_token notification contained unexpected <%s> tag", child.Tag)
			continue
		}
		if tokenType := ag.String("type"); tokenType != "trusted_contact" {
			cli.Log.Warnf("privacy_token notification contained unexpected token type %s", tokenType)
			continue
		}
		token, ok := child.Content.([]byte)
		if !ok {
			cli.Log.Warnf("privacy_token notification contained non-binary token")
			continue
		}
		timestamp := ag.UnixTime("t")
		if !ag.OK() {
			cli.Log.Warnf("privacy_token notification is missing some fields: %v", ag.Error())
		}
		err := cli.Store.PrivacyTokens.PutPrivacyTokens(ctx, store.PrivacyToken{
			User:      senderLID,
			Token:     token,
			Timestamp: timestamp,
		})
		if err != nil {
			cli.Log.Errorf("Failed to save privacy token from %s: %v", senderLID, err)
		} else {
			cli.Log.Debugf("Received privacy token from %s (ts: %v)", senderLID, timestamp)
		}
	}
}

func (cli *Client) parseNewsletterMessages(node *waBinary.Node) []*types.NewsletterMessage {
	children := node.GetChildren()
	output := make([]*types.NewsletterMessage, 0, len(children))
	for _, child := range children {
		if child.Tag != "message" {
			continue
		}
		ag := child.AttrGetter()
		msg := types.NewsletterMessage{
			MessageServerID: ag.Int("server_id"),
			MessageID:       ag.String("id"),
			Type:            ag.String("type"),
			Timestamp:       ag.UnixTime("t"),
			ViewsCount:      0,
			ReactionCounts:  nil,
		}
		for _, subchild := range child.GetChildren() {
			switch subchild.Tag {
			case "plaintext":
				byteContent, ok := subchild.Content.([]byte)
				if ok {
					msg.Message = new(waE2E.Message)
					err := proto.Unmarshal(byteContent, msg.Message)
					if err != nil {
						cli.Log.Warnf("Failed to unmarshal newsletter message: %v", err)
						msg.Message = nil
					}
				}
			case "views_count":
				msg.ViewsCount = subchild.AttrGetter().Int("count")
			case "reactions":
				msg.ReactionCounts = make(map[string]int)
				for _, reaction := range subchild.GetChildren() {
					rag := reaction.AttrGetter()
					msg.ReactionCounts[rag.String("code")] = rag.Int("count")
				}
			}
		}
		output = append(output, &msg)
	}
	return output
}

func (cli *Client) handleNewsletterNotification(ctx context.Context, node *waBinary.Node) {
	ag := node.AttrGetter()
	liveUpdates := node.GetChildByTag("live_updates")
	cli.dispatchEvent(&events.NewsletterLiveUpdate{
		JID:      ag.JID("from"),
		Time:     ag.UnixTime("t"),
		Messages: cli.parseNewsletterMessages(&liveUpdates),
	})
}

type newsLetterEventWrapper struct {
	Data newsletterEvent `json:"data"`
}

type newsletterEvent struct {
	Join       *events.NewsletterJoin       `json:"xwa2_notify_newsletter_on_join"`
	Leave      *events.NewsletterLeave      `json:"xwa2_notify_newsletter_on_leave"`
	MuteChange *events.NewsletterMuteChange `json:"xwa2_notify_newsletter_on_mute_change"`
	// _on_admin_metadata_update -> id, thread_metadata, messages
	// _on_metadata_update
	// _on_state_change -> id, is_requestor, state
	NotifyAccountReachoutTimelock *events.NotifyAccountReachoutTimelock `json:"xwa2_notify_account_reachout_timelock"`
}

func (cli *Client) handleMexNotification(ctx context.Context, node *waBinary.Node) {
	for _, child := range node.GetChildren() {
		if child.Tag != "update" {
			continue
		}
		mnd := events.MexNotificationData{
			Timestamp: node.AttrGetter().OptionalUnixTime("t"),
			OpName:    child.AttrGetter().OptionalString("op_name"),
		}
		childData, ok := child.Content.([]byte)
		if !ok {
			continue
		}
		var wrapper newsLetterEventWrapper
		err := json.Unmarshal(childData, &wrapper)
		if err != nil {
			cli.Log.Errorf("Failed to unmarshal JSON in mex event: %v", err)
			continue
		}
		if wrapper.Data.Join != nil {
			wrapper.Data.Join.Mex = mnd
			cli.dispatchEvent(wrapper.Data.Join)
		} else if wrapper.Data.Leave != nil {
			wrapper.Data.Leave.Mex = mnd
			cli.dispatchEvent(wrapper.Data.Leave)
		} else if wrapper.Data.MuteChange != nil {
			wrapper.Data.MuteChange.Mex = mnd
			cli.dispatchEvent(wrapper.Data.MuteChange)
		} else if wrapper.Data.NotifyAccountReachoutTimelock != nil {
			wrapper.Data.NotifyAccountReachoutTimelock.Mex = mnd
			cli.dispatchEvent(wrapper.Data.NotifyAccountReachoutTimelock)
		}
	}
}

func (cli *Client) handleStatusNotification(ctx context.Context, node *waBinary.Node) {
	ag := node.AttrGetter()
	child, found := node.GetOptionalChildByTag("set")
	if !found {
		cli.Log.Debugf("Status notifcation did not contain child with tag 'set'")
		return
	}
	// kavtov-fork (55.1-10, class 2): a nil Content is the privacy-gated bare
	// `<set hash="...">` shape (a legitimate cleared/empty status, matching
	// WAWebHandleAboutNotification.js) — dispatch an empty UserAbout instead of warning.
	// Any OTHER non-[]byte, non-nil shape is still genuinely unrecognized and still warns.
	var status []byte
	switch content := child.Content.(type) {
	case []byte:
		status = content
	case nil:
	default:
		cli.Log.Warnf("Set status notification has unexpected content (%T)", content)
		return
	}
	cli.dispatchEvent(&events.UserAbout{
		JID:       ag.JID("from"),
		Timestamp: ag.UnixTime("t"),
		Status:    string(status),
	})
}

func (cli *Client) handleNotification(ctx context.Context, node *waBinary.Node) {
	var cancelled bool
	defer cli.maybeDeferredAck(ctx, node)(&cancelled)
	ag := node.AttrGetter()
	notifType := ag.String("type")
	if !ag.OK() {
		return
	}
	switch notifType {
	case "encrypt":
		go cli.handleEncryptNotification(ctx, node)
	case "server_sync":
		go cli.handleAppStateNotification(ctx, node)
	case "account_sync":
		go cli.handleAccountSyncNotification(ctx, node)
	case "devices":
		cli.handleDeviceNotification(ctx, node)
	case "fbid:devices":
		cli.handleFBDeviceNotification(ctx, node)
	case "w:gp2":
		evt, lidPairs, redactedPhones, err := cli.parseGroupNotification(node)
		if err != nil {
			cli.Log.Errorf("Failed to parse group notification: %v", err)
		} else {
			err = cli.Store.LIDs.PutManyLIDMappings(ctx, lidPairs)
			if err != nil {
				cli.Log.Errorf("Failed to store LID mappings from group notification: %v", err)
			}
			err = cli.Store.Contacts.PutManyRedactedPhones(ctx, redactedPhones)
			if err != nil {
				cli.Log.Warnf("Failed to store redacted phones from group notification: %v", err)
			}
			cancelled = cli.dispatchEvent(evt)
		}
	case "picture":
		cli.handlePictureNotification(ctx, node)
	case "mediaretry":
		cli.handleMediaRetryNotification(ctx, node)
	case "privacy_token":
		cli.handlePrivacyTokenNotification(ctx, node)
	case "link_code_companion_reg":
		go cli.tryHandleCodePairNotification(ctx, node)
	case "newsletter":
		cli.handleNewsletterNotification(ctx, node)
	case "mex":
		cli.handleMexNotification(ctx, node)
	case "status":
		cli.handleStatusNotification(ctx, node)
	case "passkey_prologue_request":
		cli.handlePasskeyNotification(ctx, node)
	case "crsc_continuation":
		go cli.tryHandlePasskeyContinuationNotification(ctx, node)
	case "companion_reg_refresh":
		_, refresh := node.GetOptionalChildByTag("companion_reg_refresh")
		_, rotateQR := node.GetOptionalChildByTag("pair-device-rotate-qr")
		if refresh || rotateQR {
			cli.rotateADVSecret(ctx)
		} else {
			cli.Log.Debugf("Unrecognized companion reg refresh notification: %s", node)
		}
	// Other types: business, disappearing_mode, server, status, pay, psa
	default:
		cli.Log.Debugf("Unhandled notification with type %s", notifType)
	}
}
