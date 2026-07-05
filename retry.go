// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime/debug"
	"sync"
	"time"

	"go.mau.fi/libsignal/ecc"
	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/keys/prekey"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/signalerror"
	"google.golang.org/protobuf/proto"

	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waCommon"
	"go.mau.fi/whatsmeow/proto/waConsumerApplication"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waMsgApplication"
	"go.mau.fi/whatsmeow/proto/waMsgTransport"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
)

// Number of sent messages to cache in memory for handling retry receipts.
const recentMessagesSize = 256

type recentMessageKey struct {
	To types.JID
	ID types.MessageID
}

type RecentMessage struct {
	wa *waE2E.Message
	fb *waMsgApplication.MessageApplication
	// isPeer marks a message sent via SendPeerMessage (category=peer). kavtov: peer
	// messages are kept in the in-memory ring only (never the DB retry buffer) so they
	// can be re-served on a retry receipt with PEER framing instead of the malformed
	// DeviceSentMessage wrap. See debug session retry-store-miss-never-stored.
	isPeer bool
}

func (rm RecentMessage) IsEmpty() bool {
	return rm.wa == nil && rm.fb == nil
}

func (cli *Client) addRecentMessage(ctx context.Context, to types.JID, id types.MessageID, wa *waE2E.Message, fb *waMsgApplication.MessageApplication, isPeer bool) error {
	// kavtov: peer messages (req.Peer) are NOT written to the DB retry buffer — the DB
	// is write-bound and peer retries only need to be servable for the brief window the
	// requesting device retries (~seconds). They are always kept in the in-memory ring
	// below so a retry receipt can be served from getRecentMessage (retry.go:109).
	if cli.UseRetryMessageStore && !isPeer {
		var buf []byte
		var format string
		var err error
		if wa != nil {
			buf, err = proto.Marshal(wa)
			format = "wa"
		} else if fb != nil {
			buf, err = proto.Marshal(fb)
			format = "fb"
		}
		if err != nil {
			return fmt.Errorf("failed to marshal message for retry store: %w", err)
		}
		if buf != nil {
			err = cli.Store.EventBuffer.AddOutgoingEvent(ctx, to, id, format, buf)
			if err != nil {
				return fmt.Errorf("failed to add message to retry store: %w", err)
			}
			if time.Since(cli.lastRetryStoreClear) > 12*time.Hour {
				err = cli.Store.EventBuffer.DeleteOldOutgoingEvents(ctx)
				if err != nil {
					return fmt.Errorf("failed to clear old messages from retry store: %w", err)
				}
			}
		}
	}
	cli.recentMessagesLock.Lock()
	key := recentMessageKey{to, id}
	if cli.recentMessagesList[cli.recentMessagesPtr].ID != "" {
		delete(cli.recentMessagesMap, cli.recentMessagesList[cli.recentMessagesPtr])
	}
	cli.recentMessagesMap[key] = RecentMessage{wa: wa, fb: fb, isPeer: isPeer}
	cli.recentMessagesList[cli.recentMessagesPtr] = key
	cli.recentMessagesPtr++
	if cli.recentMessagesPtr >= len(cli.recentMessagesList) {
		cli.recentMessagesPtr = 0
	}
	cli.recentMessagesLock.Unlock()
	return nil
}

func (cli *Client) getRecentMessage(to types.JID, id types.MessageID) RecentMessage {
	cli.recentMessagesLock.RLock()
	defer cli.recentMessagesLock.RUnlock()
	return cli.recentMessagesMap[recentMessageKey{to, id}]
}

// shouldWrapDeviceSentRetry reports whether an outgoing-message retry should be re-wrapped
// as a DeviceSentMessage. This is true for own-account (IsFromMe) DM retries, but NOT for
// peer messages (msg.isPeer): peer messages must be re-sent with PEER framing instead
// (see applyPeerRetryAttrs and the peer content shape in handleRetryReceipt). Wrapping a
// peer message as DeviceSentMessage produces the malformed resend upstream deferred.
func shouldWrapDeviceSentRetry(receipt *events.Receipt, msg *RecentMessage) bool {
	return receipt.IsFromMe && !msg.isPeer
}

// applyPeerRetryAttrs mutates a retry message node's attrs to use PEER framing, mirroring
// preparePeerMessageNode (send.go): type=text, category=peer, and push_priority for the
// app-state-sync-key-request / history-sync-on-demand peer request types. The dominant
// PLACEHOLDER_MESSAGE_RESEND request (PEER_DATA_OPERATION_REQUEST_MESSAGE) gets neither.
// It deliberately does NOT set device_fanout (peer sends never do).
func applyPeerRetryAttrs(attrs waBinary.Attrs, wa *waE2E.Message) {
	attrs["type"] = "text"
	attrs["category"] = "peer"
	if wa.GetProtocolMessage().GetType() == waE2E.ProtocolMessage_APP_STATE_SYNC_KEY_REQUEST {
		attrs["push_priority"] = "high"
	} else if wa.GetProtocolMessage().GetPeerDataOperationRequestMessage().GetPeerDataOperationRequestType() == waE2E.PeerDataOperationRequestType_HISTORY_SYNC_ON_DEMAND {
		attrs["push_priority"] = "high_force"
		attrs["privacy_sensitive"] = "1"
	}
}

// getMessageForRetry looks up the outgoing message for a retry receipt by messageID.
// msgTimestamp is the original message send-time from the retry node's "t" attribute
// (retry.go:231); used to add age= to RETRY_STORE_MISS for age-expiry vs never-stored
// classification. Pass time.Time{} (zero) when the timestamp is unavailable.
func (cli *Client) getMessageForRetry(ctx context.Context, receipt *events.Receipt, messageID types.MessageID, msgTimestamp time.Time) (*RecentMessage, error) {
	msg := cli.getRecentMessage(receipt.Chat, messageID)
	if !msg.IsEmpty() {
		cli.Log.Debugf("Found message in local cache to accept retry receipt for %s/%s from %s", receipt.Chat, messageID, receipt.Sender)
		return &msg, nil
	}
	var altChat types.JID
	var err error
	switch receipt.Chat.Server {
	case types.DefaultUserServer:
		altChat, err = cli.Store.LIDs.GetLIDForPN(ctx, receipt.Chat)
	case types.HiddenUserServer:
		altChat, err = cli.Store.LIDs.GetPNForLID(ctx, receipt.Chat)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get alternate JID for %s: %w", receipt.Chat, err)
	} else if !altChat.IsEmpty() {
		msg = cli.getRecentMessage(altChat, messageID)
		if !msg.IsEmpty() {
			cli.Log.Debugf("Found message in local cache with alternate chat JID %s to accept retry receipt for %s/%s from %s", altChat, receipt.Chat, messageID, receipt.Sender)
			return &msg, nil
		}
	}
	if cli.UseRetryMessageStore {
		format, buf, err := cli.Store.EventBuffer.GetOutgoingEvent(ctx, receipt.Chat, altChat, messageID)
		if err == nil {
			return parseRecentMessage(format, buf)
		}
		// kavtov: own-account (DeviceSentMessage / IsFromMe) retries arrive keyed by our own
		// account, but the message was stored under its destination chat — so the (chat,id)
		// lookup above misses. We only ever receive a retry receipt for a message we sent, so
		// the message is in the store (within retention) under some chat; look it up by id alone.
		if errors.Is(err, sql.ErrNoRows) && receipt.Chat.User == cli.getOwnID().User {
			formatByID, bufByID, errByID := cli.Store.EventBuffer.GetOutgoingEventByID(ctx, messageID)
			if errByID == nil {
				cli.Log.Infof("Served retry receipt by message-id (self-chat fallback) for %s/%s from %s", receipt.Chat, messageID, receipt.Sender)
				return parseRecentMessage(formatByID, bufByID)
			}
			if !errors.Is(errByID, sql.ErrNoRows) {
				return nil, fmt.Errorf("failed to get message from retry store by id: %w", errByID)
			}
		}
		// kavtov-fork (29-08 gap-closure): add age= to split age-expiry (benign,
		// age>48h eviction by store.go:1439 DELETE) from never-stored (structural, age<48h).
		age := "unknown"
		if !msgTimestamp.IsZero() {
			age = time.Since(msgTimestamp).Round(time.Second).String()
		}
		cli.Log.Warnf("RETRY_STORE_MISS msgID=%s chat=%s altChat=%s account=%s altEmpty=%v age=%s retrySender=%s senderDevice=%d senderAgent=%d senderIsOwn=%v isGroup=%v isFromMe=%v err=%v",
			messageID, receipt.Chat, altChat, cli.getOwnID().User, altChat.IsEmpty(), age, receipt.Sender, receipt.Sender.Device, receipt.Sender.RawAgent, receipt.Sender.User == cli.getOwnID().User, receipt.IsGroup, receipt.IsFromMe, err)
		return nil, fmt.Errorf("failed to get message from retry store: %w", err)
	}
	waMsg := cli.GetMessageForRetry(receipt.Sender, receipt.Chat, messageID)
	if waMsg != nil {
		cli.Log.Debugf("Found message in GetMessageForRetry to accept retry receipt for %s/%s from %s", receipt.Chat, messageID, receipt.Sender)
		return &RecentMessage{wa: waMsg}, nil
	}
	return nil, nil
}

func parseRecentMessage(format string, buf []byte) (*RecentMessage, error) {
	var rm RecentMessage
	var err error
	switch format {
	case "wa":
		rm.wa = &waE2E.Message{}
		err = proto.Unmarshal(buf, rm.wa)
	case "fb":
		rm.fb = &waMsgApplication.MessageApplication{}
		err = proto.Unmarshal(buf, rm.fb)
	default:
		err = fmt.Errorf("unknown format in retry store: %s", format)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal payload in retry store: %w", err)
	}
	return &rm, nil
}

const recreateSessionTimeout = 1 * time.Hour

func (cli *Client) shouldRecreateSession(ctx context.Context, retryCount int, jid types.JID) (reason string, recreate bool) {
	cli.sessionRecreateHistoryLock.Lock()
	defer cli.sessionRecreateHistoryLock.Unlock()
	if contains, err := cli.Store.ContainsSession(ctx, jid.SignalAddress()); err != nil {
		return "", false
	} else if !contains {
		cli.sessionRecreateHistory[jid] = time.Now()
		return "we don't have a Signal session with them", true
	} else if retryCount < 2 {
		return "", false
	}
	prevTime, ok := cli.sessionRecreateHistory[jid]
	if !ok || prevTime.Add(recreateSessionTimeout).Before(time.Now()) {
		cli.sessionRecreateHistory[jid] = time.Now()
		return "retry count > 1 and over an hour since last recreation", true
	}
	return "", false
}

type incomingRetryKey struct {
	jid       types.JID
	messageID types.MessageID
}

// kavtov-fork (38.5): key for the per-account bot-resend blacklist.
// Group is the group JID string; Sender is the bare user (SignalAddressUser),
// so a device-rotating bot accumulates under one key.
type botResendKey struct {
	Group  string
	Sender string
}

// botResendBlacklistThreshold is the number of cumulative skmsg decrypts failures
// for a (group, sender) before the resend-request stanza to that bot is suppressed.
// The ack, phone request, and donor scan are NOT suppressed. Code default (no env
// flag): fleet-wide aggregation across all accounts makes 3 total misses enough.
const botResendBlacklistThreshold = 3

// botResendBlacklistTTL bounds how long a (group, sender) stays suppressed. After
// this window IsBlacklisted re-probes (drops the entry + resets its count) so a
// recovered bot is retried rather than permanently dropped — no silent loss.
const botResendBlacklistTTL = 7 * 24 * time.Hour

// claimKey is the key for the process-wide PhoneRequestClaims map.
type claimKey struct {
	Group string
	MsgID string
}

// phoneRequestClaimTTL is the expiry for a PhoneRequestClaims entry. If the
// claiming account's phone never delivers within this window, the next miss
// re-claims and fires a fresh phone request (no loss).
const phoneRequestClaimTTL = 5 * time.Second

// PhoneRequestClaims is a process-wide, concurrency-safe claim map used to ensure
// that only one managed account sends the phone-fetch request for a given group
// message. Shared across all per-account Clients; injected by the driver.
type PhoneRequestClaims struct {
	mu     sync.Mutex
	claims map[claimKey]time.Time
}

// NewPhoneRequestClaims creates a new PhoneRequestClaims instance.
func NewPhoneRequestClaims() *PhoneRequestClaims {
	return &PhoneRequestClaims{claims: make(map[claimKey]time.Time)}
}

// TryClaim claims the (group, msgID) pair for the calling account.
// Returns true if this caller should proceed with the phone request:
// - no existing claim, or the existing claim is older than phoneRequestClaimTTL.
// Returns false if another account already holds a live claim (skip the request).
func (p *PhoneRequestClaims) TryClaim(group, msgID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	k := claimKey{Group: group, MsgID: msgID}
	if t, ok := p.claims[k]; ok && time.Since(t) < phoneRequestClaimTTL {
		return false
	}
	p.claims[k] = time.Now()
	return true
}

// incrementBotResendBlacklist delegates one skmsg-decrypt miss to the shared,
// fleet-wide BotResendBlacklist and logs BOT_RESEND_BLACKLISTED exactly once when
// this miss first crosses botResendBlacklistThreshold. Client-owned logging keeps
// the log-once semantics while BotResendBlacklist stays log-free (persistFunc
// carries no logger). nil BotResendBL (bare &Client{}) is a safe no-op.
func (cli *Client) incrementBotResendBlacklist(group, sender string) {
	if cli.BotResendBL == nil {
		return
	}
	if cli.BotResendBL.Increment(group, sender) && cli.Log != nil {
		cli.Log.Warnf("BOT_RESEND_BLACKLISTED group=%s sender=%s", group, sender)
	}
}

// isBotResendBlacklisted reports whether the (group, sender) pair is currently
// suppressed in the shared blacklist. Called in sendRetryReceipt to suppress the
// futile resend-request stanza to the bot. nil BotResendBL returns false.
func (cli *Client) isBotResendBlacklisted(group, sender string) bool {
	if cli.BotResendBL == nil {
		return false
	}
	return cli.BotResendBL.IsBlacklisted(group, sender)
}

func (cli *Client) tryHandleRetryReceipt(ctx context.Context, receipt *events.Receipt, node *waBinary.Node) {
	defer func() {
		err := recover()
		if err != nil {
			cli.Log.Errorf("Retry receipt handler panicked: %v\n%s", err, debug.Stack())
		}
	}()
	if cli.retrySema != nil {
		err := cli.retrySema.Acquire(ctx, 1)
		if err != nil {
			return
		}
		defer cli.retrySema.Release(1)
	}
	err := cli.handleRetryReceipt(ctx, receipt, node)
	if err != nil {
		cli.Log.Errorf("Failed to handle retry receipt for %s/%s from %s: %v", receipt.Chat, receipt.MessageIDs[0], receipt.Sender, err)
	}
}

// handleRetryReceipt handles an incoming retry receipt for an outgoing message.
func (cli *Client) handleRetryReceipt(ctx context.Context, receipt *events.Receipt, node *waBinary.Node) error {
	retryChild, ok := node.GetOptionalChildByTag("retry")
	if !ok {
		return &ElementMissingError{Tag: "retry", In: "retry receipt"}
	}
	ag := retryChild.AttrGetter()
	messageID := ag.String("id")
	timestamp := ag.UnixTime("t")
	retryCount := ag.Int("count")
	if !ag.OK() {
		return ag.Error()
	}
	// Process prekey bundle BEFORE checking if message exists.
	// This ensures we establish a session with the requester even if we can't
	// find the original message. This way, our next group message will include
	// SKDM for them, fixing the "no sender key" error for future messages.
	if _, hasKeys := node.GetOptionalChildByTag("keys"); hasKeys {
		bundle, bundleErr := nodeToPreKeyBundle(uint32(receipt.Sender.Device), *node)
		if bundleErr != nil {
			cli.Log.Warnf("Failed to parse prekey bundle from retry receipt from %s: %v", receipt.Sender, bundleErr)
		} else if bundle != nil {
			encryptionIdentity := receipt.Sender
			if receipt.Sender.Server == types.DefaultUserServer {
				lidForPN, err := cli.Store.LIDs.GetLIDForPN(ctx, receipt.Sender)
				if err != nil {
					cli.Log.Warnf("Failed to get LID for %s: %v", receipt.Sender, err)
				} else if !lidForPN.IsEmpty() {
					cli.migrateSessionStore(ctx, receipt.Sender, lidForPN)
					encryptionIdentity = lidForPN
				}
			}
			builder := session.NewBuilderFromSignal(cli.Store, encryptionIdentity.SignalAddress(), pbSerializer)
			processErr := builder.ProcessBundle(ctx, bundle)
			// WR-02 note (2026-06-10): D-10 (35.2-03) makes the whatsmeow-store
			// IsTrustedIdentity accept every key rotation (store.go +
			// cached_identity_store.go), so a STORE-level untrusted-identity verdict
			// can no longer reach this branch. It is deliberately KEPT (not dead
			// code): libsignal can still surface ErrUntrustedIdentity from its own
			// internal state diverging (e.g. a stale session record's identity vs the
			// stored one), and clearing + reprocessing remains the correct response
			// for that class. Same applies to clearUntrustedIdentity (message.go) and
			// the decryptDM AutoTrustIdentity retry.
			if cli.AutoTrustIdentity && errors.Is(processErr, signalerror.ErrUntrustedIdentity) {
				cli.Log.Warnf("Got untrusted identity processing prekey bundle from retry receipt from %s, clearing and retrying", receipt.Sender)
				if clearErr := cli.clearUntrustedIdentity(ctx, encryptionIdentity); clearErr != nil {
					cli.Log.Errorf("Failed to clear untrusted identity for %s: %v", encryptionIdentity, clearErr)
				} else {
					processErr = builder.ProcessBundle(ctx, bundle)
				}
			}
			if processErr != nil {
				cli.Log.Warnf("Failed to process prekey bundle from retry receipt from %s: %v", receipt.Sender, processErr)
			} else {
				cli.Log.Infof("Established session with %s from retry receipt prekey bundle (message %s)", receipt.Sender, messageID)
			}
		}
	}

	msg, err := cli.getMessageForRetry(ctx, receipt, messageID, timestamp)
	if err != nil {
		return err
	} else if msg == nil {
		return fmt.Errorf("couldn't find message %s", messageID)
	}
	var fbConsumerMsg *waConsumerApplication.ConsumerApplication
	if msg.fb != nil {
		subProto, ok := msg.fb.GetPayload().GetSubProtocol().GetSubProtocol().(*waMsgApplication.MessageApplication_SubProtocolPayload_ConsumerMessage)
		if ok {
			fbConsumerMsg, err = subProto.Decode()
			if err != nil {
				return fmt.Errorf("failed to decode consumer message for retry: %w", err)
			}
		}
	}

	retryKey := incomingRetryKey{receipt.Sender, messageID}
	cli.incomingRetryRequestCounterLock.Lock()
	cli.incomingRetryRequestCounter[retryKey]++
	internalCounter := cli.incomingRetryRequestCounter[retryKey]
	cli.incomingRetryRequestCounterLock.Unlock()
	if internalCounter >= 10 {
		cli.Log.Warnf("Dropping retry request from %s for %s: internal retry counter is %d", messageID, receipt.Sender, internalCounter)
		return nil
	}

	var fbSKDM *waMsgTransport.MessageTransport_Protocol_Ancillary_SenderKeyDistributionMessage
	var fbDSM *waMsgTransport.MessageTransport_Protocol_Integral_DeviceSentMessage
	if receipt.IsGroup {
		builder := groups.NewGroupSessionBuilder(cli.Store, pbSerializer)
		senderKeyName := protocol.NewSenderKeyName(receipt.Chat.String(), cli.getOwnLID().SignalAddress())
		signalSKDMessage, err := builder.Create(ctx, senderKeyName)
		if err != nil {
			cli.Log.Warnf("Failed to create sender key distribution message to include in retry of %s in %s to %s: %v", messageID, receipt.Chat, receipt.Sender, err)
		} else if msg.wa != nil {
			msg.wa.SenderKeyDistributionMessage = &waE2E.SenderKeyDistributionMessage{
				GroupID:                             proto.String(receipt.Chat.String()),
				AxolotlSenderKeyDistributionMessage: signalSKDMessage.Serialize(),
			}
		} else {
			fbSKDM = &waMsgTransport.MessageTransport_Protocol_Ancillary_SenderKeyDistributionMessage{
				GroupID:                             proto.String(receipt.Chat.String()),
				AxolotlSenderKeyDistributionMessage: signalSKDMessage.Serialize(),
			}
		}
	} else if shouldWrapDeviceSentRetry(receipt, msg) {
		// kavtov: a normal own-device (DeviceSent fan-out) message is re-wrapped as
		// DeviceSentMessage. A PEER message (msg.isPeer) must NOT be wrapped — it is
		// re-sent with peer framing below (category=peer, meta node, no DeviceSent wrap),
		// matching the original preparePeerMessageNode send. Wrapping a peer message would
		// produce the malformed resend upstream deferred ("Peer message retries aren't
		// implemented yet"). See debug session retry-store-miss-never-stored.
		if msg.wa != nil {
			msg.wa = &waE2E.Message{
				DeviceSentMessage: &waE2E.DeviceSentMessage{
					DestinationJID: proto.String(receipt.Chat.String()),
					Message:        msg.wa,
				},
			}
		} else {
			fbDSM = &waMsgTransport.MessageTransport_Protocol_Integral_DeviceSentMessage{
				DestinationJID: proto.String(receipt.Chat.String()),
			}
		}
	}
	if msg.isPeer && msg.fb != nil {
		// Both peer callers (immediateRequestMessageFromPhone, appstate recovery) build
		// waE2E ProtocolMessages; an fb peer message is not a path we can frame. Fail safe.
		return fmt.Errorf("cannot retry fb peer message %s: peer fb retries are unsupported", messageID)
	}

	// TODO pre-retry callback for fb
	if cli.PreRetryCallback != nil && !cli.PreRetryCallback(receipt, messageID, retryCount, msg.wa) {
		cli.Log.Debugf("Cancelled retry receipt in PreRetryCallback")
		return nil
	}

	var plaintext, frankingTag []byte
	if msg.wa != nil {
		plaintext, err = proto.Marshal(msg.wa)
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
	} else {
		plaintext, err = proto.Marshal(msg.fb)
		if err != nil {
			return fmt.Errorf("failed to marshal consumer message: %w", err)
		}
		frankingHash := hmac.New(sha256.New, msg.fb.GetMetadata().GetFrankingKey())
		frankingHash.Write(plaintext)
		frankingTag = frankingHash.Sum(nil)
	}
	_, hasKeys := node.GetOptionalChildByTag("keys")
	var bundle *prekey.Bundle
	if hasKeys {
		bundle, err = nodeToPreKeyBundle(uint32(receipt.Sender.Device), *node)
		if err != nil {
			return fmt.Errorf("failed to read prekey bundle in retry receipt: %w", err)
		}
	} else if reason, recreate := cli.shouldRecreateSession(ctx, retryCount, receipt.Sender); recreate {
		cli.Log.Debugf("Fetching prekeys for %s for handling retry receipt with no prekey bundle because %s", receipt.Sender, reason)
		var keys map[types.JID]preKeyResp
		keys, err = cli.fetchPreKeys(ctx, []types.JID{receipt.Sender})
		if err != nil {
			return err
		}
		bundle, err = keys[receipt.Sender].bundle, keys[receipt.Sender].err
		if err != nil {
			return fmt.Errorf("failed to fetch prekeys: %w", err)
		} else if bundle == nil {
			return fmt.Errorf("didn't get prekey bundle for %s (response size: %d)", receipt.Sender, len(keys))
		}
	}
	encAttrs := waBinary.Attrs{}
	var msgAttrs messageAttrs
	if msg.wa != nil {
		msgAttrs.MediaType = getMediaTypeFromMessage(msg.wa)
		msgAttrs.Type = getTypeFromMessage(msg.wa)
	} else if fbConsumerMsg != nil {
		msgAttrs = getAttrsFromFBMessage(fbConsumerMsg)
	} else {
		msgAttrs.Type = "text"
	}
	if msgAttrs.MediaType != "" {
		encAttrs["mediatype"] = msgAttrs.MediaType
	}
	var encrypted *waBinary.Node
	var includeDeviceIdentity bool
	if msg.wa != nil {
		encryptionIdentity := receipt.Sender
		if receipt.Sender.Server == types.DefaultUserServer {
			lidForPN, err := cli.Store.LIDs.GetLIDForPN(ctx, receipt.Sender)
			if err != nil {
				cli.Log.Warnf("Failed to get LID for %s: %v", receipt.Sender, err)
			} else if !lidForPN.IsEmpty() {
				cli.migrateSessionStore(ctx, receipt.Sender, lidForPN)
				encryptionIdentity = lidForPN
			}
		}
		encrypted, includeDeviceIdentity, err = cli.encryptMessageForDevice(ctx, plaintext, encryptionIdentity, bundle, encAttrs, nil)
	} else {
		encrypted, err = cli.encryptMessageForDeviceV3(ctx, &waMsgTransport.MessageTransport_Payload{
			ApplicationPayload: &waCommon.SubProtocol{
				Payload: plaintext,
				Version: proto.Int32(FBMessageApplicationVersion),
			},
			FutureProof: waCommon.FutureProofBehavior_PLACEHOLDER.Enum(),
		}, fbSKDM, fbDSM, receipt.Sender, bundle, encAttrs)
	}
	if err != nil {
		return fmt.Errorf("failed to encrypt message for retry: %w", err)
	}
	encrypted.Attrs["count"] = retryCount

	attrs := waBinary.Attrs{
		"to":   node.Attrs["from"],
		"type": msgAttrs.Type,
		"id":   messageID,
		"t":    timestamp.Unix(),
	}
	if msg.isPeer {
		// kavtov: re-send a peer message with PEER framing, mirroring
		// preparePeerMessageNode (send.go) but reusing the SAME messageID through the
		// retry-node path (a fresh SendPeerMessage would mint a new ID and escape the
		// internalCounter >= 10 loop guard above). category=peer, no device_fanout.
		applyPeerRetryAttrs(attrs, msg.wa)
	} else if !receipt.IsGroup {
		attrs["device_fanout"] = false
	}
	if participant, ok := node.Attrs["participant"]; ok {
		attrs["participant"] = participant
	}
	if recipient, ok := node.Attrs["recipient"]; ok {
		attrs["recipient"] = recipient
	}
	if edit, ok := node.Attrs["edit"]; ok {
		attrs["edit"] = edit
	}
	var content []waBinary.Node
	if msg.isPeer {
		// kavtov: peer content shape mirrors preparePeerMessageNode (send.go): a meta
		// node (appdata=default) followed by the encrypted node, plus the device identity
		// node when a prekey message was produced (includeDeviceIdentity == isPreKey).
		content = []waBinary.Node{{
			Tag:   "meta",
			Attrs: waBinary.Attrs{"appdata": "default"},
		}, *encrypted}
		if includeDeviceIdentity {
			content = append(content, cli.makeDeviceIdentityNode())
		}
	} else if msg.wa != nil {
		content = cli.getMessageContent(
			*encrypted, msg.wa, attrs, includeDeviceIdentity, nodeExtraParams{},
		)
	} else {
		content = []waBinary.Node{
			*encrypted,
			{Tag: "franking", Content: []waBinary.Node{{Tag: "franking_tag", Content: frankingTag}}},
		}
	}
	err = cli.sendNode(ctx, waBinary.Node{
		Tag:     "message",
		Attrs:   attrs,
		Content: content,
	})
	if err != nil {
		return fmt.Errorf("failed to send retry message: %w", err)
	}
	cli.Log.Debugf("Sent retry #%d for %s/%s to %s", retryCount, receipt.Chat, messageID, receipt.Sender)
	return nil
}

func (cli *Client) cancelDelayedRequestFromPhone(msgID types.MessageID) {
	if !cli.AutomaticMessageRerequestFromPhone || cli.MessengerConfig != nil {
		return
	}
	cli.pendingPhoneRerequestsLock.RLock()
	cancelPendingRequest, ok := cli.pendingPhoneRerequests[msgID]
	if ok {
		cancelPendingRequest()
	}
	cli.pendingPhoneRerequestsLock.RUnlock()
}

// RequestFromPhoneDelay specifies how long to wait for the sender to resend the message before requesting from your phone.
// This is only used if Client.AutomaticMessageRerequestFromPhone is true.
var RequestFromPhoneDelay = 5 * time.Second

func (cli *Client) delayedRequestMessageFromPhone(info *types.MessageInfo) {
	if !cli.AutomaticMessageRerequestFromPhone || cli.MessengerConfig != nil {
		return
	}
	cli.pendingPhoneRerequestsLock.Lock()
	_, alreadyRequesting := cli.pendingPhoneRerequests[info.ID]
	if alreadyRequesting {
		cli.pendingPhoneRerequestsLock.Unlock()
		return
	}
	ctx, cancel := context.WithCancel(cli.BackgroundEventCtx)
	defer cancel()
	cli.pendingPhoneRerequests[info.ID] = cancel
	cli.pendingPhoneRerequestsLock.Unlock()

	defer func() {
		cli.pendingPhoneRerequestsLock.Lock()
		delete(cli.pendingPhoneRerequests, info.ID)
		cli.pendingPhoneRerequestsLock.Unlock()
	}()
	select {
	case <-time.After(RequestFromPhoneDelay):
	case <-ctx.Done():
		cli.Log.Debugf("Cancelled delayed request for message %s from phone", info.ID)
		return
	}
	cli.immediateRequestMessageFromPhone(ctx, info)
}

func (cli *Client) immediateRequestMessageFromPhone(ctx context.Context, info *types.MessageInfo) {
	_, err := cli.SendPeerMessage(ctx, cli.BuildUnavailableMessageRequest(info.Chat, info.Sender, info.ID))
	if err != nil {
		cli.Log.Warnf("Failed to send request for unavailable message %s to phone: %v", info.ID, err)
	} else {
		cli.Log.Debugf("Requested message %s from phone", info.ID)
	}
	return
}

func (cli *Client) clearDelayedMessageRequests() {
	cli.pendingPhoneRerequestsLock.Lock()
	defer cli.pendingPhoneRerequestsLock.Unlock()
	for _, cancel := range cli.pendingPhoneRerequests {
		cancel()
	}
}

// kavtov-fork (35.2-02 D-05/D-08/D-09): bounded retry-attempt store types.

// retryAttemptKey identifies a retry by both message ID AND bare sender user (device-agnostic)
// so different senders for the same message get independent counts.
type retryAttemptKey struct {
	MsgID  string
	Sender string // info.Sender.User — bare JID user (no device suffix)
}

// retryAttemptEntry holds the per-(msgID,sender) state for the retry cap.
// Value-typed (no pointers) to stay GC-friendly per the 35.1 lesson.
// Terminal is set once to prevent duplicate SENDERKEY_TERMINAL logs (Task 2).
// slot is the entry's index in retryAttemptsList (WR-03 lockstep invariant:
// every map entry owns exactly one ring slot, and clearMessageRetrySender
// zeroes that slot when it deletes the map entry — so a cleared-then-re-added
// key can never occupy two slots, and ring eviction can never delete a LIVE
// entry through a stale slot).
type retryAttemptEntry struct {
	Count    int
	Terminal bool
	slot     int
}

// retryAttemptsListSize is the ring-buffer capacity for the retry-attempt store.
// Must equal retryStoreSKMsgSize at runtime; both are in this file.
// At ~6000 skmsg failures/hr and 3 retries per message the working set is
// ~6000 distinct (msgID,sender) keys/hr; 4096 covers ~40 minutes of the peak
// failure rate without evicting active entries mid-flight.
const retryAttemptsListSize = 4096

// retryStoreSKMsgSize is the ring capacity exposed as a var so tests can override it.
// Tests that want a smaller cap should save/restore this value.
var retryStoreSKMsgSize = retryAttemptsListSize

// recoveredMsgIDsListSize is the ring capacity for the recovered-msgID set.
// 4096 matches retryAttemptsListSize — the set tracks at most as many IDs
// as the retry-attempt store can hold at once.
const recoveredMsgIDsListSize = 4096

// recoveredMsgIDsSize is the effective ring capacity exposed as a var so tests can
// override it. Save/restore around the test when changing from the default.
var recoveredMsgIDsSize = recoveredMsgIDsListSize

// retryCapSKMsg is the number of retry receipts sent for group/sender-key class
// messages before giving up. Declared as a var (not const) so tests can override it
// (save/restore this value).
var retryCapSKMsg = 3 // default: 3 receipts per (msgID, sender) for skmsg class

// registerRetryAttempt records one retry attempt for (msgID, senderUser) and returns
// (count, proceed, logTerminal).
//   - proceed=false means the cap has been reached or content was already recovered
//     (short-circuit); no retry receipt should be sent.
//   - logTerminal=true means this is the first give-up for this (msgID, sender) and the
//     caller must emit SENDERKEY_TERMINAL. The Terminal flag is set in the entry so
//     subsequent calls return logTerminal=false (exactly-once guarantee, D-07).
//
// isSKMsg=true applies the skmsg cap (retryCapSKMsg, default 3); false applies the
// session-class cap (>=5, preserving upstream behavior — D-08).
// group is used only in the SENDERKEY_TERMINAL log (passed to caller via logTerminal).
// retryCountInMsg>0 on the first observation seeds the count to retryCountInMsg+1 (restart after
// driver restart, Pitfall 6). Lazy-init under messageRetriesLock; bare &Client{} is safe.
//
// D-06 short-circuit: for attempt #2+ (count >= 2), if the msgID is in the recovered set,
// proceed=false and logTerminal=true (contentRecovered=true for the terminal log).
// Attempt #1 is NEVER short-circuited (phone-fetch rides attempt #1 per D-06).
func (cli *Client) registerRetryAttempt(msgID string, senderUser string, group string, retryCountInMsg int, isSKMsg bool) (count int, proceed bool, logTerminal bool) {
	cli.messageRetriesLock.Lock()
	defer cli.messageRetriesLock.Unlock()

	if cli.retryAttempts == nil {
		// Lazy init: the production constructor does not pre-allocate this map; a bare
		// &Client{} (tests / direct construction) must not nil-panic.
		cli.retryAttempts = make(map[retryAttemptKey]retryAttemptEntry, retryStoreSKMsgSize)
	}

	k := retryAttemptKey{MsgID: msgID, Sender: senderUser}
	e, existed := cli.retryAttempts[k]

	if !existed {
		// New entry: evict the oldest ring slot if full (ring-map idiom).
		// ringSize caps the effective ring capacity; it may be smaller than the
		// backing array (retryAttemptsListSize) when a test overrides retryStoreSKMsgSize.
		ringSize := retryStoreSKMsgSize
		if ringSize <= 0 || ringSize > retryAttemptsListSize {
			ringSize = retryAttemptsListSize
		}
		// Evict the ring slot we are about to overwrite — after the ring has
		// wrapped once every non-sentinel slot holds a live key. WR-03: a slot
		// zeroed by clearMessageRetrySender (MsgID == "") is an empty sentinel,
		// not an occupant; and the map delete only fires when the map entry
		// actually OWNS this slot (entry.slot == ptr), so a stale slot can never
		// evict a live entry that has since moved to a different slot.
		old := cli.retryAttemptsList[cli.retryAttemptsPtr]
		if old.MsgID != "" {
			if oldEntry, ok := cli.retryAttempts[old]; ok && oldEntry.slot == cli.retryAttemptsPtr {
				delete(cli.retryAttempts, old)
			}
		}
		e.slot = cli.retryAttemptsPtr
		cli.retryAttemptsList[cli.retryAttemptsPtr] = k
		cli.retryAttemptsPtr++
		if cli.retryAttemptsPtr >= ringSize {
			cli.retryAttemptsPtr = 0
		}
	}

	e.Count++
	// In case the message is a retry response and we restarted in between, seed the
	// count from the message's embedded count (Pitfall 6: always retryCountInMsg+1).
	if e.Count == 1 && retryCountInMsg > 0 {
		e.Count = retryCountInMsg + 1
	}
	count = e.Count

	if isSKMsg {
		cap := retryCapSKMsg
		if cap <= 0 {
			cap = 3
		}
		// D-06 short-circuit: for attempt #2+ (count >= 2), check if content was already
		// recovered via phone-fetch. Attempt #1 is NEVER short-circuited (phone-fetch rides
		// attempt #1 per D-06; it also triggers the immediateRequestMessageFromPhone below).
		if count >= 2 && cli.isRecoveredMsgID(msgID) {
			// Content already arrived; no more receipts needed.
			if !e.Terminal {
				e.Terminal = true
				logTerminal = true // caller emits SENDERKEY_TERMINAL with contentRecovered=true
			}
			cli.retryAttempts[k] = e
			proceed = false
			return
		}
		proceed = count <= cap
		if !proceed && !e.Terminal {
			// First give-up for this (msgID, sender): emit exactly one terminal log.
			e.Terminal = true
			logTerminal = true // caller emits SENDERKEY_TERMINAL with contentRecovered=false
		}
	} else {
		// Session-class: preserve existing upstream behavior (D-08).
		proceed = count < 5
	}
	cli.retryAttempts[k] = e
	return
}

// recordRecoveredMsgID records a message ID as content-recovered (phone-fetch success).
// Called from handlePlaceholderResendResponse's success branch (same branch as
// placeholderResendOk.Add, so the two always agree).
// Lazy-init under recoveredMsgIDsLock; safe from bare &Client{}.
func (cli *Client) recordRecoveredMsgID(msgID string) {
	cli.recoveredMsgIDsLock.Lock()
	defer cli.recoveredMsgIDsLock.Unlock()

	if cli.recoveredMsgIDs == nil {
		// Lazy init: the production constructor does not pre-allocate this map; a bare
		// &Client{} (tests / direct construction) must not nil-panic.
		cli.recoveredMsgIDs = make(map[string]struct{}, recoveredMsgIDsSize)
	}

	if _, exists := cli.recoveredMsgIDs[msgID]; exists {
		return // already recorded; dedup without consuming a ring slot
	}

	ringSize := recoveredMsgIDsSize
	if ringSize <= 0 || ringSize > recoveredMsgIDsListSize {
		ringSize = recoveredMsgIDsListSize
	}
	// Evict the slot we are about to overwrite (ring-map idiom, same as retryAttempts).
	old := cli.recoveredMsgIDsList[cli.recoveredMsgIDsPtr]
	if old != "" {
		delete(cli.recoveredMsgIDs, old)
	}
	cli.recoveredMsgIDs[msgID] = struct{}{}
	cli.recoveredMsgIDsList[cli.recoveredMsgIDsPtr] = msgID
	cli.recoveredMsgIDsPtr++
	if cli.recoveredMsgIDsPtr >= ringSize {
		cli.recoveredMsgIDsPtr = 0
	}
}

// isRecoveredMsgID reports whether the message ID is in the recovered set.
// Read-only (does not evict); guarded by recoveredMsgIDsLock.
func (cli *Client) isRecoveredMsgID(msgID string) bool {
	cli.recoveredMsgIDsLock.Lock()
	defer cli.recoveredMsgIDsLock.Unlock()
	if cli.recoveredMsgIDs == nil {
		return false
	}
	_, ok := cli.recoveredMsgIDs[msgID]
	return ok
}

// clearMessageRetrySender removes the retry-attempt entry for (msgID, senderUser).
// Called on successful decrypt to allow a fresh retry loop if needed.
// The senderUser must be the bare JID user (info.Sender.User).
//
// WR-03 (2026-06-10): the map delete alone left the key in retryAttemptsList;
// a later re-entry for the same key inserted a SECOND ring slot, and when the
// ring pointer reached the stale first slot, delete(retryAttempts, old)
// evicted the LIVE entry — resetting the cap (up to 3 extra receipts) and
// losing the Terminal flag, so SENDERKEY_TERMINAL could double-fire for the
// same (msgID, sender) (D-07 exactly-once violation, D-04 numerator
// double-count). The ring wraps every ~40 min at peak failure rates, so this
// was live. Fix: zero the entry's ring slot (empty-key sentinel) in lockstep
// with the map delete; eviction skips sentinel slots and only deletes when the
// map entry owns the slot being recycled.
func (cli *Client) clearMessageRetrySender(msgID string, senderUser string) {
	cli.messageRetriesLock.Lock()
	defer cli.messageRetriesLock.Unlock()
	if cli.retryAttempts == nil {
		return
	}
	k := retryAttemptKey{MsgID: msgID, Sender: senderUser}
	e, ok := cli.retryAttempts[k]
	if !ok {
		return
	}
	if e.slot >= 0 && e.slot < len(cli.retryAttemptsList) && cli.retryAttemptsList[e.slot] == k {
		cli.retryAttemptsList[e.slot] = retryAttemptKey{}
	}
	delete(cli.retryAttempts, k)
}

// clearMessageRetry removes retry state for the given message ID.
// message.go:474 calls this with info.ID after a successful decrypt; info.Sender.User is
// also in scope there but the call site uses only the ID. This shim accepts an optional
// senderUser so callers that have the sender can be precise. Without senderUser it is a
// no-op (the (msgID,sender)-keyed store can't clear without the sender). The primary
// clear path is clearMessageRetrySender called from the decrypt-success site with both.
func (cli *Client) clearMessageRetry(msgID types.MessageID) {
	// No-op shim: the real clear uses clearMessageRetrySender(msgID, senderUser).
	// This stub is kept so internals.go:645 sendRetryReceipt call sites continue to compile;
	// clearMessageRetry is no longer the right clear hook (senderUser is needed).
}

// classifyRetryEnc scans a message node's children for <enc> nodes and returns
// the embedded retry count and whether the failing class is skmsg.
//
// WR-01 (2026-06-10): the previous classification required exactly one child
// (len(children) == 1 && children[0].Tag == "enc"). The node passed to
// sendRetryReceipt is the FULL message node (message.go decryptMessages error
// path), which routinely carries non-enc children (meta, verified_name,
// franking — see parseMessageInfo) and can carry multiple enc children
// (pkmsg + skmsg on group sends with an attached SKDM — the
// SENDER_KEY_MISMATCH class). Any such node misclassified a failing skmsg as
// session-class: cap 5 instead of 3, NO SENDERKEY_TERMINAL line (D-04
// permanent-loss numerator undercount), and lost retryCountInMsg
// restart-seeding.
//
// Classification rule: if ANY enc child has type=skmsg, the message is
// skmsg-class (for mixed pkmsg+skmsg the pairwise leg decrypts via the normal
// session; the leg that fails and drives the group retry loop is the
// sender-key one). retryCountInMsg is taken from the skmsg child when present,
// else from a session-class enc child (preserving the previous session-class
// seeding behavior).
func classifyRetryEnc(children []waBinary.Node) (retryCountInMsg int, isSKMsg bool) {
	for _, child := range children {
		if child.Tag != "enc" {
			continue
		}
		ag := child.AttrGetter()
		if ag.OptionalString("type") == "skmsg" {
			isSKMsg = true
			retryCountInMsg = ag.OptionalInt("count")
		} else if !isSKMsg {
			retryCountInMsg = ag.OptionalInt("count")
		}
	}
	return
}

// sendRetryReceipt sends a retry receipt for an incoming message.
func (cli *Client) sendRetryReceipt(ctx context.Context, node *waBinary.Node, info *types.MessageInfo, forceIncludeIdentity bool) {
	id, _ := node.Attrs["id"].(string)
	retryCountInMsg, isSKMsg := classifyRetryEnc(node.GetChildren())

	retryCount, proceed, logTerminal := cli.registerRetryAttempt(id, info.Sender.User, info.Chat.String(), retryCountInMsg, isSKMsg)
	if !proceed {
		if logTerminal && isSKMsg {
			// D-07: SENDERKEY_TERMINAL is the permanent-loss numerator for D-04 measurement.
			// Tag string and key names are load-bearing for the journalctl grep in plan 35.2-07;
			// do not rename them.
			// Known accepted gap (RESEARCH Open Question 2): a message whose sender never re-sends
			// produces no attempt #2+ and therefore no terminal line; the D-04 journalctl
			// decrypt-fail leg catches those. A timer sweep is intentionally NOT added.
			contentRecovered := cli.isRecoveredMsgID(id)
			cli.Log.Warnf("SENDERKEY_TERMINAL msgID=%s sender=%s group=%s retries=%d contentRecovered=%t",
				id, info.Sender.User, info.Chat.String(), retryCount, contentRecovered)
		} else if !isSKMsg {
			cli.Log.Warnf("Not sending any more retry receipts for %s", id)
		}
		return
	}
	if retryCount == 1 {
		// forceIncludeIdentity marks the "can't decrypt, must re-fetch" failures (dominated by
		// group no-sender-key, where the key is permanently lost). For those the message never
		// arrives on its own, so the RequestFromPhoneDelay (5s) is pure latency before the phone
		// request fires anyway — fetch immediately to cut ride-alert latency. Same request count,
		// just sooner. Transient cases (negligible volume) also fetch immediately, which is fine.
		//
		// kavtov-fork (38.5): ask-once gate — for group decrypt-fails, only one managed
		// account sends the phone-fetch request per (group, message). The first account
		// to TryClaim wins; others skip. If nil (gate disabled), fires unconditionally.
		//
		// 2026-06-30 incident: master-gate the phone-fetch behind AutomaticMessageRerequestFromPhone
		// (previously unconditional for groups). The group phone-fetch storm (~34.7k/day) correlated
		// with WhatsApp 401 device_removed companion removals + up-to-60s ride-alert latency. With the
		// flag off (KAVTOV_PHONE_REREQUEST unset) NO phone-fetch fires; the standard retry receipt
		// (sender resend) below is unaffected.
		doPhoneRequest := cli.AutomaticMessageRerequestFromPhone
		if doPhoneRequest && info.IsGroup && cli.PhoneRequestClaims != nil {
			doPhoneRequest = cli.PhoneRequestClaims.TryClaim(info.Chat.String(), info.ID)
		}
		if doPhoneRequest {
			if cli.SynchronousAck || forceIncludeIdentity {
				cli.immediateRequestMessageFromPhone(ctx, info)
			} else {
				go cli.delayedRequestMessageFromPhone(info)
			}
		}
	}
	// kavtov-fork (38.5): blacklist gate — for group messages from a bot that has
	// accumulated >= botResendBlacklistThreshold cumulative decrypt fails, skip the
	// resend-request stanza (GenOnePreKey + sendNode). The ack (caller) and the
	// phone request (above) are unaffected.
	if info.IsGroup && cli.isBotResendBlacklisted(info.Chat.String(), info.Sender.User) {
		return
	}

	var registrationIDBytes [4]byte
	binary.BigEndian.PutUint32(registrationIDBytes[:], cli.Store.RegistrationID)
	attrs := buildBaseReceipt(info.ID, node)
	attrs["type"] = "retry"
	if info.Type == "peer_msg" && info.IsFromMe {
		attrs["category"] = "peer"
	}
	payload := waBinary.Node{
		Tag:   "receipt",
		Attrs: attrs,
		Content: []waBinary.Node{
			{Tag: "retry", Attrs: waBinary.Attrs{
				"count": retryCount,
				"id":    id,
				"t":     node.Attrs["t"],
				"v":     1,
				// error="0" matches Baileys/WA-Web's inner <retry> node (messages-recv.ts);
				// upstream whatsmeow omits it. Likely a no-op (the sender reads only count),
				// but the cleanest low-risk content variant the deployed SKDM instrument can measure.
				"error": "0",
			}},
			{Tag: "registration", Content: registrationIDBytes[:]},
		},
	}
	// kavtov-fork (quick-260705-ill): prekey gate conformance. WA Web
	// (WAWebSendRetryReceiptJob.js:6 module constant d = 2, gate at :110 `e >= d`) attaches the
	// <keys> identity+prekey bundle only at retryCount>=2. This fork previously forced the bundle
	// onto attempt 1 for group no-sender-key misses via forceIncludeIdentity -- the suspected
	// WhatsApp 401/403 companion-removal fingerprint. Per the group-retry gap analysis
	// (wa_protocol WA-SKDM-GRPRETRY-001 / retry-receipt-protocol.md "Prekey gate"): the sender's
	// honor/drop decision is hasDevice-based and the group retry carries no
	// sender-key-redistribution request, so attempt-1 keys have unproven recovery value for the
	// group-miss class while being the anomalous fingerprint. The pairwise (non-skmsg)
	// forceIncludeIdentity path is deliberately preserved (low volume; genuine
	// session-establishment recovery need) -- a conscious, scoped deviation from strict conformance.
	if retryCount > 1 || (forceIncludeIdentity && !isSKMsg) {
		if key, err := cli.Store.PreKeys.GenOnePreKey(ctx); err != nil {
			cli.Log.Errorf("Failed to get prekey for retry receipt: %v", err)
		} else if deviceIdentity, err := proto.Marshal(cli.Store.Account); err != nil {
			cli.Log.Errorf("Failed to marshal account info: %v", err)
			return
		} else {
			payload.Content = append(payload.GetChildren(), waBinary.Node{
				Tag: "keys",
				Content: []waBinary.Node{
					{Tag: "type", Content: []byte{ecc.DjbType}},
					{Tag: "identity", Content: cli.Store.IdentityKey.Pub[:]},
					preKeyToNode(key),
					preKeyToNode(cli.Store.SignedPreKey),
					{Tag: "device-identity", Content: deviceIdentity},
				},
			})
		}
	}
	err := cli.sendNode(ctx, payload)
	if err != nil {
		cli.Log.Errorf("Failed to send retry receipt for %s: %v", id, err)
	} else {
		cli.Log.Infof("Sent retry receipt for message %s from %s (attempt %d, forceIncludeIdentity=%v)", id, info.SourceString(), retryCount, forceIncludeIdentity)
	}
}
