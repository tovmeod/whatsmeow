// Copyright (c) 2021 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package whatsmeow

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/libsignal/groups"
	"go.mau.fi/libsignal/protocol"
	"go.mau.fi/libsignal/session"
	"go.mau.fi/libsignal/signalerror"
	"go.mau.fi/util/random"
	"google.golang.org/protobuf/proto"

	"go.mau.fi/whatsmeow/appstate"
	waBinary "go.mau.fi/whatsmeow/binary"
	"go.mau.fi/whatsmeow/proto/waE2E"
	"go.mau.fi/whatsmeow/proto/waHistorySync"
	"go.mau.fi/whatsmeow/proto/waLidMigrationSyncPayload"
	"go.mau.fi/whatsmeow/proto/waWeb"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/types/events"
	"go.mau.fi/whatsmeow/util/walltime"
)

var pbSerializer = store.SignalProtobufSerializer

func (cli *Client) handleEncryptedMessage(ctx context.Context, node *waBinary.Node) {
	info, err := cli.parseMessageInfo(node)
	if err != nil {
		cli.Log.Warnf("Failed to parse message: %v", err)
	} else {
		if !info.SenderAlt.IsEmpty() {
			cli.StoreLIDPNMapping(ctx, info.SenderAlt, info.Sender)
		} else if !info.RecipientAlt.IsEmpty() {
			cli.StoreLIDPNMapping(ctx, info.RecipientAlt, info.Chat)
		}
		if info.VerifiedName != nil && len(info.VerifiedName.Details.GetVerifiedName()) > 0 {
			go cli.updateBusinessName(ctx, info.Sender, info.SenderAlt, info, info.VerifiedName.Details.GetVerifiedName())
		}
		if len(info.PushName) > 0 && info.PushName != "-" && (cli.MessengerConfig == nil || info.PushName != "username") {
			go cli.updatePushName(ctx, info.Sender, info.SenderAlt, info, info.PushName)
		}
		if info.Sender.Server == types.NewsletterServer {
			var cancelled bool
			defer cli.maybeDeferredAck(ctx, node)(&cancelled)
			cancelled = cli.handlePlaintextMessage(ctx, info, node)
		} else {
			cli.decryptMessages(ctx, info, node)
		}
	}
}

func (cli *Client) parseMessageSource(node *waBinary.Node, requireParticipant bool) (source types.MessageSource, err error) {
	clientID := cli.getOwnID()
	clientLID := cli.getOwnLID()
	if clientID.IsEmpty() {
		err = ErrNotLoggedIn
		return
	}
	ag := node.AttrGetter()
	from := ag.JID("from")
	source.AddressingMode = types.AddressingMode(ag.OptionalString("addressing_mode"))
	if from.Server == types.GroupServer || from.Server == types.BroadcastServer {
		source.IsGroup = true
		source.Chat = from
		if requireParticipant {
			source.Sender = ag.JID("participant")
		} else {
			source.Sender = ag.OptionalJIDOrEmpty("participant")
		}
		if source.AddressingMode == types.AddressingModeLID {
			source.SenderAlt = ag.OptionalJIDOrEmpty("participant_pn")
		} else {
			source.SenderAlt = ag.OptionalJIDOrEmpty("participant_lid")
		}
		if source.Sender.User == clientID.User || source.Sender.User == clientLID.User {
			source.IsFromMe = true
		}
		if from.Server == types.BroadcastServer {
			source.BroadcastListOwner = ag.OptionalJIDOrEmpty("recipient")
			participants, ok := node.GetOptionalChildByTag("participants")
			if ok && source.IsFromMe {
				children := participants.GetChildren()
				source.BroadcastRecipients = make([]types.BroadcastRecipient, 0, len(children))
				for _, child := range children {
					if child.Tag != "to" {
						continue
					}
					cag := child.AttrGetter()
					mainJID := cag.JID("jid")
					if mainJID.Server == types.HiddenUserServer {
						source.BroadcastRecipients = append(source.BroadcastRecipients, types.BroadcastRecipient{
							LID: mainJID,
							PN:  cag.OptionalJIDOrEmpty("peer_recipient_pn"),
						})
					} else {
						source.BroadcastRecipients = append(source.BroadcastRecipients, types.BroadcastRecipient{
							LID: cag.OptionalJIDOrEmpty("peer_recipient_lid"),
							PN:  mainJID,
						})
					}
				}
			}
		}
	} else if from.Server == types.NewsletterServer {
		source.Chat = from
		source.Sender = from
		// TODO IsFromMe?
	} else if from.User == clientID.User || from.User == clientLID.User {
		if from.Server == types.HostedServer {
			from.Server = types.DefaultUserServer
		} else if from.Server == types.HostedLIDServer {
			from.Server = types.HiddenUserServer
		}
		source.IsFromMe = true
		source.Sender = from
		recipient := ag.OptionalJID("recipient")
		if recipient != nil {
			source.Chat = *recipient
		} else {
			source.Chat = from.ToNonAD()
		}
		if source.Chat.Server == types.HiddenUserServer || source.Chat.Server == types.HostedLIDServer {
			source.RecipientAlt = ag.OptionalJIDOrEmpty("peer_recipient_pn")
		} else {
			source.RecipientAlt = ag.OptionalJIDOrEmpty("peer_recipient_lid")
		}
	} else if from.IsBot() {
		source.Sender = from
		meta := node.GetChildByTag("meta")
		ag = meta.AttrGetter()
		targetChatJID := ag.OptionalJID("target_chat_jid")
		if targetChatJID != nil {
			source.Chat = targetChatJID.ToNonAD()
		} else {
			source.Chat = from
		}
	} else {
		if from.Server == types.HostedServer {
			from.Server = types.DefaultUserServer
		} else if from.Server == types.HostedLIDServer {
			from.Server = types.HiddenUserServer
		}
		source.Chat = from.ToNonAD()
		source.Sender = from
		if source.Sender.Server == types.HiddenUserServer || source.Chat.Server == types.HostedLIDServer {
			source.SenderAlt = ag.OptionalJIDOrEmpty("sender_pn")
		} else {
			source.SenderAlt = ag.OptionalJIDOrEmpty("sender_lid")
		}
	}
	if !source.SenderAlt.IsEmpty() && source.SenderAlt.Device == 0 {
		source.SenderAlt.Device = source.Sender.Device
	}
	err = ag.Error()
	return
}

func (cli *Client) parseMsgBotInfo(node waBinary.Node) (botInfo types.MsgBotInfo, err error) {
	botNode := node.GetChildByTag("bot")

	ag := botNode.AttrGetter()
	botInfo.EditType = types.BotEditType(ag.String("edit"))
	if botInfo.EditType == types.EditTypeInner || botInfo.EditType == types.EditTypeLast {
		botInfo.EditTargetID = types.MessageID(ag.String("edit_target_id"))
		botInfo.EditSenderTimestampMS = ag.UnixMilli("sender_timestamp_ms")
	}
	err = ag.Error()
	return
}

func (cli *Client) parseMsgMetaInfo(node waBinary.Node) (metaInfo types.MsgMetaInfo, err error) {
	metaNode := node.GetChildByTag("meta")

	ag := metaNode.AttrGetter()
	metaInfo.TargetID = types.MessageID(ag.OptionalString("target_id"))
	metaInfo.TargetSender = ag.OptionalJIDOrEmpty("target_sender_jid")
	metaInfo.TargetChat = ag.OptionalJIDOrEmpty("target_chat_jid")
	deprecatedLIDSession, ok := ag.GetBool("deprecated_lid_session", false)
	if ok {
		metaInfo.DeprecatedLIDSession = &deprecatedLIDSession
	}
	metaInfo.ThreadMessageID = types.MessageID(ag.OptionalString("thread_msg_id"))
	metaInfo.ThreadMessageSenderJID = ag.OptionalJIDOrEmpty("thread_msg_sender_jid")
	err = ag.Error()
	return
}

func (cli *Client) parseMessageInfo(node *waBinary.Node) (*types.MessageInfo, error) {
	var info types.MessageInfo
	var err error
	info.MessageSource, err = cli.parseMessageSource(node, true)
	if err != nil {
		return nil, err
	}
	ag := node.AttrGetter()
	info.ID = types.MessageID(ag.String("id"))
	info.ServerID = types.MessageServerID(ag.OptionalInt("server_id"))
	info.Timestamp = ag.UnixTime("t")
	info.PushName = ag.OptionalString("notify")
	info.Category = ag.OptionalString("category")
	info.Type = ag.OptionalString("type")
	info.Edit = types.EditAttribute(ag.OptionalString("edit"))
	if !ag.OK() {
		return nil, ag.Error()
	}

	for _, child := range node.GetChildren() {
		switch child.Tag {
		case "multicast":
			info.Multicast = true
		case "verified_name":
			info.VerifiedName, err = parseVerifiedNameContent(child)
			if err != nil {
				cli.Log.Warnf("Failed to parse verified_name node in %s: %v", info.ID, err)
			}
		case "bot":
			info.MsgBotInfo, err = cli.parseMsgBotInfo(child)
			if err != nil {
				cli.Log.Warnf("Failed to parse <bot> node in %s: %v", info.ID, err)
			}
		case "meta":
			info.MsgMetaInfo, err = cli.parseMsgMetaInfo(child)
			if err != nil {
				cli.Log.Warnf("Failed to parse <meta> node in %s: %v", info.ID, err)
			}
		case "franking":
			// TODO
		case "trace":
			// TODO
		default:
			if mediaType, ok := child.AttrGetter().GetString("mediatype", false); ok {
				info.MediaType = mediaType
			}
		}
	}

	return &info, nil
}

func (cli *Client) handlePlaintextMessage(ctx context.Context, info *types.MessageInfo, node *waBinary.Node) (handlerFailed bool) {
	// TODO edits have an additional <meta msg_edit_t="1696321271735" original_msg_t="1696321248"/> node
	plaintext, ok := node.GetOptionalChildByTag("plaintext")
	if !ok {
		// 3:
		return
	}
	plaintextBody, ok := plaintext.Content.([]byte)
	if !ok {
		cli.Log.Warnf("Plaintext message from %s doesn't have byte content", info.SourceString())
		return
	}

	var msg waE2E.Message
	err := proto.Unmarshal(plaintextBody, &msg)
	if err != nil {
		cli.Log.Warnf("Error unmarshaling plaintext message from %s: %v", info.SourceString(), err)
		return
	}
	cli.storeMessageSecret(ctx, info, &msg)
	evt := &events.Message{
		Info:       *info,
		RawMessage: &msg,
	}
	meta, ok := node.GetOptionalChildByTag("meta")
	if ok {
		evt.NewsletterMeta = &events.NewsletterMessageMeta{
			EditTS:     meta.AttrGetter().UnixMilli("msg_edit_t"),
			OriginalTS: meta.AttrGetter().UnixTime("original_msg_t"),
		}
	}
	return cli.dispatchEvent(evt.UnwrapRaw())
}

func (cli *Client) migrateSessionStore(ctx context.Context, pn, lid types.JID) {
	err := cli.Store.Sessions.MigratePNToLID(ctx, pn, lid)
	if err != nil {
		cli.Log.Errorf("Failed to migrate signal store from %s to %s: %v", pn, lid, err)
	}
}

func (cli *Client) decryptMessages(ctx context.Context, info *types.MessageInfo, node *waBinary.Node) {
	// Phase 17.5.1-04: per-message wall-time observation covers every
	// exit path (unavailable early-return, success-path ack, error
	// returns, panics). Quantiles surface alongside cache metrics in
	// store/sqlstore.cache_wiring.go emitMetricsLoop every 5 minutes.
	// kavtov-fork: Phase 17.5.3 DEFER-01 fix — wrap in closure so time.Since
	// evaluates when the deferred call RUNS (function exit), not at defer-setup.
	// Previously: defer walltime.DecryptHistogram.Observe(time.Since(start)) — this
	// evaluated time.Since(start) eagerly at the defer statement (nanoseconds
	// after function entry), making every observation near-zero and the entire
	// p50/p95/p99 metric meaningless garbage.
	start := time.Now()
	defer func() { walltime.DecryptHistogram.Observe(time.Since(start)) }()
	unavailableNode, ok := node.GetOptionalChildByTag("unavailable")
	if ok && len(node.GetChildrenByTag("enc")) == 0 {
		uType := events.UnavailableType(unavailableNode.AttrGetter().String("type"))
		cli.Log.Warnf("Unavailable message %s from %s (type: %q)", info.ID, info.SourceString(), uType)
		cli.backgroundIfAsyncAck(func() {
			cli.immediateRequestMessageFromPhone(ctx, info)
			cli.sendAck(ctx, node, 0)
		})
		cli.dispatchEvent(&events.UndecryptableMessage{Info: *info, IsUnavailable: true, UnavailableType: uType})
		return
	}

	children := node.GetChildren()
	cli.Log.Debugf("Decrypting message from %s", info.SourceString())
	containsDirectMsg := false
	senderEncryptionJID := info.Sender
	if info.Sender.Server == types.DefaultUserServer && !info.Sender.IsBot() {
		if info.SenderAlt.Server == types.HiddenUserServer {
			senderEncryptionJID = info.SenderAlt
			cli.migrateSessionStore(ctx, info.Sender, info.SenderAlt)
		} else if lid, err := cli.Store.LIDs.GetLIDForPN(ctx, info.Sender); err != nil {
			cli.Log.Errorf("Failed to get LID for %s: %v", info.Sender, err)
		} else if !lid.IsEmpty() {
			cli.migrateSessionStore(ctx, info.Sender, lid)
			senderEncryptionJID = lid
			info.SenderAlt = lid
		} else {
			cli.Log.Warnf("No LID found for %s", info.Sender)
		}
	}
	// D-CACHE-06: DECRYPT no longer prefetches via a context-scope session
	// cache — the CachedSessionStore wrapper (wired into device.Sessions
	// by sqlstore.Container.initializeDevice) now serves session reads
	// from a process-shared LRU.
	//
	// Phase 17.5 FIX: the prior ack-after-flush gate (an anonymous-interface
	// type-assertion against the session-store flush method, formerly
	// inserted just before the success-path ack) was removed along with the
	// write-back machinery in cached_session_store.go. The wrapper is now a
	// strict write-through cache: every PutSession returns only after the
	// inner store has acknowledged the write, so there is no "pending dirty
	// state" to drain before acking. D-CACHE-03 is trivially satisfied by
	// the synchronous write contract.
	var recognizedStanza, protobufFailed bool
	var encTypes []string
	for _, child := range children {
		if child.Tag != "enc" {
			continue
		}
		recognizedStanza = true
		ag := child.AttrGetter()
		encType, ok := ag.GetString("type", false)
		if !ok {
			continue
		}
		encTypes = append(encTypes, encType)
		var decrypted []byte
		var ciphertextHash *[32]byte
		var err error
		if encType == "pkmsg" || encType == "msg" {
			decrypted, ciphertextHash, err = cli.decryptDM(ctx, &child, senderEncryptionJID, encType == "pkmsg", info.Timestamp)
			containsDirectMsg = true
		} else if info.IsGroup && encType == "skmsg" {
			decrypted, ciphertextHash, err = cli.decryptGroupMsg(ctx, &child, senderEncryptionJID, info.Chat, info.Timestamp)
		} else if encType == "msmsg" && info.Sender.IsBot() {
			targetSenderJID := info.MsgMetaInfo.TargetSender
			if targetSenderJID.User == "" {
				if info.Sender.Server == types.BotServer {
					targetSenderJID = cli.getOwnLID()
				} else {
					targetSenderJID = cli.getOwnID()
				}
			}
			var decryptMessageID string
			if info.MsgBotInfo.EditType == types.EditTypeInner || info.MsgBotInfo.EditType == types.EditTypeLast {
				decryptMessageID = info.MsgBotInfo.EditTargetID
			} else {
				decryptMessageID = info.ID
			}
			var msMsg waE2E.MessageSecretMessage
			var messageSecret []byte
			if messageSecret, _, err = cli.Store.MsgSecrets.GetMessageSecret(ctx, info.Chat, targetSenderJID, info.MsgMetaInfo.TargetID); err != nil {
				err = fmt.Errorf("failed to get message secret for %s: %v", info.MsgMetaInfo.TargetID, err)
			} else if messageSecret == nil {
				err = fmt.Errorf("message secret for %s not found", info.MsgMetaInfo.TargetID)
			} else if err = proto.Unmarshal(child.Content.([]byte), &msMsg); err != nil {
				err = fmt.Errorf("failed to unmarshal MessageSecretMessage protobuf: %v", err)
			} else {
				decrypted, err = cli.decryptBotMessage(ctx, messageSecret, &msMsg, decryptMessageID, targetSenderJID, info)
			}
		} else {
			cli.Log.Warnf("Unhandled encrypted message (type %s) from %s", encType, info.SourceString())
			continue
		}

		if errors.Is(err, EventAlreadyProcessed) {
			cli.Log.Debugf("Ignoring message %s from %s: %v", info.ID, info.SourceString(), err)
			continue
		} else if errors.Is(err, signalerror.ErrOldCounter) {
			cli.Log.Warnf("Ignoring message %s from %s: %v", info.ID, info.SourceString(), err)
			continue
		} else if err != nil {
			cli.Log.Warnf("Error decrypting message %s from %s (encTypes=%v, containsDirectMsg=%v): %v", info.ID, info.SourceString(), encTypes, containsDirectMsg, err)
			if ctx.Err() != nil || errors.Is(err, context.Canceled) {
				return
			}
			// Force include identity (our prekeys) in retry when:
			// 1. No sender key for group decryption (need SKDM)
			// 2. No session for pairwise decryption
			// 3. Sender used an old/invalid prekey ID (critical after data loss/recovery)
			// 4. No valid sessions (session exists but chain state is invalid)
			// 5. Sender key state mismatch (have sender key but wrong chain iteration)
			isUnavailable := (encType == "skmsg" && errors.Is(err, signalerror.ErrNoSenderKeyForUser)) ||
				(encType == "skmsg" && errors.Is(err, signalerror.ErrNoSenderKeyStateForID)) ||
				errors.Is(err, signalerror.ErrNoSessionForUser) ||
				errors.Is(err, signalerror.ErrNoValidSessions) ||
				errors.Is(err, signalerror.ErrNoOneTimeKeyFound)
			// Log senders that haven't distributed SKDM to us yet
			if encType == "skmsg" && errors.Is(err, signalerror.ErrNoSenderKeyForUser) {
				cli.Log.Debugf("SENDER_NEEDS_SESSION: sender=%s group=%s containsDirectMsg=%v - sender has not distributed SKDM to us yet", senderEncryptionJID.String(), info.Chat.String(), containsDirectMsg)
			}
			// Log sender key state mismatch for diagnostics
			if encType == "skmsg" && errors.Is(err, signalerror.ErrNoSenderKeyStateForID) {
				cli.Log.Warnf("SENDER_KEY_MISMATCH: sender=%s group=%s containsDirectMsg=%v error=%v", senderEncryptionJID.String(), info.Chat.String(), containsDirectMsg, err)
			}
			// Log stale prekey ID errors - sender has cached old prekey, retry with fresh prekeys should fix
			if errors.Is(err, signalerror.ErrNoOneTimeKeyFound) {
				cli.Log.Warnf("STALE_PREKEY: sender=%s - sender used old prekey ID, sending retry with fresh prekeys", senderEncryptionJID.String())
			}
			if encType == "msmsg" {
				cli.backgroundIfAsyncAck(func() {
					cli.sendAck(ctx, node, NackMissingMessageSecret)
				})
			} else if cli.SynchronousAck {
				cli.sendRetryReceipt(ctx, node, info, isUnavailable)
				// TODO this probably isn't supposed to ack
				cli.sendAck(ctx, node, 0)
				// Proactively establish session for pairwise session errors
				if errors.Is(err, signalerror.ErrNoSessionForUser) {
					go cli.establishSessionWithSender(context.WithoutCancel(ctx), senderEncryptionJID)
				}
			} else {
				go cli.sendRetryReceipt(context.WithoutCancel(ctx), node, info, isUnavailable)
				go cli.sendAck(ctx, node, 0)
				// Proactively establish session for pairwise session errors
				if errors.Is(err, signalerror.ErrNoSessionForUser) {
					go cli.establishSessionWithSender(context.WithoutCancel(ctx), senderEncryptionJID)
				}
			}
			cli.dispatchEvent(&events.UndecryptableMessage{
				Info:            *info,
				IsUnavailable:   isUnavailable,
				DecryptFailMode: events.DecryptFailMode(ag.OptionalString("decrypt-fail")),
			})
			return
		}
		retryCount := ag.OptionalInt("count")
		cli.cancelDelayedRequestFromPhone(info.ID)
		cli.clearMessageRetry(info.ID)

		var msg waE2E.Message
		var handlerFailed bool
		switch ag.Int("v") {
		case 2:
			err = proto.Unmarshal(decrypted, &msg)
			if err != nil {
				cli.Log.Warnf("Error unmarshaling decrypted message from %s: %v", info.SourceString(), err)
				protobufFailed = true
				continue
			}
			protobufFailed = false
			handlerFailed = cli.handleDecryptedMessage(ctx, info, &msg, retryCount)
		case 3:
			handlerFailed, protobufFailed = cli.handleDecryptedArmadillo(ctx, info, decrypted, retryCount)
		default:
			cli.Log.Warnf("Unknown version %d in decrypted message from %s", ag.Int("v"), info.SourceString())
		}
		if handlerFailed {
			cli.Log.Warnf("Handler for %s failed", info.ID)
			return
		}
		if ciphertextHash != nil && cli.EnableDecryptedEventBuffer {
			// Use the context passed to decryptMessages
			err = cli.Store.EventBuffer.ClearBufferedEventPlaintext(ctx, *ciphertextHash)
			if err != nil {
				zerolog.Ctx(ctx).Err(err).
					Hex("ciphertext_hash", ciphertextHash[:]).
					Str("message_id", info.ID).
					Msg("Failed to clear buffered event plaintext")
			} else {
				zerolog.Ctx(ctx).Debug().
					Hex("ciphertext_hash", ciphertextHash[:]).
					Str("message_id", info.ID).
					Msg("Deleted event plaintext from buffer")
			}

			if time.Since(cli.lastDecryptedBufferClear) > 12*time.Hour && ctx.Err() == nil {
				cli.lastDecryptedBufferClear = time.Now()
				go func() {
					err := cli.Store.EventBuffer.DeleteOldBufferedHashes(context.WithoutCancel(ctx))
					if err != nil {
						zerolog.Ctx(ctx).Err(err).Msg("Failed to delete old buffered hashes")
					}
				}()
			}
		}
	}
	cli.backgroundIfAsyncAck(func() {
		if !recognizedStanza {
			cli.sendAck(ctx, node, NackUnrecognizedStanza)
		} else if protobufFailed {
			cli.sendAck(ctx, node, NackInvalidProtobuf)
		} else {
			cli.sendMessageReceipt(ctx, info, node)
		}
	})
	return
}

func (cli *Client) clearUntrustedIdentity(ctx context.Context, target types.JID) error {
	err := cli.Store.Identities.DeleteIdentity(ctx, target.SignalAddress().String())
	if err != nil {
		return fmt.Errorf("failed to delete identity: %w", err)
	}
	err = cli.Store.Sessions.DeleteSession(ctx, target.SignalAddress().String())
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}
	go cli.dispatchEvent(&events.IdentityChange{JID: target, Timestamp: time.Now(), Implicit: true})
	return nil
}

var EventAlreadyProcessed = errors.New("event was already processed")

func (cli *Client) bufferedDecrypt(
	ctx context.Context,
	ciphertext []byte,
	serverTimestamp time.Time,
	decrypt func(context.Context) ([]byte, error),
	extraHashData ...string,
) (plaintext []byte, ciphertextHash [32]byte, err error) {
	if !cli.EnableDecryptedEventBuffer {
		plaintext, err = decrypt(ctx)
		return
	}
	hasher := sha256.New()
	hasher.Write(ciphertext)
	for _, part := range extraHashData {
		hasher.Write([]byte{0})
		hasher.Write([]byte(part))
	}
	hasher.Write([]byte{0, 0})
	ciphertextHash = *(*[32]byte)(hasher.Sum(nil))
	var buf *store.BufferedEvent
	buf, err = cli.Store.EventBuffer.GetBufferedEvent(ctx, ciphertextHash)
	if err != nil {
		err = fmt.Errorf("failed to get buffered event: %w", err)
		return
	} else if buf != nil {
		if buf.Plaintext == nil {
			zerolog.Ctx(ctx).Debug().
				Hex("ciphertext_hash", ciphertextHash[:]).
				Time("insertion_time", buf.InsertTime).
				Msg("Returning event already processed error")
			err = fmt.Errorf("%w at %s", EventAlreadyProcessed, buf.InsertTime.String())
			return
		}
		zerolog.Ctx(ctx).Debug().
			Hex("ciphertext_hash", ciphertextHash[:]).
			Time("insertion_time", buf.InsertTime).
			Msg("Returning previously decrypted plaintext")
		plaintext = buf.Plaintext
		return
	}

	err = cli.Store.EventBuffer.DoDecryptionTxn(ctx, func(ctx context.Context) (innerErr error) {
		plaintext, innerErr = decrypt(ctx)
		if innerErr != nil {
			return
		}
		innerErr = cli.Store.EventBuffer.PutBufferedEvent(ctx, ciphertextHash, plaintext, serverTimestamp)
		if innerErr != nil {
			innerErr = fmt.Errorf("failed to save decrypted event to buffer: %w", innerErr)
		}
		return
	})
	if err == nil {
		zerolog.Ctx(ctx).Debug().
			Hex("ciphertext_hash", ciphertextHash[:]).
			Msg("Successfully decrypted and saved event")
	}
	return
}

func (cli *Client) decryptDM(ctx context.Context, child *waBinary.Node, from types.JID, isPreKey bool, serverTS time.Time) ([]byte, *[32]byte, error) {
	content, ok := child.Content.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("message content is not a byte slice")
	}

	builder := session.NewBuilderFromSignal(cli.Store, from.SignalAddress(), pbSerializer)
	cipher := session.NewCipher(builder, from.SignalAddress())
	var plaintext []byte
	var ciphertextHash [32]byte
	if isPreKey {
		preKeyMsg, err := protocol.NewPreKeySignalMessageFromBytes(content, pbSerializer.PreKeySignalMessage, pbSerializer.SignalMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse prekey message: %w", err)
		}
		plaintext, ciphertextHash, err = cli.bufferedDecrypt(ctx, content, serverTS, func(decryptCtx context.Context) ([]byte, error) {
			pt, innerErr := cipher.DecryptMessage(decryptCtx, preKeyMsg)
			if cli.AutoTrustIdentity && errors.Is(innerErr, signalerror.ErrUntrustedIdentity) {
				cli.Log.Warnf("Got %v error while trying to decrypt prekey message from %s, clearing stored identity and retrying", innerErr, from)
				if innerErr = cli.clearUntrustedIdentity(decryptCtx, from); innerErr != nil {
					innerErr = fmt.Errorf("failed to clear untrusted identity: %w", innerErr)
					return nil, innerErr
				}
				pt, innerErr = cipher.DecryptMessage(decryptCtx, preKeyMsg)
			}
			return pt, innerErr
		}, "prekey", from.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt prekey message: %w", err)
		}
	} else {
		msg, err := protocol.NewSignalMessageFromBytes(content, pbSerializer.SignalMessage)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse normal message: %w", err)
		}
		plaintext, ciphertextHash, err = cli.bufferedDecrypt(ctx, content, serverTS, func(decryptCtx context.Context) ([]byte, error) {
			return cipher.Decrypt(decryptCtx, msg)
		}, "normal", from.String())
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt normal message: %w", err)
		}
	}
	var err error
	plaintext, err = unpadMessage(plaintext, child.AttrGetter().Int("v"))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to unpad message: %w", err)
	}
	return plaintext, &ciphertextHash, nil
}

func (cli *Client) decryptGroupMsg(ctx context.Context, child *waBinary.Node, from types.JID, chat types.JID, serverTS time.Time) ([]byte, *[32]byte, error) {
	content, ok := child.Content.([]byte)
	if !ok {
		return nil, nil, fmt.Errorf("message content is not a byte slice")
	}

	msg, err := protocol.NewSenderKeyMessageFromBytes(content, pbSerializer.SenderKeyMessage)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse group message: %w", err)
	}
	// kavtov-fork: Phase 27 — device-tolerant group sender-key lookup. WhatsApp delivers the SKDM
	// and the skmsg with inconsistent device numbers for the same sender key; the message keyID
	// (not the device label) identifies the key. decryptGroupSenderKey tries the sender's stored
	// device-qualified records (labeled device first) and lets GroupCipher select the state by
	// keyID + verify the signature (a wrong candidate fails closed). Each candidate decrypts under
	// its own address, so the ratchet writes back to the correct record. No :0 normalization, no merge.
	plaintext, ciphertextHash, err := cli.bufferedDecrypt(ctx, content, serverTS, func(decryptCtx context.Context) ([]byte, error) {
		return cli.decryptGroupSenderKey(decryptCtx, chat, from, msg)
	}, "senderkey", chat.String(), from.String())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decrypt group message: %w", err)
	}
	plaintext, err = unpadMessage(plaintext, child.AttrGetter().Int("v"))
	if err != nil {
		return nil, nil, err
	}
	return plaintext, &ciphertextHash, nil
}

// decryptGroupSenderKey performs the Phase-27 device-tolerant group sender-key lookup. It
// enumerates the sender's stored device-qualified records for the group (a cache-served call —
// see CachedSenderKeyStore) and attempts decryption against each, trying the labeled device first.
// libsignal's GroupCipher selects the key state by the message keyID and verifies the signature,
// so a wrong candidate fails closed (never a mis-decrypt); the winning candidate's ratchet is
// written back to its own device record by GroupCipher.Decrypt. There is no error-class branching:
// we try every stored device for the sender and let the keyID pick. Returns ErrNoSenderKeyForUser
// when no stored device record decrypts the message (so the retry-receipt path is unchanged).
func (cli *Client) decryptGroupSenderKey(ctx context.Context, chat, from types.JID, msg *protocol.SenderKeyMessage) ([]byte, error) {
	devices, err := cli.Store.SenderKeys.GetSenderKeyDevices(ctx, chat.String(), from.SignalAddressUser())
	if err != nil {
		return nil, fmt.Errorf("failed to enumerate sender-key devices: %w", err)
	}
	// Try the labeled device first (the common case), then the remaining devices.
	labeled := from.SignalAddress().String()
	ordered := make([]string, 0, len(devices))
	for _, sid := range devices {
		if sid == labeled {
			ordered = append(ordered, sid)
		}
	}
	for _, sid := range devices {
		if sid != labeled {
			ordered = append(ordered, sid)
		}
	}
	for _, sid := range ordered {
		sep := strings.LastIndex(sid, ":")
		if sep < 0 {
			cli.Log.Debugf("Skipping malformed sender-key id %q (no colon separator)", sid)
			continue
		}
		devID, parseErr := strconv.ParseUint(sid[sep+1:], 10, 32)
		if parseErr != nil {
			cli.Log.Debugf("Skipping malformed sender-key id %q (bad device id: %v)", sid, parseErr)
			continue
		}
		name := protocol.NewSenderKeyName(chat.String(), protocol.NewSignalAddress(sid[:sep], uint32(devID)))
		cipher := groups.NewGroupCipher(groups.NewGroupSessionBuilder(cli.Store, pbSerializer), name, cli.Store)
		plaintext, decErr := cipher.Decrypt(ctx, msg)
		if decErr == nil {
			// kavtov-fork (P2a): KEY-path decrypt success. If this inbound tuple was previously a
			// total miss, this is a genuine per-tuple convergence (NOT PDO content-recovery, which
			// runs elsewhere and installs no key). Emit ONE INFO and drop the entry.
			if cli.clearFailedSenderKeyTuple(labeled, chat.String()) {
				cli.Log.Infof("SENDER_KEY_CONVERGED keypath sender=%s device=%d group=%s prevFailed=true", from.SignalAddressUser(), from.Device, chat.String())
			}
			return plaintext, nil
		}
		cli.Log.Debugf("Group sender-key candidate %q did not decrypt: %v", sid, decErr)
	}
	// kavtov-fork (P2a): total miss for this inbound (sender,device,group) tuple. Record it so a
	// later KEY-path decrypt success for the same tuple is recognizable as convergence.
	cli.recordFailedSenderKeyTuple(labeled, chat.String())
	return nil, signalerror.ErrNoSenderKeyForUser
}

// kavtov-fork (P2a): bounded recently-failed group sender-key tuple set. See client.go field doc.
// failedSenderKeyTuplesSize caps the set; the failing working set is a few hundred distinct tuples
// per ~8-min window (~289 sender|group pairs observed, more once device-qualified) against ~0
// current convergence, so 4096 holds the entire failing population indefinitely until a tuple
// actually converges. Memory is trivial (a few hundred KB of small structs); err large so the
// signal this instrument exists to catch is never evicted before it can fire. Eviction is a ring
// buffer (oldest tuple dropped when full), identical to recentMessages, with dedup on add.
const failedSenderKeyTuplesSize = 4096

// failedSenderKeyTuple keys the failed-set by the inbound sender's device-qualified signal address
// (e.g. "34278519877736_1:1") plus the group JID. Keying by the INBOUND device (not the winning
// stored device) is deliberate: convergence means "a later message from this inbound
// (sender,device,group) now decrypts", regardless of which stored record supplied the key.
type failedSenderKeyTuple struct {
	Sender string // from.SignalAddress().String()
	Group  string // chat.String()
}

// recordFailedSenderKeyTuple marks an inbound (sender,device,group) tuple as a total decrypt miss.
// Dedups on add (the failure load repeats the same tuples heavily) so a duplicate does not consume
// a ring slot and evict a still-unconverged tuple. Guarded by failedSenderKeyTuplesLock; safe under
// the concurrent decrypt path.
func (cli *Client) recordFailedSenderKeyTuple(sender, group string) {
	key := failedSenderKeyTuple{Sender: sender, Group: group}
	cli.failedSenderKeyTuplesLock.Lock()
	defer cli.failedSenderKeyTuplesLock.Unlock()
	if cli.failedSenderKeyTuples == nil {
		// Lazy init: the production constructor seeds this, but a bare &Client{} (tests / direct
		// construction) must not nil-panic on the hot decrypt path.
		cli.failedSenderKeyTuples = make(map[failedSenderKeyTuple]struct{}, failedSenderKeyTuplesSize)
	}
	if _, exists := cli.failedSenderKeyTuples[key]; exists {
		return
	}
	if old := cli.failedSenderKeyTuplesList[cli.failedSenderKeyTuplesPtr]; old.Sender != "" {
		delete(cli.failedSenderKeyTuples, old)
	}
	cli.failedSenderKeyTuples[key] = struct{}{}
	cli.failedSenderKeyTuplesList[cli.failedSenderKeyTuplesPtr] = key
	cli.failedSenderKeyTuplesPtr++
	if cli.failedSenderKeyTuplesPtr >= len(cli.failedSenderKeyTuplesList) {
		cli.failedSenderKeyTuplesPtr = 0
	}
}

// clearFailedSenderKeyTuple removes an inbound (sender,group) tuple from the failed set and reports
// whether it was present. A true result means this tuple previously failed and has now decrypted via
// the KEY path — a genuine per-tuple convergence. The stale ring-list slot is left to be overwritten
// by the ring (a cleared entry just becomes a no-op delete when its slot recycles).
func (cli *Client) clearFailedSenderKeyTuple(sender, group string) bool {
	key := failedSenderKeyTuple{Sender: sender, Group: group}
	cli.failedSenderKeyTuplesLock.Lock()
	defer cli.failedSenderKeyTuplesLock.Unlock()
	if _, exists := cli.failedSenderKeyTuples[key]; !exists {
		return false
	}
	delete(cli.failedSenderKeyTuples, key)
	return true
}

// isFailedSenderKeyTuple reports whether an inbound (sender,group) tuple is CURRENTLY in the failed
// set, WITHOUT mutating it. Read-only by design: clearing on SKDM arrival would suppress the later
// SENDER_KEY_CONVERGED signal (which fires only when the decrypt-success path sees prevFailed=true),
// so the SKDM-reception instrument must only PROBE, never clear. Guarded by the same lock as
// record/clear; safe under the concurrent decrypt + receive paths.
func (cli *Client) isFailedSenderKeyTuple(sender, group string) bool {
	key := failedSenderKeyTuple{Sender: sender, Group: group}
	cli.failedSenderKeyTuplesLock.Lock()
	defer cli.failedSenderKeyTuplesLock.Unlock()
	_, exists := cli.failedSenderKeyTuples[key]
	return exists
}

const checkPadding = true

func isValidPadding(plaintext []byte) bool {
	lastByte := plaintext[len(plaintext)-1]
	expectedPadding := bytes.Repeat([]byte{lastByte}, int(lastByte))
	return bytes.HasSuffix(plaintext, expectedPadding)
}

func unpadMessage(plaintext []byte, version int) ([]byte, error) {
	if version == 3 {
		return plaintext, nil
	} else if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext is empty")
	} else if checkPadding && !isValidPadding(plaintext) {
		return nil, fmt.Errorf("plaintext doesn't have expected padding")
	} else {
		return plaintext[:len(plaintext)-int(plaintext[len(plaintext)-1])], nil
	}
}

func padMessage(plaintext []byte) []byte {
	pad := random.Bytes(1)
	pad[0] &= 0xf
	if pad[0] == 0 {
		pad[0] = 0xf
	}
	plaintext = append(plaintext, bytes.Repeat(pad, int(pad[0]))...)
	return plaintext
}

func (cli *Client) handleSenderKeyDistributionMessage(ctx context.Context, chat, from types.JID, axolotlSKDM []byte) {
	builder := groups.NewGroupSessionBuilder(cli.Store, pbSerializer)
	// kavtov-fork: Phase 27 — device-qualified store; the message keyID disambiguates devices; device-tolerant lookup (27-01) finds the record regardless of which device the skmsg is labeled with.
	senderKeyName := protocol.NewSenderKeyName(chat.String(), from.SignalAddress())
	// kavtov-fork (STEP 1 instrument): is this arriving SKDM for a tuple that is CURRENTLY stuck (a
	// prior total decrypt miss recorded by the P2a failed-set)? Keyed IDENTICALLY to the decrypt path
	// (from.SignalAddress().String() + chat.String(), see decryptGroupSenderKey ~:700/:739). Probe is
	// read-only; it never clears the tuple (clearing belongs to the convergence success hook). Fires
	// at most once per arriving SKDM for an already-stuck tuple → low volume, general, no hardcoded
	// sender. Fills the prod blind spot: successful SKDM receipt is Debug-only (:847), so today an
	// arriving key for a stuck tuple is invisible. installed=y/n distinguishes "arrived AND processed"
	// from "arrived but failed to install" (a stuck tuple specifically, not the generic :844 Errorf).
	wasFailed := cli.isFailedSenderKeyTuple(from.SignalAddress().String(), chat.String())
	sdkMsg, err := protocol.NewSenderKeyDistributionMessageFromBytes(axolotlSKDM, pbSerializer.SenderKeyDistributionMessage)
	if err != nil {
		cli.Log.Errorf("Failed to parse sender key distribution message from %s for %s: %v", from, chat, err)
		if wasFailed {
			cli.Log.Infof("SKDM_FOR_FAILED_TUPLE sender=%s device=%d group=%s installed=n stage=parse", from.SignalAddressUser(), from.Device, chat.String())
		}
		return
	}
	err = builder.Process(ctx, senderKeyName, sdkMsg)
	if err != nil {
		cli.Log.Errorf("Failed to process sender key distribution message from %s for %s: %v", from, chat, err)
		if wasFailed {
			cli.Log.Infof("SKDM_FOR_FAILED_TUPLE sender=%s device=%d group=%s installed=n stage=process", from.SignalAddressUser(), from.Device, chat.String())
		}
		return
	}
	if wasFailed {
		cli.Log.Infof("SKDM_FOR_FAILED_TUPLE sender=%s device=%d group=%s installed=y", from.SignalAddressUser(), from.Device, chat.String())
	}
	cli.Log.Debugf("Processed sender key distribution message from %s in %s", senderKeyName.Sender().String(), senderKeyName.GroupID())
}

func (cli *Client) handleHistorySyncNotificationLoop() {
	defer func() {
		cli.historySyncHandlerStarted.Store(false)
		err := recover()
		if err != nil {
			cli.Log.Errorf("History sync handler panicked: %v\n%s", err, debug.Stack())
		}

		// Check in case something new appeared in the channel between the loop stopping
		// and the atomic variable being updated. If yes, restart the loop.
		if len(cli.historySyncNotifications) > 0 && cli.historySyncHandlerStarted.CompareAndSwap(false, true) {
			cli.Log.Warnf("New history sync notifications appeared after loop stopped, restarting loop...")
			go cli.handleHistorySyncNotificationLoop()
		}
	}()
	ctx := cli.BackgroundEventCtx
	for {
		select {
		case notif := <-cli.historySyncNotifications:
			blob, err := cli.DownloadHistorySync(ctx, notif, false)
			if err != nil {
				cli.Log.Errorf("Failed to download history sync: %v", err)
			} else {
				cli.dispatchEvent(&events.HistorySync{Data: blob})
				err = cli.DeleteMedia(ctx, MediaHistory, notif.GetDirectPath(), notif.GetFileEncSHA256(), notif.GetEncHandle())
				if err != nil {
					cli.Log.Warnf("Failed to delete history sync media from server: %v", err)
				}
			}
		case <-time.After(1 * time.Minute):
			return
		}
	}
}

// SendHistorySyncServerErrorReceipt sends a history sync server-error receipt, which
// asks the phone to re-upload the referenced history sync payload.
func (cli *Client) SendHistorySyncServerErrorReceipt(ctx context.Context, msgID types.MessageID, mediaKey []byte) error {
	ciphertext, iv, err := encryptMediaRetryReceipt(msgID, mediaKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt history sync server-error receipt: %w", err)
	}
	ownID := cli.getOwnID().ToNonAD()
	if ownID.IsEmpty() {
		return ErrNotLoggedIn
	}
	err = cli.sendNode(ctx, waBinary.Node{
		Tag: "receipt",
		Attrs: waBinary.Attrs{
			"id":       string(msgID),
			"type":     "server-error",
			"to":       ownID,
			"category": "peer",
		},
		Content: []waBinary.Node{
			{Tag: "encrypt", Content: []waBinary.Node{
				{Tag: "enc_p", Content: ciphertext},
				{Tag: "enc_iv", Content: iv},
			}},
		},
	})
	if err != nil {
		return fmt.Errorf("Failed to send history sync server-error receipt: %w", err)
	}
	return nil
}

// DownloadHistorySync will download and parse the history sync blob from the given history sync notification.
//
// You only need to call this manually if you set [Client.ManualHistorySyncDownload] to true.
// By default, whatsmeow will call this automatically and dispatch an [events.HistorySync] with the parsed data.
func (cli *Client) DownloadHistorySync(ctx context.Context, notif *waE2E.HistorySyncNotification, synchronousStorage bool) (*waHistorySync.HistorySync, error) {
	var data []byte
	var err error
	if notif.InitialHistBootstrapInlinePayload != nil {
		data = notif.InitialHistBootstrapInlinePayload
	} else if data, err = cli.Download(ctx, notif); err != nil {
		return nil, fmt.Errorf("failed to download: %w", err)
	}
	var historySync waHistorySync.HistorySync
	if reader, err := zlib.NewReader(bytes.NewReader(data)); err != nil {
		return nil, fmt.Errorf("failed to prepare to decompress: %w", err)
	} else if rawData, err := io.ReadAll(reader); err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	} else if err = proto.Unmarshal(rawData, &historySync); err != nil {
		return nil, fmt.Errorf("failed to unmarshal: %w", err)
	}
	cli.Log.Debugf("Received history sync (type %s, chunk %d, progress %d)", historySync.GetSyncType(), historySync.GetChunkOrder(), historySync.GetProgress())
	doStorage := func(ctx context.Context) {
		if err := cli.storeNCTSalt(ctx, historySync.GetNctSalt()); err != nil {
			cli.Log.Warnf("Failed to store NCT salt from history sync: %v", err)
		}
		if historySync.GetSyncType() == waHistorySync.HistorySync_PUSH_NAME {
			cli.handleHistoricalPushNames(ctx, historySync.GetPushnames())
		} else if len(historySync.GetConversations()) > 0 {
			cli.storeHistoricalMessageSecrets(ctx, historySync.GetConversations())
		}
		if len(historySync.GetPhoneNumberToLidMappings()) > 0 {
			cli.storeHistoricalPNLIDMappings(ctx, historySync.GetPhoneNumberToLidMappings())
		}
		if historySync.GlobalSettings != nil {
			cli.storeGlobalSettings(ctx, historySync.GlobalSettings)
		}
	}
	if synchronousStorage {
		doStorage(ctx)
	} else {
		go doStorage(context.WithoutCancel(ctx))
	}
	return &historySync, nil
}

func (cli *Client) handleAppStateSyncKeyShare(ctx context.Context, keys *waE2E.AppStateSyncKeyShare) {
	onlyResyncIfNotSynced := true

	cli.Log.Debugf("Got %d new app state keys", len(keys.GetKeys()))
	cli.appStateKeyRequestsLock.RLock()
	for _, key := range keys.GetKeys() {
		marshaledFingerprint, err := proto.Marshal(key.GetKeyData().GetFingerprint())
		if err != nil {
			cli.Log.Errorf("Failed to marshal fingerprint of app state sync key %X", key.GetKeyID().GetKeyID())
			continue
		}
		_, isReRequest := cli.appStateKeyRequests[hex.EncodeToString(key.GetKeyID().GetKeyID())]
		if isReRequest {
			onlyResyncIfNotSynced = false
		}
		err = cli.Store.AppStateKeys.PutAppStateSyncKey(ctx, key.GetKeyID().GetKeyID(), store.AppStateSyncKey{
			Data:        key.GetKeyData().GetKeyData(),
			Fingerprint: marshaledFingerprint,
			Timestamp:   key.GetKeyData().GetTimestamp(),
		})
		if err != nil {
			cli.Log.Errorf("Failed to store app state sync key %X: %v", key.GetKeyID().GetKeyID(), err)
			continue
		}
		cli.Log.Debugf("Received app state sync key %X (ts: %d)", key.GetKeyID().GetKeyID(), key.GetKeyData().GetTimestamp())
	}
	cli.appStateKeyRequestsLock.RUnlock()

	for _, name := range appstate.AllPatchNames {
		err := cli.FetchAppState(ctx, name, false, onlyResyncIfNotSynced)
		if err != nil {
			cli.Log.Errorf("Failed to do initial fetch of app state %s: %v", name, err)
		}
	}
}

func (cli *Client) handlePlaceholderResendResponse(msg *waE2E.PeerDataOperationRequestResponseMessage) (ok bool) {
	reqID := msg.GetStanzaID()
	parts := msg.GetPeerDataOperationResult()
	cli.Log.Debugf("Handling response to placeholder resend request %s with %d items", reqID, len(parts))
	ok = true
	for i, part := range parts {
		var webMsg waWeb.WebMessageInfo
		if resp := part.GetPlaceholderMessageResendResponse(); resp == nil {
			cli.Log.Warnf("Missing response in item #%d of response to %s", i+1, reqID)
		} else if err := proto.Unmarshal(resp.GetWebMessageInfoBytes(), &webMsg); err != nil {
			cli.Log.Warnf("Failed to unmarshal protobuf web message in item #%d of response to %s: %v", i+1, reqID, err)
		} else if msgEvt, err := cli.ParseWebMessage(types.EmptyJID, &webMsg); err != nil {
			cli.Log.Warnf("Failed to parse web message info in item #%d of response to %s: %v", i+1, reqID, err)
		} else {
			msgEvt.UnavailableRequestID = reqID
			ok = !cli.dispatchEvent(msgEvt) && ok
		}
	}
	return
}

func (cli *Client) handleProtocolMessage(ctx context.Context, info *types.MessageInfo, msg *waE2E.Message) (ok bool) {
	ok = true
	protoMsg := msg.GetProtocolMessage()

	if !info.IsFromMe {
		return
	}

	if protoMsg.GetHistorySyncNotification() != nil {
		if !cli.ManualHistorySyncDownload {
			cli.historySyncNotifications <- protoMsg.HistorySyncNotification
			if cli.historySyncHandlerStarted.CompareAndSwap(false, true) {
				go cli.handleHistorySyncNotificationLoop()
			}
		}
		if !(cli.ManualHistorySyncDownload && cli.DisableManualHistorySyncReceipt) {
			go func() {
				err := cli.SendProtocolMessageReceipt(ctx, info.ID, types.ReceiptTypeHistorySync)
				if err != nil {
					cli.Log.Warnf("Failed to send acknowledgement for protocol message %s: %v", info.ID, err)
				}
			}()
		}
	}

	if protoMsg.GetLidMigrationMappingSyncMessage() != nil {
		cli.storeLIDSyncMessage(ctx, protoMsg.GetLidMigrationMappingSyncMessage().GetEncodedMappingPayload())
	}

	if info.Sender.Device == 0 {
		peerResp := protoMsg.GetPeerDataOperationRequestResponseMessage()
		switch peerResp.GetPeerDataOperationRequestType() {
		case waE2E.PeerDataOperationRequestType_PLACEHOLDER_MESSAGE_RESEND:
			ok = cli.handlePlaceholderResendResponse(peerResp) && ok
		case waE2E.PeerDataOperationRequestType_COMPANION_SYNCD_SNAPSHOT_FATAL_RECOVERY:
			ok = cli.handleAppStateRecovery(ctx, peerResp.GetStanzaID(), peerResp.GetPeerDataOperationResult()) && ok
		}
	}

	if protoMsg.GetAppStateSyncKeyShare() != nil {
		go cli.handleAppStateSyncKeyShare(context.WithoutCancel(ctx), protoMsg.AppStateSyncKeyShare)
	}

	if info.Category == "peer" {
		go func() {
			err := cli.SendProtocolMessageReceipt(ctx, info.ID, types.ReceiptTypePeerMsg)
			if err != nil {
				cli.Log.Warnf("Failed to send acknowledgement for protocol message %s: %v", info.ID, err)
			}
		}()
	}
	return
}

func (cli *Client) processProtocolParts(ctx context.Context, info *types.MessageInfo, msg *waE2E.Message) (ok bool) {
	ok = true
	cli.storeMessageSecret(ctx, info, msg)
	// Hopefully sender key distribution messages and protocol messages can't be inside ephemeral messages
	if msg.GetDeviceSentMessage().GetMessage() != nil {
		msg = msg.GetDeviceSentMessage().GetMessage()
	}
	if msg.GetSenderKeyDistributionMessage() != nil {
		if !info.IsGroup {
			cli.Log.Warnf("Got sender key distribution message in non-group chat from %s", info.Sender)
		} else {
			encryptionIdentity := info.Sender
			if encryptionIdentity.Server == types.DefaultUserServer && info.SenderAlt.Server == types.HiddenUserServer {
				encryptionIdentity = info.SenderAlt
			}
			cli.handleSenderKeyDistributionMessage(ctx, info.Chat, encryptionIdentity, msg.SenderKeyDistributionMessage.AxolotlSenderKeyDistributionMessage)
		}
	}
	// N.B. Edits are protocol messages, but they're also wrapped inside EditedMessage,
	// which is only unwrapped after processProtocolParts, so this won't trigger for edits.
	if msg.GetProtocolMessage() != nil {
		ok = cli.handleProtocolMessage(ctx, info, msg) && ok
	}
	return
}

func (cli *Client) storeMessageSecret(ctx context.Context, info *types.MessageInfo, msg *waE2E.Message) {
	if msgSecret := msg.GetMessageContextInfo().GetMessageSecret(); len(msgSecret) > 0 {
		err := cli.Store.MsgSecrets.PutMessageSecret(ctx, info.Chat, info.Sender, info.ID, msgSecret)
		if err != nil {
			cli.Log.Errorf("Failed to store message secret key for %s: %v", info.ID, err)
		} else {
			cli.Log.Debugf("Stored message secret key for %s", info.ID)
		}
	}
}

func (cli *Client) storeHistoricalMessageSecrets(ctx context.Context, conversations []*waHistorySync.Conversation) {
	var secrets []store.MessageSecretInsert
	var privacyTokens []store.PrivacyToken
	ownID := cli.getOwnID().ToNonAD()
	if ownID.IsEmpty() {
		return
	}
	for _, conv := range conversations {
		chatJID, _ := types.ParseJID(conv.GetID())
		if chatJID.IsEmpty() {
			continue
		}
		if chatJID.Server == types.DefaultUserServer && conv.GetTcToken() != nil {
			privacyTokens = append(privacyTokens, store.PrivacyToken{
				User:            chatJID,
				Token:           conv.GetTcToken(),
				Timestamp:       time.Unix(int64(conv.GetTcTokenTimestamp()), 0),
				SenderTimestamp: time.Unix(int64(conv.GetTcTokenSenderTimestamp()), 0),
			})
		}
		for _, msg := range conv.GetMessages() {
			if secret := msg.GetMessage().GetMessageSecret(); secret != nil {
				var senderJID types.JID
				msgKey := msg.GetMessage().GetKey()
				if msgKey.GetFromMe() {
					senderJID = ownID
				} else if chatJID.Server == types.DefaultUserServer {
					senderJID = chatJID
				} else if msgKey.GetParticipant() != "" {
					senderJID, _ = types.ParseJID(msgKey.GetParticipant())
				} else if msg.GetMessage().GetParticipant() != "" {
					senderJID, _ = types.ParseJID(msg.GetMessage().GetParticipant())
				}
				if senderJID.IsEmpty() || msgKey.GetID() == "" {
					continue
				}
				secrets = append(secrets, store.MessageSecretInsert{
					Chat:   chatJID,
					Sender: senderJID,
					ID:     msgKey.GetID(),
					Secret: secret,
				})
			}
		}
	}
	if len(secrets) > 0 {
		cli.Log.Debugf("Storing %d message secret keys in history sync", len(secrets))
		err := cli.Store.MsgSecrets.PutMessageSecrets(ctx, secrets)
		if err != nil {
			cli.Log.Errorf("Failed to store message secret keys in history sync: %v", err)
		} else {
			cli.Log.Infof("Stored %d message secret keys from history sync", len(secrets))
		}
	}
	if len(privacyTokens) > 0 {
		cli.Log.Debugf("Storing %d privacy tokens in history sync", len(privacyTokens))
		err := cli.Store.PrivacyTokens.PutPrivacyTokens(ctx, privacyTokens...)
		if err != nil {
			cli.Log.Errorf("Failed to store privacy tokens in history sync: %v", err)
		} else {
			cli.Log.Infof("Stored %d privacy tokens from history sync", len(privacyTokens))
		}
	}
}

func (cli *Client) storeLIDSyncMessage(ctx context.Context, msg []byte) {
	var decoded waLidMigrationSyncPayload.LIDMigrationMappingSyncPayload
	err := proto.Unmarshal(msg, &decoded)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).Msg("Failed to unmarshal LID migration mapping sync payload")
		return
	}
	if cli.Store.LIDMigrationTimestamp == 0 && decoded.GetChatDbMigrationTimestamp() > 0 {
		cli.Store.LIDMigrationTimestamp = int64(decoded.GetChatDbMigrationTimestamp())
		err = cli.Store.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Int64("lid_migration_timestamp", cli.Store.LIDMigrationTimestamp).
				Msg("Failed to save chat DB LID migration timestamp")
		} else {
			zerolog.Ctx(ctx).Debug().
				Int64("lid_migration_timestamp", cli.Store.LIDMigrationTimestamp).
				Msg("Saved chat DB LID migration timestamp")
		}
	}
	lidPairs := make([]store.LIDMapping, len(decoded.PnToLidMappings))
	for i, mapping := range decoded.PnToLidMappings {
		lidPairs[i] = store.LIDMapping{
			LID: types.JID{User: strconv.FormatUint(mapping.GetAssignedLid(), 10), Server: types.HiddenUserServer},
			PN:  types.JID{User: strconv.FormatUint(mapping.GetPn(), 10), Server: types.DefaultUserServer},
		}
	}
	err = cli.Store.LIDs.PutManyLIDMappings(ctx, lidPairs)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Int("pair_count", len(lidPairs)).
			Msg("Failed to store phone number to LID mappings from sync message")
	} else {
		zerolog.Ctx(ctx).Debug().
			Int("pair_count", len(lidPairs)).
			Msg("Stored PN-LID mappings from sync message")
	}
}

func (cli *Client) storeGlobalSettings(ctx context.Context, settings *waHistorySync.GlobalSettings) {
	if cli.Store.LIDMigrationTimestamp == 0 && settings.GetChatDbLidMigrationTimestamp() > 0 {
		cli.Store.LIDMigrationTimestamp = settings.GetChatDbLidMigrationTimestamp()
		err := cli.Store.Save(ctx)
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Int64("lid_migration_timestamp", cli.Store.LIDMigrationTimestamp).
				Msg("Failed to save chat DB LID migration timestamp")
		} else {
			zerolog.Ctx(ctx).Debug().
				Int64("lid_migration_timestamp", cli.Store.LIDMigrationTimestamp).
				Msg("Saved chat DB LID migration timestamp")
		}
	}
}

func (cli *Client) storeHistoricalPNLIDMappings(ctx context.Context, mappings []*waHistorySync.PhoneNumberToLIDMapping) {
	lidPairs := make([]store.LIDMapping, 0, len(mappings))
	for _, mapping := range mappings {
		pn, err := types.ParseJID(mapping.GetPnJID())
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("pn_jid", mapping.GetPnJID()).
				Str("lid_jid", mapping.GetLidJID()).
				Msg("Failed to parse phone number from history sync")
			continue
		}
		if pn.Server == types.LegacyUserServer {
			pn.Server = types.DefaultUserServer
		}
		lid, err := types.ParseJID(mapping.GetLidJID())
		if err != nil {
			zerolog.Ctx(ctx).Err(err).
				Str("pn_jid", mapping.GetPnJID()).
				Str("lid_jid", mapping.GetLidJID()).
				Msg("Failed to parse LID from history sync")
			continue
		}
		lidPairs = append(lidPairs, store.LIDMapping{
			LID: lid,
			PN:  pn,
		})
	}
	err := cli.Store.LIDs.PutManyLIDMappings(ctx, lidPairs)
	if err != nil {
		zerolog.Ctx(ctx).Err(err).
			Int("pair_count", len(lidPairs)).
			Msg("Failed to store phone number to LID mappings from history sync")
	} else {
		zerolog.Ctx(ctx).Debug().
			Int("pair_count", len(lidPairs)).
			Msg("Stored PN-LID mappings from history sync")
	}
}

func (cli *Client) handleDecryptedMessage(ctx context.Context, info *types.MessageInfo, msg *waE2E.Message, retryCount int) (handlerFailed bool) {
	ok := cli.processProtocolParts(ctx, info, msg)
	if !ok {
		return false
	}
	evt := &events.Message{Info: *info, RawMessage: msg, RetryCount: retryCount}
	return cli.dispatchEvent(evt.UnwrapRaw())
}

// SendProtocolMessageReceipt sends a receipt for a protocol message back to the phone.
func (cli *Client) SendProtocolMessageReceipt(ctx context.Context, id types.MessageID, msgType types.ReceiptType) error {
	if len(id) == 0 {
		return nil
	}
	err := cli.sendNode(ctx, waBinary.Node{
		Tag: "receipt",
		Attrs: waBinary.Attrs{
			"id":   string(id),
			"type": string(msgType),
			"to":   cli.getOwnID().ToNonAD(),
		},
		Content: nil,
	})
	if err != nil {
		return err
	}
	return nil
}

// establishSessionWithSender proactively fetches prekeys and establishes a Signal session.
// This allows future messages from the sender to be decrypted.
// Should be called in a goroutine after a decryption failure with ErrNoSessionForUser.
func (cli *Client) establishSessionWithSender(ctx context.Context, sender types.JID) {
	cli.sessionRecreateHistoryLock.Lock()
	lastAttempt, ok := cli.sessionRecreateHistory[sender]
	if ok && time.Since(lastAttempt) < 5*time.Minute {
		cli.sessionRecreateHistoryLock.Unlock()
		cli.Log.Debugf("Skipping session establishment with %s (attempted %s ago)", sender, time.Since(lastAttempt))
		return
	}
	cli.sessionRecreateHistory[sender] = time.Now()
	cli.sessionRecreateHistoryLock.Unlock()

	cli.Log.Infof("Proactively fetching prekeys to establish session with %s", sender)
	bundles := cli.fetchPreKeysNoError(ctx, []types.JID{sender})
	bundle, ok := bundles[sender]
	if !ok || bundle == nil {
		cli.Log.Warnf("No prekey bundle received for %s", sender)
		return
	}
	builder := session.NewBuilderFromSignal(cli.Store, sender.SignalAddress(), pbSerializer)
	err := builder.ProcessBundle(ctx, bundle)
	if cli.AutoTrustIdentity && errors.Is(err, signalerror.ErrUntrustedIdentity) {
		cli.Log.Warnf("Got untrusted identity while establishing session with %s, clearing and retrying", sender)
		if clearErr := cli.clearUntrustedIdentity(ctx, sender); clearErr != nil {
			cli.Log.Errorf("Failed to clear untrusted identity for %s: %v", sender, clearErr)
			return
		}
		err = builder.ProcessBundle(ctx, bundle)
	}
	if err != nil {
		cli.Log.Warnf("Failed to establish session with %s: %v", sender, err)
	} else {
		cli.Log.Infof("Successfully established session with %s", sender)
	}
}
