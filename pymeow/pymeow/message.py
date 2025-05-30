"""
Message handling functionality for WhatsApp.

Port of whatsmeow/message.go
"""
import asyncio
import base64
import contextlib
import hashlib
import io
import logging
import time
import zlib
from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple, Union, cast

from google.protobuf.message import Message as ProtobufMessage

# Protocol Buffer imports
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from .generated.waHistorySync import WAWebProtobufsHistorySync_pb2 as waHistorySync_pb2
from .generated.waWeb import WAWebProtobufsWeb_pb2 as waWeb_pb2

# appstate is now ported
from . import appstate
from .appstate.keys import ALL_PATCH_NAMES
from .binary import node as binary_node
from .store import AppStateSyncKey, PrivacyToken, MessageSecretInsert
# types module is now ported
from .types import events, jid, message
from .types.user import VerifiedName
from enum import Enum, auto
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

# Import message types from the properly ported module
message_types = message
# util module is now ported and verified
import os
import struct
import asyncio
from .util.hkdfutil import expand_hmac, sha256
from .util.gcmutil import decrypt
from google.protobuf import message as proto_message

# TODO: Add imports for session, protocol, and groups modules
# These are referenced in the code but not imported

# Logger
logger = logging.getLogger(__name__)

# Constants
EVENT_ALREADY_PROCESSED = Exception("event was already processed")
CHECK_PADDING = True

# Message Secret Types
class MsgSecretType:
    ENC_SECRET_POLL_VOTE = "Poll Vote"
    ENC_SECRET_REACTION = "Enc Reaction"
    ENC_SECRET_COMMENT = "Enc Comment"
    ENC_SECRET_REPORT_TOKEN = "Report Token"
    ENC_SECRET_EVENT_RESPONSE = "Event Response"
    ENC_SECRET_EVENT_EDIT = "Event Edit"
    ENC_SECRET_BOT_MSG = "Bot Message"

# Global variables
# In Go, SignalProtobufSerializer is used, but in Python serialization is handled internally by the record classes
pb_serializer = None

# Request from phone delay in seconds
REQUEST_FROM_PHONE_DELAY = 5


class MessageHandlingMixin:
    """Client methods for handling encrypted messages."""

    def apply_bot_message_hkdf(self, message_secret: bytes) -> bytes:
        """
        Apply HKDF to a message secret for bot message decryption.

        Args:
            message_secret: The message secret to apply HKDF to

        Returns:
            The HKDF-expanded message secret
        """
        return sha256(message_secret, None, MsgSecretType.ENC_SECRET_BOT_MSG.encode(), 32)

    def generate_msg_secret_key(self, modification_type: str, modification_sender: jid.JID,
                              orig_msg_id: message_types.MessageID, orig_msg_sender: jid.JID,
                              orig_msg_secret: bytes) -> tuple[bytes, bytes]:
        """
        Generate a message secret key for decrypting encrypted messages.

        Args:
            modification_type: The type of modification
            modification_sender: The JID of the sender of the modification
            orig_msg_id: The ID of the original message
            orig_msg_sender: The JID of the sender of the original message
            orig_msg_secret: The secret of the original message

        Returns:
            A tuple of (secret_key, additional_data)
        """
        orig_msg_sender_str = orig_msg_sender.to_non_ad().user_string()
        modification_sender_str = modification_sender.to_non_ad().user_string()

        use_case_secret = bytearray()
        use_case_secret.extend(orig_msg_id.encode())
        use_case_secret.extend(orig_msg_sender_str.encode())
        use_case_secret.extend(modification_sender_str.encode())
        use_case_secret.extend(modification_type.encode())

        secret_key = sha256(orig_msg_secret, None, use_case_secret, 32)
        additional_data = None

        if modification_type in [MsgSecretType.ENC_SECRET_POLL_VOTE, MsgSecretType.ENC_SECRET_EVENT_RESPONSE, ""]:
            additional_data = f"{orig_msg_id}\0{modification_sender_str}".encode()

        return secret_key, additional_data

    async def decrypt_bot_message(self, ctx: Any, message_secret: bytes,
                                 ms_msg: Any, decrypt_message_id: str,
                                 target_sender_jid: jid.JID, info: message_types.MessageInfo) -> bytes:
        """
        Decrypt a bot message.

        Args:
            ctx: The context
            message_secret: The message secret
            ms_msg: The message secret message
            decrypt_message_id: The message ID to decrypt
            target_sender_jid: The target sender JID
            info: The message info

        Returns:
            The decrypted message

        Raises:
            Exception: If decryption fails
        """
        new_key, additional_data = self.generate_msg_secret_key(
            "", info.sender, decrypt_message_id, target_sender_jid,
            self.apply_bot_message_hkdf(message_secret)
        )

        try:
            plaintext = decrypt_gcm(new_key, ms_msg.enc_iv, ms_msg.enc_payload, additional_data)
            return plaintext
        except Exception as err:
            raise Exception(f"failed to decrypt secret message: {err}")

    async def send_retry_receipt(self, ctx: Any, node: binary_node.Node,
                               info: message_types.MessageInfo, is_unavailable: bool = False):
        """
        Send a retry receipt for an incoming message.

        Args:
            ctx: The context
            node: The message node
            info: The message info
            is_unavailable: Whether the message is unavailable

        Returns:
            None
        """
        message_id = node.attrs.get("id", "")
        children = node.get_children()
        retry_count_in_msg = 0

        if len(children) == 1 and children[0].tag == "enc":
            retry_count_in_msg = int(children[0].attrs.get("count", 0))

        # Increment retry count
        self.message_retries_lock.acquire()
        if not hasattr(self, 'message_retries'):
            self.message_retries = {}
        self.message_retries[message_id] = self.message_retries.get(message_id, 0) + 1
        retry_count = self.message_retries[message_id]

        # If the message is a retry response and we restarted in between, find the count from the message
        if retry_count == 1 and retry_count_in_msg > 0:
            retry_count = retry_count_in_msg + 1
            self.message_retries[message_id] = retry_count
        self.message_retries_lock.release()

        # Don't send more than 5 retry receipts for the same message
        if retry_count >= 5:
            self.log.warning(f"Not sending any more retry receipts for {message_id}")
            return

        # If this is the first retry, start the delayed request from phone
        if retry_count == 1:
            asyncio.create_task(self.delayed_request_message_from_phone(info))

        # Create registration ID bytes
        registration_id_bytes = struct.pack(">I", self.store.registration_id)

        # Create receipt attributes
        attrs = {
            "id": message_id,
            "type": "retry",
            "to": node.attrs.get("from")
        }

        # Add recipient and participant if present
        if "recipient" in node.attrs:
            attrs["recipient"] = node.attrs["recipient"]
        if "participant" in node.attrs:
            attrs["participant"] = node.attrs["participant"]

        # Create payload
        payload = binary_node.Node(
            tag="receipt",
            attrs=attrs,
            content=[
                binary_node.Node(
                    tag="retry",
                    attrs={
                        "count": retry_count,
                        "id": message_id,
                        "t": node.attrs.get("t"),
                        "v": 1
                    }
                ),
                binary_node.Node(
                    tag="registration",
                    content=registration_id_bytes
                )
            ]
        )

        # Add keys if needed
        if retry_count > 1 or is_unavailable:
            try:
                key = await self.store.pre_keys.gen_one_pre_key()
                device_identity = self.store.account.SerializeToString()

                payload.content.append(
                    binary_node.Node(
                        tag="keys",
                        content=[
                            binary_node.Node(tag="type", content=b"\x05"),  # DjbType
                            binary_node.Node(tag="identity", content=self.store.identity_key.pub),
                            self.pre_key_to_node(key),
                            self.pre_key_to_node(self.store.signed_pre_key),
                            binary_node.Node(tag="device-identity", content=device_identity)
                        ]
                    )
                )
            except Exception as err:
                self.log.error(f"Failed to get prekey for retry receipt: {err}")

        # Send the node
        try:
            await self.send_node(payload)
        except Exception as err:
            self.log.error(f"Failed to send retry receipt for {message_id}: {err}")

    def pre_key_to_node(self, key):
        """
        Convert a pre-key to a binary node.

        Args:
            key: The pre-key to convert

        Returns:
            The binary node
        """
        return binary_node.Node(
            tag="key",
            attrs={
                "id": key.key_id
            },
            content=key.key_pair.public
        )

    async def delayed_request_message_from_phone(self, info: message_types.MessageInfo):
        """
        Request a message from the phone after a delay.

        Args:
            info: The message info

        Returns:
            None
        """
        # Check if automatic message rerequest from phone is enabled
        if not getattr(self, 'automatic_message_rerequest_from_phone', False) or getattr(self, 'messenger_config', None) is not None:
            return

        # Check if we're already requesting this message
        self.pending_phone_rerequests_lock.acquire()
        if not hasattr(self, 'pending_phone_rerequests'):
            self.pending_phone_rerequests = {}
        already_requesting = info.id in self.pending_phone_rerequests
        if already_requesting:
            self.pending_phone_rerequests_lock.release()
            return

        # Create a cancellation function
        cancel_event = asyncio.Event()

        def cancel():
            cancel_event.set()

        # Store the cancellation function
        self.pending_phone_rerequests[info.id] = cancel
        self.pending_phone_rerequests_lock.release()

        # Clean up when we're done
        try:
            # Wait for the delay or cancellation
            try:
                await asyncio.wait_for(cancel_event.wait(), REQUEST_FROM_PHONE_DELAY)
                self.log.debug(f"Cancelled delayed request for message {info.id} from phone")
                return
            except asyncio.TimeoutError:
                # Timeout means we should proceed with the request
                pass

            # Send the request to the phone
            try:
                await self.send_message(
                    self.get_own_id().to_non_ad(),
                    self.build_unavailable_message_request(info.chat, info.sender, info.id),
                    {"peer": True}
                )
                self.log.debug(f"Requested message {info.id} from phone")
            except Exception as err:
                self.log.warning(f"Failed to send request for unavailable message {info.id} to phone: {err}")
        finally:
            # Clean up
            self.pending_phone_rerequests_lock.acquire()
            if info.id in self.pending_phone_rerequests:
                del self.pending_phone_rerequests[info.id]
            self.pending_phone_rerequests_lock.release()

    def cancel_delayed_request_from_phone(self, msg_id: str):
        """
        Cancel a delayed request for a message from the phone.

        Args:
            msg_id: The message ID

        Returns:
            None
        """
        # Check if automatic message rerequest from phone is enabled
        if not getattr(self, 'automatic_message_rerequest_from_phone', False) or getattr(self, 'messenger_config', None) is not None:
            return

        # Cancel the request if it exists
        self.pending_phone_rerequests_lock.acquire()
        if hasattr(self, 'pending_phone_rerequests') and msg_id in self.pending_phone_rerequests:
            cancel = self.pending_phone_rerequests[msg_id]
            cancel()
        self.pending_phone_rerequests_lock.release()

    def clear_delayed_message_requests(self):
        """
        Cancel all delayed message requests.

        Returns:
            None
        """
        self.pending_phone_rerequests_lock.acquire()
        if hasattr(self, 'pending_phone_rerequests'):
            for cancel in self.pending_phone_rerequests.values():
                cancel()
        self.pending_phone_rerequests_lock.release()

    def maybe_deferred_ack(self, node: binary_node.Node) -> Callable:
        """
        Return a function that will send an acknowledgment for the given node.

        If synchronous_ack is True, the function will send the acknowledgment when called.
        Otherwise, it will start a task to send the acknowledgment and return a no-op function.

        Args:
            node: The node to acknowledge

        Returns:
            A function that will send the acknowledgment when called
        """
        if getattr(self, 'synchronous_ack', False):
            # Return a function that will send the acknowledgment when called
            return lambda: self.send_ack(node)
        else:
            # Start a task to send the acknowledgment and return a no-op function
            asyncio.create_task(self.send_ack(node))
            return lambda: None

    async def send_ack(self, node: binary_node.Node):
        """
        Send an acknowledgment for the given node.

        Args:
            node: The node to acknowledge

        Returns:
            None
        """
        attrs = {
            "class": node.tag,
            "id": node.attrs.get("id")
        }

        attrs["to"] = node.attrs.get("from")

        if "participant" in node.attrs:
            attrs["participant"] = node.attrs["participant"]

        if "recipient" in node.attrs:
            attrs["recipient"] = node.attrs["recipient"]

            # TODO: This hack probably needs to be removed at some point
            recipient_jid = node.attrs["recipient"]
            if (isinstance(recipient_jid, jid.JID) and
                    recipient_jid.server == jid.BOT_SERVER and
                    node.tag == "message"):
                alt_recipient = jid.BOT_JID_MAP.get(recipient_jid)
                if alt_recipient:
                    attrs["recipient"] = alt_recipient

        if node.tag != "message" and "type" in node.attrs:
            attrs["type"] = node.attrs["type"]

        try:
            await self.send_node(binary_node.Node(
                tag="ack",
                attrs=attrs
            ))
        except Exception as err:
            self.log.warning(f"Failed to send acknowledgement for {node.tag} {node.attrs.get('id')}: {err}")

    async def update_business_name(self, ctx: Any, user: jid.JID,
                                  message_info: message_types.MessageInfo, name: str):
        """
        Update the business name of a user.

        Args:
            ctx: The context
            user: The user JID
            message_info: The message info
            name: The new business name

        Returns:
            None
        """
        if not hasattr(self.store, 'contacts') or self.store.contacts is None:
            return

        try:
            changed, previous_name = await self.store.contacts.put_business_name(user, name)
            if changed:
                self.log.debug(f"Business name of {user} changed from {previous_name} to {name}, dispatching event")
                self.dispatch_event(events.BusinessName(
                    jid=user,
                    message=message_info,
                    old_business_name=previous_name,
                    new_business_name=name
                ))
        except Exception as err:
            self.log.error(f"Failed to save business name of {user} in device store: {err}")

    async def update_push_name(self, ctx: Any, user: jid.JID,
                              message_info: message_types.MessageInfo, name: str):
        """
        Update the push name of a user.

        Args:
            ctx: The context
            user: The user JID
            message_info: The message info
            name: The new push name

        Returns:
            None
        """
        if not hasattr(self.store, 'contacts') or self.store.contacts is None:
            return

        user = user.to_non_ad()

        try:
            changed, previous_name = await self.store.contacts.put_push_name(user, name)
            if changed:
                self.log.debug(f"Push name of {user} changed from {previous_name} to {name}, dispatching event")
                self.dispatch_event(events.PushName(
                    jid=user,
                    message=message_info,
                    old_push_name=previous_name,
                    new_push_name=name
                ))
        except Exception as err:
            self.log.error(f"Failed to save push name of {user} in device store: {err}")

    def parse_verified_name_content(self, node: binary_node.Node) -> Optional[VerifiedName]:
        """
        Parse a verified name node.

        Args:
            node: The verified name node

        Returns:
            The parsed verified name, or None if parsing failed
        """
        raw_cert = node.content
        if not isinstance(raw_cert, bytes):
            return None

        try:
            # Import the necessary protobuf classes
            from .generated.waVnameCert import waVnameCert_pb2

            # Parse the certificate
            cert = waVnameCert_pb2.VerifiedNameCertificate()
            cert.ParseFromString(raw_cert)

            # Parse the certificate details
            cert_details = waVnameCert_pb2.VerifiedNameCertificate_Details()
            cert_details.ParseFromString(cert.details)

            # Create and return the verified name
            return VerifiedName(
                certificate=cert,
                details=cert_details
            )
        except Exception as err:
            self.log.error(f"Failed to parse verified name content: {err}")
            return None

    async def handle_encrypted_message(self, node: binary_node.Node) -> None:
        """
        Handle an encrypted message node from WhatsApp.

        Args:
            node: The binary node containing the encrypted message
        """
        ctx = contextlib.nullcontext()
        info = None
        try:
            info = await self.parse_message_info(node)
        except Exception as err:
            self.log.warning(f"Failed to parse message: {err}")
            return

        if not info.sender_alt.is_empty():
            await self.store_lidpn_mapping(ctx, info.sender_alt, info.sender)
        elif not info.recipient_alt.is_empty():
            await self.store_lidpn_mapping(ctx, info.recipient_alt, info.chat)

        if (info.verified_name is not None and
                len(info.verified_name.details.get_verified_name()) > 0):
            asyncio.create_task(
                self.update_business_name(
                    info.sender,
                    info,
                    info.verified_name.details.get_verified_name()
                )
            )

        if len(info.push_name) > 0 and info.push_name != "-":
            asyncio.create_task(
                self.update_push_name(info.sender, info, info.push_name)
            )

        maybe_deferred_ack = self.maybe_deferred_ack(node)
        try:
            if info.sender.server == jid.NEWSLETTER_SERVER:
                await self.handle_plaintext_message(info, node)
            else:
                await self.decrypt_messages(info, node)
        finally:
            if maybe_deferred_ack:
                maybe_deferred_ack()

    async def parse_message_source(
        self, node: binary_node.Node, require_participant: bool = False
    ) -> message_types.MessageSource:
        """
        Parse the message source from a node.

        Args:
            node: The binary node containing the message
            require_participant: Whether a participant is required

        Returns:
            The parsed message source

        Raises:
            Exception: If not logged in or if required attributes are missing
        """
        source = message_types.MessageSource()
        client_id = self.get_own_id()
        client_lid = self.store.get_lid()

        if client_id.is_empty():
            raise Exception("not logged in")

        attrs = node.attrs
        from_jid = jid.JID.from_string(attrs.get("from", ""))
        source.addressing_mode = message_types.AddressingMode(
            attrs.get("addressing_mode", "")
        )

        if from_jid.server == jid.GROUP_SERVER or from_jid.server == jid.BROADCAST_SERVER:
            source.is_group = True
            source.chat = from_jid

            if require_participant:
                source.sender = jid.JID.from_string(attrs.get("participant", ""))
            else:
                participant = attrs.get("participant")
                if participant:
                    source.sender = jid.JID.from_string(participant)

            if source.addressing_mode == message_types.AddressingMode.LID:
                participant_pn = attrs.get("participant_pn")
                if participant_pn:
                    source.sender_alt = jid.JID.from_string(participant_pn)
            else:
                participant_lid = attrs.get("participant_lid")
                if participant_lid:
                    source.sender_alt = jid.JID.from_string(participant_lid)

            if (source.sender.user == client_id.user or
                    source.sender.user == client_lid.user):
                source.is_from_me = True

            if from_jid.server == jid.BROADCAST_SERVER:
                recipient = attrs.get("recipient")
                if recipient:
                    source.broadcast_list_owner = jid.JID.from_string(recipient)

        elif from_jid.server == jid.NEWSLETTER_SERVER:
            source.chat = from_jid
            source.sender = from_jid
            # TODO: IsFromMe?

        elif from_jid.user == client_id.user or from_jid.user == client_lid.user:
            source.is_from_me = True
            source.sender = from_jid

            recipient = attrs.get("recipient")
            if recipient:
                source.chat = jid.JID.from_string(recipient)
            else:
                source.chat = from_jid.to_non_ad()

            if source.addressing_mode == message_types.AddressingMode.LID:
                peer_recipient_pn = attrs.get("peer_recipient_pn")
                if peer_recipient_pn:
                    source.recipient_alt = jid.JID.from_string(peer_recipient_pn)
            else:
                peer_recipient_lid = attrs.get("peer_recipient_lid")
                if peer_recipient_lid:
                    source.recipient_alt = jid.JID.from_string(peer_recipient_lid)

        elif from_jid.is_bot():
            source.sender = from_jid

            meta = node.get_child_by_tag("meta")
            if meta:
                target_chat_jid = meta.attrs.get("target_chat_jid")
                if target_chat_jid:
                    source.chat = jid.JID.from_string(target_chat_jid).to_non_ad()
                else:
                    source.chat = from_jid
        else:
            source.chat = from_jid.to_non_ad()
            source.sender = from_jid

            if source.addressing_mode == message_types.AddressingMode.LID:
                sender_pn = attrs.get("sender_pn")
                if sender_pn:
                    source.sender_alt = jid.JID.from_string(sender_pn)
            else:
                sender_lid = attrs.get("sender_lid")
                if sender_lid:
                    source.sender_alt = jid.JID.from_string(sender_lid)

        if not source.sender_alt.is_empty() and source.sender_alt.device == 0:
            source.sender_alt.device = source.sender.device

        return source

    async def parse_msg_bot_info(
        self, node: binary_node.Node
    ) -> message_types.MsgBotInfo:
        """
        Parse bot info from a message node.

        Args:
            node: The binary node containing the message

        Returns:
            The parsed bot info
        """
        bot_info = message_types.MsgBotInfo()
        bot_node = node.get_child_by_tag("bot")

        if not bot_node:
            return bot_info

        edit_type = bot_node.attrs.get("edit", "")
        bot_info.edit_type = message_types.BotEditType(edit_type)

        if (bot_info.edit_type == message_types.BotEditType.INNER or
                bot_info.edit_type == message_types.BotEditType.LAST):
            bot_info.edit_target_id = message_types.MessageID(
                bot_node.attrs.get("edit_target_id", "")
            )
            bot_info.edit_sender_timestamp_ms = int(
                bot_node.attrs.get("sender_timestamp_ms", 0)
            )

        return bot_info

    async def parse_msg_meta_info(
        self, node: binary_node.Node
    ) -> message_types.MsgMetaInfo:
        """
        Parse meta info from a message node.

        Args:
            node: The binary node containing the message

        Returns:
            The parsed meta info
        """
        meta_info = message_types.MsgMetaInfo()
        meta_node = node.get_child_by_tag("meta")

        if not meta_node:
            return meta_info

        target_id = meta_node.attrs.get("target_id")
        if target_id:
            meta_info.target_id = message_types.MessageID(target_id)

        target_sender = meta_node.attrs.get("target_sender_jid")
        if target_sender:
            meta_info.target_sender = jid.JID.from_string(target_sender)

        deprecated_lid_session = meta_node.attrs.get("deprecated_lid_session")
        if deprecated_lid_session is not None:
            meta_info.deprecated_lid_session = deprecated_lid_session.lower() == "true"

        thread_msg_id = meta_node.attrs.get("thread_msg_id")
        if thread_msg_id:
            meta_info.thread_message_id = message_types.MessageID(thread_msg_id)

        thread_msg_sender_jid = meta_node.attrs.get("thread_msg_sender_jid")
        if thread_msg_sender_jid:
            meta_info.thread_message_sender_jid = jid.JID.from_string(
                thread_msg_sender_jid
            )

        return meta_info

    async def parse_message_info(
        self, node: binary_node.Node
    ) -> message_types.MessageInfo:
        """
        Parse message info from a node.

        Args:
            node: The binary node containing the message

        Returns:
            The parsed message info

        Raises:
            Exception: If required attributes are missing
        """
        info = message_types.MessageInfo()
        info.message_source = await self.parse_message_source(node, True)

        attrs = node.attrs
        info.id = message_types.MessageID(attrs.get("id", ""))

        server_id = attrs.get("server_id")
        if server_id:
            info.server_id = message_types.MessageServerID(int(server_id))

        timestamp = attrs.get("t")
        if timestamp:
            info.timestamp = int(timestamp)

        info.push_name = attrs.get("notify", "")
        info.category = attrs.get("category", "")
        info.type = attrs.get("type", "")

        edit = attrs.get("edit")
        if edit:
            info.edit = message_types.EditAttribute(edit)

        for child in node.children:
            if child.tag == "multicast":
                info.multicast = True
            elif child.tag == "verified_name":
                try:
                    info.verified_name = await self.parse_verified_name_content(child)
                except Exception as err:
                    self.log.warning(
                        f"Failed to parse verified_name node in {info.id}: {err}"
                    )
            elif child.tag == "bot":
                try:
                    info.msg_bot_info = await self.parse_msg_bot_info(child)
                except Exception as err:
                    self.log.warning(
                        f"Failed to parse <bot> node in {info.id}: {err}"
                    )
            elif child.tag == "meta":
                try:
                    info.msg_meta_info = await self.parse_msg_meta_info(child)
                except Exception as err:
                    self.log.warning(
                        f"Failed to parse <meta> node in {info.id}: {err}"
                    )
            elif child.tag == "franking":
                # TODO
                pass
            elif child.tag == "trace":
                # TODO
                pass
            else:
                media_type = child.attrs.get("mediatype")
                if media_type:
                    info.media_type = media_type

        return info

    async def handle_plaintext_message(
        self, info: message_types.MessageInfo, node: binary_node.Node
    ) -> None:
        """
        Handle a plaintext message.

        Args:
            info: The message info
            node: The binary node containing the message
        """
        # TODO edits have an additional <meta msg_edit_t="1696321271735" original_msg_t="1696321248"/> node
        plaintext = node.get_child_by_tag("plaintext")
        if not plaintext:
            return

        plaintext_body = plaintext.content
        if not isinstance(plaintext_body, bytes):
            self.log.warning(
                f"Plaintext message from {info.source_string()} doesn't have byte content"
            )
            return

        msg = waE2E_pb2.Message()
        try:
            msg.ParseFromString(plaintext_body)
        except Exception as err:
            self.log.warning(
                f"Error unmarshaling plaintext message from {info.source_string()}: {err}"
            )
            return

        await self.store_message_secret(info, msg)

        evt = events.Message(
            info=info,
            raw_message=msg
        )

        meta = node.get_child_by_tag("meta")
        if meta:
            evt.newsletter_meta = events.NewsletterMessageMeta(
                edit_ts=int(meta.attrs.get("msg_edit_t", 0)),
                original_ts=int(meta.attrs.get("original_msg_t", 0))
            )

        self.dispatch_event(evt.unwrap_raw())

    async def migrate_session_store(
        self, pn: jid.JID, lid: jid.JID
    ) -> None:
        """
        Migrate a session from phone number to LID.

        Args:
            pn: The phone number JID
            lid: The LID JID
        """
        try:
            await self.store.sessions.migrate_pn_to_lid(pn, lid)
        except Exception as err:
            self.log.error(f"Failed to migrate signal store from {pn} to {lid}: {err}")

    async def decrypt_messages(
        self, info: message_types.MessageInfo, node: binary_node.Node
    ) -> None:
        """
        Decrypt messages in a node.

        Args:
            info: The message info
            node: The binary node containing the encrypted messages
        """
        unavailable_node = node.get_child_by_tag("unavailable")
        if unavailable_node and len(node.get_children_by_tag("enc")) == 0:
            u_type = events.UnavailableType(unavailable_node.attrs.get("type", ""))
            self.log.warning(
                f"Unavailable message {info.id} from {info.source_string()} (type: {u_type})"
            )
            asyncio.create_task(self.delayed_request_message_from_phone(info))
            self.dispatch_event(
                events.UndecryptableMessage(
                    info=info,
                    is_unavailable=True,
                    unavailable_type=u_type
                )
            )
            return

        children = node.children
        self.log.debug(f"Decrypting message from {info.source_string()}")
        handled = False
        contains_direct_msg = False
        sender_encryption_jid = info.sender

        if (info.sender.server == jid.DEFAULT_USER_SERVER and
                not info.sender.is_bot()):
            if info.sender_alt.server == jid.HIDDEN_USER_SERVER:
                sender_encryption_jid = info.sender_alt
                await self.migrate_session_store(info.sender, info.sender_alt)
            else:
                try:
                    lid = await self.store.lids.get_lid_for_pn(info.sender)
                    if not lid.is_empty():
                        await self.migrate_session_store(info.sender, lid)
                        sender_encryption_jid = lid
                        info.sender_alt = lid
                    else:
                        self.log.warning(f"No LID found for {info.sender}")
                except Exception as err:
                    self.log.error(f"Failed to get LID for {info.sender}: {err}")

        for child in children:
            if child.tag != "enc":
                continue

            enc_type = child.attrs.get("type")
            if not enc_type:
                continue

            decrypted = None
            ciphertext_hash = None

            try:
                if enc_type == "pkmsg" or enc_type == "msg":
                    decrypted, ciphertext_hash = await self.decrypt_dm(
                        child,
                        sender_encryption_jid,
                        enc_type == "pkmsg",
                        info.timestamp
                    )
                    contains_direct_msg = True
                elif info.is_group and enc_type == "skmsg":
                    decrypted, ciphertext_hash = await self.decrypt_group_msg(
                        child,
                        sender_encryption_jid,
                        info.chat,
                        info.timestamp
                    )
                elif enc_type == "msmsg" and info.sender.is_bot():
                    target_sender_jid = info.msg_meta_info.target_sender
                    message_secret_sender_jid = target_sender_jid

                    if target_sender_jid.user == "":
                        if info.sender.server == jid.BOT_SERVER:
                            target_sender_jid = self.store.get_lid()
                        else:
                            target_sender_jid = self.get_own_id()
                        message_secret_sender_jid = self.get_own_id()

                    decrypt_message_id = ""
                    if (info.msg_bot_info.edit_type == message_types.BotEditType.INNER or
                            info.msg_bot_info.edit_type == message_types.BotEditType.LAST):
                        decrypt_message_id = info.msg_bot_info.edit_target_id
                    else:
                        decrypt_message_id = info.id

                    ms_msg = waE2E_pb2.MessageSecretMessage()

                    try:
                        message_secret = await self.store.msg_secrets.get_message_secret(
                            info.chat,
                            message_secret_sender_jid,
                            info.msg_meta_info.target_id
                        )

                        if not message_secret:
                            raise Exception(
                                f"message secret for {info.msg_meta_info.target_id} not found"
                            )

                        ms_msg.ParseFromString(child.content)
                        decrypted = await self.decrypt_bot_message(
                            message_secret,
                            ms_msg,
                            decrypt_message_id,
                            target_sender_jid,
                            info
                        )
                    except Exception as err:
                        raise Exception(f"failed to get message secret: {err}")
                else:
                    self.log.warning(
                        f"Unhandled encrypted message (type {enc_type}) from {info.source_string()}"
                    )
                    continue
            except Exception as err:
                if isinstance(err, EVENT_ALREADY_PROCESSED.__class__) and str(err) == str(EVENT_ALREADY_PROCESSED):
                    self.log.debug(
                        f"Ignoring message {info.id} from {info.source_string()}: {err}"
                    )
                    return
                else:
                    self.log.warning(
                        f"Error decrypting message from {info.source_string()}: {err}"
                    )
                    is_unavailable = (
                        enc_type == "skmsg" and
                        not contains_direct_msg and
                        "ErrNoSenderKeyForUser" in str(err)
                    )

                    if enc_type != "msmsg":
                        asyncio.create_task(
                            self.send_retry_receipt(node, info, is_unavailable)
                        )

                    self.dispatch_event(
                        events.UndecryptableMessage(
                            info=info,
                            is_unavailable=is_unavailable,
                            decrypt_fail_mode=events.DecryptFailMode(
                                child.attrs.get("decrypt-fail", "")
                            )
                        )
                    )
                    return

            retry_count = int(child.attrs.get("count", 0))
            self.cancel_delayed_request_from_phone(info.id)

            version = int(child.attrs.get("v", 0))
            if version == 2:
                msg = waE2E_pb2.Message()
                try:
                    msg.ParseFromString(decrypted)
                except Exception as err:
                    self.log.warning(
                        f"Error unmarshaling decrypted message from {info.source_string()}: {err}"
                    )
                    continue

                await self.handle_decrypted_message(info, msg, retry_count)
                handled = True
            elif version == 3:
                handled = await self.handle_decrypted_armadillo(info, decrypted, retry_count)
            else:
                self.log.warning(
                    f"Unknown version {version} in decrypted message from {info.source_string()}"
                )

            if ciphertext_hash and self.enable_decrypted_event_buffer:
                try:
                    await self.store.event_buffer.clear_buffered_event_plaintext(ciphertext_hash)
                    logger.debug(
                        f"Deleted event plaintext from buffer (ciphertext_hash: {ciphertext_hash.hex()})"
                    )
                except Exception as err:
                    logger.error(
                        f"Failed to clear buffered event plaintext (ciphertext_hash: {ciphertext_hash.hex()}): {err}"
                    )

                if time.time() - self.last_decrypted_buffer_clear > 12 * 60 * 60:
                    self.last_decrypted_buffer_clear = time.time()
                    asyncio.create_task(
                        self.store.event_buffer.delete_old_buffered_hashes()
                    )

        if handled:
            asyncio.create_task(self.send_message_receipt(info))

    async def clear_untrusted_identity(self, target: jid.JID) -> None:
        """
        Clear an untrusted identity.

        Args:
            target: The JID of the untrusted identity

        Raises:
            Exception: If the identity or session could not be deleted
        """
        try:
            await self.store.identities.delete_identity(target.signal_address())
        except Exception as err:
            raise Exception(f"failed to delete identity: {err}")

        try:
            await self.store.sessions.delete_session(target.signal_address())
        except Exception as err:
            raise Exception(f"failed to delete session: {err}")

        asyncio.create_task(
            self.dispatch_event(
                events.IdentityChange(
                    jid=target,
                    timestamp=time.time(),
                    implicit=True
                )
            )
        )

    async def buffered_decrypt(
        self,
        ciphertext: bytes,
        server_timestamp: int,
        decrypt_func: Callable[[], Awaitable[bytes]]
    ) -> Tuple[bytes, bytes]:
        """
        Decrypt with buffering to avoid duplicate decryption.

        Args:
            ciphertext: The ciphertext to decrypt
            server_timestamp: The server timestamp
            decrypt_func: The function to decrypt the ciphertext

        Returns:
            A tuple of (plaintext, ciphertext_hash)

        Raises:
            Exception: If decryption fails or the event was already processed
        """
        if not self.enable_decrypted_event_buffer:
            plaintext = await decrypt_func()
            return plaintext, b""

        ciphertext_hash = hashlib.sha256(ciphertext).digest()

        try:
            buf = await self.store.event_buffer.get_buffered_event(ciphertext_hash)
            if buf:
                if buf.plaintext is None:
                    logger.debug(
                        f"Returning event already processed error (ciphertext_hash: {ciphertext_hash.hex()}, insertion_time: {buf.insert_time})"
                    )
                    raise Exception(
                        f"{EVENT_ALREADY_PROCESSED} at {buf.insert_time}"
                    )

                logger.debug(
                    f"Returning previously decrypted plaintext (ciphertext_hash: {ciphertext_hash.hex()}, insertion_time: {buf.insert_time})"
                )
                return buf.plaintext, ciphertext_hash
        except Exception as err:
            raise Exception(f"failed to get buffered event: {err}")

        try:
            async with self.store.event_buffer.decryption_txn():
                plaintext = await decrypt_func()
                await self.store.event_buffer.put_buffered_event(
                    ciphertext_hash,
                    plaintext,
                    server_timestamp
                )

            logger.debug(
                f"Successfully decrypted and saved event (ciphertext_hash: {ciphertext_hash.hex()})"
            )
            return plaintext, ciphertext_hash
        except Exception as err:
            raise err

    async def decrypt_dm(
        self,
        child: binary_node.Node,
        from_jid: jid.JID,
        is_prekey: bool,
        server_ts: int
    ) -> Tuple[bytes, bytes]:
        """
        Decrypt a direct message.

        Args:
            child: The node containing the encrypted message
            from_jid: The sender JID
            is_prekey: Whether this is a prekey message
            server_ts: The server timestamp

        Returns:
            A tuple of (plaintext, ciphertext_hash)

        Raises:
            Exception: If decryption fails
        """
        content = child.content
        if not isinstance(content, bytes):
            raise Exception("message content is not a byte slice")

        builder = session.Builder.from_signal(
            self.store,
            from_jid.signal_address(),
            pb_serializer
        )
        cipher = session.Cipher(builder, from_jid.signal_address())

        if is_prekey:
            try:
                prekey_msg = protocol.PreKeySignalMessage.from_bytes(
                    content,
                    pb_serializer.pre_key_signal_message,
                    pb_serializer.signal_message
                )

                async def decrypt_prekey():
                    try:
                        return await cipher.decrypt_message(prekey_msg)
                    except Exception as err:
                        if self.auto_trust_identity and "UntrustedIdentity" in str(err):
                            self.log.warning(
                                f"Got {err} error while trying to decrypt prekey message from {from_jid}, clearing stored identity and retrying"
                            )
                            try:
                                await self.clear_untrusted_identity(from_jid)
                                return await cipher.decrypt_message(prekey_msg)
                            except Exception as inner_err:
                                raise Exception(
                                    f"failed to clear untrusted identity: {inner_err}"
                                )
                        raise err

                plaintext, ciphertext_hash = await self.buffered_decrypt(
                    content,
                    server_ts,
                    decrypt_prekey
                )

            except Exception as err:
                raise Exception(f"failed to decrypt prekey message: {err}")
        else:
            try:
                msg = protocol.SignalMessage.from_bytes(
                    content,
                    pb_serializer.signal_message
                )

                plaintext, ciphertext_hash = await self.buffered_decrypt(
                    content,
                    server_ts,
                    lambda: cipher.decrypt(msg)
                )

            except Exception as err:
                raise Exception(f"failed to decrypt normal message: {err}")

        try:
            plaintext = unpad_message(plaintext, int(child.attrs.get("v", 0)))
        except Exception as err:
            raise Exception(f"failed to unpad message: {err}")

        return plaintext, ciphertext_hash

    async def decrypt_group_msg(
        self,
        child: binary_node.Node,
        from_jid: jid.JID,
        chat: jid.JID,
        server_ts: int
    ) -> Tuple[bytes, bytes]:
        """
        Decrypt a group message.

        Args:
            child: The node containing the encrypted message
            from_jid: The sender JID
            chat: The chat JID
            server_ts: The server timestamp

        Returns:
            A tuple of (plaintext, ciphertext_hash)

        Raises:
            Exception: If decryption fails
        """
        content = child.content
        if not isinstance(content, bytes):
            raise Exception("message content is not a byte slice")

        sender_key_name = protocol.SenderKeyName(
            chat.to_string(),
            from_jid.signal_address()
        )
        builder = groups.GroupSessionBuilder(self.store, pb_serializer)
        cipher = groups.GroupCipher(builder, sender_key_name, self.store)

        try:
            msg = protocol.SenderKeyMessage.from_bytes(
                content,
                pb_serializer.sender_key_message
            )

            plaintext, ciphertext_hash = await self.buffered_decrypt(
                content,
                server_ts,
                lambda: cipher.decrypt(msg)
            )

        except Exception as err:
            raise Exception(f"failed to decrypt group message: {err}")

        try:
            plaintext = unpad_message(plaintext, int(child.attrs.get("v", 0)))
        except Exception as err:
            raise Exception(f"failed to unpad message: {err}")

        return plaintext, ciphertext_hash

def is_valid_padding(plaintext: bytes) -> bool:
    """
    Check if the padding in a message is valid.

    Args:
        plaintext: The padded message

    Returns:
        Whether the padding is valid
    """
    last_byte = plaintext[-1]
    expected_padding = bytes([last_byte] * last_byte)
    return plaintext.endswith(expected_padding)

def unpad_message(plaintext: bytes, version: int) -> bytes:
    """
    Remove padding from a message.

    Args:
        plaintext: The padded message
        version: The protocol version

    Returns:
        The unpadded message

    Raises:
        Exception: If the plaintext is empty or has invalid padding
    """
    if version == 3:
        return plaintext
    elif len(plaintext) == 0:
        raise Exception("plaintext is empty")
    elif CHECK_PADDING and not is_valid_padding(plaintext):
        raise Exception("plaintext doesn't have expected padding")
    else:
        padding_length = plaintext[-1]
        return plaintext[:-padding_length]

def pad_message(plaintext: bytes) -> bytes:
    """
    Add padding to a message.

    Args:
        plaintext: The message to pad

    Returns:
        The padded message
    """
    pad = bytearray(os.urandom(1))
    pad[0] &= 0xf
    if pad[0] == 0:
        pad[0] = 0xf

    padding = bytes([pad[0]] * pad[0])
    return plaintext + padding

class MessageProcessingMixin:
    """Additional client methods for handling messages."""

    async def handle_sender_key_distribution_message(
        self, chat: jid.JID, from_jid: jid.JID, axolotl_skdm: bytes
    ) -> None:
        """
        Handle a sender key distribution message.

        Args:
            chat: The chat JID
            from_jid: The sender JID
            axolotl_skdm: The sender key distribution message
        """
        builder = groups.GroupSessionBuilder(self.store, pb_serializer)
        sender_key_name = protocol.SenderKeyName(
            chat.to_string(),
            from_jid.signal_address()
        )

        try:
            sdk_msg = protocol.SenderKeyDistributionMessage.from_bytes(
                axolotl_skdm,
                pb_serializer.sender_key_distribution_message
            )

            await builder.process(sender_key_name, sdk_msg)
            self.log.debug(
                f"Processed sender key distribution message from {sender_key_name.sender()} in {sender_key_name.group_id()}"
            )

        except Exception as err:
            self.log.error(
                f"Failed to process sender key distribution message from {from_jid} for {chat}: {err}"
            )

    async def handle_history_sync_notification_loop(self) -> None:
        """Handle history sync notifications in a loop."""
        try:
            self.history_sync_handler_started.set(True)

            while True:
                try:
                    notif = await self.history_sync_notifications.get()
                    await self.handle_history_sync_notification(notif)
                except asyncio.CancelledError:
                    break
                except Exception as err:
                    self.log.error(f"Error handling history sync notification: {err}")

        except Exception as err:
            self.log.error(f"History sync handler failed: {err}")
        finally:
            self.history_sync_handler_started.set(False)

            # Check if new notifications appeared while we were shutting down
            if not self.history_sync_notifications.empty() and not self.history_sync_handler_started.get():
                self.log.warning(
                    "New history sync notifications appeared after loop stopped, restarting loop..."
                )
                asyncio.create_task(self.handle_history_sync_notification_loop())

    async def handle_history_sync_notification(
        self, notif: waE2E_pb2.HistorySyncNotification
    ) -> None:
        """
        Handle a history sync notification.

        Args:
            notif: The history sync notification
        """
        try:
            data = await self.download(notif)

            with io.BytesIO(data) as data_io:
                with zlib.decompressobj().decompress(data_io.read()) as raw_data:
                    history_sync = waHistorySync_pb2.HistorySync()
                    history_sync.ParseFromString(raw_data)

                    self.log.debug(
                        f"Received history sync (type {history_sync.sync_type}, chunk {history_sync.chunk_order})"
                    )

                    if history_sync.sync_type == waHistorySync_pb2.HistorySync.PUSH_NAME:
                        asyncio.create_task(
                            self.handle_historical_push_names(history_sync.pushnames)
                        )
                    elif len(history_sync.conversations) > 0:
                        asyncio.create_task(
                            self.store_historical_message_secrets(history_sync.conversations)
                        )

                    self.dispatch_event(
                        events.HistorySync(
                            data=history_sync
                        )
                    )

        except Exception as err:
            self.log.error(f"Failed to handle history sync notification: {err}")

    async def handle_app_state_sync_key_share(
        self, keys: waE2E_pb2.AppStateSyncKeyShare
    ) -> None:
        """
        Handle app state sync key share.

        Args:
            keys: The app state sync keys
        """
        only_resync_if_not_synced = True

        self.log.debug(f"Got {len(keys.keys)} new app state keys")

        async with self.app_state_key_requests_lock:
            for key in keys.keys:
                try:
                    marshaled_fingerprint = key.key_data.fingerprint.SerializeToString()

                    key_id_hex = key.key_id.key_id.hex()
                    is_re_request = key_id_hex in self.app_state_key_requests

                    if is_re_request:
                        only_resync_if_not_synced = False

                    await self.store.app_state_keys.put_app_state_sync_key(
                        key.key_id.key_id,
                        AppStateSyncKey(
                            data=key.key_data.key_data,
                            fingerprint=marshaled_fingerprint,
                            timestamp=key.key_data.timestamp
                        )
                    )

                    self.log.debug(
                        f"Received app state sync key {key.key_id.key_id.hex()} (ts: {key.key_data.timestamp})"
                    )

                except Exception as err:
                    self.log.error(
                        f"Failed to store app state sync key {key.key_id.key_id.hex()}: {err}"
                    )

        for name in ALL_PATCH_NAMES:
            try:
                await self.fetch_app_state(
                    name,
                    False,
                    only_resync_if_not_synced
                )
            except Exception as err:
                self.log.error(
                    f"Failed to do initial fetch of app state {name}: {err}"
                )

    async def handle_placeholder_resend_response(
        self, msg: waE2E_pb2.PeerDataOperationRequestResponseMessage
    ) -> None:
        """
        Handle a placeholder resend response.

        Args:
            msg: The response message
        """
        req_id = msg.stanza_id
        parts = msg.peer_data_operation_result

        self.log.debug(
            f"Handling response to placeholder resend request {req_id} with {len(parts)} items"
        )

        for i, part in enumerate(parts):
            resp = part.placeholder_message_resend_response
            if not resp:
                self.log.warning(
                    f"Missing response in item #{i+1} of response to {req_id}"
                )
                continue

            web_msg = waWeb_pb2.WebMessageInfo()
            try:
                web_msg.ParseFromString(resp.web_message_info_bytes)

                msg_evt = await self.parse_web_message(jid.JID(), web_msg)
                msg_evt.unavailable_request_id = req_id
                self.dispatch_event(msg_evt)

            except Exception as err:
                self.log.warning(
                    f"Failed to parse web message in item #{i+1} of response to {req_id}: {err}"
                )

    async def handle_protocol_message(
        self, info: message_types.MessageInfo, msg: waE2E_pb2.Message
    ) -> None:
        """
        Handle a protocol message.

        Args:
            info: The message info
            msg: The protocol message
        """
        proto_msg = msg.protocol_message

        if proto_msg.history_sync_notification and info.is_from_me:
            await self.history_sync_notifications.put(proto_msg.history_sync_notification)

            if not self.history_sync_handler_started.get():
                asyncio.create_task(self.handle_history_sync_notification_loop())

            asyncio.create_task(
                self.send_protocol_message_receipt(
                    info.id,
                    message_types.ReceiptType.HISTORY_SYNC
                )
            )

        if (proto_msg.peer_data_operation_request_response_message and
                proto_msg.peer_data_operation_request_response_message.peer_data_operation_request_type ==
                waE2E_pb2.PeerDataOperationRequestType.PLACEHOLDER_MESSAGE_RESEND):
            asyncio.create_task(
                self.handle_placeholder_resend_response(
                    proto_msg.peer_data_operation_request_response_message
                )
            )

        if proto_msg.app_state_sync_key_share and info.is_from_me:
            asyncio.create_task(
                self.handle_app_state_sync_key_share(
                    proto_msg.app_state_sync_key_share
                )
            )

        if info.category == "peer":
            asyncio.create_task(
                self.send_protocol_message_receipt(
                    info.id,
                    message_types.ReceiptType.PEER_MSG
                )
            )

    async def process_protocol_parts(
        self, info: message_types.MessageInfo, msg: waE2E_pb2.Message
    ) -> None:
        """
        Process protocol parts of a message.

        Args:
            info: The message info
            msg: The message
        """
        await self.store_message_secret(info, msg)

        # Hopefully sender key distribution messages and protocol messages can't be inside ephemeral messages
        if msg.device_sent_message and msg.device_sent_message.message:
            msg = msg.device_sent_message.message

        if msg.sender_key_distribution_message:
            if not info.is_group:
                self.log.warning(
                    f"Got sender key distribution message in non-group chat from {info.sender}"
                )
            else:
                encryption_identity = info.sender
                if (encryption_identity.server == jid.DEFAULT_USER_SERVER and
                        info.sender_alt.server == jid.HIDDEN_USER_SERVER):
                    encryption_identity = info.sender_alt

                await self.handle_sender_key_distribution_message(
                    info.chat,
                    encryption_identity,
                    msg.sender_key_distribution_message.axolotl_sender_key_distribution_message
                )

        # N.B. Edits are protocol messages, but they're also wrapped inside EditedMessage,
        # which is only unwrapped after processProtocolParts, so this won't trigger for edits.
        if msg.protocol_message:
            await self.handle_protocol_message(info, msg)

    async def store_message_secret(
        self, info: message_types.MessageInfo, msg: waE2E_pb2.Message
    ) -> None:
        """
        Store a message secret.

        Args:
            info: The message info
            msg: The message
        """
        if (msg.message_context_info and
                msg.message_context_info.message_secret):
            try:
                await self.store.msg_secrets.put_message_secret(
                    info.chat,
                    info.sender,
                    info.id,
                    msg.message_context_info.message_secret
                )
                self.log.debug(f"Stored message secret key for {info.id}")
            except Exception as err:
                self.log.error(
                    f"Failed to store message secret key for {info.id}: {err}"
                )

    async def store_historical_message_secrets(
        self, conversations: List[waHistorySync_pb2.Conversation]
    ) -> None:
        """
        Store message secrets from history sync.

        Args:
            conversations: The conversations from history sync
        """
        secrets = []
        privacy_tokens = []
        own_id = self.get_own_id().to_non_ad()

        if own_id.is_empty():
            return

        for conv in conversations:
            chat_jid = jid.JID.from_string(conv.id)
            if chat_jid.is_empty():
                continue

            if (chat_jid.server == jid.DEFAULT_USER_SERVER and
                    conv.tc_token):
                ts = conv.tc_token_sender_timestamp
                if ts == 0:
                    ts = conv.tc_token_timestamp

                privacy_tokens.append(
                    PrivacyToken(
                        user=chat_jid,
                        token=conv.tc_token,
                        timestamp=ts
                    )
                )

            for msg in conv.messages:
                if (msg.message and
                        msg.message.message_secret):
                    sender_jid = jid.JID()
                    msg_key = msg.message.key

                    if msg_key.from_me:
                        sender_jid = own_id
                    elif chat_jid.server == jid.DEFAULT_USER_SERVER:
                        sender_jid = chat_jid
                    elif msg_key.participant:
                        sender_jid = jid.JID.from_string(msg_key.participant)
                    elif msg.message.participant:
                        sender_jid = jid.JID.from_string(msg.message.participant)

                    if sender_jid.is_empty() or not msg_key.id:
                        continue

                    secrets.append(
                        MessageSecretInsert(
                            chat=chat_jid,
                            sender=sender_jid,
                            id=msg_key.id,
                            secret=msg.message.message_secret
                        )
                    )

        if secrets:
            self.log.debug(
                f"Storing {len(secrets)} message secret keys in history sync"
            )
            try:
                await self.store.msg_secrets.put_message_secrets(secrets)
                self.log.info(
                    f"Stored {len(secrets)} message secret keys from history sync"
                )
            except Exception as err:
                self.log.error(
                    f"Failed to store message secret keys in history sync: {err}"
                )

        if privacy_tokens:
            self.log.debug(
                f"Storing {len(privacy_tokens)} privacy tokens in history sync"
            )
            try:
                await self.store.privacy_tokens.put_privacy_tokens(*privacy_tokens)
                self.log.info(
                    f"Stored {len(privacy_tokens)} privacy tokens from history sync"
                )
            except Exception as err:
                self.log.error(
                    f"Failed to store privacy tokens in history sync: {err}"
                )

    async def handle_decrypted_message(
        self,
        info: message_types.MessageInfo,
        msg: waE2E_pb2.Message,
        retry_count: int
    ) -> None:
        """
        Handle a decrypted message.

        Args:
            info: The message info
            msg: The decrypted message
            retry_count: The retry count
        """
        await self.process_protocol_parts(info, msg)

        evt = events.Message(
            info=info,
            raw_message=msg,
            retry_count=retry_count
        )

        self.dispatch_event(evt.unwrap_raw())

    async def send_protocol_message_receipt(
        self, id: message_types.MessageID, msg_type: message_types.ReceiptType
    ) -> None:
        """
        Send a receipt for a protocol message.

        Args:
            id: The message ID
            msg_type: The receipt type
        """
        client_id = self.store.id
        if not id or not client_id:
            return

        try:
            await self.send_node(
                binary_node.Node(
                    tag="receipt",
                    attrs={
                        "id": id,
                        "type": msg_type,
                        "to": jid.JID(
                            user=client_id.user,
                            server=jid.LEGACY_USER_SERVER
                        ).to_string()
                    }
                )
            )
        except Exception as err:
            self.log.warning(
                f"Failed to send acknowledgement for protocol message {id}: {err}"
            )
