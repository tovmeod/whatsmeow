"""
Notification handling for WhatsApp.

Port of whatsmeow/notification.go
"""
import asyncio
import json
import logging
import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List, Callable, Set, Tuple, Union

import google.protobuf.proto

from .binary.node import Node, NodeAttributes, Attrs
from .types import events, jid
from .types.jid import JID, SERVER_JID
from .types.events.message import GroupNotification, MessageReceipt, ReceiptType
from .types.events.events import (
    Picture, IdentityChange, UserAbout, Blocklist, BlocklistAction,
    BlocklistChange, BlocklistChangeAction, NewsletterLiveUpdate,
    NewsletterJoin, NewsletterLeave, NewsletterMuteChange
)
from .types.newsletter import NewsletterMessage
from .generated.waE2E import WAE2E_pb2
from .store import PrivacyToken

# TODO: Verify import when appstate is ported
from .appstate import AppState

# TODO: Verify import when store is ported
from .store.store import Store

logger = logging.getLogger(__name__)

@dataclass
class NewsletterEventWrapper:
    """Wrapper for newsletter events from Go newsLetterEventWrapper."""
    data: 'NewsletterEvent'

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'NewsletterEventWrapper':
        """Parse from JSON data."""
        return cls(data=NewsletterEvent.from_json(data.get("data", {})))


@dataclass
class NewsletterEvent:
    """Newsletter event data from Go newsletterEvent."""
    join: Optional[NewsletterJoin] = None
    leave: Optional[NewsletterLeave] = None
    mute_change: Optional[NewsletterMuteChange] = None
    # Additional fields that might be in the Go implementation:
    # admin_metadata_update: Optional[Any] = None
    # metadata_update: Optional[Any] = None
    # state_change: Optional[Any] = None

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'NewsletterEvent':
        """Parse from JSON data."""
        join_data = data.get("xwa2_notify_newsletter_on_join")
        leave_data = data.get("xwa2_notify_newsletter_on_leave")
        mute_change_data = data.get("xwa2_notify_newsletter_on_mute_change")

        return cls(
            join=NewsletterJoin(**join_data) if join_data else None,
            leave=NewsletterLeave(**leave_data) if leave_data else None,
            mute_change=NewsletterMuteChange(**mute_change_data) if mute_change_data else None
        )

# Constants
MIN_PREKEY_COUNT = 5  # Minimum number of prekeys to maintain


class NotificationMixin:
    """
    Mixin class for notification handling functionality.

    This class contains methods for handling various types of notifications
    from the WhatsApp server.
    """

    def __init__(self, store: Store, log: Optional[logging.Logger] = None):
        """
        Initialize the client.

        Args:
            store: The store to use for persistent data
            log: Logger to use for logging
        """
        self.store = store
        self.user_devices_cache = {}
        self.user_devices_cache_lock = asyncio.Lock()

    def dispatch_event(self, evt: Any) -> None:
        """
        Dispatch an event to registered handlers.

        Args:
            evt: The event to dispatch
        """
        # This is a placeholder implementation
        logger.debug(f"Event dispatched: {evt}")

    async def handle_encrypt_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle encryption-related notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        from_jid = node.attrs.get_jid("from")
        if from_jid == jid.SERVER:
            count = node.get_child_by_tag("count")
            if not count:
                logger.warning(f"Didn't get count element in encryption notification {node.xml_string()}")
                return

            attrs = count.attrs
            otks_left = attrs.get_int("value")
            if otks_left is None:
                logger.warning(f"Didn't get number of OTKs left in encryption notification {node.xml_string()}")
                return

            logger.info(f"Got prekey count from server: {node.xml_string()}")
            if otks_left < MIN_PREKEY_COUNT:
                await self.upload_prekeys(ctx)
        elif node.get_optional_child_by_tag("identity")[0]:
            logger.debug(f"Got identity change for {from_jid}: {node.xml_string()}, deleting all identities/sessions for that number")
            try:
                await self.store.identities.delete_all_identities(from_jid.user)
            except Exception as e:
                logger.warning(f"Failed to delete all identities of {from_jid} from store after identity change: {e}")

            try:
                await self.store.sessions.delete_all_sessions(from_jid.user)
            except Exception as e:
                logger.warning(f"Failed to delete all sessions of {from_jid} from store after identity change: {e}")

            timestamp = node.attrs.get_unix_time("t")
            self.dispatch_event(IdentityChange(jid=from_jid, timestamp=timestamp))
        else:
            logger.debug(f"Got unknown encryption notification from server: {node.xml_string()}")

    async def handle_app_state_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle app state notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        for collection in node.get_children_by_tag("collection"):
            attrs = collection.attrs
            name = attrs.get_string("name")
            version = attrs.get_uint64("version")
            logger.debug(f"Got server sync notification that app state {name} has updated to version {version}")

            try:
                # TODO: Implement fetch_app_state when appstate is ported
                await self.fetch_app_state(ctx, name, False, False)
            except Exception as e:
                # There are some app state changes right before a remote logout, so stop syncing if we're disconnected
                if str(e) in ["IQDisconnected", "NotConnected"]:
                    logger.debug(f"Failed to sync app state after notification: {e}, not trying to sync other states")
                    return
                logger.error(f"Failed to sync app state after notification: {e}")

    async def handle_picture_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle profile picture change notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        timestamp = node.attrs.get_unix_time("t")
        for child in node.get_children():
            attrs = child.attrs
            evt = Picture(
                timestamp=timestamp,
                jid=attrs.get_jid("jid"),
                author=attrs.get_optional_jid("author"),
                remove=False,
                picture_id=""
            )

            if child.tag == "delete":
                evt.remove = True
            elif child.tag == "add":
                evt.picture_id = attrs.get_string("id")
            elif child.tag == "set":
                # TODO: sometimes there's a hash and no ID?
                evt.picture_id = attrs.get_string("id")
            else:
                continue

            if attrs.error:
                logger.debug(f"Ignoring picture change notification with unexpected attributes: {attrs.error}")
                continue

            self.dispatch_event(evt)

    async def handle_device_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle device list change notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        async with self.user_devices_cache_lock:
            attrs = node.attrs
            from_jid = attrs.get_jid("from")
            from_lid = attrs.get_optional_jid("lid")

            if from_lid:
                await self.store_lid_pn_mapping(ctx, from_lid, from_jid)

            cached = self.user_devices_cache.get(from_jid)
            if not cached:
                logger.debug(f"No device list cached for {from_jid}, ignoring device list notification")
                return

            cached_lid = None
            cached_lid_hash = ""
            if from_lid:
                cached_lid = self.user_devices_cache.get(from_lid)
                if cached_lid:
                    cached_lid_hash = self.participant_list_hash_v2(cached_lid.get("devices", []))

            cached_participant_hash = self.participant_list_hash_v2(cached.get("devices", []))

            for child in node.get_children():
                if child.tag not in ["add", "remove"]:
                    logger.debug(f"Unknown device list change tag {child.tag}")
                    continue

                child_attrs = child.attrs
                device_hash = child_attrs.get_string("device_hash")
                device_lid_hash = child_attrs.get_optional_string("device_lid_hash")
                device_child, _ = child.get_optional_child_by_tag("device")

                if not device_child:
                    continue

                device_attrs = device_child.attrs
                changed_device_jid = device_attrs.get_jid("jid")
                changed_device_lid = device_attrs.get_optional_jid("lid")

                if child.tag == "add":
                    cached["devices"].append(changed_device_jid)
                    if changed_device_lid and cached_lid:
                        cached_lid["devices"].append(changed_device_lid)
                elif child.tag == "remove":
                    cached["devices"] = [d for d in cached["devices"] if d != changed_device_jid]
                    if changed_device_lid and cached_lid:
                        cached_lid["devices"] = [d for d in cached_lid["devices"] if d != changed_device_lid]

                new_participant_hash = self.participant_list_hash_v2(cached["devices"])
                if new_participant_hash == device_hash:
                    logger.debug(f"{from_jid}'s device list hash changed from {cached_participant_hash} to {device_hash} ({child.tag}). New hash matches")
                    self.user_devices_cache[from_jid] = cached
                else:
                    logger.warning(f"{from_jid}'s device list hash changed from {cached_participant_hash} to {device_hash} ({child.tag}). New hash doesn't match ({new_participant_hash})")
                    if from_jid in self.user_devices_cache:
                        del self.user_devices_cache[from_jid]

                if from_lid and changed_device_lid and device_lid_hash and cached_lid:
                    new_lid_participant_hash = self.participant_list_hash_v2(cached_lid["devices"])
                    if new_lid_participant_hash == device_lid_hash:
                        logger.debug(f"{from_lid}'s device list hash changed from {cached_lid_hash} to {device_lid_hash} ({child.tag}). New hash matches")
                        self.user_devices_cache[from_lid] = cached_lid
                    else:
                        logger.warning(f"{from_lid}'s device list hash changed from {cached_lid_hash} to {device_lid_hash} ({child.tag}). New hash doesn't match ({new_lid_participant_hash})")
                        if from_lid in self.user_devices_cache:
                            del self.user_devices_cache[from_lid]

    async def handle_fb_device_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle Facebook device list notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        async with self.user_devices_cache_lock:
            from_jid = node.attrs.get_jid("from")
            devices_node = node.get_child_by_tag("devices")
            if devices_node:
                user_devices = self.parse_fb_device_list(from_jid, devices_node)
                self.user_devices_cache[from_jid] = user_devices

    async def handle_own_devices_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle notifications about changes to the user's own device list.

        Args:
            ctx: The async context
            node: The notification node
        """
        async with self.user_devices_cache_lock:
            own_id = self.get_own_id().to_non_ad()
            if own_id.is_empty():
                logger.debug("Ignoring own device change notification, session was deleted")
                return

            cached = self.user_devices_cache.get(own_id)
            if not cached:
                logger.debug("Ignoring own device change notification, device list not cached")
                return

            old_hash = self.participant_list_hash_v2(cached.get("devices", []))
            expected_new_hash = node.attrs.get_string("dhash")

            new_device_list = []
            for child in node.get_children():
                device_jid = child.attrs.get_jid("jid")
                if child.tag == "device" and not device_jid.is_empty():
                    new_device_list.append(device_jid)

            new_hash = self.participant_list_hash_v2(new_device_list)
            if new_hash != expected_new_hash:
                logger.debug(f"Received own device list change notification {old_hash} -> {new_hash}, but expected hash was {expected_new_hash}")
                if own_id in self.user_devices_cache:
                    del self.user_devices_cache[own_id]
            else:
                logger.debug(f"Received own device list change notification {old_hash} -> {new_hash}")
                self.user_devices_cache[own_id] = {"devices": new_device_list, "dhash": expected_new_hash}

    async def handle_blocklist(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle blocklist change notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        attrs = node.attrs
        evt = Blocklist(
            action=BlocklistAction(attrs.get_optional_string("action") or ""),
            d_hash=attrs.get_string("dhash"),
            prev_d_hash=attrs.get_optional_string("prev_dhash"),
            changes=[]
        )

        for child in node.get_children():
            child_attrs = child.attrs
            change = BlocklistChange(
                jid=child_attrs.get_jid("jid"),
                action=BlocklistChangeAction(child_attrs.get_string("action"))
            )

            if child_attrs.error:
                logger.warning(f"Unexpected data in blocklist event child {child.xml_string()}: {child_attrs.error}")
                continue

            evt.changes.append(change)

        self.dispatch_event(evt)

    async def handle_account_sync_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle account sync notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        for child in node.get_children():
            if child.tag == "privacy":
                await self.handle_privacy_settings_notification(ctx, child)
            elif child.tag == "devices":
                await self.handle_own_devices_notification(ctx, child)
            elif child.tag == "picture":
                self.dispatch_event(Picture(
                    timestamp=node.attrs.get_unix_time("t"),
                    jid=self.get_own_id().to_non_ad(),
                    author=None,
                    remove=False,
                    picture_id=""
                ))
            elif child.tag == "blocklist":
                await self.handle_blocklist(ctx, child)
            else:
                logger.debug(f"Unhandled account sync item {child.tag}")

    async def handle_privacy_token_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle privacy token notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        own_id = self.get_own_id().to_non_ad()
        if own_id.is_empty():
            logger.debug("Ignoring privacy token notification, session was deleted")
            return

        tokens = node.get_child_by_tag("tokens")
        if not tokens or tokens.tag != "tokens":
            logger.warning("privacy_token notification didn't contain <tokens> tag")
            return

        parent_attrs = node.attrs
        sender = parent_attrs.get_jid("from")
        if parent_attrs.error:
            logger.warning(f"privacy_token notification didn't have a sender ({parent_attrs.error})")
            return

        for child in tokens.get_children():
            attrs = child.attrs
            if child.tag != "token":
                logger.warning(f"privacy_token notification contained unexpected <{child.tag}> tag")
                continue

            target_user = attrs.get_jid("jid")
            if target_user != own_id:
                logger.warning(f"privacy_token notification contained token for different user {target_user}")
                continue

            token_type = attrs.get_string("type")
            if token_type != "trusted_contact":
                logger.warning(f"privacy_token notification contained unexpected token type {token_type}")
                continue

            if not isinstance(child.content, bytes):
                logger.warning("privacy_token notification contained non-binary token")
                continue

            timestamp = attrs.get_unix_time("t")
            if attrs.error:
                logger.warning(f"privacy_token notification is missing some fields: {attrs.error}")

            try:
                await self.store.privacy_tokens.put_privacy_tokens(ctx, {
                    "user": sender,
                    "token": child.content,
                    "timestamp": timestamp
                })
                logger.debug(f"Stored privacy token from {sender} (ts: {timestamp})")
            except Exception as e:
                logger.error(f"Failed to save privacy token from {sender}: {e}")

    def parse_newsletter_messages(self, node: Node) -> List[Dict[str, Any]]:
        """
        Parse newsletter messages from a notification node.

        Args:
            node: The notification node

        Returns:
            List of parsed newsletter messages
        """
        children = node.get_children()
        output = []

        for child in children:
            if child.tag != "message":
                continue

            attrs = child.attrs
            msg = {
                "message_server_id": attrs.get_int("server_id"),
                "message_id": attrs.get_string("id"),
                "type": attrs.get_string("type"),
                "timestamp": attrs.get_unix_time("t"),
                "views_count": 0,
                "reaction_counts": None,
                "message": None
            }

            for subchild in child.get_children():
                if subchild.tag == "plaintext":
                    if isinstance(subchild.content, bytes):
                        try:
                            message = WAE2E_pb2.Message()
                            message.ParseFromString(subchild.content)
                            msg["message"] = message
                        except Exception as e:
                            logger.warning(f"Failed to unmarshal newsletter message: {e}")
                elif subchild.tag == "views_count":
                    msg["views_count"] = subchild.attrs.get_int("count")
                elif subchild.tag == "reactions":
                    msg["reaction_counts"] = {}
                    for reaction in subchild.get_children():
                        reaction_attrs = reaction.attrs
                        msg["reaction_counts"][reaction_attrs.get_string("code")] = reaction_attrs.get_int("count")

            output.append(msg)

        return output

    async def handle_newsletter_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle newsletter notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        attrs = node.attrs
        live_updates = node.get_child_by_tag("live_updates")
        if live_updates:
            self.dispatch_event(NewsletterLiveUpdate(
                jid=attrs.get_jid("from"),
                time=attrs.get_unix_time("t"),
                messages=self.parse_newsletter_messages(live_updates)
            ))

    async def handle_mex_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle mex notifications (used for newsletter events).

        Args:
            ctx: The async context
            node: The notification node
        """
        for child in node.get_children():
            if child.tag != "update":
                continue

            if not isinstance(child.content, bytes):
                continue

            try:
                wrapper = json.loads(child.content)
                data = wrapper.get("data", {})

                join_data = data.get("xwa2_notify_newsletter_on_join")
                if join_data:
                    self.dispatch_event(NewsletterJoin(**join_data))
                    continue

                leave_data = data.get("xwa2_notify_newsletter_on_leave")
                if leave_data:
                    self.dispatch_event(NewsletterLeave(**leave_data))
                    continue

                mute_change_data = data.get("xwa2_notify_newsletter_on_mute_change")
                if mute_change_data:
                    self.dispatch_event(NewsletterMuteChange(**mute_change_data))
            except json.JSONDecodeError as e:
                logger.error(f"Failed to unmarshal JSON in mex event: {e}")

    async def handle_status_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle status update notifications.

        Args:
            ctx: The async context
            node: The notification node
        """
        attrs = node.attrs
        child, found = node.get_optional_child_by_tag("set")
        if not found:
            logger.debug("Status notification did not contain child with tag 'set'")
            return

        if not isinstance(child.content, bytes):
            logger.warning(f"Set status notification has unexpected content ({type(child.content)})")
            return

        self.dispatch_event(UserAbout(
            jid=attrs.get_jid("from"),
            timestamp=attrs.get_unix_time("t"),
            status=child.content.decode("utf-8")
        ))

    async def handle_notification(self, node: Node) -> None:
        """
        Handle a notification from WhatsApp.

        Args:
            node: The notification node
        """
        ctx = asyncio.get_event_loop()
        attrs = node.attrs
        notif_type = attrs.get_string("type")

        if attrs.error:
            return

        # Defer acknowledgment of the notification
        # self.maybe_deferred_ack(node)

        if notif_type == "encrypt":
            asyncio.create_task(self.handle_encrypt_notification(ctx, node))
        elif notif_type == "server_sync":
            asyncio.create_task(self.handle_app_state_notification(ctx, node))
        elif notif_type == "account_sync":
            asyncio.create_task(self.handle_account_sync_notification(ctx, node))
        elif notif_type == "devices":
            await self.handle_device_notification(ctx, node)
        elif notif_type == "fbid:devices":
            await self.handle_fb_device_notification(ctx, node)
        elif notif_type == "w:gp2":
            try:
                evt = await self.parse_group_notification(node)
                self.dispatch_event(evt)
            except Exception as e:
                logger.error(f"Failed to parse group notification: {e}")
        elif notif_type == "picture":
            await self.handle_picture_notification(ctx, node)
        elif notif_type == "mediaretry":
            await self.handle_media_retry_notification(ctx, node)
        elif notif_type == "privacy_token":
            await self.handle_privacy_token_notification(ctx, node)
        elif notif_type == "link_code_companion_reg":
            asyncio.create_task(self.try_handle_code_pair_notification(ctx, node))
        elif notif_type == "newsletter":
            await self.handle_newsletter_notification(ctx, node)
        elif notif_type == "mex":
            await self.handle_mex_notification(ctx, node)
        elif notif_type == "status":
            await self.handle_status_notification(ctx, node)
        else:
            logger.warning(f"Unhandled notification with type {notif_type}")

    # Helper methods that would be implemented elsewhere in the client
    def get_own_id(self):
        """Get the client's own JID."""
        # Placeholder implementation
        return jid.JID(user="", server="", device=0)

    async def upload_prekeys(self, ctx):
        """Upload prekeys to the server."""
        # Placeholder implementation
        logger.info("Uploading prekeys")

    async def store_lid_pn_mapping(self, ctx, lid, pn):
        """Store a mapping between a LID and a phone number."""
        # Placeholder implementation
        logger.debug(f"Storing LID-PN mapping: {lid} -> {pn}")

    def participant_list_hash_v2(self, participants: List[JID]) -> str:
        """
        Generate participant list hash v2 from device list.

        Args:
            participants: List of JID objects representing devices

        Returns:
            A hash string in the format "2:<base64-encoded-hash>"
        """
        # Convert JIDs to strings using their AD representation
        participant_strings = [part.ad_string() for part in participants]

        # Sort the strings
        participant_strings.sort()

        # Join the strings and compute SHA-256 hash
        joined = "".join(participant_strings)
        hash_bytes = hashlib.sha256(joined.encode()).digest()

        # Encode the first 6 bytes of the hash in base64
        import base64
        encoded = base64.b64encode(hash_bytes[:6], altchars=b'-_').decode().rstrip('=')

        # Return the hash in the format "2:<base64-encoded-hash>"
        return f"2:{encoded}"

    def parse_fb_device_list(self, jid: JID, devices_node: Node) -> Dict[str, Any]:
        """
        Parse Facebook device list from node.

        Args:
            jid: The JID of the user
            devices_node: The node containing the device list

        Returns:
            A dictionary containing the devices and hash
        """
        children = devices_node.get_children()
        devices = []

        for device in children:
            device_id = device.attrs.get_int("id")
            if device.tag != "device" or device_id is None:
                continue

            # Create a copy of the JID with the device ID
            device_jid = JID(user=jid.user, server=jid.server, device=device_id)
            devices.append(device_jid)

        # Return a dictionary similar to the Go deviceCache struct
        return {
            "devices": devices,
            "dhash": devices_node.attrs.get_string("dhash")
        }

    async def parse_group_notification(self, node):
        """Parse a group notification."""
        # Placeholder implementation
        return GroupNotification()

    async def handle_media_retry_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle media retry notifications.

        This method is implemented in mediaretry.go in the Go version.

        Args:
            ctx: The async context
            node: The notification node
        """
        # TODO: Implement based on mediaretry.go
        logger.debug(f"Handling media retry notification: {node.xml_string()}")

    async def handle_privacy_settings_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle privacy settings notifications.

        This method is implemented in privacysettings.go in the Go version.

        Args:
            ctx: The async context
            node: The notification node
        """
        # TODO: Implement based on privacysettings.go
        logger.debug(f"Handling privacy settings notification: {node.xml_string()}")

    async def try_handle_code_pair_notification(self, ctx: asyncio.Context, node: Node) -> None:
        """
        Handle code pair notifications.

        This method is implemented in pair-code.go in the Go version.

        Args:
            ctx: The async context
            node: The notification node
        """
        # TODO: Implement based on pair-code.go
        logger.debug(f"Handling code pair notification: {node.xml_string()}")

    async def fetch_app_state(self, ctx, name, force, full):
        """Fetch app state from the server."""
        # Placeholder implementation
        logger.debug(f"Fetching app state: {name}")


class Client(NotificationMixin):
    """
    WhatsApp client implementation.

    This class inherits from NotificationMixin to include all notification
    handling functionality. It serves as the main client interface.
    """
    pass
