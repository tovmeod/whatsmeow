"""
Notification handling for WhatsApp.

Port of whatsmeow/notification.go
"""
import json
import logging
from typing import TYPE_CHECKING, Any, List

from . import appstate
from .appstate import WAPatchName
from .binary.node import Node
from .datatypes import events
from .datatypes.jid import JID
from .datatypes.message import MessageID, MessageServerID
from .generated.waE2E import WAWebProtobufsE2E_pb2
from .prekeys import upload_prekeys

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)

MIN_PREKEY_COUNT = 5


async def handle_encrypt_notification(client: "Client", node: Node) -> None:
    """Handle encryption-related notifications."""
    from_jid = node.attr_getter().jid("from")

    if from_jid == JID.server_jid():
        count = node.get_child_by_tag("count")
        ag = count.attr_getter()
        otks_left = ag.int("value")
        if not ag.ok():
            logger.warning(f"Didn't get number of OTKs left in encryption notification {node.xml_string()}")
            return
        logger.info(f"Got prekey count from server: {node.xml_string()}")
        if otks_left < MIN_PREKEY_COUNT:
            await upload_prekeys(client)
    elif node.get_optional_child_by_tag("identity")[0] is not None:
        logger.debug(f"Got identity change for {from_jid}: {node.xml_string()}, deleting all identities/sessions for that number")
        try:
            await client.store.identities.delete_all_identities(from_jid.user)
        except Exception as err:
            logger.warning(f"Failed to delete all identities of {from_jid} from store after identity change: {err}")

        try:
            await client.store.sessions.delete_all_sessions(from_jid.user)
        except Exception as err:
            logger.warning(f"Failed to delete all sessions of {from_jid} from store after identity change: {err}")

        ts = node.attr_getter().unix_time("t")
        await client.dispatch_event(events.IdentityChange(jid=from_jid, timestamp=ts))
    else:
        logger.debug(f"Got unknown encryption notification from server: {node.xml_string()}")


async def handle_app_state_notification(client: "Client", node: Node) -> None:
    """Handle app state synchronization notifications."""
    for collection in node.get_children_by_tag("collection"):
        ag = collection.attr_getter()
        name = WAPatchName(ag.string("name"))
        version = ag.uint64("version")
        logger.debug(f"Got server sync notification that app state {name} has updated to version {version}")

        try:
            await appstate.fetch_app_state(client, name, False, False)
        except Exception as err:
            # Check for specific disconnection errors
            if "disconnected" in str(err).lower() or "not connected" in str(err).lower():
                logger.debug(f"Failed to sync app state after notification: {err}, not trying to sync other states")
                return
            else:
                logger.error(f"Failed to sync app state after notification: {err}")


async def handle_picture_notification(client: "Client", node: Node) -> None:
    """Handle profile picture change notifications."""
    ts = node.attr_getter().unix_time("t")
    for child in node.get_children():
        ag = child.attr_getter()
        jid = ag.jid("jid")
        author = ag.optional_jid_or_empty("author")

        evt = events.Picture(
            timestamp=ts,
            jid=jid,
            author=author
        )

        if child.tag == "delete":
            evt.remove = True
        elif child.tag == "add":
            evt.picture_id = ag.string("id")
        elif child.tag == "set":
            # TODO: sometimes there's a hash and no ID?
            evt.picture_id = ag.string("id")
        else:
            continue

        if not ag.ok():
            logger.debug(f"Ignoring picture change notification with unexpected attributes: {ag.error()}")
            continue

        await client.dispatch_event(evt)


async def handle_device_notification(client: "Client", node: Node) -> None:
    """Handle device list change notifications."""
    async with client.user_devices_cache_lock:
        ag = node.attr_getter()
        from_jid = ag.jid("from")
        from_lid = ag.optional_jid("lid")

        if from_lid is not None:
            await client.store_lid_pn_mapping(from_lid, from_jid)

        cached = client.user_devices_cache.get(from_jid)
        if cached is None:
            logger.debug(f"No device list cached for {from_jid}, ignoring device list notification")
            return

        cached_lid = None
        cached_lid_hash = ""
        if from_lid is not None:
            cached_lid = client.user_devices_cache.get(from_lid)
            if cached_lid is not None:
                cached_lid_hash = participant_list_hash_v2(cached_lid.devices)

        cached_participant_hash = participant_list_hash_v2(cached.devices)

        for child in node.get_children():
            if child.tag not in ("add", "remove"):
                logger.debug(f"Unknown device list change tag {child.tag}")
                continue

            cag = child.attr_getter()
            device_hash = cag.string("device_hash")
            device_lid_hash = cag.optional_string("device_lid_hash")
            device_child, _ = child.get_optional_child_by_tag("device")
            changed_device_jid = device_child.attr_getter().jid("jid")
            changed_device_lid = device_child.attr_getter().optional_jid("lid")

            if child.tag == "add":
                cached.devices.append(changed_device_jid)
                if changed_device_lid is not None and cached_lid is not None:
                    cached_lid.devices.append(changed_device_lid)
            elif child.tag == "remove":
                cached.devices = [d for d in cached.devices if d != changed_device_jid]
                if changed_device_lid is not None and cached_lid is not None:
                    cached_lid.devices = [d for d in cached_lid.devices if d != changed_device_lid]

            new_participant_hash = participant_list_hash_v2(cached.devices)
            if new_participant_hash == device_hash:
                logger.debug(f"{from_jid}'s device list hash changed from {cached_participant_hash} to {device_hash} ({child.tag}). New hash matches")
                client.user_devices_cache[from_jid] = cached
            else:
                logger.warning(f"{from_jid}'s device list hash changed from {cached_participant_hash} to {device_hash} ({child.tag}). New hash doesn't match ({new_participant_hash})")
                client.user_devices_cache.pop(from_jid, None)

            if from_lid is not None and changed_device_lid is not None and device_lid_hash and cached_lid is not None:
                new_lid_participant_hash = participant_list_hash_v2(cached_lid.devices)
                if new_lid_participant_hash == device_lid_hash:
                    logger.debug(f"{from_lid}'s device list hash changed from {cached_lid_hash} to {device_lid_hash} ({child.tag}). New hash matches")
                    client.user_devices_cache[from_lid] = cached_lid
                else:
                    logger.warning(f"{from_lid}'s device list hash changed from {cached_lid_hash} to {device_lid_hash} ({child.tag}). New hash doesn't match ({new_lid_participant_hash})")
                    client.user_devices_cache.pop(from_lid, None)


async def handle_fb_device_notification(client: "Client", node: Node) -> None:
    """Handle Facebook device list notifications."""
    async with client.user_devices_cache_lock:
        jid = node.attr_getter().jid("from")
        user_devices = parse_fb_device_list(jid, node.get_child_by_tag("devices"))
        client.user_devices_cache[jid] = user_devices


async def handle_own_devices_notification(client: "Client", node: Node) -> None:
    """Handle own device list change notifications."""
    async with client.user_devices_cache_lock:
        own_id = get_own_id(client).to_non_ad()
        if own_id.is_empty():
            logger.debug("Ignoring own device change notification, session was deleted")
            return

        cached = client.user_devices_cache.get(own_id)
        if cached is None:
            logger.debug("Ignoring own device change notification, device list not cached")
            return

        old_hash = participant_list_hash_v2(cached.devices)
        expected_new_hash = node.attr_getter().string("dhash")
        new_device_list = []

        for child in node.get_children():
            jid = child.attr_getter().jid("jid")
            if child.tag == "device" and not jid.is_empty():
                new_device_list.append(jid)

        new_hash = participant_list_hash_v2(new_device_list)
        if new_hash != expected_new_hash:
            logger.debug(f"Received own device list change notification {old_hash} -> {new_hash}, but expected hash was {expected_new_hash}")
            client.user_devices_cache.pop(own_id, None)
        else:
            logger.debug(f"Received own device list change notification {old_hash} -> {new_hash}")
            from .client import DeviceCache
            client.user_devices_cache[own_id] = DeviceCache(devices=new_device_list, dhash=expected_new_hash)


async def handle_blocklist(client: "Client", node: Node) -> None:
    """Handle blocklist change notifications."""
    ag = node.attr_getter()
    evt = events.Blocklist(
        action=events.BlocklistAction(ag.optional_string("action") or ""),
        d_hash=ag.string("dhash"),
        prev_d_hash=ag.optional_string("prev_dhash")
    )

    for child in node.get_children():
        ag = child.attr_getter()
        change = events.BlocklistChange(
            jid=ag.jid("jid"),
            action=events.BlocklistChangeAction(ag.string("action"))
        )
        if not ag.ok():
            logger.warning(f"Unexpected data in blocklist event child {child.xml_string()}: {ag.error()}")
            continue
        evt.changes.append(change)

    await client.dispatch_event(evt)


async def handle_account_sync_notification(client: "Client", node: Node) -> None:
    """Handle account synchronization notifications."""
    for child in node.get_children():
        if child.tag == "privacy":
            await handle_privacy_settings_notification(client, child)
        elif child.tag == "devices":
            await handle_own_devices_notification(client, child)
        elif child.tag == "picture":
            await client.dispatch_event(events.Picture(
                jid=get_own_id(client).to_non_ad(),
                author=get_own_id(client).to_non_ad(),
                timestamp=node.attr_getter().unix_time("t"),
            ))
        elif child.tag == "blocklist":
            await handle_blocklist(client, child)
        else:
            logger.debug(f"Unhandled account sync item {child.tag}")


async def handle_privacy_token_notification(client: "Client", node: Node) -> None:
    """Handle privacy token notifications."""
    own_id = get_own_id(client).to_non_ad()
    if own_id.is_empty():
        logger.debug("Ignoring privacy token notification, session was deleted")
        return

    tokens = node.get_child_by_tag("tokens")
    if tokens.tag != "tokens":
        logger.warning("privacy_token notification didn't contain <tokens> tag")
        return

    parent_ag = node.attr_getter()
    sender = parent_ag.jid("from")
    if not parent_ag.ok():
        logger.warning(f"privacy_token notification didn't have a sender ({parent_ag.error()})")
        return

    for child in tokens.get_children():
        ag = child.attr_getter()
        if child.tag != "token":
            logger.warning(f"privacy_token notification contained unexpected <{child.tag}> tag")
        else:
            target_user = ag.jid("jid")
            if target_user != own_id:
                logger.warning(f"privacy_token notification contained token for different user {target_user}")
                continue

            token_type = ag.string("type")
            if token_type != "trusted_contact":
                logger.warning(f"privacy_token notification contained unexpected token type {token_type}")
                continue

            if not isinstance(child.content, bytes):
                logger.warning("privacy_token notification contained non-binary token")
                continue

            timestamp = ag.unix_time("t")
            if not ag.ok():
                logger.warning(f"privacy_token notification is missing some fields: {ag.error()}")

            try:
                from .store.store import PrivacyToken
                await client.store.privacy_tokens.put_privacy_tokens([PrivacyToken(
                    user=sender,
                    token=child.content,
                    timestamp=timestamp
                )])
                logger.debug(f"Stored privacy token from {sender} (ts: {timestamp})")
            except Exception as err:
                logger.error(f"Failed to save privacy token from {sender}: {err}")


def parse_newsletter_messages(client: "Client", node: Node) -> List[Any]:
    """Parse newsletter messages from a node."""
    children = node.get_children()
    output = []

    for child in children:
        if child.tag != "message":
            continue

        ag = child.attr_getter()
        from .datatypes.newsletter import NewsletterMessage
        msg = NewsletterMessage(
            message_server_id=MessageServerID(ag.int("server_id")),
            message_id=MessageID(ag.string("id")),
            type=ag.string("type"),
            timestamp=ag.unix_time("t"),
            views_count=0,
            reaction_counts={}
        )

        for subchild in child.get_children():
            if subchild.tag == "plaintext":
                if isinstance(subchild.content, bytes):
                    try:
                        msg.message = WAWebProtobufsE2E_pb2.Message() # type: ignore[attr-defined]
                        msg.message.ParseFromString(subchild.content)
                    except Exception as err:
                        logger.warning(f"Failed to unmarshal newsletter message: {err}")
                        msg.message = None
            elif subchild.tag == "views_count":
                msg.views_count = subchild.attr_getter().int("count")
            elif subchild.tag == "reactions":
                msg.reaction_counts = {}
                for reaction in subchild.get_children():
                    rag = reaction.attr_getter()
                    msg.reaction_counts[rag.string("code")] = rag.int("count")

        output.append(msg)
    return output


async def handle_newsletter_notification(client: "Client", node: Node) -> None:
    """Handle newsletter live update notifications."""
    ag = node.attr_getter()
    live_updates = node.get_child_by_tag("live_updates")

    await client.dispatch_event(events.NewsletterLiveUpdate(
        jid=ag.jid("from"),
        time=ag.unix_time("t"),
        messages=parse_newsletter_messages(client, live_updates)
    ))


async def handle_mex_notification(client: "Client", node: Node) -> None:
    """Handle mex notifications (newsletter events)."""
    for child in node.get_children():
        if child.tag != "update":
            continue

        if not isinstance(child.content, bytes):
            continue

        try:
            data = json.loads(child.content.decode('utf-8'))
            wrapper_data = data.get("data", {})

            if "xwa2_notify_newsletter_on_join" in wrapper_data:
                join_event = wrapper_data["xwa2_notify_newsletter_on_join"]
                await client.dispatch_event(events.NewsletterJoin(**join_event))
            elif "xwa2_notify_newsletter_on_leave" in wrapper_data:
                leave_event = wrapper_data["xwa2_notify_newsletter_on_leave"]
                await client.dispatch_event(events.NewsletterLeave(**leave_event))
            elif "xwa2_notify_newsletter_on_mute_change" in wrapper_data:
                mute_event = wrapper_data["xwa2_notify_newsletter_on_mute_change"]
                await client.dispatch_event(events.NewsletterMuteChange(**mute_event))
        except Exception as err:
            logger.error(f"Failed to unmarshal JSON in mex event: {err}")


async def handle_status_notification(client: "Client", node: Node) -> None:
    """Handle status/about change notifications."""
    ag = node.attr_getter()
    child, found = node.get_optional_child_by_tag("set")
    if not found:
        logger.debug("Status notification did not contain child with tag 'set'")
        return

    if not isinstance(child.content, bytes):
        logger.warning(f"Set status notification has unexpected content ({type(child.content)})")
        return

    await client.dispatch_event(events.UserAbout(
        jid=ag.jid("from"),
        timestamp=ag.unix_time("t"),
        status=child.content.decode('utf-8')
    ))


async def handle_notification(client: "Client", node: Node) -> None:
    """Main notification handler that dispatches to specific handlers."""
    ag = node.attr_getter()
    notif_type = ag.string("type")
    if not ag.ok():
        return

    # TODO: Implement maybeDeferredAck

    if notif_type == "encrypt":
        await handle_encrypt_notification(client, node)
    elif notif_type == "server_sync":
        await handle_app_state_notification(client, node)
    elif notif_type == "account_sync":
        await handle_account_sync_notification(client, node)
    elif notif_type == "devices":
        await handle_device_notification(client, node)
    elif notif_type == "fbid:devices":
        await handle_fb_device_notification(client, node)
    elif notif_type == "w:gp2":
        try:
            evt = await parse_group_notification(client, node)
            await client.dispatch_event(evt)
        except Exception as err:
            logger.error(f"Failed to parse group notification: {err}")
    elif notif_type == "picture":
        await handle_picture_notification(client, node)
    elif notif_type == "mediaretry":
        await handle_media_retry_notification(client, node)
    elif notif_type == "privacy_token":
        await handle_privacy_token_notification(client, node)
    elif notif_type == "link_code_companion_reg":
        await try_handle_code_pair_notification(client, node)
    elif notif_type == "newsletter":
        await handle_newsletter_notification(client, node)
    elif notif_type == "mex":
        await handle_mex_notification(client, node)
    elif notif_type == "status":
        await handle_status_notification(client, node)
    else:
        logger.debug(f"Unhandled notification with type {notif_type}")


# Helper functions that need to be implemented elsewhere or imported
def get_own_id(client: "Client") -> JID:
    """Get the client's own JID."""
    # This should be implemented in the client
    return client.get_own_id()


def participant_list_hash_v2(devices: List[JID]) -> str:
    """Calculate participant list hash v2."""
    # This should be implemented based on the Go version
    # Placeholder implementation
    return ""


def parse_fb_device_list(jid: JID, node: Node) -> Any:
    """Parse Facebook device list."""
    # This should be implemented based on the Go version
    # Placeholder implementation
    from .client import DeviceCache
    return DeviceCache(devices=[], dhash="")


async def handle_privacy_settings_notification(client: "Client", node: Node) -> None:
    """Handle privacy settings notifications."""
    # This should be implemented based on the Go version
    pass


async def handle_media_retry_notification(client: "Client", node: Node) -> None:
    """Handle media retry notifications."""
    # This should be implemented based on the Go version
    pass


async def parse_group_notification(client: "Client", node: Node) -> Any:
    """Parse group notifications."""
    # This should be implemented based on the Go version
    pass


async def try_handle_code_pair_notification(client: "Client", node: Node) -> None:
    """Handle code pair notifications."""
    # This should be implemented based on the Go version
    pass
