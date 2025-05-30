"""
Presence handling for WhatsApp.

Port of whatsmeow/presence.go
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any, List

from .binary.node import Node, Attrs
from .exceptions import NoPushNameError, NoPrivacyTokenError
from .types.jid import JID
from .types.presence import Presence, ChatPresence, ChatPresenceMedia
from .types.events import PresenceEvent, ChatPresenceEvent
from .types.message import MessageSource

logger = logging.getLogger(__name__)


async def handle_chat_state(client, node: Node) -> None:
    """
    Handle a chat state update (typing notification).

    Args:
        client: The client instance
        node: The chat state node
    """
    try:
        source, err = client.parse_message_source(node, True)
        if err:
            logger.warning(f"Failed to parse chat state update: {err}")
            return

        if len(node.children) != 1:
            logger.warning(f"Failed to parse chat state update: unexpected number of children in element ({len(node.children)})")
            return

        child = node.children[0]
        presence = ChatPresence(child.tag)

        if presence != ChatPresence.COMPOSING and presence != ChatPresence.PAUSED:
            logger.warning(f"Unrecognized chat presence state {child.tag}")
            return

        media = ChatPresenceMedia.TEXT
        if presence == ChatPresence.COMPOSING:
            media_attr = child.attrs.get("media", "")
            if media_attr:
                media = ChatPresenceMedia(media_attr)

        await client.dispatch_event(ChatPresenceEvent(
            message_source=source,
            state=presence,
            media=media
        ))
    except Exception as e:
        logger.error(f"Error handling chat state: {e}")


async def handle_presence(client, node: Node) -> None:
    """
    Handle a presence update.

    Args:
        client: The client instance
        node: The presence node
    """
    try:
        evt = PresenceEvent(
            from_jid=JID.from_string(node.attrs.get("from", "")),
            unavailable=False
        )

        presence_type = node.attrs.get("type", "")
        if presence_type == "unavailable":
            evt.unavailable = True
        elif presence_type:
            logger.debug(f"Unrecognized presence type '{presence_type}' in presence event from {evt.from_jid}")

        last_seen = node.attrs.get("last", "")
        if last_seen and last_seen != "deny":
            try:
                timestamp = int(last_seen)
                evt.last_seen = datetime.fromtimestamp(timestamp)
            except ValueError:
                logger.warning(f"Invalid last seen timestamp: {last_seen}")

        await client.dispatch_event(evt)
    except Exception as e:
        logger.error(f"Error handling presence: {e}")


async def send_presence(client, state: Presence) -> None:
    """
    Update the user's presence status on WhatsApp.

    You should call this at least once after connecting so that the server has your pushname.
    Otherwise, other users will see "-" as the name.

    Args:
        client: The client instance
        state: The presence state to send

    Raises:
        NoPushNameError: If the client's push name is not set
    """
    if not client.store.push_name:
        raise NoPushNameError()

    if state == Presence.AVAILABLE:
        client.send_active_receipts = 1
    else:
        client.send_active_receipts = 0

    await client.send_node(Node(
        tag="presence",
        attrs=Attrs({
            "name": client.store.push_name,
            "type": state.value
        })
    ))


async def subscribe_presence(client, jid: JID) -> None:
    """
    Ask the WhatsApp servers to send presence updates of a specific user to this client.

    After subscribing to this event, you should start receiving PresenceEvent for that user
    in normal event handlers.

    Also, it seems that the WhatsApp servers require you to be online to receive presence status
    from other users, so you should mark yourself as online before trying to use this function:

        await client.send_presence(Presence.AVAILABLE)

    Args:
        client: The client instance
        jid: The JID to subscribe to

    Raises:
        NoPrivacyTokenError: If the client doesn't have a privacy token for the user and
                            ErrorOnSubscribePresenceWithoutToken is set
    """
    privacy_token, err = await client.store.privacy_tokens.get_privacy_token(None, jid)
    if err:
        raise Exception(f"Failed to get privacy token: {err}")
    elif not privacy_token:
        if client.error_on_subscribe_presence_without_token:
            raise NoPrivacyTokenError(f"No privacy token for {jid}")
        else:
            logger.debug(f"Trying to subscribe to presence of {jid} without privacy token")

    req = Node(
        tag="presence",
        attrs=Attrs({
            "type": "subscribe",
            "to": str(jid)
        })
    )

    if privacy_token:
        req.children = [Node(
            tag="tctoken",
            content=privacy_token.token
        )]

    await client.send_node(req)


async def send_chat_presence(client, jid: JID, state: ChatPresence, media: ChatPresenceMedia = None) -> None:
    """
    Update the user's typing status in a specific chat.

    The media parameter can be set to indicate the user is recording media (like a voice message)
    rather than typing a text message.

    Args:
        client: The client instance
        jid: The JID of the chat
        state: The chat presence state
        media: The media type (only used with COMPOSING state)
    """
    own_id = client.get_own_id()
    if own_id.is_empty():
        raise Exception("Not logged in")

    content = [Node(tag=state.value)]

    if state == ChatPresence.COMPOSING and media:
        content[0].attrs = Attrs({
            "media": media.value
        })

    await client.send_node(Node(
        tag="chatstate",
        attrs=Attrs({
            "from": str(own_id),
            "to": str(jid)
        }),
        children=content
    ))
