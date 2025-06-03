"""
Presence handling for WhatsApp.

Port of whatsmeow/presence.go
"""
import logging
from datetime import datetime
from typing import Optional

from .binary.node import Node, Attrs
from .exceptions import NoPushNameError, ErrNotLoggedIn, NoPrivacyTokenError
from .types.jid import JID
from .types.presence import Presence, ChatPresence, ChatPresenceMedia
from .types.events.events import PresenceEvent, ChatPresenceEvent

logger = logging.getLogger(__name__)


async def handle_chat_state(client, node: Node) -> None:
    """
    Handle a chat state update (typing notification).

    Args:
        client: The client instance
        node: The chat state node
    """
    try:
        source = await client.parse_message_source(node, True)
        if source is None:
            logger.warning("Failed to parse chat state update")
            return

        children = node.get_children()
        if len(children) != 1:
            logger.warning(f"Failed to parse chat state update: unexpected number of children in element ({len(children)})")
            return

        child = children[0]
        presence = ChatPresence(child.tag)

        if presence != ChatPresence.COMPOSING and presence != ChatPresence.PAUSED:
            logger.warning(f"Unrecognized chat presence state {child.tag}")
            return

        ag = child.attr_getter()
        media = ChatPresenceMedia(ag.optional_string("media") or "")

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
        ag = node.attr_getter()
        from_jid = ag.jid("from")

        evt = PresenceEvent(
            from_jid=from_jid,
            unavailable=False,
            last_seen=None
        )

        presence_type = ag.optional_string("type")
        if presence_type == "unavailable":
            evt.unavailable = True
        elif presence_type:
            logger.debug(f"Unrecognized presence type '{presence_type}' in presence event from {evt.from_jid}")

        last_seen = ag.optional_string("last")
        if last_seen and last_seen != "deny":
            evt.last_seen = ag.unix_time("last")

        if not ag.ok():
            logger.warning(f"Error parsing presence event: {ag.errors}")
        else:
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
    if not len(client.store.push_name):
        raise NoPushNameError()

    if state == Presence.AVAILABLE:
        client.send_active_receipts.compare_and_swap(0, 1)
    else:
        client.send_active_receipts.compare_and_swap(1, 0)

    await client.send_node(Node(
        tag="presence",
        attributes=Attrs({
            "name": client.store.push_name,
            "type": str(state)
        })
    ))


async def subscribe_presence(client, jid: JID) -> None:
    """
    Ask the WhatsApp servers to send presence updates of a specific user to this client.

    After subscribing to this event, you should start receiving PresenceEvent for that user
    in normal event handlers.

    Also, it seems that the WhatsApp servers require you to be online to receive presence status
    from other users, so you should mark yourself as online before trying to use this function:

        await send_presence(client, Presence.AVAILABLE)

    Args:
        client: The client instance
        jid: The JID to subscribe to

    Raises:
        NoPrivacyTokenError: If the client doesn't have a privacy token for the user and
                          error_on_subscribe_presence_without_token is set
    """
    privacy_token = await client.store.privacy_tokens.get_privacy_token(None, jid)
    if privacy_token is None:
        if client.error_on_subscribe_presence_without_token:
            raise NoPrivacyTokenError(f"for {jid.to_non_ad()}")
        else:
            logger.debug(f"Trying to subscribe to presence of {jid} without privacy token")

    req = Node(
        tag="presence",
        attributes=Attrs({
            "type": "subscribe",
            "to": str(jid)
        })
    )

    if privacy_token is not None:
        req.content = [Node(
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

    Raises:
        ErrNotLoggedIn: If the client is not logged in
    """
    own_id = client.get_own_id()
    if own_id.is_empty():
        raise ErrNotLoggedIn()

    content = [Node(tag=str(state))]

    if state == ChatPresence.COMPOSING and media and len(str(media)) > 0:
        content[0].attributes = Attrs({
            "media": str(media)
        })

    await client.send_node(Node(
        tag="chatstate",
        attributes=Attrs({
            "from": str(own_id),
            "to": str(jid)
        }),
        content=content
    ))
