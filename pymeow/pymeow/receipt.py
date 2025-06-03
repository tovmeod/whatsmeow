"""
Receipt handling implementation for WhatsApp.

Port of whatsmeow/receipt.go - uses composition pattern instead of mixins.
Each function receives the client as the first argument.
"""

import asyncio
import logging
from datetime import datetime
from typing import Callable, List, Optional, Union

from .binary.node import Node, Attrs
from .types import ReceiptType
from .types.jid import JID
from .types.message import MessageID, MessageInfo
from .types.events import Receipt
from .exceptions import ElementMissingError

logger = logging.getLogger(__name__)


async def handle_receipt(client, node: Node) -> None:
    """
    Handle a receipt node from the WhatsApp server.

    Args:
        client: The WhatsApp client instance
        node: The receipt node to handle
    """
    defer_ack = maybe_deferred_ack(client, node)
    try:
        receipt = await parse_receipt(client, node)
        if receipt is not None:
            if receipt.type == ReceiptType.RETRY:
                asyncio.create_task(_handle_retry_receipt_task(client, receipt, node))
            await client.dispatch_event(receipt)
    except Exception as e:
        logger.warning(f"Failed to parse receipt: {e}")
    finally:
        defer_ack()


async def _handle_retry_receipt_task(client, receipt: Receipt, node: Node) -> None:
    """
    Handle a retry receipt in a separate task.

    Args:
        client: The WhatsApp client instance
        receipt: The parsed receipt
        node: The original receipt node
    """
    try:
        await client.handle_retry_receipt(receipt, node)
    except Exception as e:
        logger.error(
            f"Failed to handle retry receipt for {receipt.message_source.chat}/"
            f"{receipt.message_ids[0]} from {receipt.message_source.sender}: {e}"
        )


def handle_grouped_receipt(client, partial_receipt: Receipt, participants: Node) -> None:
    """
    Handle a grouped receipt (for group chats).

    Args:
        client: The WhatsApp client instance
        partial_receipt: The partial receipt with common information
        participants: The participants node containing individual receipt information
    """
    pag = participants.attr_getter()
    partial_receipt.message_ids = [pag.string("key")]

    for child in participants.get_children():
        if child.tag != "user":
            logger.warning(f"Unexpected node in grouped receipt participants: {child.xml_string()}")
            continue

        ag = child.attr_getter()
        receipt = Receipt(
            message_source=partial_receipt.message_source.copy(),
            message_ids=partial_receipt.message_ids[:],  # Copy the list
            timestamp=ag.unix_time("t"),
            type=partial_receipt.type,
            message_sender=ag.jid("jid")
        )

        # Update the sender for this specific receipt
        receipt.message_source.sender = ag.jid("jid")

        if not ag.ok():
            logger.warning(f"Failed to parse user node {child.xml_string()} in grouped receipt: {ag.error()}")
            continue

        asyncio.create_task(client.dispatch_event(receipt))


async def parse_receipt(client, node: Node) -> Optional[Receipt]:
    """
    Parse a receipt node into a Receipt object.

    Args:
        client: The WhatsApp client instance
        node: The receipt node to parse

    Returns:
        The parsed Receipt object, or None if this is a grouped receipt

    Raises:
        Exception: If there's an error parsing the receipt
    """
    ag = node.attr_getter()
    source = await client.parse_message_source(node, False)

    receipt = Receipt(
        message_source=source,
        message_ids=[],  # Will be filled later
        timestamp=ag.unix_time("t"),
        type=ReceiptType(ag.optional_string("type") or ""),
        message_sender=ag.optional_jid_or_empty("recipient")
    )

    # Handle grouped receipts
    if source.is_group and source.sender.is_empty():
        participant_tags = node.get_children_by_tag("participants")
        if not participant_tags:
            raise ElementMissingError(tag="participants", in_location="grouped receipt")

        for pcp in participant_tags:
            handle_grouped_receipt(client, receipt, pcp)

        return None

    # Handle normal receipts
    main_message_id = ag.string("id")
    if not ag.ok():
        raise Exception(f"Failed to parse read receipt attrs: {ag.errors}")

    receipt_children = node.get_children()
    if len(receipt_children) == 1 and receipt_children[0].tag == "list":
        list_children = receipt_children[0].get_children()
        receipt.message_ids = [main_message_id]

        for item in list_children:
            if item.tag == "item" and "id" in item.attrs:
                message_id = item.attrs["id"]
                if isinstance(message_id, str):
                    receipt.message_ids.append(message_id)
    else:
        receipt.message_ids = [main_message_id]

    return receipt


def maybe_deferred_ack(client, node: Node) -> Callable[[], None]:
    """
    Create a function that will send an acknowledgement for the given node.

    If synchronous_ack is True, the function will send the acknowledgement when called.
    Otherwise, it will start a task to send the acknowledgement and return a no-op function.

    Args:
        client: The WhatsApp client instance
        node: The node to acknowledge

    Returns:
        A function that will send the acknowledgement when called
    """
    if client.synchronous_ack:
        return lambda: asyncio.create_task(send_ack(client, node))
    else:
        asyncio.create_task(send_ack(client, node))
        return lambda: None


async def send_ack(client, node: Node) -> None:
    """
    Send an acknowledgement for the given node.

    Args:
        client: The WhatsApp client instance
        node: The node to acknowledge
    """
    attrs = Attrs({
        "class": node.tag,
        "id": node.attrs["id"],
    })

    attrs["to"] = node.attrs["from"]

    if "participant" in node.attrs:
        attrs["participant"] = node.attrs["participant"]

    if "recipient" in node.attrs:
        attrs["recipient"] = node.attrs["recipient"]

        # TODO: this hack probably needs to be removed at some point
        recipient_jid = node.attrs["recipient"]
        if isinstance(recipient_jid, JID) and recipient_jid.server == client.get_bot_server() and node.tag == "message":
            # Check if bot_jid_map is available
            bot_jid_map = getattr(client, 'bot_jid_map', None)
            if bot_jid_map and recipient_jid in bot_jid_map:
                attrs["recipient"] = bot_jid_map[recipient_jid]

    if node.tag != "message" and "type" in node.attrs:
        attrs["type"] = node.attrs["type"]

    try:
        await client.send_node(Node(
            tag="ack",
            attributes=attrs
        ))
    except Exception as e:
        logger.warning(f"Failed to send acknowledgement for {node.tag} {node.attrs['id']}: {e}")


async def mark_read(client, ids: List[MessageID], timestamp: datetime, chat: JID, sender: JID,
                   *receipt_type_extra: ReceiptType) -> None:
    """
    Send a read receipt for the given message IDs including the given timestamp as the read at time.

    The first JID parameter (chat) must always be set to the chat ID (user ID in DMs and group ID in group chats).
    The second JID parameter (sender) must be set in group chats and must be the user ID who sent the message.

    You can mark multiple messages as read at the same time, but only if the messages were sent by the same user.
    To mark messages by different users as read, you must call mark_read multiple times (once for each user).

    To mark a voice message as played, specify ReceiptType.PLAYED as the last parameter.
    Providing more than one receipt type will raise an exception: the parameter is only a vararg for backwards compatibility.

    Args:
        client: The WhatsApp client instance
        ids: The IDs of the messages to mark as read
        timestamp: The timestamp to include in the receipt
        chat: The chat ID (user ID in DMs and group ID in group chats)
        sender: The user ID who sent the message (required for group chats)
        *receipt_type_extra: The type of receipt to send (defaults to ReceiptType.READ)

    Raises:
        Exception: If no message IDs are specified or too many receipt types are provided
    """
    if not ids:
        raise Exception("no message IDs specified")

    if len(receipt_type_extra) == 0:
        receipt_type = ReceiptType.READ
    elif len(receipt_type_extra) == 1:
        receipt_type = receipt_type_extra[0]
    else:
        raise Exception("too many receipt types specified")

    node = Node(
        tag="receipt",
        attributes=Attrs({
            "id": ids[0],
            "type": str(receipt_type),
            "to": chat,
            "t": int(timestamp.timestamp()),
        })
    )

    # Handle privacy settings - check if newsletter server or privacy settings indicate no read receipts
    privacy_settings = await client.get_privacy_settings()
    if (chat.server == client.get_newsletter_server() or
        privacy_settings.read_receipts == client.get_privacy_setting_none()):
        if receipt_type == ReceiptType.READ:
            node.attrs["type"] = str(ReceiptType.READ_SELF)
            # TODO: change played to played-self?

    # Handle sender for group chats
    if (not sender.is_empty() and
        chat.server != client.get_default_user_server() and
        chat.server != client.get_hidden_user_server() and
        chat.server != client.get_messenger_server()):
        node.attrs["participant"] = sender.to_non_ad()

    # Handle multiple message IDs
    if len(ids) > 1:
        children = []
        for i in range(1, len(ids)):
            children.append(Node(
                tag="item",
                attributes=Attrs({"id": ids[i]})
            ))

        node.content = [Node(
            tag="list",
            content=children
        )]

    await client.send_node(node)


def set_force_active_delivery_receipts(client, active: bool) -> None:
    """
    Force the client to send normal delivery receipts (which will show up as the two gray ticks on WhatsApp),
    even if the client isn't marked as online.

    By default, clients that haven't been marked as online will send delivery receipts with type="inactive",
    which is transmitted to the sender, but not rendered in the official WhatsApp apps.
    This is consistent with how WhatsApp web works when it's not in the foreground.

    To mark the client as online, use:
        await send_presence(client, types.PresenceAvailable)

    Note that if you turn this off (i.e. call set_force_active_delivery_receipts(client, False)),
    receipts will act like the client is offline until send_presence is called again.

    Args:
        client: The WhatsApp client instance
        active: Whether to force active delivery receipts
    """
    if client is None:
        return

    if active:
        client.send_active_receipts.store(2)
    else:
        client.send_active_receipts.store(0)


async def send_message_receipt(client, info: MessageInfo) -> None:
    """
    Send a receipt for a received message.

    Args:
        client: The WhatsApp client instance
        info: Information about the message
    """
    attrs = Attrs({
        "id": info.id,
    })

    if info.message_source.is_from_me:
        attrs["type"] = str(ReceiptType.SENDER)
    elif client.send_active_receipts.load() == 0:
        attrs["type"] = str(ReceiptType.INACTIVE)

    attrs["to"] = info.chat

    if info.message_source.is_group:
        attrs["participant"] = info.sender
    elif info.message_source.is_from_me:
        attrs["recipient"] = info.sender
    else:
        # Override the to attribute with the JID version with a device number
        attrs["to"] = info.sender

    try:
        await client.send_node(Node(
            tag="receipt",
            attributes=attrs
        ))
    except Exception as e:
        logger.warning(f"Failed to send receipt for {info.id}: {e}")
