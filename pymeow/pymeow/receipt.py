"""
Receipt handling implementation for WhatsApp.

Port of whatsmeow/receipt.go - uses composition pattern instead of mixins.
Each function receives the client as the first argument.
"""

import asyncio
import logging
from datetime import datetime
from typing import Callable, List, Optional, Tuple, TYPE_CHECKING

from . import retry, privacysettings, message
from .binary.node import Node, Attrs
from .types import ReceiptType
from .types.botmap import BOT_JID_MAP
from .types.events.events import ReceiptTypeRead
from .types.jid import JID, BOT_SERVER, NEWSLETTER_SERVER, DEFAULT_USER_SERVER, HIDDEN_USER_SERVER, MESSENGER_SERVER
from .types.message import MessageID, MessageInfo
from .types.events import Receipt
from .exceptions import ElementMissingError

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)


async def handle_receipt(client, node: Node) -> None:
    """
    Port of Go method handleReceipt from receipt.go.

    Handle a receipt node from the WhatsApp server.

    Args:
        client: The WhatsApp client instance
        node: The receipt node to handle
    """
    # TODO: Review maybe_deferred_ack implementation
    # TODO: Review parse_receipt implementation
    # TODO: Review handle_retry_receipt implementation
    # TODO: Review dispatch_event implementation

    try:
        receipt, err = await parse_receipt(client, node)
        if err is not None:
            logger.warning(f"Failed to parse receipt: {err}")
        elif receipt is not None:
            if receipt.type == ReceiptType.RETRY:
                # Create async task equivalent to Go's goroutine
                async def retry_task():
                    try:
                        err = await retry.handle_retry_receipt(client, receipt, node)
                        if err is not None:
                            logger.error(
                                f"Failed to handle retry receipt for {receipt.message_source.chat}/"
                                f"{receipt.message_ids[0]} from {receipt.message_source.sender}: {err}"
                            )
                    except Exception as e:
                        logger.error(
                            f"Failed to handle retry receipt for {receipt.message_source.chat}/"
                            f"{receipt.message_ids[0]} from {receipt.message_source.sender}: {e}"
                        )

                # Execute in background (equivalent to Go's goroutine)
                asyncio.create_task(retry_task())

            client.dispatch_event(receipt)
    finally:
        client.create_task(send_ack(client, node))


async def handle_grouped_receipt(client: 'Client', partial_receipt: Receipt, participants: Node) -> None:
    """
    Port of Go method handleGroupedReceipt from receipt.go.

    Handle a grouped receipt (for group chats) by processing each participant.

    Args:
        client: The WhatsApp client instance
        partial_receipt: The partial receipt with common information
        participants: The participants node containing individual receipt information
    """
    # TODO: Review Node.attr_getter implementation
    # TODO: Review Node.get_children implementation
    # TODO: Review Node.xml_string implementation
    # TODO: Review dispatch_event implementation

    pag = participants.attr_getter()
    partial_receipt.message_ids = [pag.string("key")]

    for child in participants.get_children():
        if child.tag != "user":
            logger.warning(f"Unexpected node in grouped receipt participants: {child.xml_string()}")
            continue

        ag = child.attr_getter()
        receipt = partial_receipt  # Direct assignment (Go does shallow copy)
        receipt.timestamp = ag.unix_time("t")
        receipt.message_source.sender = ag.jid("jid")

        if not ag.ok():
            logger.warning(f"Failed to parse user node {child.xml_string()} in grouped receipt: {ag.error()}")
            continue

        # Create async task equivalent to Go's goroutine
        await client.dispatch_event(receipt)


async def parse_receipt(client: 'Client', node: Node) -> Tuple[Optional[Receipt], Optional[Exception]]:
    """
    Port of Go method parseReceipt from receipt.go.

    Parse a receipt node into a Receipt object.

    Args:
        client: The WhatsApp client instance
        node: The receipt node to parse

    Returns:
        Tuple containing (Receipt object or None, error or None)
    """
    # TODO: Review Node.attr_getter implementation
    # TODO: Review parse_message_source implementation
    # TODO: Review Receipt class implementation
    # TODO: Review ReceiptType implementation
    # TODO: Review ElementMissingError implementation
    # TODO: Review handle_grouped_receipt implementation

    ag = node.attr_getter()
    source, err = await message.parse_message_source(client, node, False)
    if err is not None:
        return None, err

    receipt = Receipt(
        message_source=source,
        timestamp=ag.unix_time("t"),
        type=ReceiptType(ag.optional_string("type")),
        message_sender=ag.optional_jid_or_empty("recipient")
    )

    if source.is_group and source.sender.is_empty():
        participant_tags = node.get_children_by_tag("participants")
        if len(participant_tags) == 0:
            return None, ElementMissingError(tag="participants", in_location="grouped receipt")

        for pcp in participant_tags:
            await handle_grouped_receipt(client, receipt, pcp)

        return None, None

    main_message_id = ag.string("id")
    if not ag.ok():
        return None, Exception(f"failed to parse read receipt attrs: {ag.errors}")

    receipt_children = node.get_children()
    if len(receipt_children) == 1 and receipt_children[0].tag == "list":
        list_children = receipt_children[0].get_children()
        # Equivalent to Go's make([]string, 1, len(listChildren)+1)
        receipt.message_ids = [main_message_id]

        for item in list_children:
            if item.tag == "item" and "id" in item.attrs:
                item_id = item.attrs["id"]
                if isinstance(item_id, str):
                    receipt.message_ids.append(item_id)
    else:
        receipt.message_ids = [main_message_id]

    return receipt, None


# todo: maybe I don't need this method
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


async def send_ack(client: 'Client', node: Node) -> None:
    """
    Port of Go method sendAck from receipt.go.

    Send an acknowledgement for the given node.

    Args:
        client: The WhatsApp client instance
        node: The node to acknowledge
    """
    # TODO: Review Attrs implementation
    # TODO: Review Node implementation
    # TODO: Review send_node implementation
    # TODO: Review BotServer constant
    # TODO: Review BotJIDMap implementation

    attrs = Attrs({
        "class": node.tag,
        "id": node.attrs["id"],
    })

    attrs["to"] = node.attrs["from"]

    if "participant" in node.attrs:
        attrs["participant"] = node.attrs["participant"]

    if "recipient" in node.attrs:
        attrs["recipient"] = node.attrs["recipient"]

        # TODO this hack probably needs to be removed at some point
        recipient = node.attrs["recipient"]
        if isinstance(recipient, JID) and recipient.server == BOT_SERVER and node.tag == "message":
            if recipient in BOT_JID_MAP:
                attrs["recipient"] = BOT_JID_MAP[recipient]

    if node.tag != "message" and "type" in node.attrs:
        attrs["type"] = node.attrs["type"]

    err = await client.send_node(Node(
        tag="ack",
        attrs=attrs
    ))

    if err is not None:
        logger.warning(f"Failed to send acknowledgement for {node.tag} {node.attrs['id']}: {err}")


async def mark_read(
    client: 'Client',
    ids: List[MessageID],
    timestamp: datetime,
    chat: JID,
    sender: JID,
    *receipt_type_extra: ReceiptType
) -> Optional[Exception]:
    """
    Port of Go method MarkRead from receipt.go.

    Send a read receipt for the given message IDs including the given timestamp as the read at time.

    The first JID parameter (chat) must always be set to the chat ID (user ID in DMs and group ID in group chats).
    The second JID parameter (sender) must be set in group chats and must be the user ID who sent the message.

    You can mark multiple messages as read at the same time, but only if the messages were sent by the same user.
    To mark messages by different users as read, you must call mark_read multiple times (once for each user).

    To mark a voice message as played, specify RECEIPT_TYPE_PLAYED as the last parameter.
    Providing more than one receipt type will panic: the parameter is only a vararg for backwards compatibility.

    Args:
        client: The WhatsApp client instance
        ids: The IDs of the messages to mark as read
        timestamp: The timestamp to include in the receipt
        chat: The chat ID (user ID in DMs and group ID in group chats)
        sender: The user ID who sent the message (required for group chats)
        *receipt_type_extra: The type of receipt to send (defaults to RECEIPT_TYPE_READ)

    Returns:
        Exception if error occurred, None if successful
    """
    # TODO: Review MessageID type implementation
    # TODO: Review ReceiptType constants implementation
    # TODO: Review Node implementation
    # TODO: Review Attrs implementation
    # TODO: Review get_privacy_settings implementation
    # TODO: Review send_node implementation

    if len(ids) == 0:
        return Exception("no message IDs specified")

    receipt_type = ReceiptTypeRead
    if len(receipt_type_extra) == 1:
        receipt_type = receipt_type_extra[0]
    elif len(receipt_type_extra) > 1:
        raise Exception("too many receipt types specified")

    node = Node(
        tag="receipt",
        attrs=Attrs({
            "id": ids[0],
            "type": str(receipt_type),
            "to": chat,
            "t": int(timestamp.timestamp()),
        })
    )

    if (chat.server == NEWSLETTER_SERVER or
        (await privacysettings.get_privacy_settings(client)).read_receipts == privacysettings.PrivacySetting.NONE):
        if receipt_type == ReceiptTypeRead:
            node.attrs["type"] = str(ReceiptType.READ_SELF)
            # TODO change played to played-self?

    if (not sender.is_empty() and
        chat.server != DEFAULT_USER_SERVER and
        chat.server != HIDDEN_USER_SERVER and
        chat.server != MESSENGER_SERVER):
        node.attrs["participant"] = sender.to_non_ad()

    if len(ids) > 1:
        children = []
        for i in range(1, len(ids)):
            child_node = Node(tag="item", attrs=Attrs({"id": ids[i]}))
            children.append(child_node)

        node.content = [Node(
            tag="list",
            content=children
        )]

    return client.send_node(node)


def set_force_active_delivery_receipts(
    client: 'Client',
    active: bool
) -> None:
    """
    Port of Go method SetForceActiveDeliveryReceipts from receipts.go.

    Force the client to send normal delivery receipts (which will show up as the two gray ticks on WhatsApp),
    even if the client isn't marked as online.

    By default, clients that haven't been marked as online will send delivery receipts with type="inactive",
    which is transmitted to the sender, but not rendered in the official WhatsApp apps.
    This is consistent with how WhatsApp web works when it's not in the foreground.

    To mark the client as online, use:
        client.send_presence(types.PRESENCE_AVAILABLE)

    Note that if you turn this off (i.e. call set_force_active_delivery_receipts(client, False)),
    receipts will act like the client is offline until send_presence is called again.

    Args:
        client: The WhatsApp client instance
        active: Whether to force active delivery receipts

    Returns:
        None
    """
    # TODO: Review send_active_receipts implementation
    # TODO: Review atomic Store operation implementation

    if client is None:
        return

    if active:
        client.send_active_receipts.store(2)
    else:
        client.send_active_receipts.store(0)


async def send_message_receipt(
    client: 'Client',
    info: MessageInfo
) -> None:
    """
    Port of Go method sendMessageReceipt from receipts.go.

    Send a receipt for a received message.

    Args:
        client: The WhatsApp client instance
        info: Information about the message

    Returns:
        None
    """
    # TODO: Review Attrs implementation
    # TODO: Review MessageInfo properties implementation
    # TODO: Review send_active_receipts.load implementation
    # TODO: Review RECEIPT_TYPE_* constants implementation
    # TODO: Review send_node implementation
    # TODO: Review Node implementation

    attrs = Attrs({
        "id": info.id,
    })

    if info.is_from_me:
        attrs["type"] = str(ReceiptType.SENDER)
    elif client.send_active_receipts.load() == 0:
        attrs["type"] = str(ReceiptType.INACTIVE)

    attrs["to"] = info.chat

    if info.message_source.is_group:
        attrs["participant"] = info.sender
    elif info.is_from_me:
        attrs["recipient"] = info.sender
    else:
        # Override the to attribute with the JID version with a device number
        attrs["to"] = info.sender

    err = await client.send_node(Node(
        tag="receipt",
        attrs=attrs
    ))

    if err is not None:
        logger.warning("Failed to send receipt for %s: %v", info.id, err)
