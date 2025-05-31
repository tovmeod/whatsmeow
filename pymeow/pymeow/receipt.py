"""
Receipt handling implementation for WhatsApp.

Port of whatsmeow/receipt.go
"""
import asyncio
import logging
from datetime import datetime
from typing import Callable, List, Optional, Tuple, Union

from .binary.node import Node, Attrs
from .types.jid import JID
from .types.message import MessageID, MessageSource
from .types.events import Receipt
from .types.presence import ReceiptType
from .exceptions import ElementMissingError

logger = logging.getLogger(__name__)

class ReceiptMixin:
    """Mixin for handling message receipts in WhatsApp."""

    async def handle_receipt(self, node: Node) -> None:
        """
        Handle a receipt node from the WhatsApp server.

        Args:
            node: The receipt node to handle
        """
        defer_ack = self.maybe_deferred_ack(node)
        try:
            receipt = await self.parse_receipt(node)
            if receipt is not None:
                if receipt.type == ReceiptType.RETRY:
                    asyncio.create_task(self._handle_retry_receipt_task(receipt, node))
                self.dispatch_event(receipt)
        except Exception as e:
            logger.warning(f"Failed to parse receipt: {e}")
        finally:
            defer_ack()

    async def _handle_retry_receipt_task(self, receipt: Receipt, node: Node) -> None:
        """
        Handle a retry receipt in a separate task.

        Args:
            receipt: The parsed receipt
            node: The original receipt node
        """
        try:
            await self.handle_retry_receipt(receipt, node)
        except Exception as e:
            logger.error(f"Failed to handle retry receipt for {receipt.message_source.chat}/{receipt.message_ids[0]} from {receipt.message_source.sender}: {e}")

    def handle_grouped_receipt(self, partial_receipt: Receipt, participants: Node) -> None:
        """
        Handle a grouped receipt (for group chats).

        Args:
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
                message_source=partial_receipt.message_source,
                message_ids=partial_receipt.message_ids,
                timestamp=ag.unix_time("t"),
                type=partial_receipt.type,
                message_sender=ag.jid("jid")
            )

            if not ag.ok():
                logger.warning(f"Failed to parse user node {child.xml_string()} in grouped receipt: {ag.error()}")
                continue

            asyncio.create_task(self.dispatch_event(receipt))

    async def parse_receipt(self, node: Node) -> Optional[Receipt]:
        """
        Parse a receipt node into a Receipt object.

        Args:
            node: The receipt node to parse

        Returns:
            The parsed Receipt object, or None if this is a grouped receipt

        Raises:
            Exception: If there's an error parsing the receipt
        """
        ag = node.attr_getter()
        source = await self.parse_message_source(node, False)

        receipt = Receipt(
            message_source=source,
            message_ids=[],  # Will be filled later
            timestamp=ag.unix_time("t"),
            type=ReceiptType(ag.optional_string("type")),
            message_sender=ag.optional_jid_or_empty("recipient")
        )

        # Handle grouped receipts
        if source.is_group and source.sender.is_empty():
            participant_tags = node.get_children_by_tag("participants")
            if not participant_tags:
                raise ElementMissingError(tag="participants", in_="grouped receipt")

            for pcp in participant_tags:
                self.handle_grouped_receipt(receipt, pcp)

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
                    receipt.message_ids.append(item.attrs["id"])
        else:
            receipt.message_ids = [main_message_id]

        return receipt

    def maybe_deferred_ack(self, node: Node) -> Callable[[], None]:
        """
        Create a function that will send an acknowledgement for the given node.

        If synchronous_ack is True, the function will send the acknowledgement when called.
        Otherwise, it will start a task to send the acknowledgement and return a no-op function.

        Args:
            node: The node to acknowledge

        Returns:
            A function that will send the acknowledgement when called
        """
        if self.synchronous_ack:
            return lambda: self.send_ack(node)
        else:
            asyncio.create_task(self.send_ack(node))
            return lambda: None

    async def send_ack(self, node: Node) -> None:
        """
        Send an acknowledgement for the given node.

        Args:
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
            if isinstance(recipient_jid, JID) and recipient_jid.server == "broadcast" and node.tag == "message":
                # Check if bot_jid_map is defined
                if hasattr(self, 'bot_jid_map') and recipient_jid in self.bot_jid_map:
                    attrs["recipient"] = self.bot_jid_map[recipient_jid]

        if node.tag != "message" and "type" in node.attrs:
            attrs["type"] = node.attrs["type"]

        try:
            await self.send_node(Node(
                tag="ack",
                attrs=attrs
            ))
        except Exception as e:
            logger.warning(f"Failed to send acknowledgement for {node.tag} {node.attrs['id']}: {e}")

    async def mark_read(self, ids: List[MessageID], timestamp: datetime, chat: JID, sender: JID,
                  receipt_type_extra: Optional[ReceiptType] = None) -> None:
        """
        Send a read receipt for the given message IDs.

        The first JID parameter (chat) must always be set to the chat ID (user ID in DMs and group ID in group chats).
        The second JID parameter (sender) must be set in group chats and must be the user ID who sent the message.

        You can mark multiple messages as read at the same time, but only if the messages were sent by the same user.
        To mark messages by different users as read, you must call mark_read multiple times (once for each user).

        Args:
            ids: The IDs of the messages to mark as read
            timestamp: The timestamp to include in the receipt
            chat: The chat ID (user ID in DMs and group ID in group chats)
            sender: The user ID who sent the message (required for group chats)
            receipt_type_extra: The type of receipt to send (defaults to ReceiptType.READ)

        Returns:
            None

        Raises:
            Exception: If no message IDs are specified
        """
        if not ids:
            raise Exception("No message IDs specified")

        receipt_type = receipt_type_extra or ReceiptType.READ

        node = Node(
            tag="receipt",
            attrs=Attrs({
                "id": ids[0],
                "type": receipt_type.value,
                "to": chat,
                "t": int(timestamp.timestamp()),
            })
        )

        # Handle privacy settings
        if chat.server == "newsletter" or (await self.get_privacy_settings()).read_receipts == "none":
            if receipt_type == ReceiptType.READ:
                node.attrs["type"] = ReceiptType.READ_SELF.value
                # TODO: change played to played-self?

        # Handle sender for group chats
        if (not sender.is_empty() and
            chat.server != "s.whatsapp.net" and
            chat.server != "lid" and
            chat.server != "c.us"):
            node.attrs["participant"] = sender.to_non_ad()

        # Handle multiple message IDs
        if len(ids) > 1:
            children = []
            for i in range(1, len(ids)):
                children.append(Node(
                    tag="item",
                    attrs=Attrs({"id": ids[i]})
                ))

            node.content = [Node(
                tag="list",
                content=children
            )]

        await self.send_node(node)

    def set_force_active_delivery_receipts(self, active: bool) -> None:
        """
        Force the client to send normal delivery receipts (which will show up as the two gray ticks on WhatsApp),
        even if the client isn't marked as online.

        By default, clients that haven't been marked as online will send delivery receipts with type="inactive",
        which is transmitted to the sender, but not rendered in the official WhatsApp apps.
        This is consistent with how WhatsApp web works when it's not in the foreground.

        To mark the client as online, use:
            await client.send_presence(types.PresenceAvailable)

        Note that if you turn this off (i.e. call set_force_active_delivery_receipts(False)),
        receipts will act like the client is offline until send_presence is called again.

        Args:
            active: Whether to force active delivery receipts
        """
        if active:
            self.send_active_receipts = 2
        else:
            self.send_active_receipts = 0

    async def send_message_receipt(self, info: MessageSource) -> None:
        """
        Send a receipt for a received message.

        Args:
            info: Information about the message
        """
        attrs = Attrs({
            "id": info.id,
        })

        if info.is_from_me:
            attrs["type"] = ReceiptType.SENDER.value
        elif self.send_active_receipts == 0:
            attrs["type"] = ReceiptType.INACTIVE.value

        attrs["to"] = info.chat

        if info.is_group:
            attrs["participant"] = info.sender
        elif info.is_from_me:
            attrs["recipient"] = info.sender
        else:
            # Override the to attribute with the JID version with a device number
            attrs["to"] = info.sender

        try:
            await self.send_node(Node(
                tag="receipt",
                attrs=attrs
            ))
        except Exception as e:
            logger.warning(f"Failed to send receipt for {info.id}: {e}")
