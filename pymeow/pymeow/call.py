"""
Call handling implementation for WhatsApp.

Port of whatsmeow/call.go
"""

import logging
from typing import TYPE_CHECKING

from . import receipt, send
from .binary.node import Attrs, Node
from .exceptions import ErrNotLoggedIn
from .datatypes.call import BasicCallMeta, CallRemoteMeta
from .datatypes.events.call import (
    CallAccept,
    CallOffer,
    CallOfferNotice,
    CallPreAccept,
    CallReject,
    CallRelayLatency,
    CallTerminate,
    CallTransport,
    UnknownCallEvent,
)
from .datatypes.jid import JID

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)


async def handle_call_event(client: 'Client', node: Node) -> None:
    """
    Handle a call event node from the WhatsApp server.

    Args:
        client: The WhatsApp client instance
        node: The call event node to handle
    """
    try:
        children = node.get_children()
        if len(children) != 1:
            await client.dispatch_event(UnknownCallEvent(node=node))
            return

        ag = node.attr_getter()
        child = children[0]
        cag = child.attr_getter()

        basic_meta = BasicCallMeta(
            from_jid=ag.jid("from"),
            timestamp=ag.unix_time("t"),
            call_creator=cag.jid("call-creator"),
            call_id=cag.string("call-id")
        )

        if child.tag == "offer":
            await client.dispatch_event(CallOffer(
                basic_call_meta=basic_meta,
                call_remote_meta=CallRemoteMeta(
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version")
                ),
                data=child
            ))
        elif child.tag == "offer_notice":
            await client.dispatch_event(CallOfferNotice(
                basic_call_meta=basic_meta,
                media=cag.string("media"),
                type_=cag.string("type"),
                data=child
            ))
        elif child.tag == "relaylatency":
            await client.dispatch_event(CallRelayLatency(
                basic_call_meta=basic_meta,
                data=child
            ))
        elif child.tag == "accept":
            await client.dispatch_event(CallAccept(
                basic_call_meta=basic_meta,
                call_remote_meta=CallRemoteMeta(
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version")
                ),
                data=child
            ))
        elif child.tag == "preaccept":
            await client.dispatch_event(CallPreAccept(
                basic_call_meta=basic_meta,
                call_remote_meta=CallRemoteMeta(
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version")
                ),
                data=child
            ))
        elif child.tag == "transport":
            await client.dispatch_event(CallTransport(
                basic_call_meta=basic_meta,
                call_remote_meta=CallRemoteMeta(
                    remote_platform=ag.string("platform"),
                    remote_version=ag.string("version")
                ),
                data=child
            ))
        elif child.tag == "terminate":
            await client.dispatch_event(CallTerminate(
                basic_call_meta=basic_meta,
                reason=cag.string("reason"),
                data=child
            ))
        elif child.tag == "reject":
            await client.dispatch_event(CallReject(
                basic_call_meta=basic_meta,
                data=child
            ))
        else:
            await client.dispatch_event(UnknownCallEvent(node=node))

    except Exception as e:
        logger.warning(f"Failed to handle call event: {e}")
    finally:
        client.create_task(receipt.send_ack(client, node))


async def reject_call(client: 'Client', call_from: JID, call_id: str) -> None:
    """
    Reject an incoming call.

    Args:
        client: The WhatsApp client instance
        call_from: The JID of the user who initiated the call
        call_id: The call ID to reject

    Raises:
        ErrNotLoggedIn: If the client is not logged in
    """
    own_id = client.get_own_id()
    if own_id.is_empty():
        raise ErrNotLoggedIn()

    own_id = own_id.to_non_ad()
    call_from = call_from.to_non_ad()

    await client.send_node(Node(
        tag="call",
        attrs=Attrs({
            "id": send.generate_message_id(client),
            "from": own_id,
            "to": call_from
        }),
        content=[Node(
            tag="reject",
            attrs=Attrs({
                "call-id": call_id,
                "call-creator": call_from,
                "count": "0"
            }),
            content=None
        )]
    ))
