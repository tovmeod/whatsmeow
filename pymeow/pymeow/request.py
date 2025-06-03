"""
WhatsApp request handling functionality.

This module provides functionality for handling requests and responses in the WhatsApp client,
including info queries (IQ) and handling disconnections.

Port of whatsmeow/request.go
"""

import asyncio
import logging
from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional, Tuple, TYPE_CHECKING

from .binary.node import Node
from .types.jid import JID
from .exceptions import (
    IQError,
    parse_iq_error,
    ErrClientIsNil,
    ErrNotConnected,
    ErrIQTimedOut,
    DisconnectedError
)

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .client import Client

# Constants
DEFAULT_REQUEST_TIMEOUT = 75.0  # seconds

# XML stream end node used to detect disconnections
XML_STREAM_END_NODE = Node(tag="xmlstreamend")


class InfoQueryType(Enum):
    """Type of info query."""
    SET = "set"
    GET = "get"


@dataclass
class InfoQuery:
    """
    Represents an info query to be sent to the WhatsApp server.

    This is the Python equivalent of the Go infoQuery struct.
    """
    namespace: str
    type: InfoQueryType
    to: Optional[JID] = None
    target: Optional[JID] = None
    id: str = ""
    content: Any = None
    timeout: float = 0.0
    no_retry: bool = False
    context: Optional[asyncio.Task] = None


def generate_request_id(client: 'Client') -> str:
    """
    Generate a unique request ID.

    Args:
        client: The client instance

    Returns:
        A unique request ID string
    """
    # Increment the counter and get the new value
    client.id_counter += 1
    return f"{client.unique_id}{client.id_counter}"


def is_disconnect_node(node: Node) -> bool:
    """
    Check if the given node is a disconnect node.

    Args:
        node: The node to check

    Returns:
        True if the node is a disconnect node, False otherwise
    """
    return node == XML_STREAM_END_NODE or node.tag == "stream:error"


def is_auth_error_disconnect(node: Node) -> bool:
    """
    Check if the given disconnect node is an error that shouldn't cause retrying.

    Args:
        node: The node to check

    Returns:
        True if the node is an auth error disconnect, False otherwise
    """
    if node.tag != "stream:error":
        return False

    code = node.attrs.get("code", "")
    conflict, found = node.get_optional_child_by_tag("conflict")
    conflict_type = ""

    if found and conflict:
        conflict_type = conflict.attr_getter().optional_string("type")

    return code == "401" or conflict_type == "replaced" or conflict_type == "device_removed"


async def clear_response_waiters(client: 'Client', node: Node) -> None:
    """
    Clear all response waiters with the given node.

    Args:
        client: The client instance
        node: The node to send to all waiters
    """
    async with client.response_waiters_lock:
        for waiter in client.response_waiters.values():
            try:
                waiter.put_nowait(node)
            except asyncio.QueueFull:
                pass  # Skip if queue is full
        client.response_waiters.clear()


async def wait_response(client: 'Client', req_id: str) -> asyncio.Queue:
    """
    Create a queue to wait for a response with the given request ID.

    Args:
        client: The client instance
        req_id: The request ID to wait for

    Returns:
        A queue that will receive the response
    """
    queue = asyncio.Queue(maxsize=1)
    async with client.response_waiters_lock:
        client.response_waiters[req_id] = queue
    return queue


async def cancel_response(client: 'Client', req_id: str, queue: asyncio.Queue) -> None:
    """
    Cancel waiting for a response.

    Args:
        client: The client instance
        req_id: The request ID to cancel
        queue: The queue to close
    """
    async with client.response_waiters_lock:
        client.response_waiters.pop(req_id, None)
    # Note: asyncio.Queue doesn't need explicit closing


async def receive_response(client: 'Client', data: Node) -> bool:
    """
    Handle a received response node.

    Args:
        client: The client instance
        data: The response node

    Returns:
        True if the response was handled, False otherwise
    """
    node_id = data.attrs.get("id")
    if not isinstance(node_id, str) or (data.tag != "iq" and data.tag != "ack"):
        return False

    async with client.response_waiters_lock:
        waiter = client.response_waiters.pop(node_id, None)

    if waiter is None:
        return False

    try:
        waiter.put_nowait(data)
    except asyncio.QueueFull:
        pass  # Skip if queue is full

    return True


async def send_iq_async_and_get_data(client: 'Client', query: InfoQuery) -> Tuple[Optional[asyncio.Queue], Optional[bytes], Optional[Exception]]:
    """
    Send an info query asynchronously and return the response queue and raw data.

    Args:
        client: The client instance
        query: The info query to send

    Returns:
        Tuple of (response_queue, raw_data, error)
    """
    if client is None:
        return None, None, ErrClientIsNil()

    if not query.id:
        query.id = generate_request_id(client)

    waiter = await wait_response(client, query.id)

    attrs = {
        "id": query.id,
        "xmlns": query.namespace,
        "type": query.type.value,
    }

    if query.to and not query.to.is_empty():
        attrs["to"] = str(query.to)

    if query.target and not query.target.is_empty():
        attrs["target"] = str(query.target)

    node = Node(
        tag="iq",
        attributes=attrs,
        content=query.content
    )

    try:
        data = await client.send_node_and_get_data(node)
        return waiter, data, None
    except Exception as e:
        await cancel_response(client, query.id, waiter)
        return None, None, e


async def send_iq_async(client: 'Client', query: InfoQuery) -> Tuple[Optional[asyncio.Queue], Optional[Exception]]:
    """
    Send an info query asynchronously.

    Args:
        client: The client instance
        query: The info query to send

    Returns:
        Tuple of (response_queue, error)
    """
    queue, _, error = await send_iq_async_and_get_data(client, query)
    return queue, error


async def send_iq(client: 'Client', query: InfoQuery) -> Node:
    """
    Send an info query and wait for the response.

    Args:
        client: The client instance
        query: The info query to send

    Returns:
        The response node

    Raises:
        Various exceptions depending on the error type
    """
    res_queue, data, error = await send_iq_async_and_get_data(client, query)
    if error:
        raise error

    if query.timeout == 0:
        query.timeout = DEFAULT_REQUEST_TIMEOUT

    try:
        # Wait for response with timeout
        res = await asyncio.wait_for(res_queue.get(), timeout=query.timeout)

        if is_disconnect_node(res):
            if query.no_retry:
                raise DisconnectedError("info query", res)

            res = await retry_frame(client, "info query", query.id, data, res, query.timeout)

        res_type = res.attrs.get("type", "")
        if res.tag != "iq" or (res_type != "result" and res_type != "error"):
            raise IQError(raw_node=res)
        elif res_type == "error":
            raise parse_iq_error(res)

        return res

    except asyncio.TimeoutError:
        raise ErrIQTimedOut()
    except asyncio.CancelledError:
        raise


async def retry_frame(client: 'Client', req_type: str, req_id: str, data: bytes, orig_resp: Node, timeout: float) -> Node:
    """
    Retry sending a frame after a disconnection.

    Args:
        client: The client instance
        req_type: The type of request being retried
        req_id: The ID of the request
        data: The raw data of the original request
        orig_resp: The original response that indicated a disconnection
        timeout: The timeout duration for the retry

    Returns:
        The response node

    Raises:
        DisconnectedError: If the retry fails due to disconnection
        ErrIQTimedOut: If the retry times out
        ErrNotConnected: If not connected
    """
    if is_auth_error_disconnect(orig_resp):
        logger.debug(f"{req_id} ({req_type}) was interrupted by websocket disconnection "
                        f"({orig_resp.xml_string()}), not retrying as it looks like an auth error")
        raise DisconnectedError(req_type, orig_resp)

    logger.debug(f"{req_id} ({req_type}) was interrupted by websocket disconnection "
                    f"({orig_resp.xml_string()}), waiting for reconnect to retry...")

    if not await client.wait_for_connection(5.0):
        logger.debug(f"Websocket didn't reconnect within 5 seconds of failed {req_type} ({req_id})")
        raise DisconnectedError(req_type, orig_resp)

    # Use client's socket access pattern
    async with client.socket_lock:
        sock = client.socket

    if sock is None:
        raise ErrNotConnected()

    resp_queue = await wait_response(client, req_id)

    try:
        await sock.send_frame(data)
    except Exception as e:
        await cancel_response(client, req_id, resp_queue)
        raise e

    try:
        if timeout > 0:
            resp = await asyncio.wait_for(resp_queue.get(), timeout=timeout)
        else:
            resp = await resp_queue.get()
    except asyncio.TimeoutError:
        raise ErrIQTimedOut()
    except asyncio.CancelledError:
        raise

    if is_disconnect_node(resp):
        logger.debug(f"Retrying {req_type} {req_id} was interrupted by websocket disconnection "
                        f"({resp.xml_string()}), not retrying anymore")
        raise DisconnectedError(f"{req_type} (retry)", resp)

    return resp
