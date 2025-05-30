"""
WhatsApp request handling functionality.

This module provides functionality for handling requests and responses in the WhatsApp client,
including info queries (IQ) and handling disconnections.

Port of whatsmeow/request.go
"""
from dataclasses import dataclass, field
from enum import Enum
import asyncio
import time
from typing import Any, Dict, Optional, Union, List, Set, Tuple, cast

from .binary.node import Node
from .types.jid import JID
from .exceptions import PymeowError, IQError, TimeoutError, ProtocolError


# XML stream end node used to detect disconnections
XML_STREAM_END_NODE = Node(tag="xmlstreamend", attributes={}, content=None)

# Default timeout for requests in seconds
DEFAULT_REQUEST_TIMEOUT = 75.0


class DisconnectedError(PymeowError):
    """Raised when a request is interrupted by a websocket disconnection."""

    def __init__(self, action: str, node: Node):
        self.action = action
        self.node = node
        super().__init__(f"{action} was interrupted by websocket disconnection: {node.tag}")


class ErrIQTimedOut(TimeoutError):
    """Raised when an info query times out."""

    def __init__(self):
        super().__init__("Info query timed out")


class InfoQueryType(Enum):
    """Type of info query."""

    SET = "set"
    GET = "get"


@dataclass
class InfoQuery:
    """
    Represents an info query to be sent to the WhatsApp server.

    This is the Python equivalent of the Go infoQuery struct.

    Attributes:
        namespace: The XML namespace for the query
        type: The type of query (GET or SET)
        to: The destination JID (optional)
        target: The target JID (optional)
        id: A unique identifier for the request
        content: The content of the query
        timeout: The timeout duration for the request in seconds
        no_retry: Whether to retry the request if it fails due to disconnection
        context: The asyncio event loop context for the request
    """

    namespace: str
    type: InfoQueryType
    to: Optional[JID] = None
    target: Optional[JID] = None
    id: str = ""
    content: Any = None

    # Optional parameters
    timeout: Optional[float] = None
    no_retry: bool = False
    context: Optional[asyncio.AbstractEventLoop] = None

    def __post_init__(self):
        """Initialize default values after instance creation."""
        if self.timeout is None:
            self.timeout = DEFAULT_REQUEST_TIMEOUT

        if self.context is None:
            self.context = asyncio.get_event_loop()


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

    code = node.attributes.get("code", "")
    conflict = node.get_optional_child_by_tag("conflict")
    conflict_type = ""

    if conflict:
        conflict_type = conflict.attributes.get("type", "")

    return code == "401" or conflict_type == "replaced" or conflict_type == "device_removed"


def parse_iq_error(node: Node) -> IQError:
    """
    Parse an IQ error node into an appropriate exception.

    Args:
        node: The error node to parse

    Returns:
        An IQError instance or subclass
    """
    # In the Go code, this function parses the error node and returns
    # a specific error type based on the error code. For now, we'll
    # just return a generic IQError.
    return IQError(raw_node=node)


async def retry_frame(client, req_type: str, req_id: str, data: bytes, orig_resp: Node,
                      ctx: Optional[asyncio.AbstractEventLoop] = None,
                      timeout: Optional[float] = None) -> Tuple[Node, Optional[Exception]]:
    """
    Retry sending a frame after a disconnection.

    Args:
        client: The WhatsApp client
        req_type: The type of request being retried
        req_id: The ID of the request
        data: The raw data of the original request
        orig_resp: The original response that indicated a disconnection
        ctx: The asyncio context for the request
        timeout: The timeout duration for the retry

    Returns:
        A tuple containing the response node and any error that occurred

    Raises:
        DisconnectedError: If the retry fails due to disconnection
        ErrIQTimedOut: If the retry times out
    """
    if is_auth_error_disconnect(orig_resp):
        client.log.debug(
            f"{req_id} ({req_type}) was interrupted by websocket disconnection "
            f"({orig_resp.tag}), not retrying as it looks like an auth error"
        )
        return None, DisconnectedError(action=req_type, node=orig_resp)

    client.log.debug(
        f"{req_id} ({req_type}) was interrupted by websocket disconnection "
        f"({orig_resp.tag}), waiting for reconnect to retry..."
    )

    # Wait for reconnection
    if not await client.wait_for_connection(5.0):
        client.log.debug(f"Websocket didn't reconnect within 5 seconds of failed {req_type} ({req_id})")
        return None, DisconnectedError(action=req_type, node=orig_resp)

    # Get the socket
    sock = client.socket
    if sock is None:
        return None, ValueError("Not connected")

    # Set up a waiter for the response
    response_queue = asyncio.Queue(maxsize=1)
    async with client.response_waiters_lock:
        client.response_waiters[req_id] = response_queue

    # Send the frame
    try:
        await sock.send_frame(data)
    except Exception as e:
        async with client.response_waiters_lock:
            client.response_waiters.pop(req_id, None)
        return None, e

    # Wait for the response
    try:
        if timeout is None:
            timeout = DEFAULT_REQUEST_TIMEOUT

        if ctx is None:
            ctx = asyncio.get_event_loop()

        # Create a task to wait for the response
        resp_task = asyncio.create_task(response_queue.get())

        # Wait for the response or timeout
        done, pending = await asyncio.wait(
            [resp_task],
            timeout=timeout,
            return_when=asyncio.FIRST_COMPLETED
        )

        # Cancel any pending tasks
        for task in pending:
            task.cancel()

        # Check if we got a response
        if resp_task in done:
            resp = await resp_task
        else:
            async with client.response_waiters_lock:
                client.response_waiters.pop(req_id, None)
            return None, ErrIQTimedOut()

        # Check if the response is a disconnect
        if is_disconnect_node(resp):
            client.log.debug(
                f"Retrying {req_type} {req_id} was interrupted by websocket disconnection "
                f"({resp.tag}), not retrying anymore"
            )
            return None, DisconnectedError(action=f"{req_type} (retry)", node=resp)

        return resp, None
    except asyncio.CancelledError:
        async with client.response_waiters_lock:
            client.response_waiters.pop(req_id, None)
        raise
    except Exception as e:
        async with client.response_waiters_lock:
            client.response_waiters.pop(req_id, None)
        return None, e
