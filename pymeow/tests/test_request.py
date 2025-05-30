"""
Tests for the request handling implementation.
"""
import asyncio
import unittest
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import timedelta

from pymeow.pymeow.request import (
    Request,
    RequestManager,
    RequestHandler,
    InfoQuery,
    InfoQueryType,
    IQError,
    DisconnectedError,
    ErrIQTimedOut,
    ErrNotConnected,
    ErrClientIsNil,
)
from pymeow.pymeow.binary import node as binary_node

class TestRequestManager(unittest.IsolatedAsyncioTestCase):
    """Test the request manager."""

    async def test_make_request(self):
        """Test making a request and handling the response."""
        manager = RequestManager()

        # Create a task to handle the response after a delay
        async def handle_response():
            await asyncio.sleep(0.1)
            tag = list(manager._pending.keys())[0]
            manager.handle_response(tag, "test_response")

        # Start the task
        asyncio.create_task(handle_response())

        # Make the request
        response = await manager.make_request("test_namespace", "test_data")

        # Check the response
        self.assertEqual(response, "test_response")

        # Check that the request was removed from pending
        self.assertEqual(len(manager._pending), 0)

class TestRequestHandler(unittest.IsolatedAsyncioTestCase):
    """Test the request handler."""

    async def asyncSetUp(self):
        """Set up the test."""
        self.mock_client = MagicMock()
        self.mock_client.send_node_and_get_data = AsyncMock(return_value=(b"test_data", None))
        self.mock_client.wait_for_connection = AsyncMock(return_value=True)
        self.mock_client.socket = MagicMock()
        self.mock_client.socket.send_frame = AsyncMock(return_value=None)
        self.mock_client.log = MagicMock()

        self.handler = RequestHandler(self.mock_client)
        self.handler.unique_id = "test_"

    async def test_generate_request_id(self):
        """Test generating a request ID."""
        id1 = self.handler.generate_request_id()
        id2 = self.handler.generate_request_id()

        self.assertEqual(id1, "test_1")
        self.assertEqual(id2, "test_2")

    async def test_is_disconnect_node(self):
        """Test checking if a node indicates a disconnection."""
        # Test with xmlstreamend node
        node = binary_node.Node("xmlstreamend", {})
        self.assertTrue(self.handler.is_disconnect_node(node))

        # Test with stream:error node
        node = binary_node.Node("stream:error", {})
        self.assertTrue(self.handler.is_disconnect_node(node))

        # Test with other node
        node = binary_node.Node("other", {})
        self.assertFalse(self.handler.is_disconnect_node(node))

    async def test_is_auth_error_disconnect(self):
        """Test checking if a disconnect node is due to an authentication error."""
        # Test with 401 code
        node = binary_node.Node("stream:error", {"code": "401"})
        self.assertTrue(self.handler.is_auth_error_disconnect(node))

        # Test with replaced conflict type
        conflict_node = binary_node.Node("conflict", {"type": "replaced"})
        node = binary_node.Node("stream:error", {}, [conflict_node])
        self.assertTrue(self.handler.is_auth_error_disconnect(node))

        # Test with device_removed conflict type
        conflict_node = binary_node.Node("conflict", {"type": "device_removed"})
        node = binary_node.Node("stream:error", {}, [conflict_node])
        self.assertTrue(self.handler.is_auth_error_disconnect(node))

        # Test with other node
        node = binary_node.Node("other", {})
        self.assertFalse(self.handler.is_auth_error_disconnect(node))

    async def test_wait_and_cancel_response(self):
        """Test setting up a waiter for a response and canceling it."""
        # Wait for a response
        waiter = await self.handler.wait_response("test_id")

        # Check that the waiter was added
        self.assertIn("test_id", self.handler.response_waiters)

        # Cancel the response
        await self.handler.cancel_response("test_id")

        # Check that the waiter was removed
        self.assertNotIn("test_id", self.handler.response_waiters)

    async def test_receive_response(self):
        """Test handling a received response."""
        # Wait for a response
        waiter = await self.handler.wait_response("test_id")

        # Create a response node
        node = binary_node.Node("iq", {"id": "test_id"})

        # Handle the response
        result = await self.handler.receive_response(node)

        # Check that the response was handled
        self.assertTrue(result)

        # Check that the waiter was removed
        self.assertNotIn("test_id", self.handler.response_waiters)

        # Check that the waiter received the node
        received_node = await waiter.get()
        self.assertEqual(received_node, node)

    async def test_send_iq(self):
        """Test sending an info query and waiting for the response."""
        # Create a mock response
        mock_response = binary_node.Node("iq", {"type": "result"})

        # Mock the wait_response method to return a queue with the mock response
        original_wait_response = self.handler.wait_response

        async def mock_wait_response(req_id):
            queue = await original_wait_response(req_id)
            await queue.put(mock_response)
            return queue

        self.handler.wait_response = mock_wait_response

        # Create an info query
        query = InfoQuery(
            namespace="test_namespace",
            type=InfoQueryType.GET,
            to=None,
            content=None,
        )

        # Send the query
        response, err = await self.handler.send_iq(query)

        # Check the response
        self.assertEqual(response, mock_response)
        self.assertIsNone(err)

        # Check that the client's send_node_and_get_data method was called
        self.mock_client.send_node_and_get_data.assert_called_once()

        # Restore the original wait_response method
        self.handler.wait_response = original_wait_response

    async def test_send_iq_error(self):
        """Test sending an info query and getting an error response."""
        # Create a mock error response
        mock_response = binary_node.Node("iq", {"type": "error"})

        # Mock the wait_response method to return a queue with the mock response
        original_wait_response = self.handler.wait_response

        async def mock_wait_response(req_id):
            queue = await original_wait_response(req_id)
            await queue.put(mock_response)
            return queue

        self.handler.wait_response = mock_wait_response

        # Mock the parse_iq_error method to return a specific error
        self.handler.parse_iq_error = lambda res: IQError(raw_node=res)

        # Create an info query
        query = InfoQuery(
            namespace="test_namespace",
            type=InfoQueryType.GET,
            to=None,
            content=None,
        )

        # Send the query
        response, err = await self.handler.send_iq(query)

        # Check the response
        self.assertEqual(response, mock_response)
        self.assertIsInstance(err, IQError)

        # Restore the original wait_response method
        self.handler.wait_response = original_wait_response

    async def test_send_iq_timeout(self):
        """Test sending an info query and timing out."""
        # Create an info query with a short timeout
        query = InfoQuery(
            namespace="test_namespace",
            type=InfoQueryType.GET,
            to=None,
            content=None,
            timeout=timedelta(milliseconds=1),  # Very short timeout
        )

        # Send the query
        response, err = await self.handler.send_iq(query)

        # Check the response
        self.assertIsNone(response)
        self.assertIsInstance(err, ErrIQTimedOut)

    async def test_retry_frame(self):
        """Test retrying a frame after a disconnection."""
        # Create a mock response
        mock_response = binary_node.Node("iq", {"type": "result"})

        # Mock the wait_response method to return a queue with the mock response
        original_wait_response = self.handler.wait_response

        async def mock_wait_response(req_id):
            queue = await original_wait_response(req_id)
            await queue.put(mock_response)
            return queue

        self.handler.wait_response = mock_wait_response

        # Create a disconnect node
        disconnect_node = binary_node.Node("stream:error", {})

        # Retry the frame
        response, err = await self.handler.retry_frame(
            "test_req_type",
            "test_id",
            b"test_data",
            disconnect_node,
            1.0,
        )

        # Check the response
        self.assertEqual(response, mock_response)
        self.assertIsNone(err)

        # Check that the client's wait_for_connection method was called
        self.mock_client.wait_for_connection.assert_called_once_with(5)

        # Check that the socket's send_frame method was called
        self.mock_client.socket.send_frame.assert_called_once_with(b"test_data")

        # Restore the original wait_response method
        self.handler.wait_response = original_wait_response

if __name__ == "__main__":
    unittest.main()
