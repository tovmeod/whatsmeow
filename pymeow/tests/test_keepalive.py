"""
Tests for the keepalive functionality.

This tests the keepalive mechanism that maintains the connection with the WhatsApp server.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, call
from datetime import datetime, timedelta

from ..pymeow.keepalive import KeepAliveMixin, KEEP_ALIVE_RESPONSE_DEADLINE, KEEP_ALIVE_MAX_FAIL_TIME
from ..pymeow.types.events.events import KeepAliveTimeout, KeepAliveRestored
from ..pymeow.binary.node import Node

# Real test values captured from logs
SAMPLE_PING_NODE_XML = '<iq id="b7e0afa7-e9da-4ed7-8c3b-0247dbb98a6e" type="get" to="s.whatsapp.net" xmlns="w:p"></iq>'
# No response in logs, but we can use a similar format to the ping
SAMPLE_RESPONSE_XML = '<iq id="b7e0afa7-e9da-4ed7-8c3b-0247dbb98a6e" type="result" from="s.whatsapp.net" to="user@s.whatsapp.net"></iq>'

class TestKeepAlive(KeepAliveMixin):
    """Test class for keepalive functionality."""

    def __init__(self):
        """Initialize the test class."""
        self.enable_auto_reconnect = True
        self.dispatch_event = AsyncMock()
        self.disconnect = AsyncMock()
        self._auto_reconnect = AsyncMock()
        self.send_iq_async = AsyncMock()

# Patch keepalive intervals to very short durations for fast testing
@pytest.fixture(autouse=True)
def fast_keepalive_intervals():
    """Make keepalive intervals very short for testing."""
    with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MIN', timedelta(milliseconds=10)):
        with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MAX', timedelta(milliseconds=20)):
            yield

# Properly mock asyncio.sleep to avoid actual delays
@pytest.fixture
def mock_asyncio_sleep():
    with patch('asyncio.sleep', new_callable=AsyncMock) as mock_sleep:
        yield mock_sleep

# Properly mock random.randint to return a fixed value
@pytest.fixture
def mock_random():
    with patch('pymeow.pymeow.keepalive.random.randint', return_value=15) as mock_rand:  # 15ms interval
        yield mock_rand

# Properly mock datetime.now for predictable timestamps
@pytest.fixture
def mock_datetime():
    fixed_time = datetime(2024, 1, 1, 12, 0, 0)
    with patch('pymeow.pymeow.keepalive.datetime') as mock_dt:
        mock_dt.now.return_value = fixed_time
        mock_dt.timedelta = timedelta  # Keep the real timedelta
        # Keep the real datetime class for creating instances
        mock_dt.datetime = datetime
        yield mock_dt

# Remove this fixture as it's not working properly
# @pytest.fixture
# def mock_create_task():
#     """Mock asyncio.create_task to execute coroutines immediately."""
#     async def immediate_execution(coro):
#         return await coro
#
#     with patch('asyncio.create_task', side_effect=immediate_execution) as mock:
#         yield mock

@pytest.mark.asyncio
async def test_keepalive_loop_success(mock_asyncio_sleep, mock_random):
    """Test keepalive loop with successful pings."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock _send_keep_alive to return success twice, then stop
    call_count = 0
    async def mock_send_keep_alive():
        nonlocal call_count
        call_count += 1
        if call_count >= 2:  # Stop after 2 calls
            return False, False  # Should stop
        return True, True  # Success

    test_instance._send_keep_alive = AsyncMock(side_effect=mock_send_keep_alive)

    # Use timeout to prevent infinite hanging
    try:
        await asyncio.wait_for(test_instance._keepalive_loop(), timeout=1.0)
    except asyncio.TimeoutError:
        pytest.fail("Keepalive loop did not stop within timeout - check mock logic")

    # Verify _send_keep_alive was called exactly 2 times
    assert test_instance._send_keep_alive.call_count == 2

    # Verify asyncio.sleep was called with the expected short interval (15ms = 0.015s)
    mock_asyncio_sleep.assert_called_with(0.015)

    # Verify no timeout events were dispatched (all successful)
    timeout_events = [call for call in test_instance.dispatch_event.call_args_list
                     if isinstance(call[0][0], KeepAliveTimeout)]
    assert len(timeout_events) == 0

    # Verify no reconnect was attempted
    test_instance.disconnect.assert_not_called()
    test_instance._auto_reconnect.assert_not_called()

@pytest.mark.asyncio
async def test_keepalive_loop_failure_and_recovery(mock_asyncio_sleep, mock_random):
    """Test keepalive loop with failure and recovery."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock _send_keep_alive to return failure then success then stop
    call_count = 0
    async def mock_send_keep_alive():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return False, True  # First call: failure but continue
        elif call_count == 2:
            return True, True   # Second call: success but continue
        else:
            return False, False  # Third call and beyond: stop the loop

    test_instance._send_keep_alive = AsyncMock(side_effect=mock_send_keep_alive)

    # Track created tasks so we can wait for them
    created_tasks = []
    original_create_task = asyncio.create_task

    def tracking_create_task(coro):
        """Track created tasks so we can wait for them."""
        task = original_create_task(coro)
        created_tasks.append(task)
        return task

    # Patch create_task in the keepalive module
    with patch('pymeow.pymeow.keepalive.asyncio.create_task', side_effect=tracking_create_task):
        # Use timeout to prevent infinite hanging
        try:
            await asyncio.wait_for(test_instance._keepalive_loop(), timeout=1.0)
        except asyncio.TimeoutError:
            pytest.fail("Keepalive loop did not stop within timeout - check mock logic")

        # Wait for all background tasks to complete
        if created_tasks:
            try:
                await asyncio.wait_for(asyncio.gather(*created_tasks, return_exceptions=True), timeout=0.5)
            except asyncio.TimeoutError:
                # Cancel any remaining tasks
                for task in created_tasks:
                    if not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass

    # Give a small additional delay to ensure all async operations complete
    await asyncio.sleep(0.01)

    # Verify _send_keep_alive was called exactly 3 times
    assert test_instance._send_keep_alive.call_count == 3

    # Verify timeout event was dispatched for the first failure
    timeout_events = [call for call in test_instance.dispatch_event.call_args_list
                     if isinstance(call[0][0], KeepAliveTimeout)]
    assert len(timeout_events) == 1
    timeout_event = timeout_events[0][0][0]
    assert timeout_event.error_count == 1

    # Verify restored event was dispatched after recovery
    restored_events = [call for call in test_instance.dispatch_event.call_args_list
                      if isinstance(call[0][0], KeepAliveRestored)]
    assert len(restored_events) == 1

    # Verify no reconnect was attempted
    test_instance.disconnect.assert_not_called()
    test_instance._auto_reconnect.assert_not_called()

@pytest.mark.asyncio
async def test_keepalive_loop_multiple_failures():
    """Test keepalive loop with multiple failures triggering reconnect."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Set up datetime mock to trigger reconnect
    initial_time = datetime(2024, 1, 1, 12, 0, 0)
    later_time = initial_time + KEEP_ALIVE_MAX_FAIL_TIME + timedelta(seconds=1)

    # Mock datetime.now to return times that will trigger reconnect
    with patch('pymeow.pymeow.keepalive.datetime') as mock_datetime:
        mock_datetime.now.side_effect = [
            initial_time,   # Initial last_success
            later_time,     # Check for reconnect - this should trigger it
        ]
        mock_datetime.timedelta = timedelta  # Keep real timedelta

        # Mock random and sleep with fast intervals
        with patch('pymeow.pymeow.keepalive.random.randint', return_value=15):  # 15ms
            with patch('asyncio.sleep', new_callable=AsyncMock):
                # Mock asyncio.create_task to execute immediately
                async def immediate_task(coro):
                    return await coro

                with patch('pymeow.pymeow.keepalive.asyncio.create_task', side_effect=immediate_task):
                    # Mock _send_keep_alive to always return failure
                    test_instance._send_keep_alive = AsyncMock(return_value=(False, True))

                    # Use timeout to prevent infinite hanging
                    try:
                        await asyncio.wait_for(test_instance._keepalive_loop(), timeout=1.0)
                    except asyncio.TimeoutError:
                        pytest.fail("Keepalive loop did not stop within timeout")

                    # Verify disconnect and auto_reconnect were called
                    test_instance.disconnect.assert_called_once()
                    test_instance._auto_reconnect.assert_called_once()

@pytest.mark.asyncio
async def test_send_keep_alive_success():
    """Test successful keepalive ping."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Create a mock Node for the response
    mock_response = MagicMock(spec=Node)
    mock_response.xml_string = MagicMock(return_value=SAMPLE_RESPONSE_XML)

    # Create a future that will be returned by send_iq_async
    response_future = asyncio.Future()
    response_future.set_result(mock_response)

    # Mock send_iq_async to return the future
    test_instance.send_iq_async = AsyncMock(return_value=response_future)

    # Call the method under test
    is_success, should_continue = await test_instance._send_keep_alive()

    # Verify results
    assert is_success is True
    assert should_continue is True

    # Verify send_iq_async was called with a Node
    test_instance.send_iq_async.assert_called_once()
    call_args = test_instance.send_iq_async.call_args[0][0]
    assert isinstance(call_args, Node)
    assert call_args.tag == "iq"
    assert call_args.attributes["type"] == "get"
    assert call_args.attributes["xmlns"] == "w:p"
    assert call_args.attributes["to"] == "s.whatsapp.net"

@pytest.mark.asyncio
async def test_send_keep_alive_timeout():
    """Test keepalive ping timeout."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Create a future that will never complete (simulates timeout)
    response_future = asyncio.Future()

    # Mock send_iq_async to return the future
    test_instance.send_iq_async = AsyncMock(return_value=response_future)

    # Mock asyncio.wait_for to raise TimeoutError
    with patch('asyncio.wait_for', AsyncMock(side_effect=asyncio.TimeoutError())):
        # Call the method under test
        is_success, should_continue = await test_instance._send_keep_alive()

        # Verify results
        assert is_success is False
        assert should_continue is True

        # Verify send_iq_async was called
        test_instance.send_iq_async.assert_called_once()

@pytest.mark.asyncio
async def test_send_keep_alive_cancelled():
    """Test keepalive ping cancelled."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock send_iq_async to raise CancelledError
    test_instance.send_iq_async = AsyncMock(side_effect=asyncio.CancelledError())

    # Call the method under test
    is_success, should_continue = await test_instance._send_keep_alive()

    # Verify results
    assert is_success is False
    assert should_continue is False

    # Verify send_iq_async was called
    test_instance.send_iq_async.assert_called_once()

@pytest.mark.asyncio
async def test_send_keep_alive_error():
    """Test keepalive ping with error."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock send_iq_async to raise Exception
    test_instance.send_iq_async = AsyncMock(side_effect=Exception("Test error"))

    # Call the method under test
    is_success, should_continue = await test_instance._send_keep_alive()

    # Verify results
    assert is_success is False
    assert should_continue is True

    # Verify send_iq_async was called
    test_instance.send_iq_async.assert_called_once()

@pytest.mark.asyncio
async def test_dispatch_keepalive_timeout():
    """Test dispatching keepalive timeout event."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Call the method under test
    error_count = 3
    last_success = datetime.now() - timedelta(seconds=30)
    await test_instance._dispatch_keepalive_timeout(error_count, last_success)

    # Verify dispatch_event was called with KeepAliveTimeout
    test_instance.dispatch_event.assert_called_once()
    event = test_instance.dispatch_event.call_args[0][0]
    assert isinstance(event, KeepAliveTimeout)
    assert event.error_count == error_count
    assert event.last_success == last_success

@pytest.mark.asyncio
async def test_dispatch_keepalive_restored():
    """Test dispatching keepalive restored event."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Call the method under test
    await test_instance._dispatch_keepalive_restored()

    # Verify dispatch_event was called with KeepAliveRestored
    test_instance.dispatch_event.assert_called_once()
    event = test_instance.dispatch_event.call_args[0][0]
    assert isinstance(event, KeepAliveRestored)

@pytest.mark.asyncio
async def test_send_keep_alive_node_structure():
    """Test that the keepalive node has the correct structure."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock send_iq_async to capture the node
    captured_node = None
    async def capture_node(node):
        nonlocal captured_node
        captured_node = node
        future = asyncio.Future()
        future.set_result(MagicMock())
        return future

    test_instance.send_iq_async = capture_node

    # Call the method under test
    await test_instance._send_keep_alive()

    # Verify the node structure
    assert captured_node is not None
    assert captured_node.tag == "iq"
    assert "id" in captured_node.attributes
    assert captured_node.attributes["type"] == "get"
    assert captured_node.attributes["to"] == "s.whatsapp.net"
    assert captured_node.attributes["xmlns"] == "w:p"
    assert captured_node.content == []  # Empty content for ping

    # Verify the attributes that send_iq_async expects
    assert hasattr(captured_node, 'id')
    assert hasattr(captured_node, 'namespace')
    assert hasattr(captured_node, 'type')
    assert captured_node.namespace == "w:p"
    assert captured_node.type == "get"

@pytest.mark.asyncio
async def test_keepalive_loop_exception_handling():
    """Test that exceptions in the keepalive loop are handled properly."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Mock _send_keep_alive to raise an exception, then return stop
    call_count = 0
    async def mock_send_keep_alive():
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Test exception")
        return False, False  # Stop after first exception

    test_instance._send_keep_alive = AsyncMock(side_effect=mock_send_keep_alive)

    # Mock the logger to capture error logs
    with patch('pymeow.pymeow.keepalive.logger') as mock_logger:
        with patch('pymeow.pymeow.keepalive.random.randint', return_value=15):  # 15ms
            with patch('asyncio.sleep', new_callable=AsyncMock):
                # Use timeout to prevent infinite hanging
                try:
                    await asyncio.wait_for(test_instance._keepalive_loop(), timeout=1.0)
                except asyncio.TimeoutError:
                    pytest.fail("Keepalive loop did not stop within timeout")

                # Verify the error was logged
                mock_logger.error.assert_called()
                error_call = mock_logger.error.call_args
                assert "Unexpected error in keepalive loop" in error_call[0][0]

# Integration test with real timing (marked as slow)
@pytest.mark.slow
@pytest.mark.asyncio
async def test_keepalive_real_timing():
    """Integration test with real timing (takes a few seconds)."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Track calls
    call_times = []

    async def track_calls():
        call_times.append(datetime.now())
        if len(call_times) >= 3:  # Stop after 3 calls
            return False, False
        return True, True

    test_instance._send_keep_alive = AsyncMock(side_effect=track_calls)

    # Use fast intervals for this test too
    with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MIN', timedelta(milliseconds=50)):
        with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MAX', timedelta(milliseconds=100)):
            # Start the keepalive loop
            start_time = datetime.now()
            await test_instance._keepalive_loop()
            end_time = datetime.now()

    # Verify timing
    assert len(call_times) == 3
    total_duration = end_time - start_time
    assert total_duration.total_seconds() < 1  # Should complete quickly with short intervals

    # Verify calls were spaced out
    if len(call_times) >= 2:
        interval = call_times[1] - call_times[0]
        assert 0.025 < interval.total_seconds() < 0.15  # Between 25ms and 150ms

# Test specifically for the .value attribute issue
@pytest.mark.asyncio
async def test_send_iq_async_interface():
    """Test what send_iq_async actually expects to debug the .value issue."""
    # Create test instance
    test_instance = TestKeepAlive()

    # Create a comprehensive mock that logs all attribute access
    class AttributeTracker:
        def __init__(self):
            self.accessed_attributes = []

        def __getattr__(self, name):
            self.accessed_attributes.append(name)
            if name == 'value':
                return "mock_value"
            elif name == 'id':
                return "mock_id"
            elif name == 'namespace':
                return "w:p"
            elif name == 'type':
                return "get"
            else:
                return f"mock_{name}"

    tracker = AttributeTracker()

    # Mock send_iq_async to use our tracker
    async def mock_send_iq_with_tracking(query):
        # Try to access attributes that might be causing the issue
        try:
            _ = query.value  # This is where the error occurs
        except AttributeError as e:
            # Log what we tried to access
            print(f"AttributeError accessing .value: {e}")
            print(f"Query type: {type(query)}")
            print(f"Query attributes: {dir(query) if hasattr(query, '__dict__') else 'no __dict__'}")

        future = asyncio.Future()
        future.set_result(tracker)
        return future

    test_instance.send_iq_async = mock_send_iq_with_tracking

    # Call the method under test
    try:
        await test_instance._send_keep_alive()
    except Exception as e:
        # If it fails, we want to see what attributes were accessed
        print(f"Exception during test: {e}")
        print(f"Accessed attributes: {tracker.accessed_attributes}")
        raise

    # Print what attributes were accessed for debugging
    print(f"Successfully accessed attributes: {tracker.accessed_attributes}")
