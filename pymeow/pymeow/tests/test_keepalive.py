"""
Tests for the keepalive functionality.

This tests the keepalive mechanism that maintains the connection with the WhatsApp server.
"""
import asyncio
from datetime import datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ..pymeow.binary.node import Node
from ..pymeow.keepalive import (
    KEEP_ALIVE_MAX_FAIL_TIME,
    KeepAliveManager,
    dispatch_keepalive_restored,
    dispatch_keepalive_timeout,
    keepalive_loop,
    send_keep_alive,
)
from ..pymeow.datatypes.events.events import KeepAliveRestored, KeepAliveTimeout

# Real test values captured from logs
SAMPLE_PING_NODE_XML = '<iq id="b7e0afa7-e9da-4ed7-8c3b-0247dbb98a6e" type="get" to="s.whatsapp.net" xmlns="w:p"></iq>'
# No response in logs, but we can use a similar format to the ping
SAMPLE_RESPONSE_XML = '<iq id="b7e0afa7-e9da-4ed7-8c3b-0247dbb98a6e" type="result" from="s.whatsapp.net" to="user@s.whatsapp.net"></iq>'


class MockClient:
    """Mock client for keepalive functionality testing."""

    def __init__(self):
        """Initialize the mock client."""
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


@pytest.mark.asyncio
async def test_keepalive_loop_success(mock_asyncio_sleep, mock_random):
    """Test keepalive loop with successful pings."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_keep_alive to return success twice, then stop
    call_count = 0
    async def mock_send_keep_alive(client):
        nonlocal call_count
        call_count += 1
        if call_count >= 2:  # Stop after 2 calls
            return False, False  # Should stop
        return True, True  # Success

    # Patch the send_keep_alive function
    with patch('pymeow.pymeow.keepalive.send_keep_alive', side_effect=mock_send_keep_alive) as mock_send:
        # Use timeout to prevent infinite hanging
        try:
            await asyncio.wait_for(keepalive_loop(mock_client), timeout=1.0)
        except asyncio.TimeoutError:
            pytest.fail("Keepalive loop did not stop within timeout - check mock logic")

        # Verify send_keep_alive was called exactly 2 times
        assert mock_send.call_count == 2

        # Verify asyncio.sleep was called with the expected short interval (15ms = 0.015s)
        mock_asyncio_sleep.assert_called_with(0.015)

        # Verify no timeout events were dispatched (all successful)
        timeout_events = [call for call in mock_client.dispatch_event.call_args_list
                         if isinstance(call[0][0], KeepAliveTimeout)]
        assert len(timeout_events) == 0

        # Verify no reconnect was attempted
        mock_client.disconnect.assert_not_called()
        mock_client._auto_reconnect.assert_not_called()


@pytest.mark.asyncio
async def test_keepalive_loop_failure_and_recovery(mock_asyncio_sleep, mock_random):
    """Test keepalive loop with failure and recovery."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_keep_alive to return failure then success then stop
    call_count = 0
    async def mock_send_keep_alive(client):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return False, True  # First call: failure but continue
        elif call_count == 2:
            return True, True   # Second call: success but continue
        else:
            return False, False  # Third call and beyond: stop the loop

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
        with patch('pymeow.pymeow.keepalive.send_keep_alive', side_effect=mock_send_keep_alive) as mock_send:
            # Use timeout to prevent infinite hanging
            try:
                await asyncio.wait_for(keepalive_loop(mock_client), timeout=1.0)
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

    # Verify send_keep_alive was called exactly 3 times
    assert mock_send.call_count == 3

    # Verify timeout event was dispatched for the first failure
    timeout_events = [call_ for call_ in mock_client.dispatch_event.call_args_list
                     if isinstance(call_[0][0], KeepAliveTimeout)]
    assert len(timeout_events) == 1
    timeout_event = timeout_events[0][0][0]
    assert timeout_event.error_count == 1

    # Verify restored event was dispatched after recovery
    restored_events = [call_ for call_ in mock_client.dispatch_event.call_args_list
                      if isinstance(call_[0][0], KeepAliveRestored)]
    assert len(restored_events) == 1

    # Verify no reconnect was attempted
    mock_client.disconnect.assert_not_called()
    mock_client._auto_reconnect.assert_not_called()


@pytest.mark.asyncio
async def test_keepalive_loop_multiple_failures():
    """Test keepalive loop with multiple failures triggering reconnect."""
    # Create mock client
    mock_client = MockClient()

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
                    # Mock send_keep_alive to always return failure
                    with patch('pymeow.pymeow.keepalive.send_keep_alive', return_value=(False, True)):
                        # Use timeout to prevent infinite hanging
                        try:
                            await asyncio.wait_for(keepalive_loop(mock_client), timeout=1.0)
                        except asyncio.TimeoutError:
                            pytest.fail("Keepalive loop did not stop within timeout")

                        # Verify disconnect and auto_reconnect were called
                        mock_client.disconnect.assert_called_once()
                        mock_client._auto_reconnect.assert_called_once()


@pytest.mark.asyncio
async def test_send_keep_alive_success():
    """Test successful keepalive ping."""
    # Create mock client
    mock_client = MockClient()

    # Create a mock Node for the response
    mock_response = MagicMock(spec=Node)
    mock_response.xml_string = MagicMock(return_value=SAMPLE_RESPONSE_XML)

    # Create a queue and put the response in it
    response_queue = asyncio.Queue()
    await response_queue.put(mock_response)

    # Mock send_iq_async to return (queue, None) tuple as per the new interface
    mock_client.send_iq_async = AsyncMock(return_value=(response_queue, None))

    # Call the method under test
    is_success, should_continue = await send_keep_alive(mock_client)

    # Verify results
    assert is_success is True
    assert should_continue is True

    # Verify send_iq_async was called
    mock_client.send_iq_async.assert_called_once()


@pytest.mark.asyncio
async def test_send_keep_alive_timeout():
    """Test keepalive ping timeout."""
    # Create mock client
    mock_client = MockClient()

    # Create a queue that will never complete (simulates timeout)
    response_queue = asyncio.Queue()

    # Mock send_iq_async to return the queue
    mock_client.send_iq_async = AsyncMock(return_value=(response_queue, None))

    # Mock asyncio.wait_for to raise TimeoutError
    with patch('asyncio.wait_for', AsyncMock(side_effect=asyncio.TimeoutError())):
        # Call the method under test
        is_success, should_continue = await send_keep_alive(mock_client)

        # Verify results
        assert is_success is False
        assert should_continue is True

        # Verify send_iq_async was called
        mock_client.send_iq_async.assert_called_once()


@pytest.mark.asyncio
async def test_send_keep_alive_cancelled():
    """Test keepalive ping cancelled."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_iq_async to raise CancelledError
    mock_client.send_iq_async = AsyncMock(side_effect=asyncio.CancelledError())

    # Call the method under test
    is_success, should_continue = await send_keep_alive(mock_client)

    # Verify results
    assert is_success is False
    assert should_continue is False

    # Verify send_iq_async was called
    mock_client.send_iq_async.assert_called_once()


@pytest.mark.asyncio
async def test_send_keep_alive_error():
    """Test keepalive ping with error."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_iq_async to raise Exception
    mock_client.send_iq_async = AsyncMock(side_effect=Exception("Test error"))

    # Call the method under test
    is_success, should_continue = await send_keep_alive(mock_client)

    # Verify results
    assert is_success is False
    assert should_continue is True

    # Verify send_iq_async was called
    mock_client.send_iq_async.assert_called_once()


@pytest.mark.asyncio
async def test_dispatch_keepalive_timeout():
    """Test dispatching keepalive timeout event."""
    # Create mock client
    mock_client = MockClient()

    # Call the method under test
    error_count = 3
    last_success = datetime.now() - timedelta(seconds=30)
    await dispatch_keepalive_timeout(mock_client, error_count, last_success)

    # Verify dispatch_event was called with KeepAliveTimeout
    mock_client.dispatch_event.assert_called_once()
    event = mock_client.dispatch_event.call_args[0][0]
    assert isinstance(event, KeepAliveTimeout)
    assert event.error_count == error_count
    assert event.last_success == last_success


@pytest.mark.asyncio
async def test_dispatch_keepalive_restored():
    """Test dispatching keepalive restored event."""
    # Create mock client
    mock_client = MockClient()

    # Call the method under test
    await dispatch_keepalive_restored(mock_client)

    # Verify dispatch_event was called with KeepAliveRestored
    mock_client.dispatch_event.assert_called_once()
    event = mock_client.dispatch_event.call_args[0][0]
    assert isinstance(event, KeepAliveRestored)


@pytest.mark.asyncio
async def test_send_keep_alive_node_structure():
    """Test that the keepalive query has the correct structure."""
    from ..pymeow.request import InfoQuery, InfoQueryType  # Import the classes we need

    # Create mock client
    mock_client = MockClient()

    # Mock send_iq_async to capture the query
    captured_query = None
    async def capture_query(query):
        nonlocal captured_query
        captured_query = query
        # Return the expected tuple format (queue, error)
        response_queue = asyncio.Queue()
        await response_queue.put(MagicMock())
        return response_queue, None

    mock_client.send_iq_async = capture_query

    # Call the method under test
    await send_keep_alive(mock_client)

    # Verify the query structure
    assert captured_query is not None
    assert isinstance(captured_query, InfoQuery)

    # Verify the InfoQuery attributes
    assert hasattr(captured_query, 'id')
    assert hasattr(captured_query, 'namespace')
    assert hasattr(captured_query, 'type')
    assert hasattr(captured_query, 'to')
    assert hasattr(captured_query, 'content')

    # Verify the values
    assert captured_query.namespace == "w:p"
    assert captured_query.type == InfoQueryType.GET
    assert str(captured_query.to) == "s.whatsapp.net"
    assert captured_query.content == []  # Empty content for ping
    assert captured_query.id is not None  # Should have a UUID


@pytest.mark.asyncio
async def test_keepalive_loop_exception_handling():
    """Test that exceptions in the keepalive loop are handled properly."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_keep_alive to raise an exception, then return stop
    call_count = 0
    async def mock_send_keep_alive(client):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            raise RuntimeError("Test exception")
        return False, False  # Stop after first exception

    # Mock the logger to capture error logs
    with patch('pymeow.pymeow.keepalive.logger') as mock_logger:
        with patch('pymeow.pymeow.keepalive.random.randint', return_value=15):  # 15ms
            with patch('asyncio.sleep', new_callable=AsyncMock):
                with patch('pymeow.pymeow.keepalive.send_keep_alive', side_effect=mock_send_keep_alive):
                    # Use timeout to prevent infinite hanging
                    try:
                        await asyncio.wait_for(keepalive_loop(mock_client), timeout=1.0)
                    except asyncio.TimeoutError:
                        pytest.fail("Keepalive loop did not stop within timeout")

                    # Verify the error was logged
                    mock_logger.error.assert_called()
                    error_call = mock_logger.error.call_args
                    assert "Unexpected error in keepalive loop" in error_call[0][0]


@pytest.mark.asyncio
async def test_send_keep_alive_with_correct_interface():
    """Test send_keep_alive with the correct send_iq_async interface."""
    # Create mock client
    mock_client = MockClient()

    # Create a mock response queue
    response_queue = asyncio.Queue()

    # Create a mock response and put it in the queue
    mock_response = MagicMock()
    mock_response.xml_string = MagicMock(return_value='<iq type="result"/>')
    await response_queue.put(mock_response)

    # Mock send_iq_async to return (queue, None) as per the real interface
    async def correct_send_iq_async(query):
        return response_queue, None  # (queue, error)

    mock_client.send_iq_async = correct_send_iq_async

    # Call the method under test
    is_success, should_continue = await send_keep_alive(mock_client)

    # Verify results
    assert is_success is True
    assert should_continue is True


@pytest.mark.asyncio
async def test_send_keep_alive_with_error():
    """Test send_keep_alive when send_iq_async returns an error."""
    # Create mock client
    mock_client = MockClient()

    # Mock send_iq_async to return an error
    async def error_send_iq_async(query):
        return None, Exception("Test error")  # (queue, error)

    mock_client.send_iq_async = error_send_iq_async

    # Call the method under test
    is_success, should_continue = await send_keep_alive(mock_client)

    # Verify results
    assert is_success is False
    assert should_continue is True


@pytest.mark.asyncio
async def test_send_keep_alive_queue_timeout():
    """Test send_keep_alive when the response queue times out."""
    # Create mock client
    mock_client = MockClient()

    # Create an empty queue that will timeout
    response_queue = asyncio.Queue()

    # Mock send_iq_async to return empty queue
    async def timeout_send_iq_async(query):
        return response_queue, None  # (queue, error)

    mock_client.send_iq_async = timeout_send_iq_async

    # Mock the response deadline to be very short for fast testing
    with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_RESPONSE_DEADLINE', timedelta(milliseconds=10)):
        # Call the method under test
        is_success, should_continue = await send_keep_alive(mock_client)

        # Verify results
        assert is_success is False
        assert should_continue is True


# Tests for KeepAliveManager class
@pytest.mark.asyncio
async def test_keepalive_manager_start_stop():
    """Test KeepAliveManager start and stop functionality."""
    # Create mock client
    mock_client = MockClient()

    # Create manager
    manager = KeepAliveManager(mock_client)

    # Initially not running
    assert not manager.is_keepalive_running()

    # Mock the keepalive_loop to complete quickly
    with patch('pymeow.pymeow.keepalive.keepalive_loop') as mock_loop:
        mock_loop.return_value = asyncio.create_task(asyncio.sleep(0.01))

        # Start the loop
        await manager.start_keepalive_loop()

        # Should be running
        assert manager.is_keepalive_running()

        # Stop the loop
        await manager.stop_keepalive_loop()

        # Should not be running
        assert not manager.is_keepalive_running()


@pytest.mark.asyncio
async def test_keepalive_manager_send_keepalive():
    """Test KeepAliveManager send_keepalive method."""
    # Create mock client
    mock_client = MockClient()

    # Create manager
    manager = KeepAliveManager(mock_client)

    # Mock send_keep_alive
    with patch('pymeow.pymeow.keepalive.send_keep_alive', return_value=(True, True)) as mock_send:
        # Call send_keepalive
        result = await manager.send_keepalive()

        # Verify result
        assert result == (True, True)

        # Verify send_keep_alive was called with the client
        mock_send.assert_called_once_with(mock_client)


# Integration test with real timing (marked as slow)
@pytest.mark.slow
@pytest.mark.asyncio
async def test_keepalive_real_timing():
    """Integration test with real timing (takes a few seconds)."""
    # Create mock client
    mock_client = MockClient()

    # Track calls
    call_times = []

    async def track_calls(client):
        call_times.append(datetime.now())
        if len(call_times) >= 3:  # Stop after 3 calls
            return False, False
        return True, True

    # Use fast intervals for this test too
    with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MIN', timedelta(milliseconds=50)):
        with patch('pymeow.pymeow.keepalive.KEEP_ALIVE_INTERVAL_MAX', timedelta(milliseconds=100)):
            with patch('pymeow.pymeow.keepalive.send_keep_alive', side_effect=track_calls):
                # Start the keepalive loop
                start_time = datetime.now()
                await keepalive_loop(mock_client)
                end_time = datetime.now()

    # Verify timing
    assert len(call_times) == 3
    total_duration = end_time - start_time
    assert total_duration.total_seconds() < 1  # Should complete quickly with short intervals

    # Verify calls were spaced out
    if len(call_times) >= 2:
        interval = call_times[1] - call_times[0]
        assert 0.025 < interval.total_seconds() < 0.15  # Between 25ms and 150ms
