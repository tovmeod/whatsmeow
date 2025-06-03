"""
Keepalive mechanism for WhatsApp Web connection.

Port of whatsmeow/keepalive.go
"""
import asyncio
import logging
import random
from datetime import datetime, timedelta
from typing import Tuple, Optional, TYPE_CHECKING

from .types.events.events import KeepAliveTimeout, KeepAliveRestored

if TYPE_CHECKING:
    from .client import Client

# Logger for test values
test_log = logging.getLogger("pymeow.test_values")

# Constants for keepalive timing
KEEP_ALIVE_RESPONSE_DEADLINE = timedelta(seconds=10)
KEEP_ALIVE_INTERVAL_MIN = timedelta(seconds=20)
KEEP_ALIVE_INTERVAL_MAX = timedelta(seconds=30)
KEEP_ALIVE_MAX_FAIL_TIME = timedelta(minutes=3)

logger = logging.getLogger(__name__)


async def keepalive_loop(client: 'Client') -> None:
    """
    Main keepalive loop that periodically sends pings to the server.

    This method runs continuously until cancelled,
    sending keepalive pings at random intervals to detect connection issues.

    Args:
        client: The WhatsApp client instance
    """
    logger.debug("Starting keepalive loop")
    last_success = datetime.now()
    error_count = 0

    try:
        while True:
            # Calculate random interval between min and max (in milliseconds)
            interval_ms = random.randint(
                int(KEEP_ALIVE_INTERVAL_MIN.total_seconds() * 1000),
                int(KEEP_ALIVE_INTERVAL_MAX.total_seconds() * 1000)
            )

            # Wait for the calculated interval
            await asyncio.sleep(interval_ms / 1000.0)

            # Send keepalive ping
            is_success, should_continue = await send_keep_alive(client)

            if not should_continue:
                logger.debug("Keepalive loop stopping")
                return
            elif not is_success:
                error_count += 1

                # Dispatch timeout event
                asyncio.create_task(
                    dispatch_keepalive_timeout(client, error_count, last_success)
                )

                # Check if we should force reconnect
                if (client.enable_auto_reconnect and
                    datetime.now() - last_success > KEEP_ALIVE_MAX_FAIL_TIME):

                    logger.debug("Forcing reconnect due to keepalive failure")
                    await client.disconnect()
                    asyncio.create_task(client._auto_reconnect())
                    return
            else:
                # Ping succeeded
                if error_count > 0:
                    error_count = 0
                    asyncio.create_task(dispatch_keepalive_restored(client))
                last_success = datetime.now()

    except asyncio.CancelledError:
        logger.debug("Keepalive loop cancelled")
        return
    except Exception as e:
        logger.error(f"Unexpected error in keepalive loop: {e}", exc_info=True)


async def send_keep_alive(client: 'Client') -> Tuple[bool, bool]:
    """
    Send a keepalive ping to the server.

    Args:
        client: The WhatsApp client instance

    Returns:
        Tuple of (is_success, should_continue):
        - is_success: True if ping succeeded, False if it failed/timed out
        - should_continue: True if keepalive loop should continue, False if it should stop
    """
    try:
        from .request import InfoQuery, InfoQueryType
        from .types.jid import JID
        import uuid

        # Log test values for mocking
        test_log.info("KEEPALIVE_START: Capturing values for test mocking")

        # Create a proper InfoQuery for keepalive
        iq_id = str(uuid.uuid4())
        ping_query = InfoQuery(
            id=iq_id,
            namespace="w:p",
            type=InfoQueryType.GET,
            to=JID.server_jid(),
            content=[]  # Empty content for ping
        )

        # Log the ping query for testing
        test_log.info(f"KEEPALIVE_PING_QUERY: ID={ping_query.id}, namespace={ping_query.namespace}, type={ping_query.type}, to={ping_query.to}")

        # Send info query for keepalive using the actual client API
        # send_iq_async returns (queue, error) tuple, not a future
        response_queue, error = await client.send_iq_async(ping_query)

        if error is not None:
            logger.warning(f"Keepalive failed with error: {error}")
            return False, True  # Error but continue

        # Wait for response from the queue with timeout
        try:
            response = await asyncio.wait_for(
                response_queue.get(),  # Get response from the queue
                timeout=KEEP_ALIVE_RESPONSE_DEADLINE.total_seconds()
            )
            # Response received successfully
            # Log the response for testing
            if response:
                test_log.info(f"KEEPALIVE_RESPONSE: {response.xml_string() if hasattr(response, 'xml_string') else str(response)}")
            return True, True

        except asyncio.TimeoutError:
            logger.warning("Keepalive timed out")
            test_log.info("KEEPALIVE_TIMEOUT: Keepalive request timed out")
            return False, True  # Timeout but continue

    except asyncio.CancelledError:
        # Context was cancelled
        return False, False

    except Exception as e:
        logger.exception(f"Failed to send keepalive: {e}")
        return False, True  # Error but continue


async def dispatch_keepalive_timeout(client: 'Client', error_count: int, last_success: datetime) -> None:
    """
    Dispatch keepalive timeout event in background.

    Args:
        client: The WhatsApp client instance
        error_count: Number of consecutive keepalive errors
        last_success: Timestamp of last successful keepalive
    """
    try:
        event = KeepAliveTimeout(
            error_count=error_count,
            last_success=last_success
        )
        await client.dispatch_event(event)  # Make this async
    except Exception as e:
        logger.warning(f"Failed to dispatch keepalive timeout event: {e}")


async def dispatch_keepalive_restored(client: 'Client') -> None:
    """
    Dispatch keepalive restored event in background.

    Args:
        client: The WhatsApp client instance
    """
    try:
        event = KeepAliveRestored()
        await client.dispatch_event(event)  # Make this async
    except Exception as e:
        logger.warning(f"Failed to dispatch keepalive restored event: {e}")


class KeepAliveManager:
    """
    Manager class for keepalive functionality.

    This class provides a convenient interface for managing keepalive operations
    while using composition instead of inheritance.
    """

    def __init__(self, client: 'Client'):
        """
        Initialize the keepalive manager.

        Args:
            client: The WhatsApp client instance
        """
        self.client = client
        self._keepalive_task: Optional[asyncio.Task] = None

    async def start_keepalive_loop(self) -> None:
        """Start the keepalive loop."""
        if self._keepalive_task is None or self._keepalive_task.done():
            self._keepalive_task = asyncio.create_task(keepalive_loop(self.client))

    async def stop_keepalive_loop(self) -> None:
        """Stop the keepalive loop."""
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
            try:
                await self._keepalive_task
            except asyncio.CancelledError:
                pass
            self._keepalive_task = None

    async def send_keepalive(self) -> Tuple[bool, bool]:
        """Send a keepalive ping to the server."""
        return await send_keep_alive(self.client)

    def is_keepalive_running(self) -> bool:
        """Check if the keepalive loop is currently running."""
        return self._keepalive_task is not None and not self._keepalive_task.done()
