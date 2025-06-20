"""
Keepalive mechanism for WhatsApp Web connection.

Port of whatsmeow/keepalive.go
"""
import asyncio
import logging
import random
import uuid
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Tuple

from . import request
from .request import InfoQuery, InfoQueryType
from .datatypes import JID
from .datatypes.events.events import KeepAliveRestored, KeepAliveTimeout
from .datatypes.message import MessageID

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

async def keep_alive_loop(client: 'Client') -> None:
    """
    Port of Go method keepAliveLoop from keepalive.go.

    Main keepalive loop that periodically sends pings to detect connection issues.
    Runs continuously until the client disconnects or task is cancelled.

    Args:
        client: The WhatsApp client instance
    """
    # TODO: Review dispatchEvent implementation
    # TODO: Review sendIQAsync implementation
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

                await client.dispatch_event(KeepAliveTimeout(
                    error_count=error_count,
                    last_success=last_success
                ))

                # Check if we should force reconnect
                if (client.enable_auto_reconnect and
                    datetime.now() - last_success > KEEP_ALIVE_MAX_FAIL_TIME):

                    logger.debug("Forcing reconnect due to keepalive failure")
                    await client.disconnect()
                    client.create_task(client.auto_reconnect())
                    return
            else:
                # Ping succeeded
                if error_count > 0:
                    error_count = 0
                    await client.dispatch_event(KeepAliveRestored())
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
        # Create a proper InfoQuery for keepalive
        ping_query = InfoQuery(
            id=MessageID(str(uuid.uuid4())),
            namespace="w:p",
            type=InfoQueryType.GET,
            to=JID.server_jid(),
            content=[]  # Empty content for ping
        )

        # Send info query for keepalive using the actual client API
        # send_iq_async returns (queue, error) tuple, not a future
        response_queue = await request.send_iq_async(client, ping_query)
        # Wait for response from the queue with timeout
        try:
            response = await asyncio.wait_for(
                response_queue.get(),  # Get response from the queue
                timeout=KEEP_ALIVE_RESPONSE_DEADLINE.total_seconds()
            )
            # Response received successfully
            return True, True

        except asyncio.TimeoutError:
            logger.warning("Keepalive timed out")
            return False, True  # Timeout but continue

    except asyncio.CancelledError:
        return False, False

    except Exception as e:
        logger.exception(f"Failed to send keepalive: {e}")
        return False, True  # Error but continue
