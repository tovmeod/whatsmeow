"""
Keepalive mechanism for WhatsApp Web connection.

Port of whatsmeow/keepalive.go
"""
import asyncio
import logging
import random
from datetime import datetime, timedelta
from typing import Tuple, Optional

from .types.events.events import KeepAliveTimeout, KeepAliveRestored
from .types.jid import JID

# Logger for test values
test_log = logging.getLogger("pymeow.test_values")


# Constants for keepalive timing
KEEP_ALIVE_RESPONSE_DEADLINE = timedelta(seconds=10)
KEEP_ALIVE_INTERVAL_MIN = timedelta(seconds=20)
KEEP_ALIVE_INTERVAL_MAX = timedelta(seconds=30)
KEEP_ALIVE_MAX_FAIL_TIME = timedelta(minutes=3)

logger = logging.getLogger(__name__)

class KeepAliveMixin:
    """
    WhatsApp Web client with keepalive functionality.
    """
    async def _keepalive_loop(self) -> None:
        """
        Main keepalive loop that periodically sends pings to the server.

        This method runs continuously until cancelled,
        sending keepalive pings at random intervals to detect connection issues.
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
                is_success, should_continue = await self._send_keep_alive()

                if not should_continue:
                    logger.debug("Keepalive loop stopping")
                    return
                elif not is_success:
                    error_count += 1

                    # Dispatch timeout event
                    asyncio.create_task(
                        self._dispatch_keepalive_timeout(error_count, last_success)
                    )

                    # Check if we should force reconnect
                    if (self.enable_auto_reconnect and
                        datetime.now() - last_success > KEEP_ALIVE_MAX_FAIL_TIME):

                        logger.debug("Forcing reconnect due to keepalive failure")
                        await self.disconnect()
                        asyncio.create_task(self._auto_reconnect())
                        return
                else:
                    # Ping succeeded
                    if error_count > 0:
                        error_count = 0
                        asyncio.create_task(self._dispatch_keepalive_restored())
                    last_success = datetime.now()

        except asyncio.CancelledError:
            logger.debug("Keepalive loop cancelled")
            return
        except Exception as e:
            logger.error(f"Unexpected error in keepalive loop: {e}", exc_info=True)

    async def _send_keep_alive(self) -> Tuple[bool, bool]:
        """
        Send a keepalive ping to the server.

        Returns:
            Tuple of (is_success, should_continue):
            - is_success: True if ping succeeded, False if it failed/timed out
            - should_continue: True if keepalive loop should continue, False if it should stop
        """
        try:
            from .binary.node import Node
            from .types.jid import JID
            import uuid

            # Log test values for mocking
            test_log.info("KEEPALIVE_START: Capturing values for test mocking")

            # Create a proper IQ query node for keepalive
            iq_id = str(uuid.uuid4())
            ping_node = Node(
                tag="iq",
                attributes={
                    "id": iq_id,
                    "type": "get",
                    "to": str(JID.server_jid()),
                    "xmlns": "w:p"
                },
                content=[]  # Empty content for ping
            )

            # Add the attributes that send_iq_async expects
            ping_node.id = iq_id
            ping_node.namespace = "w:p"  # Add namespace attribute
            ping_node.type = "get"       # Add type attribute

            # Log the ping node for testing
            test_log.info(f"KEEPALIVE_PING_NODE: {ping_node.xml_string()}")

            # Send info query for keepalive using the actual client API
            resp_future = await self.send_iq_async(ping_node)

            # Wait for response with timeout
            try:
                response = await asyncio.wait_for(
                    resp_future,
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
            logger.warning(f"Failed to send keepalive: {e}")
            return False, True  # Error but continue

    async def _dispatch_keepalive_timeout(self, error_count: int, last_success: datetime) -> None:
        """Dispatch keepalive timeout event in background."""
        try:
            event = KeepAliveTimeout(
                error_count=error_count,
                last_success=last_success
            )
            await self.dispatch_event(event)  # Make this async
        except Exception as e:
            logger.warning(f"Failed to dispatch keepalive timeout event: {e}")

    async def _dispatch_keepalive_restored(self) -> None:
        """Dispatch keepalive restored event in background."""
        try:
            event = KeepAliveRestored()
            await self.dispatch_event(event)  # Make this async
        except Exception as e:
            logger.warning(f"Failed to dispatch keepalive restored event: {e}")
