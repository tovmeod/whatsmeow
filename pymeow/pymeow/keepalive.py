"""
Keepalive mechanism for WhatsApp Web connection.

Port of whatsmeow/keepalive.go
"""
import asyncio
import random
from datetime import datetime, timedelta
from typing import Tuple

from .request import InfoQuery, InfoQueryType
from .types.events import KeepAliveTimeout, KeepAliveRestored
from .types.jid import JID


# Constants for keepalive timing
KEEP_ALIVE_RESPONSE_DEADLINE = timedelta(seconds=10)
KEEP_ALIVE_INTERVAL_MIN = timedelta(seconds=20)
KEEP_ALIVE_INTERVAL_MAX = timedelta(seconds=30)
KEEP_ALIVE_MAX_FAIL_TIME = timedelta(minutes=3)


class Client:
    """
    WhatsApp Web client with keepalive functionality.

    This is a partial Client class showing only keepalive-related methods.
    In the actual implementation, this would be part of the main Client class.
    """

    def __init__(self):
        self.enable_auto_reconnect: bool = True
        self.log = None  # Placeholder for logger

    async def keep_alive_loop(self, ctx: asyncio.Task = None) -> None:
        """
        Main keepalive loop that periodically sends pings to the server.

        This method runs continuously until the context is cancelled,
        sending keepalive pings at random intervals to detect connection issues.

        Args:
            ctx: Optional asyncio task for cancellation context
        """
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
                is_success, should_continue = await self.send_keep_alive()

                if not should_continue:
                    return
                elif not is_success:
                    error_count += 1

                    # Dispatch timeout event in background
                    asyncio.create_task(
                        self._dispatch_keepalive_timeout(error_count, last_success)
                    )

                    # Check if we should force reconnect
                    if (self.enable_auto_reconnect and
                        datetime.now() - last_success > KEEP_ALIVE_MAX_FAIL_TIME):

                        if self.log:
                            self.log.debug("Forcing reconnect due to keepalive failure")

                        self.disconnect()
                        asyncio.create_task(self.auto_reconnect())
                else:
                    # Ping succeeded
                    if error_count > 0:
                        error_count = 0
                        asyncio.create_task(self._dispatch_keepalive_restored())
                    last_success = datetime.now()

        except asyncio.CancelledError:
            # Context was cancelled, exit gracefully
            return

    async def send_keep_alive(self) -> Tuple[bool, bool]:
        """
        Send a keepalive ping to the server.

        Returns:
            Tuple of (is_success, should_continue):
            - is_success: True if ping succeeded, False if it failed/timed out
            - should_continue: True if keepalive loop should continue, False if it should stop
        """
        try:
            # Send info query for keepalive
            resp_future = await self.send_iq_async(InfoQuery(
                namespace="w:p",
                type=InfoQueryType.GET,
                to=JID.server_jid(),
                content=[]
            ))

            # Wait for response with timeout
            try:
                await asyncio.wait_for(
                    resp_future,
                    timeout=KEEP_ALIVE_RESPONSE_DEADLINE.total_seconds()
                )
                # Response received successfully
                return True, True

            except asyncio.TimeoutError:
                if self.log:
                    self.log.warn("Keepalive timed out")
                return False, True  # Timeout but continue

        except asyncio.CancelledError:
            # Context was cancelled
            return False, False

        except Exception as e:
            if self.log:
                self.log.warn(f"Failed to send keepalive: {e}")
            return False, True  # Error but continue

    async def _dispatch_keepalive_timeout(self, error_count: int, last_success: datetime) -> None:
        """Dispatch keepalive timeout event in background."""
        try:
            event = KeepAliveTimeout(
                error_count=error_count,
                last_success=last_success
            )
            self.dispatch_event(event)
        except Exception as e:
            if self.log:
                self.log.warn(f"Failed to dispatch keepalive timeout event: {e}")

    async def _dispatch_keepalive_restored(self) -> None:
        """Dispatch keepalive restored event in background."""
        try:
            event = KeepAliveRestored()
            self.dispatch_event(event)
        except Exception as e:
            if self.log:
                self.log.warn(f"Failed to dispatch keepalive restored event: {e}")

    # These methods would be implemented elsewhere in the Client class
    async def send_iq_async(self, query: InfoQuery) -> asyncio.Future:
        """Send an IQ query asynchronously. Implementation in request.py"""
        raise NotImplementedError("Implemented in request.py")

    def disconnect(self) -> None:
        """Disconnect the client. Implementation in client.py"""
        raise NotImplementedError("Implemented in client.py")

    async def auto_reconnect(self) -> None:
        """Automatically reconnect the client. Implementation in client.py"""
        raise NotImplementedError("Implemented in client.py")

    def dispatch_event(self, event: object) -> None:
        """Dispatch an event to event handlers. Implementation in client.py"""
        raise NotImplementedError("Implemented in client.py")
