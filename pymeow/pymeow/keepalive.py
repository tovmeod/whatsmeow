"""
Keepalive mechanism for WhatsApp Web connection.

Port of whatsmeow/keepalive.go
"""
import asyncio
from typing import Optional, Callable
from datetime import datetime, timedelta

class Keepalive:
    """Manages keepalive pings for the WhatsApp connection."""

    def __init__(self, ping_interval: timedelta = timedelta(minutes=1)):
        self.ping_interval = ping_interval
        self._last_received = datetime.now()
        self._ping_task: Optional[asyncio.Task] = None
        self._ping_callback: Optional[Callable] = None
        self._timeout_callback: Optional[Callable] = None

    def start(self, ping_callback: Callable, timeout_callback: Callable) -> None:
        """Start the keepalive mechanism."""
        self._ping_callback = ping_callback
        self._timeout_callback = timeout_callback
        self._start_ping_task()

    def stop(self) -> None:
        """Stop the keepalive mechanism."""
        if self._ping_task:
            self._ping_task.cancel()
            self._ping_task = None

    def received_pong(self) -> None:
        """Update the last received pong time."""
        self._last_received = datetime.now()

    def _start_ping_task(self) -> None:
        """Start the ping task."""
        async def ping_loop():
            while True:
                await asyncio.sleep(self.ping_interval.total_seconds())

                # Check if we haven't received a pong in too long
                if datetime.now() - self._last_received > self.ping_interval * 3:
                    if self._timeout_callback:
                        await self._timeout_callback()
                    continue

                # Send ping
                if self._ping_callback:
                    await self._ping_callback()

        self._ping_task = asyncio.create_task(ping_loop())
