"""
Connection events handling.

Port of whatsmeow/connectionevents.go
"""
from enum import Enum, auto
from typing import Optional, Dict, Any, Callable, List
import asyncio

class ConnectionState(Enum):
    """Connection states for the WhatsApp client."""
    DISCONNECTED = auto()
    CONNECTING = auto()
    CONNECTED = auto()
    LOGGED_OUT = auto()

class ConnectionEventManager:
    """Manages connection state and events."""

    def __init__(self):
        self._state = ConnectionState.DISCONNECTED
        self._handlers: Dict[ConnectionState, List[Callable]] = {}
        self._reconnect_task: Optional[asyncio.Task] = None

    def on_state_change(self, state: ConnectionState, handler: Callable) -> None:
        """Register a handler for a specific connection state."""
        if state not in self._handlers:
            self._handlers[state] = []
        self._handlers[state].append(handler)

    async def handle_state_change(self, new_state: ConnectionState) -> None:
        """Handle a connection state change."""
        old_state = self._state
        self._state = new_state

        # Call registered handlers
        handlers = self._handlers.get(new_state, [])
        for handler in handlers:
            try:
                await handler(old_state, new_state)
            except Exception as e:
                # TODO: Proper logging
                print(f"Error in connection state handler: {e}")

        # Handle automatic reconnection
        if new_state == ConnectionState.DISCONNECTED:
            self._schedule_reconnect()

    def _schedule_reconnect(self) -> None:
        """Schedule an automatic reconnection attempt."""
        if self._reconnect_task and not self._reconnect_task.done():
            return

        async def reconnect():
            await asyncio.sleep(5)  # Basic exponential backoff should be implemented
            if self._state == ConnectionState.DISCONNECTED:
                await self.handle_state_change(ConnectionState.CONNECTING)

        self._reconnect_task = asyncio.create_task(reconnect())
