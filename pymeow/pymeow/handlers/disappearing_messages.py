"""Handlers for disappearing messages functionality."""
from typing import Optional, Dict, Any, Callable, Awaitable
from dataclasses import dataclass
from datetime import datetime, timedelta
import asyncio
import logging

from ..types.message import MessageInfo, Message
from ..types.expiration import ExpirationType

logger = logging.getLogger(__name__)

MessageCallback = Callable[[Message], Awaitable[None]]

@dataclass
class ExpirationInfo:
    """Information about a message's expiration."""
    expires_at: datetime
    duration_seconds: int
    is_ephemeral: bool = False
    viewed: bool = False

class DisappearingMessageHandler:
    """Handles disappearing message events and callbacks."""

    def __init__(self, client):
        self.client = client
        self._expiration_tasks: Dict[str, asyncio.Task] = {}
        self._callbacks = {
            'on_message_expiring': [],
            'on_message_expired': [],
            'on_ephemeral_message_viewed': []
        }

    def register_callback(self, event: str, callback: MessageCallback) -> None:
        """Register a callback for disappearing message events.

        Args:
            event: One of 'on_message_expiring', 'on_message_expired', 'on_ephemeral_message_viewed'
            callback: Async function that takes a Message object
        """
        if event not in self._callbacks:
            raise ValueError(f"Unknown event type: {event}")
        self._callbacks[event].append(callback)

    async def _trigger_callbacks(self, event: str, message: Message) -> None:
        """Trigger all registered callbacks for an event."""
        if event not in self._callbacks:
            return

        for callback in self._callbacks[event]:
            try:
                await callback(message)
            except Exception as e:
                logger.error(f"Error in {event} callback: {e}", exc_info=True)

    async def handle_expiring_message(self, message: Message) -> None:
        """Handle a message that is about to expire."""
        if not message.expiration_info:
            return

        await self._trigger_callbacks('on_message_expiring', message)

        # Schedule the expired callback
        now = datetime.utcnow()
        expires_in = (message.expiration_info.expires_at - now).total_seconds()

        if expires_in > 0:
            task = asyncio.create_task(self._schedule_message_expiration(message))
            self._expiration_tasks[message.id] = task

    async def _schedule_message_expiration(self, message: Message) -> None:
        """Schedule the expiration of a message."""
        if not message.expiration_info:
            return

        now = datetime.utcnow()
        expires_in = (message.expiration_info.expires_at - now).total_seconds()

        if expires_in > 0:
            await asyncio.sleep(expires_in)

        # Double check expiration in case it was updated
        if message.expiration_info and datetime.utcnow() >= message.expiration_info.expires_at:
            await self._handle_expired_message(message)

    async def _handle_expired_message(self, message: Message) -> None:
        """Handle an expired message."""
        await self._trigger_callbacks('on_message_expired', message)

        # Clean up any associated resources
        if message.id in self._expiration_tasks:
            del self._expiration_tasks[message.id]

    async def handle_ephemeral_message_viewed(self, message: Message) -> None:
        """Handle a view-once message that has been viewed."""
        if not message.expiration_info or not message.expiration_info.is_ephemeral:
            return

        message.expiration_info.viewed = True
        await self._trigger_callbacks('on_ephemeral_message_viewed', message)

        # For view-once messages, they should be deleted after being viewed
        await self._handle_expired_message(message)

    async def cancel_all_tasks(self) -> None:
        """Cancel all pending expiration tasks."""
        for task in self._expiration_tasks.values():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        self._expiration_tasks.clear()
