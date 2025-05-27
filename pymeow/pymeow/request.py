"""
Request handling for WhatsApp.

Port of whatsmeow/request.go
"""
import asyncio
from dataclasses import dataclass
from typing import Optional, Any, Dict, Awaitable, Callable
from datetime import datetime, timedelta

@dataclass
class Request:
    """Represents a pending WhatsApp request."""
    tag: str
    namespace: str
    data: Any
    timeout: timedelta = timedelta(seconds=20)
    response_future: Optional[asyncio.Future] = None

class RequestManager:
    """Manages pending WhatsApp requests."""

    def __init__(self):
        self._pending: Dict[str, Request] = {}
        self._request_counter = 0

    async def make_request(self, namespace: str, data: Any, timeout: timedelta = timedelta(seconds=20)) -> Any:
        """Make a request and wait for its response."""
        self._request_counter += 1
        tag = f"pymeow{self._request_counter}"

        request = Request(
            tag=tag,
            namespace=namespace,
            data=data,
            timeout=timeout,
            response_future=asyncio.Future()
        )

        self._pending[tag] = request

        try:
            return await asyncio.wait_for(request.response_future, timeout=timeout.total_seconds())
        finally:
            self._pending.pop(tag, None)

    def handle_response(self, tag: str, data: Any) -> None:
        """Handle a response for a pending request."""
        request = self._pending.get(tag)
        if request and not request.response_future.done():
            request.response_future.set_result(data)
