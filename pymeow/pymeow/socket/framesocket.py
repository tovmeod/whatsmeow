"""
Frame-based WebSocket implementation for WhatsApp.

Port of whatsmeow/socket/framesocket.go
"""
import asyncio
import struct
from typing import Optional, Callable, Awaitable

import aiohttp
from aiohttp import WSMessage, WSMsgType

from ..generated.waCommon import WACommon_pb2
from .noisesocket import NoiseSocket

class FrameSocket:
    """Handles frame-based WebSocket communication with WhatsApp servers."""

    def __init__(self):
        self.noise = NoiseSocket()
        self._ws: Optional[aiohttp.ClientWebSocketResponse] = None
        self._receive_handler: Optional[Callable[[bytes], Awaitable[None]]] = None
        self._closed = True

    async def connect(self, url: str) -> None:
        """Connect to WhatsApp WebSocket server."""
        if not self._closed:
            return

        session = aiohttp.ClientSession()
        self._ws = await session.ws_connect(url)
        self._closed = False

        # Start receive loop
        asyncio.create_task(self._receive_loop())

    async def send_frame(self, data: bytes) -> None:
        """Send an encrypted frame through the WebSocket."""
        if self._closed or not self._ws:
            raise ConnectionError("WebSocket not connected")

        # Encrypt frame if noise handshake is complete
        frame = self.noise.encrypt_frame(data)

        # Add frame header with length
        frame_with_header = struct.pack(">I", len(frame)) + frame
        await self._ws.send_bytes(frame_with_header)

    async def _receive_loop(self) -> None:
        """Handle incoming WebSocket frames."""
        if not self._ws:
            return

        try:
            async for msg in self._ws:
                if msg.type == WSMsgType.BINARY:
                    # Extract frame from websocket message
                    data = msg.data

                    # Decrypt frame if noise handshake is complete
                    frame = self.noise.decrypt_frame(data)

                    # Call receive handler if set
                    if self._receive_handler:
                        await self._receive_handler(frame)

                elif msg.type == WSMsgType.CLOSED:
                    break

        finally:
            self._closed = True
            await self._ws.close()

    def on_frame(self, handler: Callable[[bytes], Awaitable[None]]) -> None:
        """Set handler for received frames."""
        self._receive_handler = handler

    async def close(self) -> None:
        """Close the WebSocket connection."""
        if self._ws and not self._closed:
            self._closed = True
            await self._ws.close()
