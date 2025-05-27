"""
Media download handling for WhatsApp.

Port of whatsmeow/download.go and download-to-file.go
"""
import asyncio
from pathlib import Path
from typing import Optional, Dict, Any, BinaryIO
import aiohttp

from .generated.waMsgTransport import WAMsgTransport_pb2
from .mediaconn import MediaConn
from .util.cbcutil import decrypt_cbc
from .exceptions import DownloadError

class MediaDownloader:
    """Handles downloading media from WhatsApp servers."""

    def __init__(self):
        self.media_conn = MediaConn()

    async def download_media(
        self,
        message: WAMsgTransport_pb2.Message,
        decrypt: bool = True
    ) -> bytes:
        """Download media from a message."""
        media_msg = None

        # Determine which media field is set
        if message.HasField('imageMessage'):
            media_msg = message.imageMessage
        elif message.HasField('videoMessage'):
            media_msg = message.videoMessage
        elif message.HasField('documentMessage'):
            media_msg = message.documentMessage
        elif message.HasField('audioMessage'):
            media_msg = message.audioMessage
        elif message.HasField('stickerMessage'):
            media_msg = message.stickerMessage

        if not media_msg:
            raise DownloadError("No media in message")

        # Download the media
        data = await self.media_conn.download_media(
            url=media_msg.url,
            direct_path=getattr(media_msg, 'directPath', None),
            media_key=media_msg.mediaKey
        )

        # Decrypt if needed
        if decrypt and media_msg.mediaKey:
            data = self._decrypt_media(
                data,
                media_msg.mediaKey,
                media_msg.mimetype
            )

        return data

    async def download_to_file(
        self,
        message: WAMsgTransport_pb2.Message,
        output_path: str,
        decrypt: bool = True
    ) -> None:
        """Download media directly to a file."""
        data = await self.download_media(message, decrypt)

        # Write to file
        Path(output_path).write_bytes(data)

    def _decrypt_media(self, data: bytes, key: bytes, mime_type: str) -> bytes:
        """Decrypt downloaded media using the media key."""
        # TODO: Implement proper media decryption based on type
        # This should handle different media types differently
        return decrypt_cbc(key, b"\x00" * 16, data)
