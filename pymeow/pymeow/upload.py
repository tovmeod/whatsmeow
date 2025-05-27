"""
Media upload handling for WhatsApp.

Port of whatsmeow/upload.go
"""
import asyncio
from typing import Dict, Any, Optional, Tuple
import os
import mimetypes
from pathlib import Path

from .generated.waMsgTransport import WAMsgTransport_pb2
from .generated.waMediaTransport import WAMediaTransport_pb2
from .mediaconn import MediaConn, MediaConnInfo
from .util.cbcutil import encrypt_cbc
from .exceptions import UploadError

class MediaUploader:
    """Handles uploading media to WhatsApp servers."""

    def __init__(self):
        self.media_conn = MediaConn()

    async def upload(
        self,
        data: bytes,
        mime_type: Optional[str] = None,
        file_name: Optional[str] = None
    ) -> Tuple[Dict[str, Any], bytes]:
        """Upload media data to WhatsApp servers."""
        if not mime_type:
            if file_name:
                mime_type = mimetypes.guess_type(file_name)[0] or "application/octet-stream"
            else:
                mime_type = "application/octet-stream"

        # Generate media key
        media_key = os.urandom(32)

        # Encrypt media
        encrypted_data = self._encrypt_media(data, media_key, mime_type)

        # Upload to servers
        upload_info = await self.media_conn.upload_media(
            encrypted_data,
            mime_type,
            MediaConnInfo(
                auth_ttl=86400,
                max_retries=5,
                host="mmg.whatsapp.net"
            )
        )

        return upload_info, media_key

    def _encrypt_media(self, data: bytes, key: bytes, mime_type: str) -> bytes:
        """Encrypt media data for upload."""
        # TODO: Implement proper media encryption based on type
        # This should handle different media types differently
        return encrypt_cbc(key, b"\x00" * 16, data)

    async def upload_from_path(
        self,
        file_path: str,
        mime_type: Optional[str] = None
    ) -> Tuple[Dict[str, Any], bytes]:
        """Upload a file from disk to WhatsApp servers."""
        path = Path(file_path)
        data = path.read_bytes()
        return await self.upload(
            data,
            mime_type=mime_type,
            file_name=path.name
        )
