"""
Media download handling for WhatsApp.

Port of whatsmeow/download.go and download-to-file.go
"""
import asyncio
import base64
import hashlib
import hmac
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional, Dict, Any, BinaryIO, List, Protocol, Tuple, Union, TypeVar, cast
import aiohttp
from io import BytesIO

from .exceptions import PymeowError
from .generated.waE2E import waE2E_pb2
from .generated.waHistorySync import waHistorySync_pb2
from .generated.waMediaTransport import WAMediaTransport_pb2
from .generated.waServerSync import waServerSync_pb2
from .mediaconn import MediaConn
from .util.cbcutil import decrypt, decrypt_file, File
from .util.hkdfutil import sha256 as hkdf_sha256


# Define custom exceptions
class DownloadError(PymeowError):
    """Raised when there is an error downloading media."""
    pass


class DownloadHTTPError(DownloadError):
    """Raised when there is an HTTP error during download."""
    def __init__(self, response: aiohttp.ClientResponse):
        self.response = response
        self.status_code = response.status
        super().__init__(f"HTTP error during download: {response.status}")


# Error constants
ErrNothingDownloadableFound = DownloadError("Nothing downloadable found in message")
ErrUnknownMediaType = DownloadError("Unknown media type")
ErrNoURLPresent = DownloadError("No URL present in message")
ErrClientIsNil = DownloadError("Client is nil")
ErrFileLengthMismatch = DownloadError("File length mismatch")
ErrInvalidMediaSHA256 = DownloadError("Invalid media SHA256")
ErrInvalidMediaEncSHA256 = DownloadError("Invalid media encrypted SHA256")
ErrInvalidMediaHMAC = DownloadError("Invalid media HMAC")
ErrTooShortFile = DownloadError("File is too short")
ErrMediaDownloadFailedWith403 = DownloadError("Media download failed with status 403")
ErrMediaDownloadFailedWith404 = DownloadError("Media download failed with status 404")
ErrMediaDownloadFailedWith410 = DownloadError("Media download failed with status 410")


class MediaType(str, Enum):
    """Represents a type of uploaded file on WhatsApp.

    The value is the key which is used as a part of generating the encryption keys.
    """
    IMAGE = "WhatsApp Image Keys"
    VIDEO = "WhatsApp Video Keys"
    AUDIO = "WhatsApp Audio Keys"
    DOCUMENT = "WhatsApp Document Keys"
    HISTORY = "WhatsApp History Keys"
    APP_STATE = "WhatsApp App State Keys"
    LINK_THUMBNAIL = "WhatsApp Link Thumbnail Keys"


# Protocol for downloadable messages
class DownloadableMessage(Protocol):
    """Protocol for messages that can be downloaded."""
    def GetDirectPath(self) -> str: ...
    def GetMediaKey(self) -> bytes: ...
    def GetFileSHA256(self) -> bytes: ...
    def GetFileEncSHA256(self) -> bytes: ...


class MediaTypeable(Protocol):
    """Protocol for objects that can provide a media type."""
    def GetMediaType(self) -> MediaType: ...


# Protocol for downloadable thumbnails
class DownloadableThumbnail(Protocol):
    """Protocol for messages that contain a thumbnail that can be downloaded."""
    def GetThumbnailDirectPath(self) -> str: ...
    def GetThumbnailSHA256(self) -> bytes: ...
    def GetThumbnailEncSHA256(self) -> bytes: ...
    def GetMediaKey(self) -> bytes: ...
    def ProtoReflect(self) -> Any: ...


# Additional protocols for messages with length/size information
class DownloadableMessageWithLength(DownloadableMessage, Protocol):
    """Protocol for downloadable messages that include file length."""
    def GetFileLength(self) -> int: ...


class DownloadableMessageWithSizeBytes(DownloadableMessage, Protocol):
    """Protocol for downloadable messages that include file size in bytes."""
    def GetFileSizeBytes(self) -> int: ...


class DownloadableMessageWithURL(DownloadableMessage, Protocol):
    """Protocol for downloadable messages that include a URL."""
    def GetURL(self) -> str: ...


# Mapping from protobuf message types to MediaType
CLASS_TO_MEDIA_TYPE = {
    "ImageMessage": MediaType.IMAGE,
    "AudioMessage": MediaType.AUDIO,
    "VideoMessage": MediaType.VIDEO,
    "DocumentMessage": MediaType.DOCUMENT,
    "StickerMessage": MediaType.IMAGE,
    "StickerMetadata": MediaType.IMAGE,
    "HistorySyncNotification": MediaType.HISTORY,
    "ExternalBlobReference": MediaType.APP_STATE,
}

CLASS_TO_THUMBNAIL_MEDIA_TYPE = {
    "ExtendedTextMessage": MediaType.LINK_THUMBNAIL,
}

MEDIA_TYPE_TO_MMS_TYPE = {
    MediaType.IMAGE: "image",
    MediaType.AUDIO: "audio",
    MediaType.VIDEO: "video",
    MediaType.DOCUMENT: "document",
    MediaType.HISTORY: "md-msg-hist",
    MediaType.APP_STATE: "md-app-state",
    MediaType.LINK_THUMBNAIL: "thumbnail-link",
}

# Constants
MEDIA_HMAC_LENGTH = 10


class MediaDownloader:
    """Handles downloading media from WhatsApp servers."""

    def __init__(self, client=None):
        """Initialize the media downloader.

        Args:
            client: The WhatsApp client instance
        """
        self.client = client
        self.media_conn = MediaConn()
        self.http_session = None
        self.logger = None  # Will be set by the client

    async def ensure_http_session(self):
        """Ensure an HTTP session exists."""
        if self.http_session is None:
            self.http_session = aiohttp.ClientSession()

    async def download_any(self, message: waE2E_pb2.Message) -> bytes:
        """Download the first downloadable content from a message.

        Args:
            message: The message containing media

        Returns:
            The downloaded and decrypted media data

        Raises:
            DownloadError: If no downloadable content is found or download fails
        """
        if message is None:
            raise ErrNothingDownloadableFound

        if message.HasField("imageMessage"):
            return await self.download(message.imageMessage)
        elif message.HasField("videoMessage"):
            return await self.download(message.videoMessage)
        elif message.HasField("audioMessage"):
            return await self.download(message.audioMessage)
        elif message.HasField("documentMessage"):
            return await self.download(message.documentMessage)
        elif message.HasField("stickerMessage"):
            return await self.download(message.stickerMessage)
        else:
            raise ErrNothingDownloadableFound

    def get_size(self, msg: DownloadableMessage) -> int:
        """Get the size of a downloadable message.

        Args:
            msg: The downloadable message

        Returns:
            The size in bytes, or -1 if not available
        """
        try:
            return cast(DownloadableMessageWithLength, msg).GetFileLength()
        except (AttributeError, TypeError):
            pass

        try:
            return cast(DownloadableMessageWithSizeBytes, msg).GetFileSizeBytes()
        except (AttributeError, TypeError):
            pass

        return -1

    async def download_thumbnail(self, msg: DownloadableThumbnail) -> bytes:
        """Download a thumbnail from a message.

        This is primarily intended for downloading link preview thumbnails.

        Args:
            msg: The message containing a thumbnail

        Returns:
            The downloaded and decrypted thumbnail data

        Raises:
            DownloadError: If download fails
        """
        descriptor_name = msg.ProtoReflect().Descriptor().Name()
        media_type = CLASS_TO_THUMBNAIL_MEDIA_TYPE.get(descriptor_name)

        if not media_type:
            raise ErrUnknownMediaType(f"'{descriptor_name}'")

        if msg.GetThumbnailDirectPath():
            return await self.download_media_with_path(
                msg.GetThumbnailDirectPath(),
                msg.GetThumbnailEncSHA256(),
                msg.GetThumbnailSHA256(),
                msg.GetMediaKey(),
                -1,
                media_type,
                MEDIA_TYPE_TO_MMS_TYPE[media_type]
            )
        else:
            raise ErrNoURLPresent

    def get_media_type(self, msg: DownloadableMessage) -> MediaType:
        """Get the MediaType for a downloadable message.

        Args:
            msg: The downloadable message

        Returns:
            The MediaType enum value

        Raises:
            DownloadError: If the media type cannot be determined
        """
        try:
            # Try to get media type from MediaTypeable protocol
            return cast(MediaTypeable, msg).GetMediaType()
        except (AttributeError, TypeError):
            pass

        try:
            # Try to get media type from protobuf message type
            descriptor_name = msg.ProtoReflect().Descriptor().Name()
            return CLASS_TO_MEDIA_TYPE.get(descriptor_name, MediaType(""))
        except (AttributeError, TypeError):
            return MediaType("")

    async def download(self, msg: DownloadableMessage) -> bytes:
        """Download media from a message.

        Args:
            msg: The downloadable message part

        Returns:
            The downloaded and decrypted media data

        Raises:
            DownloadError: If download fails
        """
        if self.client is None:
            raise ErrClientIsNil

        media_type = self.get_media_type(msg)
        if not media_type:
            raise ErrUnknownMediaType(f"{type(msg)}")

        # Check if message has URL
        url = ""
        is_web_whatsapp_net_url = False

        try:
            url = cast(DownloadableMessageWithURL, msg).GetURL()
            is_web_whatsapp_net_url = url.startswith("https://web.whatsapp.net")
        except (AttributeError, TypeError):
            pass

        if url and not is_web_whatsapp_net_url:
            return await self.download_and_decrypt(
                url,
                msg.GetMediaKey(),
                media_type,
                self.get_size(msg),
                msg.GetFileEncSHA256(),
                msg.GetFileSHA256()
            )
        elif msg.GetDirectPath():
            return await self.download_media_with_path(
                msg.GetDirectPath(),
                msg.GetFileEncSHA256(),
                msg.GetFileSHA256(),
                msg.GetMediaKey(),
                self.get_size(msg),
                media_type,
                MEDIA_TYPE_TO_MMS_TYPE[media_type]
            )
        else:
            if is_web_whatsapp_net_url and self.logger:
                self.logger.warning(f"Got a media message with a web.whatsapp.net URL ({url}) and no direct path")
            raise ErrNoURLPresent

    async def download_fb(
        self,
        transport: WAMediaTransport_pb2.WAMediaTransport_Integral,
        media_type: MediaType
    ) -> bytes:
        """Download media from a Facebook transport message.

        Args:
            transport: The transport message
            media_type: The media type

        Returns:
            The downloaded and decrypted media data

        Raises:
            DownloadError: If download fails
        """
        return await self.download_media_with_path(
            transport.GetDirectPath(),
            transport.GetFileEncSHA256(),
            transport.GetFileSHA256(),
            transport.GetMediaKey(),
            -1,
            media_type,
            MEDIA_TYPE_TO_MMS_TYPE[media_type]
        )

    async def download_media_with_path(
        self,
        direct_path: str,
        enc_file_hash: bytes,
        file_hash: bytes,
        media_key: bytes,
        file_length: int,
        media_type: MediaType,
        mms_type: str
    ) -> bytes:
        """Download media using a direct path.

        Args:
            direct_path: The direct path to the media
            enc_file_hash: The encrypted file hash
            file_hash: The file hash
            media_key: The media key
            file_length: The expected file length
            media_type: The media type
            mms_type: The MMS type

        Returns:
            The downloaded and decrypted media data

        Raises:
            DownloadError: If download fails
        """
        # TODO: Implement refreshMediaConn when it's ported
        # For now, we'll use a hardcoded host
        hosts = [{"Hostname": "mmg.whatsapp.net"}]

        if not mms_type:
            mms_type = MEDIA_TYPE_TO_MMS_TYPE[media_type]

        for i, host in enumerate(hosts):
            media_url = (
                f"https://{host['Hostname']}{direct_path}"
                f"&hash={base64.urlsafe_b64encode(enc_file_hash).decode().rstrip('=')}"
                f"&mms-type={mms_type}&__wa-mms="
            )

            try:
                data = await self.download_and_decrypt(
                    media_url,
                    media_key,
                    media_type,
                    file_length,
                    enc_file_hash,
                    file_hash
                )
                return data
            except DownloadError as e:
                if (isinstance(e, (ErrFileLengthMismatch, ErrInvalidMediaSHA256)) or
                    str(e) in (str(ErrMediaDownloadFailedWith403),
                              str(ErrMediaDownloadFailedWith404),
                              str(ErrMediaDownloadFailedWith410))):
                    raise

                if i >= len(hosts) - 1:
                    raise DownloadError(f"Failed to download media from last host: {e}")

                if self.logger:
                    self.logger.warning(f"Failed to download media: {e}, trying with next host...")

        # This should never be reached due to the exception handling above
        raise DownloadError("Failed to download media")

    async def download_and_decrypt(
        self,
        url: str,
        media_key: bytes,
        app_info: MediaType,
        file_length: int,
        file_enc_sha256: bytes,
        file_sha256: bytes
    ) -> bytes:
        """Download and decrypt media.

        Args:
            url: The URL to download from
            media_key: The media key
            app_info: The media type
            file_length: The expected file length
            file_enc_sha256: The encrypted file hash
            file_sha256: The file hash

        Returns:
            The downloaded and decrypted media data

        Raises:
            DownloadError: If download or decryption fails
        """
        iv, cipher_key, mac_key, _ = self.get_media_keys(media_key, app_info)

        try:
            ciphertext, mac = await self.download_possibly_encrypted_media_with_retries(
                url, file_enc_sha256
            )

            # Handle unencrypted media
            if media_key is None and file_enc_sha256 is None and mac is None:
                return ciphertext

            # Validate media
            self.validate_media(iv, ciphertext, mac_key, mac)

            # Decrypt media
            data = decrypt(cipher_key, iv, ciphertext)

            # Validate length if provided
            if file_length >= 0 and len(data) != file_length:
                raise ErrFileLengthMismatch(f"Expected {file_length}, got {len(data)}")

            # Validate SHA256 if provided
            if len(file_sha256) == 32:
                data_hash = hashlib.sha256(data).digest()
                if data_hash != file_sha256:
                    raise ErrInvalidMediaSHA256

            return data

        except Exception as e:
            if isinstance(e, DownloadError):
                raise
            raise DownloadError(f"Failed to download and decrypt media: {e}")

    def get_media_keys(self, media_key: bytes, app_info: MediaType) -> Tuple[bytes, bytes, bytes, bytes]:
        """Generate media keys from a media key and app info.

        Args:
            media_key: The media key
            app_info: The media type

        Returns:
            A tuple of (iv, cipher_key, mac_key, ref_key)
        """
        media_key_expanded = hkdf_sha256(media_key, None, str(app_info).encode(), 112)
        return (
            media_key_expanded[:16],
            media_key_expanded[16:48],
            media_key_expanded[48:80],
            media_key_expanded[80:]
        )

    def should_retry_media_download(self, err: Exception) -> bool:
        """Determine if a media download should be retried.

        Args:
            err: The exception that occurred

        Returns:
            True if the download should be retried, False otherwise
        """
        if isinstance(err, (asyncio.TimeoutError, aiohttp.ClientError)):
            return True

        if isinstance(err, DownloadHTTPError):
            # Retry for 5xx errors and some 4xx errors
            status = err.status_code
            return status >= 500 or status in (408, 429)

        # Check for http2 stream errors
        if isinstance(err, Exception) and "stream error" in str(err).lower():
            return True

        return False

    async def download_possibly_encrypted_media_with_retries(
        self,
        url: str,
        checksum: Optional[bytes]
    ) -> Tuple[bytes, Optional[bytes]]:
        """Download possibly encrypted media with retries.

        Args:
            url: The URL to download from
            checksum: The checksum to validate

        Returns:
            A tuple of (file_data, mac)

        Raises:
            DownloadError: If download fails after retries
        """
        for retry_num in range(5):
            try:
                if checksum is None:
                    file_data = await self.download_media_raw(url)
                    return file_data, None
                else:
                    file_data, mac = await self.download_encrypted_media(url, checksum)
                    return file_data, mac
            except Exception as e:
                if not self.should_retry_media_download(e) or retry_num >= 4:
                    raise

                retry_duration = (retry_num + 1)

                if isinstance(e, DownloadHTTPError) and e.response.headers.get("Retry-After"):
                    try:
                        retry_duration = int(e.response.headers.get("Retry-After", "1"))
                    except ValueError:
                        pass

                if self.logger:
                    self.logger.warning(
                        f"Failed to download media due to network error: {e}, "
                        f"retrying in {retry_duration}s..."
                    )

                await asyncio.sleep(retry_duration)

        raise DownloadError("Failed to download media after retries")

    async def do_media_download_request(self, url: str) -> aiohttp.ClientResponse:
        """Make a media download request.

        Args:
            url: The URL to download from

        Returns:
            The HTTP response

        Raises:
            DownloadError: If the request fails
        """
        await self.ensure_http_session()

        headers = {
            "Origin": "https://web.whatsapp.com",
            "Referer": "https://web.whatsapp.com/",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        }

        try:
            response = await self.http_session.get(url, headers=headers)

            if response.status != 200:
                if response.status == 403:
                    raise ErrMediaDownloadFailedWith403
                elif response.status == 404:
                    raise ErrMediaDownloadFailedWith404
                elif response.status == 410:
                    raise ErrMediaDownloadFailedWith410

                raise DownloadHTTPError(response)

            return response
        except aiohttp.ClientError as e:
            raise DownloadError(f"HTTP request failed: {e}")

    async def download_media_raw(self, url: str) -> bytes:
        """Download media without decryption.

        Args:
            url: The URL to download from

        Returns:
            The raw media data

        Raises:
            DownloadError: If download fails
        """
        response = await self.do_media_download_request(url)
        try:
            return await response.read()
        finally:
            response.close()

    async def download_encrypted_media(
        self,
        url: str,
        checksum: bytes
    ) -> Tuple[bytes, bytes]:
        """Download encrypted media.

        Args:
            url: The URL to download from
            checksum: The checksum to validate

        Returns:
            A tuple of (file_data, mac)

        Raises:
            DownloadError: If download fails
        """
        data = await self.download_media_raw(url)

        if len(data) <= MEDIA_HMAC_LENGTH:
            raise ErrTooShortFile

        file_data = data[:-MEDIA_HMAC_LENGTH]
        mac = data[-MEDIA_HMAC_LENGTH:]

        if len(checksum) == 32:
            data_hash = hashlib.sha256(data).digest()
            if data_hash != checksum:
                raise ErrInvalidMediaEncSHA256

        return file_data, mac

    def validate_media(self, iv: bytes, file_data: bytes, mac_key: bytes, mac: bytes) -> None:
        """Validate media using HMAC.

        Args:
            iv: The initialization vector
            file_data: The file data
            mac_key: The MAC key
            mac: The MAC to validate

        Raises:
            DownloadError: If validation fails
        """
        h = hmac.new(mac_key, digestmod=hashlib.sha256)
        h.update(iv)
        h.update(file_data)

        if not hmac.compare_digest(h.digest()[:MEDIA_HMAC_LENGTH], mac):
            raise ErrInvalidMediaHMAC

    async def download_to_file(
        self,
        msg: DownloadableMessage,
        file_path: Union[str, Path],
        decrypt: bool = True
    ) -> None:
        """Download media to a file.

        Args:
            msg: The downloadable message
            file_path: The path to save the file to
            decrypt: Whether to decrypt the media

        Raises:
            DownloadError: If download fails
        """
        data = await self.download(msg)

        # Write to file
        if isinstance(file_path, str):
            file_path = Path(file_path)

        file_path.write_bytes(data)

    async def download_any_to_file(
        self,
        message: waE2E_pb2.Message,
        file_path: Union[str, Path]
    ) -> None:
        """Download the first downloadable content from a message to a file.

        Args:
            message: The message containing media
            file_path: The path to save the file to

        Raises:
            DownloadError: If no downloadable content is found or download fails
        """
        data = await self.download_any(message)

        # Write to file
        if isinstance(file_path, str):
            file_path = Path(file_path)

        file_path.write_bytes(data)
