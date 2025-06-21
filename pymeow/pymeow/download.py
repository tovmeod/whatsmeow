"""
Media download handling for WhatsApp.

Port of whatsmeow/download.go and download-to-file.go
"""
import asyncio
import base64
import hashlib
import hmac
import logging
from enum import Enum
from typing import TYPE_CHECKING, Optional, Tuple, Union

import aiohttp

from . import mediaconn
from .exceptions import PymeowError
from .generated.waE2E import WAWebProtobufsE2E_pb2
from .util.cbcutil import decrypt
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
class ErrUnknownMediaType(DownloadError):
    def __init__(self, media_type: str) -> None:
        super().__init__(f"Unknown media type '{media_type}'")
ErrNoURLPresent = DownloadError("No URL present in message")
ErrClientIsNil = DownloadError("Client is nil")
class ErrFileLengthMismatch(DownloadError):
    def __init__(self, file_length: int, len_data: int) -> None:
        super().__init__(f"File length mismatch: {file_length=} != {len_data=}")
class ErrInvalidMediaSHA256(DownloadError):
    def __init__(self) -> None:
        super().__init__("Invalid media SHA256")
ErrInvalidMediaEncSHA256 = DownloadError("Invalid media encrypted SHA256")
ErrInvalidMediaHMAC = DownloadError("Invalid media HMAC")
ErrTooShortFile = DownloadError("File is too short")
class ErrMediaDownloadFailedWith403(DownloadError):
    def __init__(self) -> None:
        super().__init__("Media download failed with status 403")
class ErrMediaDownloadFailedWith404(DownloadError):
    def __init__(self) -> None:
        super().__init__("Media download failed with status 404")
class ErrMediaDownloadFailedWith410(DownloadError):
    def __init__(self) -> None:
        super().__init__("Media download failed with status 410")


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


DownloadableMessage = Union[
    WAWebProtobufsE2E_pb2.HistorySyncNotification,
    WAWebProtobufsE2E_pb2.ImageMessage,
    WAWebProtobufsE2E_pb2.VideoMessage,
    WAWebProtobufsE2E_pb2.AudioMessage,
    WAWebProtobufsE2E_pb2.DocumentMessage,
    WAWebProtobufsE2E_pb2.StickerMessage,
    # Add other downloadable message types as needed
]

DownloadableThumbnailMessage = Union[
    WAWebProtobufsE2E_pb2.ExtendedTextMessage,
    # WAWebProtobufsE2E_pb2.StickerMessage,
# Don't include StickerMessage yet until we verify its thumbnail field names
    WAWebProtobufsE2E_pb2.ImageMessage,
    WAWebProtobufsE2E_pb2.VideoMessage,
    WAWebProtobufsE2E_pb2.DocumentMessage,
    # Add other message types that have thumbnail methods as needed
]

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
    "ImageMessage": MediaType.IMAGE,
    "VideoMessage": MediaType.VIDEO,
    "DocumentMessage": MediaType.DOCUMENT,
    # Add other message types that support thumbnails
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

logger = logging.getLogger(__name__)


# Global HTTP session management
_http_session = None

if TYPE_CHECKING:
    from .client import Client

async def download_any(client: 'Client', msg: Optional[WAWebProtobufsE2E_pb2.Message]) -> Tuple[
    Optional[bytes], Optional[Exception]]:
    """
    Port of Go method DownloadAny from download.go.

    Loops through the downloadable parts of the given message and downloads the first non-nil item.

    Args:
        client: The Client instance
        msg: The message containing potential downloadable content

    Returns:
        Tuple containing (data: bytes or None, error: Exception or None)
    """
    if msg is None:
        return None, ErrNothingDownloadableFound

    if msg.imageMessage is not None:
        return await download(client, msg.imageMessage), None
    elif msg.videoMessage is not None:
        return await download(client, msg.videoMessage), None
    elif msg.audioMessage is not None:
        return await download(client, msg.audioMessage), None
    elif msg.documentMessage is not None:
        return await download(client, msg.documentMessage), None
    elif msg.stickerMessage is not None:
        return await download(client, msg.stickerMessage), None
    else:
        return None, ErrNothingDownloadableFound


def get_size(msg: 'DownloadableMessage') -> int:
    """
    Port of Go function getSize from download.go.

    Gets the size of a downloadable message by checking for different size field types.

    Args:
        msg: A downloadable message object

    Returns:
        The file size in bytes, or -1 if size cannot be determined
    """
    if msg.fileLength:
        return msg.fileLength
    else:
        return -1


async def download_thumbnail(
    client: 'Client',
    msg: DownloadableThumbnailMessage
) -> Optional[bytes]:
    """
    Port of Go method DownloadThumbnail from download.go.

    Downloads a thumbnail from a message.

    This is primarily intended for downloading link preview thumbnails, which are in ExtendedTextMessage:

        msg = ...  # waE2E.Message
        thumbnail_image_bytes, err = download_thumbnail(client, ctx, msg.get_extended_text_message())

    Args:
        client: The Client instance
        msg: A downloadable thumbnail message object

    Returns:
        thumbnail data: bytes
    Raises:
        ErrNoURLPresent
    """
    # TODO: Review class_to_thumbnail_media_type mapping implementation
    # TODO: Review media_type_to_mms_type mapping implementation

    # Get the protobuf descriptor name (equivalent to msg.ProtoReflect().Descriptor().Name())
    descriptor_name = msg.DESCRIPTOR.name

    # Check if media type exists in mapping (equivalent to Go's map lookup with ok pattern)
    if descriptor_name not in CLASS_TO_THUMBNAIL_MEDIA_TYPE:
        error_msg = f"{ErrUnknownMediaType} '{descriptor_name}'"
        raise Exception(error_msg)

    media_type = CLASS_TO_THUMBNAIL_MEDIA_TYPE[descriptor_name]

    # Check if thumbnail direct path exists and has content (equivalent to len(msg.GetThumbnailDirectPath()) > 0)
    if len(msg.thumbnailDirectPath) > 0:
        return await download_media_with_path(
            client,
            msg.thumbnailDirectPath,
            msg.thumbnailEncSHA256,
            msg.thumbnailSHA256,
            msg.mediaKey,
            -1,
            media_type,
            MEDIA_TYPE_TO_MMS_TYPE[media_type]
        )
    else:
        raise ErrNoURLPresent


def get_media_type(msg: DownloadableMessage) -> Optional[MediaType]:
    """
    Port of Go function GetMediaType from download.go.

    Returns the MediaType value corresponding to the given protobuf message.

    Args:
        msg: The downloadable message object

    Returns:
        The MediaType value for the message
    """
    return CLASS_TO_MEDIA_TYPE.get(msg.DESCRIPTOR.name, None)


async def download(client: 'Client', msg: DownloadableMessage) -> Optional[bytes]:
    """
    Port of Go method `Download` from client.go.

    Downloads the attachment from the given protobuf message.
    The attachment is a specific part of a Message protobuf struct, not the message itself.

    Args:
        client: The WhatsApp client instance.
        msg: A DownloadableMessage representing a media submessage (e.g. ImageMessage).

    Returns:
        The downloaded and decrypted media data.

    Raises:
        ErrClientIsNil: If the client is None.
        ErrUnknownMediaType: If the media type cannot be determined.
        ErrNoURLPresent: If the message has no URL or direct path to download from.
    """
    # TODO: Review Client.download_and_decrypt implementation
    # TODO: Review Client.download_media_with_path implementation
    # TODO: Review get_media_type implementation
    # TODO: Review get_size implementation

    if client is None:
        raise ErrClientIsNil

    media_type = get_media_type(msg)
    if not media_type:
        raise ErrUnknownMediaType(f"{type(msg)}")

    url = ""
    is_web_whatsapp_net_url = False

    try:
        if hasattr(msg, 'URL') and msg.URL:
            url = msg.URL
            is_web_whatsapp_net_url = url.startswith("https://web.whatsapp.net")
    except (AttributeError, TypeError):
        pass

    if url and not is_web_whatsapp_net_url:
        data = await download_and_decrypt(
            client,
            url,
            msg.mediaKey,
            media_type,
            get_size(msg),
            msg.fileEncSHA256,
            msg.fileSHA256
        )
        return data
    elif msg.directPath:
        return await download_media_with_path(
            client,
            msg.directPath,
            msg.fileEncSHA256,
            msg.fileSHA256,
            msg.mediaKey,
            get_size(msg),
            media_type,
            MEDIA_TYPE_TO_MMS_TYPE[media_type]
        )
    else:
        if is_web_whatsapp_net_url:
            logger.warning(f"Got a media message with a web.whatsapp.net URL ({url}) and no direct path")
        raise ErrNoURLPresent

# async def download_fb(
#     client,
#     transport: WAMediaTransport_pb2.WAMediaTransport.Integral,
#     media_type: MediaType
# ) -> bytes:
#     """Download media from a Facebook transport message.
#
#     Args:
#         client: The WhatsApp client instance
#         transport: The transport message
#         media_type: The media type
#
#     Returns:
#         The downloaded and decrypted media data
#
#     Raises:
#         DownloadError: If download fails
#     """
#     return await download_media_with_path(
#         client,
#         transport.GetDirectPath(),
#         transport.GetFileEncSHA256(),
#         transport.GetFileSHA256(),
#         transport.GetMediaKey(),
#         -1,
#         media_type,
#         MEDIA_TYPE_TO_MMS_TYPE[media_type]
#     )

async def download_media_with_path(
    client: "Client",
    direct_path: str,
    enc_file_hash: bytes,
    file_hash: bytes,
    media_key: bytes,
    file_length: int,
    media_type: "MediaType",  # TODO: Review MediaType enum/type
    mms_type: Optional[str]
) -> Optional[bytes]:
    """
    Port of Go method DownloadMediaWithPath from client.go.

    Downloads an attachment by manually specifying the path and encryption details.

    Args:
        client: The WhatsApp client instance
        direct_path: Media direct path
        enc_file_hash: Encrypted file hash
        file_hash: SHA256 of the decrypted file
        media_key: Media encryption key
        file_length: Expected file size
        media_type: Media type identifier
        mms_type: Optional MMS type string

    Returns:
        The downloaded and decrypted media bytes

    Raises:
        Exception if download fails on all hosts
    """
    # TODO: Review MediaConn implementation
    # TODO: Review refresh_media_conn method on Client
    # TODO: Review download_and_decrypt method on Client

    if client is None:
        raise ErrClientIsNil

    media_conn = await mediaconn.refresh_media_conn(client, force=False)

    if not mms_type:
        mms_type = MEDIA_TYPE_TO_MMS_TYPE[media_type]  # TODO: Review MEDIA_TYPE_TO_MMS_TYPE mapping

    for i, host in enumerate(media_conn.hosts):
        media_url = (
            f"https://{host.hostname}{direct_path}"
            f"&hash={base64.urlsafe_b64encode(enc_file_hash).decode().rstrip('=')}"
            f"&mms-type={mms_type}&__wa-mms="
        )
        try:
            data = await download_and_decrypt(
                client,
                media_url,
                media_key,
                media_type,
                file_length,
                enc_file_hash,
                file_hash
            )
            return data
        except (
            ErrFileLengthMismatch,
            ErrInvalidMediaSHA256,
            ErrMediaDownloadFailedWith403,
            ErrMediaDownloadFailedWith404,
            ErrMediaDownloadFailedWith410
        ):
            return None  # These are allowed partial errors

        except Exception as err:
            if i >= len(media_conn.hosts) - 1:
                raise RuntimeError(f"failed to download media from last host: {err}") from err
            logger.warning(f"Failed to download media: {err}, trying with next host...")

    raise RuntimeError("Media download failed unexpectedly without error capture")

async def download_and_decrypt(
    client: "Client",
    url: str,
    media_key: bytes,
    app_info: MediaType,
    file_length: int,
    file_enc_sha256: Optional[bytes],
    file_sha256: Optional[bytes],
) -> bytes:
    """
    Port of Go method downloadAndDecrypt from media.go.

    Downloads the media from the given URL and decrypts it using the media key.

    Args:
        client: The Client instance
        url: The media download URL
        media_key: The encryption key used to derive keys for decryption
        app_info: The media type
        file_length: Expected file length (used for validation)
        file_enc_sha256: Optional SHA256 hash of encrypted file
        file_sha256: Optional SHA256 hash of decrypted file

    Returns:
        Tuple of (decrypted media bytes or None, error or None)
    Raises:
        DownloadError:
        ErrFileLengthMismatch
        ErrInvalidMediaSHA256
    """
    # TODO: Review get_media_keys implementation
    # TODO: Review client.download_possibly_encrypted_media_with_retries implementation
    # TODO: Review validate_media implementation
    # TODO: Review cbcutil.decrypt implementation

    iv, cipher_key, mac_key, _ = get_media_keys(media_key, app_info)

    ciphertext, mac = await download_possibly_encrypted_media_with_retries(client, url, file_enc_sha256)

    if media_key is None and file_enc_sha256 is None and mac is None:
        # Unencrypted media, just return the downloaded data
        return ciphertext

    assert mac is not None
    validate_media(iv, ciphertext, mac_key, mac)

    data = decrypt(cipher_key, iv, ciphertext)

    if file_length >= 0 and len(data) != file_length:
        raise ErrFileLengthMismatch(file_length, len(data))  # custom error assumed to exist

    if file_sha256 is not None and len(file_sha256) == 32:
        calculated_sha256 = hashlib.sha256(data).digest()
        if calculated_sha256 != file_sha256:
            raise ErrInvalidMediaSHA256

    return data

def get_media_keys(media_key: bytes, app_info: MediaType) -> Tuple[bytes, bytes, bytes, bytes]:
    """Generate media keys from a media key and app info.

    Args:
        media_key: The media key
        app_info: The media type

    Returns:
        A tuple of (iv, cipher_key, mac_key, ref_key)
    """
    media_key_expanded = hkdf_sha256(media_key, b'', str(app_info).encode(), 112)
    return (
        media_key_expanded[:16],
        media_key_expanded[16:48],
        media_key_expanded[48:80],
        media_key_expanded[80:]
    )

def should_retry_media_download(err: Exception) -> bool:
    """
    Port of Go method shouldRetryMediaDownload from media_download.go.

    Determine whether a media download should be retried based on the error encountered.

    Args:
        err: The exception that occurred.

    Returns:
        True if the download should be retried, False otherwise.
    """
    if isinstance(err, (asyncio.TimeoutError, aiohttp.ClientError)):
        return True

    if isinstance(err, DownloadHTTPError):
        # Retry on server errors (5xx) and some client errors
        status_code = err.status_code
        return should_retry_http_status(status_code)

    if isinstance(err, Exception) and "stream error" in str(err).lower():
        return True

    return False


def should_retry_http_status(status_code: int) -> bool:
    """
    Determine if an HTTP status code should trigger a retry.

    Port of retryafter.should functionality from Go.

    Args:
        status_code: HTTP status code

    Returns:
        True if the status code indicates a retryable error
    """
    # Server errors (5xx) are generally retryable
    if 500 <= status_code < 600:
        return True

    # Some client errors that are retryable
    retryable_4xx = {
        408,  # Request Timeout
        429,  # Too Many Requests

    }

    return status_code in retryable_4xx

async def download_possibly_encrypted_media_with_retries(
    client: 'Client',
    url: str,
    checksum: Optional[bytes],
) -> Tuple[bytes, Optional[bytes]]:
    """
    Port of Go method downloadPossiblyEncryptedMediaWithRetries from client_media.go.

    Attempt to download media (possibly encrypted) with retries.

    Args:
        client: The WhatsApp client instance
        url: The URL to download from
        checksum: Optional checksum used to verify encrypted download

    Returns:
        Tuple of (file_data, mac), where mac is only present for encrypted media

    Raises:
        DownloadError: If the download fails after all retry attempts
    """
    # TODO: Review download_media_raw implementation
    # TODO: Review download_encrypted_media implementation
    # TODO: Review should_retry_media_download implementation
    # TODO: Review DownloadHTTPError class definition

    for retry_num in range(5):
        try:
            if checksum is None:
                file_data = await download_media(client, url)
                return file_data, None
            else:
                file_data, mac = await download_encrypted_media(client, url, checksum)
                return file_data, mac

        except Exception as e:
            if not should_retry_media_download(e):
                raise

            retry_duration = retry_num + 1  # seconds by default

            if isinstance(e, DownloadHTTPError):
                retry_after_header = e.response.headers.get("Retry-After")
                if retry_after_header:
                    # TODO: Review retryafter.Parse logic if custom parsing needed
                    try:
                        retry_duration = int(retry_after_header)
                    except ValueError:
                        pass

            logger.warning(
                f"Failed to download media due to network error: {e}, "
                f"retrying in {retry_duration}s..."
            )

            try:
                await asyncio.wait_for(asyncio.sleep(retry_duration), timeout=None)
            except asyncio.CancelledError:
                raise

    raise DownloadError("Failed to download media after retries")

async def do_media_download_request(client: 'Client', url: str) -> aiohttp.ClientResponse:
    """
    Port of Go method doMediaDownloadRequest from client.go.

    Make a GET request to download media with appropriate headers.

    Args:
        client: The WhatsApp client instance
        url: The URL to download media from

    Returns:
        The aiohttp.ClientResponse object

    Raises:
        DownloadHTTPError: If the response status is not 200
        DownloadError: On network failure
        ErrMediaDownloadFailedWith403, ErrMediaDownloadFailedWith404, ErrMediaDownloadFailedWith410:
            Specific failure codes mapped from response
    """
    # TODO: Review DownloadHTTPError, DownloadError, ErrMediaDownloadFailedWith403, etc.

    headers = {
        "Origin": "https://web.whatsapp.com",  # Matches socket.Origin
        "Referer": "https://web.whatsapp.com/",
    }

    if client.messenger_config is not None:
        headers["User-Agent"] = client.messenger_config.user_agent

    try:
        response = await client.http.get(url, headers=headers)

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

async def download_media(
    client: "Client",
    url: str
) -> bytes:
    """
    Port of Go method downloadMedia from client.go.

    Downloads media content from the provided URL.

    Args:
        client: The WhatsApp client instance.
        url: The URL to download media from.

    Returns:
        the response bytes
    """
    response = await do_media_download_request(client, url)
    data = await response.read()
    return data


async def download_encrypted_media(
    client: "Client",
    url: str,
    checksum: bytes
) -> Tuple[bytes, bytes]:
    """
    Port of Go method downloadEncryptedMedia from client.go.

    Downloads and splits encrypted media into file content and MAC.
    Validates the media's checksum if provided.

    Args:
        client: The WhatsApp client instance.
        url: The URL to download media from.
        checksum: The expected SHA256 checksum of the full encrypted media.

    Returns:
        Tuple containing:
        - file_data (bytes): the actual file contents (excluding the MAC)
        - mac (bytes): the trailing media MAC
    Raises:
        Exception:
        ErrTooShortFile
        ErrInvalidMediaEncSHA256
    """
    # TODO: Review ErrTooShortFile and ErrInvalidMediaEncSHA256 definitions

    data = await download_media(client, url)
    if len(data) <= MEDIA_HMAC_LENGTH:
        raise ErrTooShortFile

    file_data = data[:-MEDIA_HMAC_LENGTH]
    mac = data[-MEDIA_HMAC_LENGTH:]

    if len(checksum) == 32:
        calculated = hashlib.sha256(data).digest()
        if calculated != checksum:
            raise ErrInvalidMediaEncSHA256

    return file_data, mac


def validate_media(iv: bytes, file_data: bytes, mac_key: bytes, mac: bytes) -> None:
    """
    Port of Go method validateMedia from decrypt.go.

    Validates the integrity of encrypted media using HMAC-SHA256.

    Args:
        iv: The initialization vector used in encryption
        file_data: The raw encrypted media bytes
        mac_key: The HMAC key
        mac: The MAC tag to validate against

    Raises:
        ErrInvalidMediaHMAC: If HMAC validation fails
    """
    # TODO: Review ErrInvalidMediaHMAC implementation
    # TODO: Review MEDIA_HMAC_LENGTH definition

    h = hmac.new(mac_key, digestmod=hashlib.sha256)
    h.update(iv)
    h.update(file_data)

    if not hmac.compare_digest(h.digest()[:MEDIA_HMAC_LENGTH], mac):
        raise ErrInvalidMediaHMAC
