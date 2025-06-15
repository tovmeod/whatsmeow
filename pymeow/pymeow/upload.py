"""
Media upload handling for WhatsApp.

Port of whatsmeow/upload.go
"""
import base64
import hashlib
import hmac
import io
import os
import tempfile
from dataclasses import dataclass
from typing import IO, TYPE_CHECKING, BinaryIO, Optional, Tuple
from urllib.parse import urlencode

import aiohttp

from .download import MEDIA_TYPE_TO_MMS_TYPE, MediaType
from .exceptions import PymeowError
from .util.cbcutil import encrypt, encrypt_stream

if TYPE_CHECKING:
    from .client import Client
    from . import mediaconn


class UploadError(PymeowError):
    """Raised when there is an error uploading media."""
    pass


@dataclass
class UploadResponse:
    """Contains the data from the attachment upload, which can be put into a message to send the attachment."""
    url: str
    direct_path: str
    handle: str
    object_id: str

    # Fields not included in the JSON response
    media_key: bytes = b""
    file_enc_sha256: bytes = b""
    file_sha256: bytes = b""
    file_length: int = 0


async def upload(client: 'Client', plaintext: bytes, app_info: MediaType) -> UploadResponse:
    """
    Upload the given attachment to WhatsApp servers.

    You should copy the fields in the response to the corresponding fields in a protobuf message.

    For example, to send an image:

        resp = await upload(client, your_image_bytes, MediaType.IMAGE)
        # handle error

        image_msg = waE2E_pb2.ImageMessage(
            caption="Hello, world!",
            mimetype="image/png",  # replace this with the actual mime type
            # you can also optionally add other fields like ContextInfo and JpegThumbnail here

            url=resp.url,
            directPath=resp.direct_path,
            mediaKey=resp.media_key,
            fileEncSHA256=resp.file_enc_sha256,
            fileSHA256=resp.file_sha256,
            fileLength=resp.file_length,
        )
        _, err = await client.send_message(target_jid, waE2E_pb2.Message(imageMessage=image_msg))
        # handle error again

    The same applies to the other message types like DocumentMessage, just replace the struct type and Message field name.

    Args:
        client: The WhatsApp client instance
        plaintext: The data to upload
        app_info: The media type

    Returns:
        UploadResponse with upload details

    Raises:
        UploadError: If the upload fails
    """
    resp = UploadResponse(url="", direct_path="", handle="", object_id="")
    resp.file_length = len(plaintext)
    resp.media_key = os.urandom(32)

    # Calculate plaintext SHA256
    plaintext_sha256 = hashlib.sha256(plaintext).digest()
    resp.file_sha256 = plaintext_sha256

    # Get media keys
    iv, cipher_key, mac_key, _ = _get_media_keys(resp.media_key, app_info)

    # Encrypt the data
    ciphertext = encrypt(cipher_key, iv, plaintext)

    # Calculate HMAC
    h = hmac.new(mac_key, digestmod=hashlib.sha256)
    h.update(iv)
    h.update(ciphertext)

    # Append HMAC to ciphertext
    data_to_upload = ciphertext + h.digest()[:10]

    # Calculate encrypted data hash
    data_hash = hashlib.sha256(data_to_upload).digest()
    resp.file_enc_sha256 = data_hash

    # Upload the data
    await _raw_upload(client, io.BytesIO(data_to_upload), len(data_to_upload),
                      resp.file_enc_sha256, app_info, False, resp)

    return resp


async def upload_reader(client: 'Client', plaintext: BinaryIO, temp_file: Optional[IO[bytes]],
                       app_info: MediaType) -> UploadResponse:
    """
    Upload the given attachment to WhatsApp servers.

    This is otherwise identical to upload(), but it reads the plaintext from a file-like object
    instead of a byte slice. A temporary file is required for the encryption process. If temp_file
    is None, a temporary file will be created and deleted after the upload.

    To use only one file, pass the same file as both plaintext and temp_file. This will cause
    the file to be overwritten with encrypted data.

    Args:
        client: The WhatsApp client instance
        plaintext: File-like object to read data from
        temp_file: Optional temporary file for encryption, will be created if None
        app_info: The media type

    Returns:
        UploadResponse with upload details

    Raises:
        UploadError: If the upload fails
    """
    resp = UploadResponse(url="", direct_path="", handle="", object_id="")
    resp.media_key = os.urandom(32)

    # Get media keys
    iv, cipher_key, mac_key, _ = _get_media_keys(resp.media_key, app_info)

    # Create temporary file if not provided
    temp_file_created = False
    actual_temp_file: IO[bytes]
    if temp_file is None:
        actual_temp_file = tempfile.NamedTemporaryFile(delete=False, mode="w+b")
        temp_file_created = True
    else:
        actual_temp_file = temp_file

    try:
        # Encrypt the stream
        resp.file_sha256, resp.file_enc_sha256, resp.file_length, upload_size = encrypt_stream(
            cipher_key, iv, mac_key, plaintext, actual_temp_file
        )

        # Seek to beginning of file for upload
        actual_temp_file.seek(0)

        # Upload the data
        await _raw_upload(client, actual_temp_file, upload_size, resp.file_enc_sha256,
                          app_info, False, resp)

        return resp

    finally:
        if temp_file_created:
            actual_temp_file.close()
            # Type narrowing: we know it's a NamedTemporaryFile if temp_file_created is True
            temp_file_obj = actual_temp_file  # type: ignore
            if hasattr(temp_file_obj, 'name'):
                os.unlink(temp_file_obj.name)


async def upload_newsletter(client: 'Client', data: bytes, app_info: MediaType) -> UploadResponse:
    """
    Upload the given attachment to WhatsApp servers without encrypting it first.

    Newsletter media works mostly the same way as normal media, with a few differences:
    * Since it's unencrypted, there's no MediaKey or FileEncSHA256 fields.
    * There's a "media handle" that needs to be passed in SendRequestExtra.

    Example:

        resp = await upload_newsletter(client, your_image_bytes, MediaType.IMAGE)
        # handle error

        image_msg = waE2E_pb2.ImageMessage(
            # Caption, mime type and other such fields work like normal
            caption="Hello, world!",
            mimetype="image/png",

            # URL and direct path are also there like normal media
            url=resp.url,
            directPath=resp.direct_path,
            fileSHA256=resp.file_sha256,
            fileLength=resp.file_length,
            # Newsletter media isn't encrypted, so the media key and file enc sha fields are not applicable
        )
        _, err = await client.send_message(newsletter_jid, waE2E_pb2.Message(imageMessage=image_msg),
                                         media_handle=resp.handle)
        # handle error again

    Args:
        client: The WhatsApp client instance
        data: The data to upload
        app_info: The media type

    Returns:
        UploadResponse with upload details

    Raises:
        UploadError: If the upload fails
    """
    resp = UploadResponse(url="", direct_path="", handle="", object_id="")
    resp.file_length = len(data)

    # Calculate hash
    hash_obj = hashlib.sha256(data)
    resp.file_sha256 = hash_obj.digest()

    # Upload the data
    await _raw_upload(client, io.BytesIO(data), resp.file_length,
                      resp.file_sha256, app_info, True, resp)

    return resp


async def upload_newsletter_reader(client: 'Client', data: BinaryIO, app_info: MediaType) -> UploadResponse:
    """
    Upload the given attachment to WhatsApp servers without encrypting it first.

    This is otherwise identical to upload_newsletter(), but it reads the plaintext from a file-like
    object instead of a byte slice. Unlike upload_reader(), this does not require a temporary file.
    However, the data needs to be hashed first, so a seekable file-like object is required to be
    able to read the data twice.

    Args:
        client: The WhatsApp client instance
        data: Seekable file-like object to read data from
        app_info: The media type

    Returns:
        UploadResponse with upload details

    Raises:
        UploadError: If the upload fails
    """
    resp = UploadResponse(url="", direct_path="", handle="", object_id="")

    # Calculate hash
    hasher = hashlib.sha256()
    file_length = 0
    chunk_size = 8192

    while True:
        chunk = data.read(chunk_size)
        if not chunk:
            break
        hasher.update(chunk)
        file_length += len(chunk)

    resp.file_length = file_length
    resp.file_sha256 = hasher.digest()

    # Seek back to beginning for upload
    data.seek(0)

    # Upload the data
    await _raw_upload(client, data, resp.file_length,
                      resp.file_sha256, app_info, True, resp)

    return resp


async def _raw_upload(client: 'Client', data_to_upload: IO[bytes], upload_size: int,
                     file_hash: bytes, app_info: MediaType, newsletter: bool,
                     resp: UploadResponse) -> None:
    """
    Internal function to handle the actual upload process.

    Args:
        client: The WhatsApp client instance
        data_to_upload: The data to upload
        upload_size: Size of the data in bytes
        file_hash: Hash of the file
        app_info: Media type information
        newsletter: Whether this is a newsletter upload
        resp: Response object to populate

    Raises:
        UploadError: If the upload fails
    """
    # Refresh media connection
    try:
        media_conn = await mediaconn.refresh_media_conn(client, False)
    except Exception as e:
        raise UploadError(f"Failed to refresh media connections: {e}")

    # Encode file hash for URL
    token = base64.urlsafe_b64encode(file_hash).decode().rstrip('=')

    # Build query parameters
    query_params = {
        "auth": media_conn.auth,
        "token": token
    }

    # Get MMS type
    mms_type = MEDIA_TYPE_TO_MMS_TYPE[app_info]
    upload_prefix = "mms"

    # Handle messenger config
    if client.messenger_config is not None:
        upload_prefix = "wa-msgr/mms"
        # Messenger upload only allows voice messages, not audio files
        if mms_type == "audio":
            mms_type = "ptt"

    # Handle newsletter uploads
    if newsletter:
        mms_type = f"newsletter-{mms_type}"
        upload_prefix = "newsletter"

    # Select host
    host = None
    if client.messenger_config is not None and media_conn.hosts:
        # Prefer last option for messenger uploads
        host = media_conn.hosts[-1].hostname
    elif media_conn.hosts:
        host = media_conn.hosts[0].hostname
    else:
        raise UploadError("No media hosts available")

    # Build upload URL
    upload_url = f"https://{host}/{upload_prefix}/{mms_type}/{token}?{urlencode(query_params)}"

    # Prepare request headers
    headers = {
        "Origin": "https://web.whatsapp.com",
        "Referer": "https://web.whatsapp.com/",
        "Content-Length": str(upload_size)
    }

    try:
        # Make the request
        async with client.http.post(upload_url, data=data_to_upload, headers=headers) as response:
            if response.status != 200:
                raise UploadError(f"Upload failed with status code {response.status}")

            # Parse response
            response_data = await response.json()

            # Update response object
            resp.url = response_data.get("url", "")
            resp.direct_path = response_data.get("direct_path", "")
            resp.handle = response_data.get("handle", "")
            resp.object_id = response_data.get("object_id", "")

    except aiohttp.ClientError as e:
        raise UploadError(f"Failed to execute request: {e}")
    except Exception as e:
        if isinstance(e, UploadError):
            raise
        raise UploadError(f"Failed to upload media: {e}")


def _get_media_keys(media_key: bytes, app_info: MediaType) -> Tuple[bytes, bytes, bytes, bytes]:
    """
    Generate media keys from a media key and app info.

    Args:
        media_key: The media key
        app_info: The media type

    Returns:
        A tuple of (iv, cipher_key, mac_key, ref_key)
    """
    # Import here to avoid circular imports
    from .util.hkdfutil import sha256 as hkdf_sha256

    media_key_expanded = hkdf_sha256(media_key, b"", str(app_info).encode(), 112)
    return (
        media_key_expanded[:16],
        media_key_expanded[16:48],
        media_key_expanded[48:80],
        media_key_expanded[80:]
    )
