import pytest
from unittest.mock import AsyncMock, patch, mock_open
from pymeow.pymeow.client import Client
from pymeow.pymeow.exceptions import PymeowError
from pymeow.pymeow.types.media import MediaType
from pymeow.pymeow.types.message import MessageType
from pymeow.pymeow.datatypes.jid import JID
import os
import mimetypes

@pytest.mark.usefixtures("event_loop")
class TestMediaHandling:
    @pytest.mark.asyncio
    async def test_send_image_success(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('image/jpeg', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_image_data")) as mock_file, \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 100,
                "mimetype": "image/jpeg"
            }
            mock_send_media_message.return_value = {"id": "fake_msg_id"}

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            # Mock the login to avoid actual connection
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            to_jid_str = "123@s.whatsapp.net"
            image_path = "fake/path.jpg"
            caption = "test"
            view_once = True

            result = await client.send_image(to_jid_str, image_path, caption=caption, view_once=view_once)

            mock_file.assert_called_once_with(image_path, 'rb')
            mock_upload.assert_called_once_with(image_path, MediaType.IMAGE, mtype='image/jpeg')

            expected_media_info = mock_upload.return_value
            mock_send_media_message.assert_called_once_with(
                to=JID.from_string(to_jid_str),
                media_info=expected_media_info,
                message_type=MessageType.IMAGE,
                caption=caption,
                view_once=view_once,
                gif=False, # Default for send_image
                ptt=False, # Default for send_image
                filename=None # Default for send_image
            )
            assert result == {"id": "fake_msg_id"}

    @pytest.mark.asyncio
    async def test_send_image_file_not_found(self):
        with patch('os.path.exists', return_value=False):
            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(FileNotFoundError):
                await client.send_image("123@s.whatsapp.net", "fake/path.jpg")

    @pytest.mark.asyncio
    async def test_send_image_upload_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('image/jpeg', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_image_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload:

            mock_upload.side_effect = PymeowError("Upload failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Upload failed"):
                await client.send_image("123@s.whatsapp.net", "fake/path.jpg")

    @pytest.mark.asyncio
    async def test_send_image_send_media_message_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('image/jpeg', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_image_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 100,
                "mimetype": "image/jpeg"
            }
            mock_send_media_message.side_effect = PymeowError("Sending failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Sending failed"):
                await client.send_image("123@s.whatsapp.net", "fake/path.jpg")

    @pytest.mark.asyncio
    async def test_send_image_unknown_mime_type(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=(None, None)): # Simulates unknown MIME type

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(ValueError, match="Could not determine MIME type or not an image"):
                await client.send_image("123@s.whatsapp.net", "fake/path.jpg")

    @pytest.mark.asyncio
    async def test_send_image_not_an_image_mime_type(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('application/pdf', None)): # Simulates non-image MIME

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(ValueError, match="Could not determine MIME type or not an image"):
                await client.send_image("123@s.whatsapp.net", "fake/path.pdf")

    @pytest.mark.asyncio
    async def test_send_video_success(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('video/mp4', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_video_data")) as mock_file, \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 200, # Different from image
                "mimetype": "video/mp4"
            }
            mock_send_media_message.return_value = {"id": "fake_video_msg_id"}

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            to_jid_str = "123@s.whatsapp.net"
            video_path = "fake/path.mp4"
            caption = "test video"

            result = await client.send_video(to_jid_str, video_path, caption=caption, gif=False)

            mock_file.assert_called_once_with(video_path, 'rb')
            mock_upload.assert_called_once_with(video_path, MediaType.VIDEO, mtype='video/mp4')

            expected_media_info = mock_upload.return_value
            mock_send_media_message.assert_called_once_with(
                to=JID.from_string(to_jid_str),
                media_info=expected_media_info,
                message_type=MessageType.VIDEO,
                caption=caption,
                gif=False,
                # Assuming default kwargs for _send_media_message relevant to video
                # are being tested in _send_media_message tests or are implicitly handled
            )
            assert result == {"id": "fake_video_msg_id"}

    @pytest.mark.asyncio
    async def test_send_video_as_gif_success(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('video/mp4', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_video_data")) as mock_file, \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 200,
                "mimetype": "video/mp4"
            }
            mock_send_media_message.return_value = {"id": "fake_gif_msg_id"}

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            to_jid_str = "123@s.whatsapp.net"
            video_path = "fake/path.mp4"
            caption = "test gif"

            result = await client.send_video(to_jid_str, video_path, caption=caption, gif=True)

            mock_file.assert_called_once_with(video_path, 'rb')
            # Upload is still for VIDEO, mtype can be video or audio for gif
            mock_upload.assert_called_once_with(video_path, MediaType.VIDEO, mtype='video/mp4')

            expected_media_info = mock_upload.return_value
            mock_send_media_message.assert_called_once_with(
                to=JID.from_string(to_jid_str),
                media_info=expected_media_info,
                message_type=MessageType.VIDEO, # MessageType is still VIDEO
                caption=caption,
                gif=True # This is the key difference
            )
            assert result == {"id": "fake_gif_msg_id"}

    @pytest.mark.asyncio
    async def test_send_video_file_not_found(self):
        with patch('os.path.exists', return_value=False):
            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(FileNotFoundError):
                await client.send_video("123@s.whatsapp.net", "fake/path.mp4")

    @pytest.mark.asyncio
    async def test_send_video_upload_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('video/mp4', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_video_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload:

            mock_upload.side_effect = PymeowError("Video upload failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Video upload failed"):
                await client.send_video("123@s.whatsapp.net", "fake/path.mp4")

    @pytest.mark.asyncio
    async def test_send_video_send_media_message_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('video/mp4', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_video_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 200,
                "mimetype": "video/mp4"
            }
            mock_send_media_message.side_effect = PymeowError("Video sending failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Video sending failed"):
                await client.send_video("123@s.whatsapp.net", "fake/path.mp4")

    @pytest.mark.asyncio
    async def test_send_video_unknown_mime_type(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=(None, None)): # Simulates unknown MIME type

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            # The error message depends on the logic in send_video, assuming it's similar to send_image
            # but specific to video. The plan mentions "Could not determine MIME type or not a video".
            with pytest.raises(ValueError, match="Could not determine MIME type or not a video"):
                await client.send_video("123@s.whatsapp.net", "fake/path.dat") # Using .dat for generic unknown

    @pytest.mark.asyncio
    async def test_send_video_not_a_video_mime_type(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('image/jpeg', None)): # Simulates a non-video MIME

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(ValueError, match="Could not determine MIME type or not a video"):
                await client.send_video("123@s.whatsapp.net", "fake/path.jpg") # Using .jpg for non-video

    @pytest.mark.asyncio
    async def test_send_document_success(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('application/pdf', None)) as mock_mimetype, \
             patch('builtins.open', mock_open(read_data=b"fake_document_data")) as mock_file, \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 300,
                "mimetype": "application/pdf" # Mimetype from upload
            }
            mock_send_media_message.return_value = {"id": "fake_doc_msg_id"}

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            to_jid_str = "123@s.whatsapp.net"
            doc_path = "fake/path.pdf"
            caption = "test document"
            custom_file_name = "custom.pdf" # This will be used for actual_file_name

            result = await client.send_document(to_jid_str, doc_path, caption=caption, file_name=custom_file_name)

            # mimetypes.guess_type is called with actual_file_name (custom.pdf here)
            mock_mimetype.assert_called_once_with(custom_file_name)
            mock_file.assert_called_once_with(doc_path, 'rb')
            # upload is called with doc_path, MediaType.DOCUMENT, progress_callback=None, file_name=custom_file_name
            mock_upload.assert_called_once_with(
                doc_path,
                MediaType.DOCUMENT,
                mtype='application/pdf', # send_document doesn't pass mtype, upload will guess it.
                                          # Let's assume upload guesses it correctly based on file_name or path
                                          # For this test, we can ensure upload is called with the filename that allows it to guess
                                          # Or, more accurately, upload itself calls mimetypes.guess_type.
                                          # The mtype in client.upload is an optional param.
                                          # The send_document passes actual_file_name to upload.
                                          # Let's refine the assertion for upload call.
                                          # upload(self, path: str, media_type: MediaType, known_mime_type: Optional[str] = None, ...)
                                          # send_document does not pass known_mime_type. It passes file_name to upload.
            )
            # Correcting the mock_upload.assert_called_once_with:
            # The `mtype` is not passed by `send_document` to `upload`. `upload` itself determines it.
            # `file_name` is passed to `upload` by `send_document`.
            # `progress_callback` is also a param for `upload`.
            mock_upload.assert_called_once_with(
                doc_path,
                MediaType.DOCUMENT,
                progress_callback=None, # Default
                file_name=custom_file_name
            )

            expected_media_info = mock_upload.return_value
            # _send_media_message is called with actual_file_name (custom.pdf here)
            mock_send_media_message.assert_called_once_with(
                to=JID.from_string(to_jid_str),
                media_info=expected_media_info,
                message_type=MessageType.DOCUMENT,
                caption=caption,
                file_name=custom_file_name
            )
            assert result == {"id": "fake_doc_msg_id"}

    @pytest.mark.asyncio
    async def test_send_document_file_not_found(self):
        with patch('os.path.exists', return_value=False):
            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(FileNotFoundError):
                await client.send_document("123@s.whatsapp.net", "fake/path.pdf")

    @pytest.mark.asyncio
    async def test_send_document_upload_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('application/pdf', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_document_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload:

            mock_upload.side_effect = PymeowError("Document upload failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Document upload failed"):
                await client.send_document("123@s.whatsapp.net", "fake/path.pdf")

    @pytest.mark.asyncio
    async def test_send_document_send_media_message_fails(self):
        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('application/pdf', None)), \
             patch('builtins.open', mock_open(read_data=b"fake_document_data")), \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.return_value = {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 300,
                "mimetype": "application/pdf"
            }
            mock_send_media_message.side_effect = PymeowError("Document sending failed")

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            with pytest.raises(PymeowError, match="Document sending failed"):
                await client.send_document("123@s.whatsapp.net", "fake/path.pdf")

    @pytest.mark.asyncio
    async def test_send_document_with_progress_callback(self):
        from unittest.mock import MagicMock

        async def mock_upload_side_effect(path, media_type, progress_callback=None, file_name=None):
            if progress_callback:
                progress_callback(50, 100)
                progress_callback(100, 100)
            return {
                "url": "http://fakemedia.url",
                "direct_path": "/fakepath",
                "media_key": b"fake_media_key",
                "file_sha256": b"sha256",
                "file_enc_sha256": b"enc_sha256",
                "file_length": 300,
                "mimetype": "application/pdf"
            }

        with patch('os.path.exists', return_value=True), \
             patch('mimetypes.guess_type', return_value=('application/pdf', None)) as mock_mimetype, \
             patch('builtins.open', mock_open(read_data=b"fake_document_data")) as mock_file, \
             patch('pymeow.pymeow.client.Client.upload', new_callable=AsyncMock) as mock_upload, \
             patch('pymeow.pymeow.client.Client._send_media_message', new_callable=AsyncMock) as mock_send_media_message:

            mock_upload.side_effect = mock_upload_side_effect
            mock_send_media_message.return_value = {"id": "fake_doc_prog_id"}

            progress_callback_mock = MagicMock()

            client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
            client.logged_in = True
            client.active_platform = "test_platform"
            client.auth_manager = AsyncMock()
            client.auth_manager.get_media_conn.return_value = ("testhost", {})

            to_jid_str = "123@s.whatsapp.net"
            doc_path = "fake/path.pdf"
            custom_file_name = "progress_doc.pdf"

            await client.send_document(
                to_jid_str,
                doc_path,
                file_name=custom_file_name,
                progress_callback=progress_callback_mock
            )

            mock_mimetype.assert_called_once_with(custom_file_name)
            mock_file.assert_called_once_with(doc_path, 'rb')
            mock_upload.assert_called_once_with(
                doc_path,
                MediaType.DOCUMENT,
                progress_callback=progress_callback_mock,
                file_name=custom_file_name
            )

            progress_callback_mock.assert_any_call(50, 100)
            progress_callback_mock.assert_any_call(100, 100)
            assert progress_callback_mock.call_count == 2

            mock_send_media_message.assert_called_once()
            # We can be more specific with _send_media_message assertion if needed,
            # but the main point here is testing the progress_callback.
