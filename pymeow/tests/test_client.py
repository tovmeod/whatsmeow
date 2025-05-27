"""
Tests for the pymeow client.
"""
import pytest
import asyncio
from unittest.mock import AsyncMock, patch, MagicMock 
from datetime import datetime # Added for timestamp in receive test
import os # For os.path mocks
import base64 # For thumbnail data if needed
import mimetypes # For mimetype guessing

from pymeow.pymeow.client import Client
from pymeow.pymeow.protocol import ProtocolNode # For verifying websocket send
from pymeow.pymeow.generated_protos.waE2E import WAWebProtobufsE2E_pb2
# Message is now an alias to WAWebProtobufsE2E_pb2.Message, but explicit import is fine for clarity in tests
from pymeow.pymeow.types import Message 
from pymeow.pymeow.exceptions import PymeowError # Kept PymeowError

@pytest.mark.asyncio
async def test_client_initialization():
    """Test that the client can be initialized."""
    client = Client()
    assert client is not None

@pytest.mark.asyncio
async def test_event_handlers():
    """Test that event handlers are called correctly."""
    client = Client()
    
    # Mock event handler
    mock_handler = AsyncMock()
    client.on('message')(mock_handler) # Using 'message' event as it's refactored
    
    # Test event dispatching with a mock Protobuf message object
    test_message_obj = MagicMock(spec=WAWebProtobufsE2E_pb2.Message)
    test_message_obj.conversation = "test content" 
    
    await client._dispatch_event('message', test_message_obj)
    
    mock_handler.assert_awaited_once_with(test_message_obj)

@pytest.mark.asyncio
async def test_send_text_message_protobuf(): 
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.device = MagicMock()
    client._auth_state.device.device_id = "TESTDEVICEIDFINAL"

    mock_ws_client = AsyncMock()
    client._websocket = mock_ws_client
    
    client._message_queue = AsyncMock() 
    client._message_queue.put = AsyncMock()

    client._is_connected = True
    client._is_authenticated = True

    test_jid = "1234567890@s.whatsapp.net"
    test_content = "Hello via Protobuf Final!"
    
    message_id = await client.send_message(test_jid, test_content)
    
    assert message_id.startswith("TESTDEVICEIDFINAL")

    client._message_queue.put.assert_awaited_once()
    args, _ = client._message_queue.put.call_args
    sent_message_id_in_queue, protocol_node_to_send, _ = args[0] 
    
    assert sent_message_id_in_queue == message_id
    assert isinstance(protocol_node_to_send, ProtocolNode)
    assert protocol_node_to_send.tag == "message"
    assert protocol_node_to_send.attrs["to"] == test_jid
    assert protocol_node_to_send.attrs["type"] == "text"
    
    assert isinstance(protocol_node_to_send.content, bytes)
    parsed_inner_proto = WAWebProtobufsE2E_pb2.Message()
    parsed_inner_proto.ParseFromString(protocol_node_to_send.content)
    assert parsed_inner_proto.conversation == test_content

@pytest.mark.asyncio
async def test_receive_text_message_protobuf():
    client = Client()
    mock_event_handler = AsyncMock()
    client.on('message')(mock_event_handler)

    # 1. Construct the inner Protobuf Message with key and timestamp info
    inner_proto_msg_with_key = WAWebProtobufsE2E_pb2.Message()
    inner_proto_msg_with_key.conversation = "Received Protobuf Text Final"
    
    server_msg_id = "server_text_msg_final"
    sender_jid = "sender_text_final@s.whatsapp.net"
    msg_timestamp = int(datetime.now().timestamp())

    inner_proto_msg_with_key.key.id = server_msg_id
    inner_proto_msg_with_key.key.remote_jid = sender_jid
    inner_proto_msg_with_key.key.from_me = False 
    inner_proto_msg_with_key.message_timestamp = msg_timestamp
    
    serialized_inner_proto_content_with_key = inner_proto_msg_with_key.SerializeToString()
    
    # 2. Simulate the dictionary that _handle_ws_message (binary_payload path) expects
    simulated_ws_input_to_client = {
        "type": "binary_payload",
        "flags": 0, 
        "tag": server_msg_id, # Stanza tag, used by client to get msg id
        "payload": serialized_inner_proto_content_with_key 
    }
    
    client._auth_state = MagicMock() 
    client._auth_state.me = "me@s.whatsapp.net" 

    # Call _handle_ws_message directly
    await client._handle_ws_message(simulated_ws_input_to_client)

    mock_event_handler.assert_awaited_once()
    args, _ = mock_event_handler.call_args
    dispatched_message_obj = args[0]
    
    assert isinstance(dispatched_message_obj, WAWebProtobufsE2E_pb2.Message)
    assert dispatched_message_obj.conversation == "Received Protobuf Text Final"
    
    assert dispatched_message_obj.key.id == server_msg_id
    assert dispatched_message_obj.key.remote_jid == sender_jid
    assert dispatched_message_obj.key.from_me == False
    assert dispatched_message_obj.message_timestamp == msg_timestamp

@pytest.mark.asyncio
async def test_error_handling():
    client = Client()
    mock_error_handler = AsyncMock()
    client.on('error')(mock_error_handler)
    
    test_error_payload = {"message": "Test error condition", "code": 500}
    await client._dispatch_event('error', test_error_payload)
    mock_error_handler.assert_awaited_once_with(test_error_payload)

@pytest.mark.asyncio
async def test_send_image_message_protobuf():
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.device = MagicMock()
    client._auth_state.device.device_id = "test_device_id_img" 
    client._auth_state.me = "test_device_id_img@s.whatsapp.net" 
    client._is_connected = True
    client._is_authenticated = True

    client._message_queue = AsyncMock()
    client._message_queue.put = AsyncMock()

    mock_upload_media_return = {
        "url": "http://mock.whatsapp.net/mms/image_mock_url",
        "direct_path": "/mms/image_mock_url",
        "media_key": b"mock_media_key_bytes", 
        "file_sha256": b"mock_sha256_hash_bytes",
        "file_enc_sha256": b"mock_enc_sha256_hash_bytes",
        "mimetype": "image/jpeg", 
        "file_length": 12345,
    }
    client.upload_media = AsyncMock(return_value=mock_upload_media_return)

    test_jid = "recipient_img@s.whatsapp.net"
    mock_image_path = "/fake/path/to/image.jpeg" 
    test_caption = "Look at this image! (Protobuf)"
    mock_thumbnail_bytes = b"fake_thumbnail_data_jpeg"

    with patch('os.path.isfile', return_value=True), \
         patch('os.path.getsize', return_value=12345), \
         patch('mimetypes.guess_type', return_value=('image/jpeg', None)):
        
        client._generate_thumbnail = MagicMock(return_value=mock_thumbnail_bytes)

        message_id = await client.send_image(
            to=test_jid,
            image_path=mock_image_path, 
            caption=test_caption
        )
    
    assert message_id.startswith("TEST_DEVICE_ID_IMG") 

    client._message_queue.put.assert_awaited_once()
    args, _ = client._message_queue.put.call_args
    sent_message_id_in_queue, protocol_node_to_send, _ = args[0]

    assert sent_message_id_in_queue == message_id
    assert isinstance(protocol_node_to_send, ProtocolNode)
    assert protocol_node_to_send.tag == "message"
    assert protocol_node_to_send.attrs["to"] == test_jid
    assert protocol_node_to_send.attrs["type"] == "image" 

    assert isinstance(protocol_node_to_send.content, bytes)
    parsed_outer_proto = WAWebProtobufsE2E_pb2.Message()
    parsed_outer_proto.ParseFromString(protocol_node_to_send.content)

    assert parsed_outer_proto.HasField('image_message')
    image_msg_proto = parsed_outer_proto.image_message
    assert image_msg_proto.caption == test_caption
    assert image_msg_proto.mimetype == "image/jpeg" 
    assert image_msg_proto.url == "http://mock.whatsapp.net/mms/image_mock_url"
    assert image_msg_proto.jpeg_thumbnail == mock_thumbnail_bytes 
    
    assert image_msg_proto.file_sha256 == b"mock_sha256_hash_bytes" 
    assert image_msg_proto.media_key == b"mock_media_key_bytes"
    assert image_msg_proto.file_length == 12345
    assert image_msg_proto.file_enc_sha256 == b"mock_enc_sha256_hash_bytes"

@pytest.mark.asyncio
async def test_receive_image_message_protobuf(): 
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.me = "user_self_jid@s.whatsapp.net"

    mock_event_handler = AsyncMock()
    client.on('message')(mock_event_handler)

    inner_proto_msg = WAWebProtobufsE2E_pb2.Message()
    
    img_msg = inner_proto_msg.image_message
    img_msg.caption = "Test Image Received"
    img_msg.mimetype = "image/jpeg"
    img_msg.url = "https://mmg.whatsapp.net/mms/image_received_url"
    img_msg.file_sha256 = b"received_image_sha256_hash"
    img_msg.file_length = 67890
    img_msg.media_key = b"received_media_key"
    img_msg.jpeg_thumbnail = b"received_thumbnail_bytes"

    server_msg_id = "server_img_msg_456"
    sender_jid = "sender_img@s.whatsapp.net"
    msg_timestamp = int(datetime.now().timestamp())

    inner_proto_msg.key.id = server_msg_id
    inner_proto_msg.key.remote_jid = sender_jid
    inner_proto_msg.key.from_me = False 
    inner_proto_msg.message_timestamp = msg_timestamp
    
    serialized_inner_proto_content_with_key = inner_proto_msg.SerializeToString()

    simulated_ws_input_to_client = {
        "type": "binary_payload",
        "flags": 0,
        "tag": server_msg_id, 
        "payload": serialized_inner_proto_content_with_key 
    }
    
    await client._handle_ws_message(simulated_ws_input_to_client)

    mock_event_handler.assert_awaited_once()
    args, _ = mock_event_handler.call_args
    dispatched_msg = args[0]
    
    assert isinstance(dispatched_msg, WAWebProtobufsE2E_pb2.Message)
    
    assert dispatched_msg.key.id == server_msg_id
    assert dispatched_msg.key.remote_jid == sender_jid
    assert dispatched_msg.key.from_me == False
    assert dispatched_msg.message_timestamp == msg_timestamp

    assert dispatched_msg.HasField('image_message')
    received_img_msg = dispatched_msg.image_message
    assert received_img_msg.caption == "Test Image Received"
    assert received_img_msg.mimetype == "image/jpeg"
    assert received_img_msg.url == "https://mmg.whatsapp.net/mms/image_received_url"
    assert received_img_msg.file_sha256 == b"received_image_sha256_hash"
    assert received_img_msg.file_length == 67890
    assert received_img_msg.media_key == b"received_media_key"
    assert received_img_msg.jpeg_thumbnail == b"received_thumbnail_bytes"

@pytest.mark.asyncio
async def test_send_audio_message_protobuf():
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.device = MagicMock()
    client._auth_state.device.device_id = "test_device_id_audio" 
    client._auth_state.me = "test_device_id_audio@s.whatsapp.net"
    client._is_connected = True
    client._is_authenticated = True
    client._message_queue = AsyncMock()
    client._message_queue.put = AsyncMock()

    mock_upload_details = {
        "url": "http://mock.whatsapp.net/mms/audio_mock_url",
        "direct_path": "/mms/audio_mock_url",
        "media_key": b"mock_audio_media_key",
        "file_sha256": b"mock_audio_sha256_hash",
        "file_enc_sha256": b"mock_audio_enc_sha256_hash",
        "mimetype": "audio/ogg; codecs=opus",
        "file_length": 23456,
    }
    client.upload_media = AsyncMock(return_value=mock_upload_details)
    
    test_jid = "recipient_audio@s.whatsapp.net"
    mock_audio_path = "/fake/path/to/audio.ogg"
    is_ptt = True 

    with patch('os.path.isfile', return_value=True), \
         patch('os.path.getsize', return_value=23456), \
         patch('mimetypes.guess_type', return_value=("audio/ogg", None)):
        
        if hasattr(client, '_send_voice_note_metadata'): 
             client._send_voice_note_metadata = AsyncMock()

        message_id = await client.send_audio(
            to=test_jid,
            audio_path=mock_audio_path,
            voice_note=is_ptt
        )
    
    assert message_id.startswith("TEST_DEVICE_ID_AUDIO") 
    client._message_queue.put.assert_awaited_once() 
    args, _ = client._message_queue.put.call_args
    _, protocol_node_to_send, _ = args[0]

    assert isinstance(protocol_node_to_send, ProtocolNode)
    assert protocol_node_to_send.attrs["to"] == test_jid
    assert protocol_node_to_send.attrs["type"] == "audio"

    assert isinstance(protocol_node_to_send.content, bytes)
    parsed_outer_proto = WAWebProtobufsE2E_pb2.Message()
    parsed_outer_proto.ParseFromString(protocol_node_to_send.content)

    assert parsed_outer_proto.HasField('audio_message')
    audio_msg_proto = parsed_outer_proto.audio_message
    assert audio_msg_proto.url == mock_upload_details["url"]
    assert audio_msg_proto.mimetype == mock_upload_details["mimetype"]
    assert audio_msg_proto.file_sha256 == mock_upload_details["file_sha256"]
    assert audio_msg_proto.file_length == mock_upload_details["file_length"]
    assert audio_msg_proto.media_key == mock_upload_details["media_key"]
    assert audio_msg_proto.ptt == is_ptt 

    if is_ptt and hasattr(client, '_send_voice_note_metadata'):
        client._send_voice_note_metadata.assert_awaited_once_with(message_id, test_jid)

@pytest.mark.asyncio
async def test_receive_audio_message_protobuf():
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.me = "user_self_jid@s.whatsapp.net"
    mock_event_handler = AsyncMock()
    client.on('message')(mock_event_handler)

    inner_proto_msg = WAWebProtobufsE2E_pb2.Message()
    audio_msg = inner_proto_msg.audio_message
    audio_msg.url = "https://mmg.whatsapp.net/mms/audio_received_url"
    audio_msg.mimetype = "audio/ogg; codecs=opus"
    audio_msg.file_sha256 = b"rcv_audio_sha256"
    audio_msg.file_length = 34567
    audio_msg.media_key = b"rcv_audio_media_key"
    audio_msg.seconds = 20
    audio_msg.ptt = True 

    server_msg_id = "server_audio_msg_789"
    sender_jid = "sender_audio@s.whatsapp.net"
    msg_timestamp = int(datetime.now().timestamp())

    inner_proto_msg.key.id = server_msg_id
    inner_proto_msg.key.remote_jid = sender_jid
    inner_proto_msg.key.from_me = False
    inner_proto_msg.message_timestamp = msg_timestamp
    
    serialized_inner_proto_content_with_key = inner_proto_msg.SerializeToString()

    simulated_ws_input_to_client = {
        "type": "binary_payload",
        "flags": 0,
        "tag": server_msg_id, 
        "payload": serialized_inner_proto_content_with_key 
    }
    
    await client._handle_ws_message(simulated_ws_input_to_client)

    mock_event_handler.assert_awaited_once()
    args, _ = mock_event_handler.call_args
    dispatched_msg = args[0]
    
    assert isinstance(dispatched_msg, WAWebProtobufsE2E_pb2.Message)
    assert dispatched_msg.key.id == server_msg_id
    assert dispatched_msg.key.remote_jid == sender_jid
    assert dispatched_msg.message_timestamp == msg_timestamp
    
    assert dispatched_msg.HasField('audio_message')
    rcv_audio_msg = dispatched_msg.audio_message
    assert rcv_audio_msg.url == "https://mmg.whatsapp.net/mms/audio_received_url"
    assert rcv_audio_msg.mimetype == "audio/ogg; codecs=opus"
    assert rcv_audio_msg.file_sha256 == b"rcv_audio_sha256"
    assert rcv_audio_msg.file_length == 34567
    assert rcv_audio_msg.seconds == 20
    assert rcv_audio_msg.ptt is True

@pytest.mark.asyncio
async def test_send_document_message_protobuf():
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.device = MagicMock()
    # Corrected: _generate_message_id uses device_id
    client._auth_state.device.device_id = "test_device_id_doc" 
    client._auth_state.me = "test_device_id_doc@s.whatsapp.net"
    client._is_connected = True
    client._is_authenticated = True
    client._message_queue = AsyncMock()
    client._message_queue.put = AsyncMock()

    mock_upload_details = {
        "url": "http://mock.whatsapp.net/mms/doc_mock_url",
        "direct_path": "/mms/doc_mock_url",
        "media_key": b"mock_doc_media_key",
        "file_sha256": b"mock_doc_sha256_hash",
        "file_enc_sha256": b"mock_doc_enc_sha256_hash",
        "mimetype": "application/pdf",
        "file_length": 56789,
    }
    client.upload_media = AsyncMock(return_value=mock_upload_details)
       
    test_jid = "recipient_doc@s.whatsapp.net"
    mock_doc_path = "/fake/path/to/document.pdf"
    # test_doc_title = "My Important Document" # Title is often derived from file_name or set explicitly in proto
    test_file_name = "Report.pdf" 
    # test_page_count = 10 # Page count might be set by client if it inspects PDF; not directly taken by send_document
    test_caption = "Check this PDF"


    with patch('os.path.isfile', return_value=True), \
         patch('os.path.getsize', return_value=56789), \
         patch('mimetypes.guess_type', return_value=("application/pdf", None)):
        
        if hasattr(client, '_generate_thumbnail'): # Documents typically don't have thumbnails in WA msgs
            client._generate_thumbnail = MagicMock(return_value=None) 

        message_id = await client.send_document(
            to=test_jid,
            file_path=mock_doc_path,
            caption=test_caption, 
            file_name=test_file_name
        )
        
    assert message_id.startswith("TEST_DEVICE_ID_DOC") # Corrected prefix based on device_id
    client._message_queue.put.assert_awaited_once()
    args, _ = client._message_queue.put.call_args
    _, protocol_node_to_send, _ = args[0]

    assert isinstance(protocol_node_to_send, ProtocolNode)
    assert protocol_node_to_send.attrs["to"] == test_jid
    # Client.send_document calls send_media with message_type='document'
    # _send_message_node (called by send_media) sets attrs['type'] to this message_type
    assert protocol_node_to_send.attrs["type"] == "document" 

    assert isinstance(protocol_node_to_send.content, bytes)
    parsed_outer_proto = WAWebProtobufsE2E_pb2.Message()
    parsed_outer_proto.ParseFromString(protocol_node_to_send.content)

    assert parsed_outer_proto.HasField('document_message')
    doc_msg_proto = parsed_outer_proto.document_message
    assert doc_msg_proto.url == mock_upload_details["url"]
    assert doc_msg_proto.mimetype == mock_upload_details["mimetype"]
    # Title in DocumentMessage is often set to the file_name by clients if not explicitly provided otherwise
    assert doc_msg_proto.title == test_file_name 
    assert doc_msg_proto.file_sha256 == mock_upload_details["file_sha256"]
    assert doc_msg_proto.file_length == mock_upload_details["file_length"]
    assert doc_msg_proto.media_key == mock_upload_details["media_key"]
    assert doc_msg_proto.file_name == test_file_name
    # page_count might not be set by send_document unless it inspects the PDF.
    # assert doc_msg_proto.page_count == test_page_count 
    assert doc_msg_proto.caption == test_caption # Caption is a field in DocumentMessage

@pytest.mark.asyncio
async def test_receive_document_message_protobuf():
    client = Client()
    client._auth_state = MagicMock()
    client._auth_state.me = "user_self_jid@s.whatsapp.net"
    mock_event_handler = AsyncMock()
    client.on('message')(mock_event_handler)

    inner_proto_msg = WAWebProtobufsE2E_pb2.Message()
    doc_msg = inner_proto_msg.document_message
    doc_msg.url = "https://mmg.whatsapp.net/mms/doc_received_url"
    doc_msg.mimetype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    doc_msg.title = "Received Report.docx" # Often same as file_name
    doc_msg.file_sha256 = b"rcv_doc_sha256"
    doc_msg.file_length = 67891
    doc_msg.media_key = b"rcv_doc_media_key"
    doc_msg.file_name = "Received Report.docx"
    doc_msg.page_count = 5
    doc_msg.caption = "Important document"
    # Example: doc_msg.jpeg_thumbnail = b"optional_doc_thumbnail_bytes" (if supported)

    server_msg_id = "server_doc_msg_abc"
    sender_jid = "sender_doc@s.whatsapp.net"
    msg_timestamp = int(datetime.now().timestamp())

    inner_proto_msg.key.id = server_msg_id
    inner_proto_msg.key.remote_jid = sender_jid
    inner_proto_msg.key.from_me = False
    inner_proto_msg.message_timestamp = msg_timestamp
       
    serialized_inner_proto_content_with_key = inner_proto_msg.SerializeToString()

    simulated_ws_input_to_client = {
        "type": "binary_payload",
        "flags": 0,
        "tag": server_msg_id,
        "payload": serialized_inner_proto_content_with_key 
    }
       
    await client._handle_ws_message(simulated_ws_input_to_client)

    mock_event_handler.assert_awaited_once()
    args, _ = mock_event_handler.call_args
    dispatched_msg = args[0]
       
    assert isinstance(dispatched_msg, WAWebProtobufsE2E_pb2.Message)
    assert dispatched_msg.key.id == server_msg_id
    assert dispatched_msg.key.remote_jid == sender_jid
    assert dispatched_msg.message_timestamp == msg_timestamp
       
    assert dispatched_msg.HasField('document_message')
    rcv_doc_msg = dispatched_msg.document_message
    assert rcv_doc_msg.url == "https://mmg.whatsapp.net/mms/doc_received_url"
    assert rcv_doc_msg.mimetype == "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    assert rcv_doc_msg.title == "Received Report.docx"
    assert rcv_doc_msg.file_name == "Received Report.docx"
    assert rcv_doc_msg.page_count == 5
    assert rcv_doc_msg.caption == "Important document"
    assert rcv_doc_msg.file_length == 67891
    assert rcv_doc_msg.file_sha256 == b"rcv_doc_sha256"
    assert rcv_doc_msg.media_key == b"rcv_doc_media_key"
