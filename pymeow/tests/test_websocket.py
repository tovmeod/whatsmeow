# pymeow/tests/test_websocket.py
import unittest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
import os # For random key generation

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import aiohttp # To mock websocket response and session

# Assuming WebSocketClient is in pymeow.pymeow.websocket
from pymeow.pymeow.websocket import WebSocketClient, ConnectionError 
# ConnectionError for testing error handling

class TestWebSocketAESGCM(unittest.TestCase):

    def setUp(self):
        # Create a dummy client object for WebSocketClient initialization
        self.mock_parent_client = MagicMock()
        # Mock logger directly on the WebSocketClient instance if it's used there
        # For this test, we'll mock the logger where it's called in websocket.py via @patch
        # However, if ws_client.logger is accessed, it needs to exist.
        self.mock_parent_client.logger = MagicMock() 


        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        
        # Mock aiohttp ClientSession and ws_connect
        self.mock_aiohttp_session = MagicMock(spec=aiohttp.ClientSession)
        self.mock_ws_response = AsyncMock(spec=aiohttp.ClientWebSocketResponse)
        self.mock_ws_response.closed = False # Simulate open connection initially
        # Make ws_connect an async mock if it's awaited
        self.mock_aiohttp_session.ws_connect = AsyncMock(return_value=self.mock_ws_response)


        self.ws_client = WebSocketClient(
            client=self.mock_parent_client,
            on_message=AsyncMock(),
            on_disconnect=AsyncMock(),
            session=self.mock_aiohttp_session 
        )
        # Directly set is_connected for tests, connect() is complex to unit test here
        self.ws_client._is_connected = True 
        self.ws_client.ws = self.mock_ws_response
        
        # Mock logger on the instance if it's used like self.logger
        # If logger is used as `websocket.logger` (module level), then patch 'pymeow.pymeow.websocket.logger'
        # Based on previous files, it seems like `logger` is module-level.
        # For methods that use self.client.logger (if any in WebSocketClient), self.mock_parent_client.logger covers it.


    def tearDown(self):
        self.loop.close()

    @patch('pymeow.pymeow.websocket.logger') # Patching module-level logger
    def test_set_aesgcm_ciphers(self, mock_logger_websocket):
        key1 = AESGCM.generate_key(bit_length=256)
        key2 = AESGCM.generate_key(bit_length=256)
        send_cipher = AESGCM(key1)
        recv_cipher = AESGCM(key2)

        self.ws_client.set_aesgcm_ciphers(send_cipher, recv_cipher)

        self.assertIs(self.ws_client.send_cipher_aesgcm, send_cipher)
        self.assertIs(self.ws_client.recv_cipher_aesgcm, recv_cipher)
        self.assertEqual(self.ws_client.send_nonce_aesgcm, 0)
        self.assertEqual(self.ws_client.recv_nonce_aesgcm, 0) # As per current implementation
        mock_logger_websocket.info.assert_called_with("AESGCM transport ciphers set in WebSocketClient.")


    def test_send_binary_encrypted_and_decrypted_loopback(self):
        # Test encryption and decryption in a loopback manner
        # This doesn't test against known vectors but ensures the implementation is self-consistent.
        
        key_bytes = AESGCM.generate_key(bit_length=256)
        send_cipher = AESGCM(key_bytes)
        recv_cipher = AESGCM(key_bytes) # Use same key for loopback decryption
        
        self.ws_client.set_aesgcm_ciphers(send_cipher, recv_cipher)

        original_data = b"test payload for AESGCM"
        
        # --- Simulate send_binary encryption part ---
        send_nonce_val = self.ws_client.send_nonce_aesgcm
        nonce_bytes = send_nonce_val.to_bytes(12, 'big')
        encrypted_payload = self.ws_client.send_cipher_aesgcm.encrypt(nonce_bytes, original_data, None)
        frame_sent = nonce_bytes + encrypted_payload
        # self.ws_client.send_nonce_aesgcm += 1 # This is done by the actual send_binary method

        # Mock the actual send_bytes on the ws connection
        self.mock_ws_response.send_bytes = AsyncMock()
        # Call the method under test
        self.loop.run_until_complete(self.ws_client.send_binary(original_data))
        # Assert that ws.send_bytes was called with the encrypted frame
        self.mock_ws_response.send_bytes.assert_awaited_once_with(frame_sent)


        # --- Simulate _handle_binary_message decryption part ---
        # Assume frame_sent is what's received by _handle_binary_message
        # The _handle_binary_message itself will call self.on_message with the WA parsed payload
        # So we need to mock self.on_message to capture the decrypted and parsed data
        mock_on_message_handler = AsyncMock()
        self.ws_client.on_message = mock_on_message_handler
        
        # Call _handle_binary_message with the encrypted frame
        self.loop.run_until_complete(self.ws_client._handle_binary_message(frame_sent))
        
        mock_on_message_handler.assert_awaited_once()
        args, _ = mock_on_message_handler.call_args
        received_message_dict = args[0]
        
        # Check the structure of the message passed to on_message
        self.assertEqual(received_message_dict["type"], "binary_payload")
        # The payload here should be the original_data after decryption and WA binary parsing
        # The current websocket._handle_binary_message parses flags, length, tag, and payload
        # For this test, the actual_payload after WA parsing should be original_data
        # This assumes the WA binary frame is just the raw original_data for simplicity in this test.
        # A more accurate test would construct a full WA binary frame.
        # Given the current _handle_binary_message, it expects specific WA frame structure.
        # Let's re-simulate frame_sent to *be* the WA frame that gets encrypted.
        
        # Re-do the simulation for send and receive for loopback
        self.ws_client.send_nonce_aesgcm = 0 # Reset nonce for this part of test
        
        # Construct a simple WA frame: flags=0, length=len(original_data), tag=dummy, payload=original_data
        wa_flags = 0x00
        wa_msg_tag_bytes = b'\x00\x00\x00\x00' # Dummy tag
        wa_payload = original_data
        wa_msg_length_bytes = len(wa_payload).to_bytes(3, 'big')
        
        unencrypted_wa_frame = bytes([wa_flags]) + wa_msg_length_bytes + wa_msg_tag_bytes + wa_payload

        # Simulate sending this WA frame (it gets encrypted)
        send_nonce_val_2 = self.ws_client.send_nonce_aesgcm
        nonce_bytes_2 = send_nonce_val_2.to_bytes(12, 'big')
        encrypted_wa_frame_payload = self.ws_client.send_cipher_aesgcm.encrypt(nonce_bytes_2, unencrypted_wa_frame, None)
        encrypted_frame_to_ws = nonce_bytes_2 + encrypted_wa_frame_payload
        self.ws_client.send_nonce_aesgcm += 1
        
        # Call _handle_binary_message with this encrypted_frame_to_ws
        self.loop.run_until_complete(self.ws_client._handle_binary_message(encrypted_frame_to_ws))
        
        mock_on_message_handler.assert_awaited_once()
        args, _ = mock_on_message_handler.call_args
        received_message_dict = args[0]

        self.assertEqual(received_message_dict["type"], "binary_payload")
        self.assertEqual(received_message_dict["flags"], wa_flags)
        self.assertEqual(received_message_dict["tag"], wa_msg_tag_bytes.hex())
        self.assertEqual(received_message_dict["payload"], wa_payload) # This is original_data

        self.assertEqual(self.ws_client.send_nonce_aesgcm, 1) # Check nonce increment

    def test_send_binary_no_cipher(self):
        # Test sending when no cipher is set (should send plaintext)
        self.ws_client.send_cipher_aesgcm = None # Ensure no cipher
        original_data = b"plaintext data"
        
        self.mock_ws_response.send_bytes = AsyncMock()
        self.loop.run_until_complete(self.ws_client.send_binary(original_data))
        
        # Verify that raw data was sent
        self.mock_ws_response.send_bytes.assert_awaited_once_with(original_data)

    @patch('pymeow.pymeow.websocket.logger') # Mock logger inside the method
    def test_handle_binary_message_decryption_failure(self, mock_logger_websocket):
        key_bytes = AESGCM.generate_key(bit_length=256)
        # Intentionally use a DIFFERENT key for recv_cipher to cause decryption error
        wrong_key_bytes = AESGCM.generate_key(bit_length=256) 
        send_cipher = AESGCM(key_bytes)
        recv_cipher = AESGCM(wrong_key_bytes)
        
        self.ws_client.set_aesgcm_ciphers(send_cipher, recv_cipher)
        self.ws_client.on_disconnect = AsyncMock() # Mock on_disconnect

        # Create a validly encrypted frame (nonce + ciphertext)
        # Nonce for send_cipher (which is different from recv_cipher)
        nonce = self.ws_client.send_nonce_aesgcm.to_bytes(12, 'big') 
        encrypted_payload = send_cipher.encrypt(nonce, b"some data", None)
        valid_frame_encrypted_with_send_key = nonce + encrypted_payload
        
        # This call should fail decryption because recv_cipher uses wrong_key_bytes
        self.loop.run_until_complete(self.ws_client._handle_binary_message(valid_frame_encrypted_with_send_key))
        
        mock_logger_websocket.error.assert_called() # Check that an error was logged
        self.ws_client.on_disconnect.assert_awaited_once() # Check disconnect was triggered

    @patch('pymeow.pymeow.websocket.logger') # Mock logger inside the method
    def test_handle_binary_message_frame_too_short(self, mock_logger_websocket):
        key_bytes = AESGCM.generate_key(bit_length=256)
        recv_cipher = AESGCM(key_bytes)
        self.ws_client.set_aesgcm_ciphers(AESGCM(key_bytes), recv_cipher) # send cipher doesn't matter here

        short_frame = b"short" # Less than 12 bytes for nonce
        
        # Mock the on_message callback to see if it's NOT called
        self.ws_client.on_message = AsyncMock()
        
        self.loop.run_until_complete(self.ws_client._handle_binary_message(short_frame))
        self.ws_client.on_message.assert_not_called()
        mock_logger_websocket.warning.assert_called_with(f"AESGCM: Received frame too short to contain nonce and tag: {len(short_frame)} bytes")


if __name__ == '__main__':
    unittest.main()
