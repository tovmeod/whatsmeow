# PyMeow Socket Tests

This directory contains tests for the PyMeow socket implementation, which is a port of the WhatsApp Web socket implementation from Go to Python.

## Test Files

### 1. test_noisesocket.py

Tests for the NoiseSocket implementation, which provides secure communication using the Noise Protocol Framework.

**Coverage:**
- Initialization in legacy mode (used by FrameSocket)
- Initialization in direct mode
- The generate_iv static method
- The encrypt_frame and decrypt_frame methods for legacy mode
- The send_frame method for direct mode
- The _receive_encrypted_frame method for direct mode
- The is_connected method
- The stop method
- The new_noise_socket function

### 2. test_framesocket.py

Tests for the FrameSocket implementation, which provides WebSocket framing and integration with NoiseSocket.

**Coverage:**
- Initialization of FrameSocket
- Connecting to a WebSocket server
- Sending frames through the WebSocket
- Receiving frames through the WebSocket
- Setting the frame handler
- Closing the WebSocket connection
- Integration with NoiseSocket in legacy mode

### 3. test_constants.py

Tests for the socket constants implementation, which ensures that the Python implementation uses the same constants as the Go implementation.

**Coverage:**
- All constants defined in the socket/constants.py file

## Testing Approach

The tests use pytest with the asyncio plugin to test asynchronous functions. They make extensive use of mocking with unittest.mock.MagicMock and AsyncMock to isolate the tests from external dependencies.

The tests ensure that the Python implementation has the same behavior as the equivalent Go code by:

1. **Verifying Function Signatures**: Ensuring that the Python functions have the same parameters and return types as their Go counterparts.
2. **Testing Core Functionality**: Testing that the core functionality of each method works as expected.
3. **Testing Edge Cases**: Testing edge cases and error handling to ensure robust behavior.
4. **Testing Integration**: Testing the integration between different components to ensure they work together correctly.
5. **Verifying Constants**: Ensuring that all constants have the same values as in the Go implementation.

## Running the Tests

To run the tests, use the following command from the project root:

```bash
pytest pymeow/tests/
```

To run a specific test file:

```bash
pytest pymeow/tests/test_noisesocket.py
```

To run a specific test function:

```bash
pytest pymeow/tests/test_noisesocket.py::test_generate_iv
```

## Test Results

All tests should pass, indicating that the Python implementation has the same behavior as the equivalent Go code.
