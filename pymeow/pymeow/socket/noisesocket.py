"""
Noise protocol socket implementation for WhatsApp Web.

Port of whatsmeow/socket/noisesocket.go
"""
import asyncio
import contextlib
import logging
import struct
from typing import TYPE_CHECKING, Awaitable, Callable

# TODO: Verify import when cipher is ported
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

if TYPE_CHECKING:
    from .framesocket import FrameSocket

logger = logging.getLogger(__name__)

class NoiseSocket:
    """
    Implements a secure socket using the Noise Protocol for WhatsApp Web.

    This class wraps a FrameSocket and provides encryption/decryption for WebSocket frames
    using AEAD ciphers.
    """

    def __init__(self, fs: 'FrameSocket', write_key: AESGCM, read_key: AESGCM,
                 on_frame: Callable[[bytes], None]):
        """
        Initialize a new NoiseSocket.

        Args:
            fs: The underlying FrameSocket
            write_key: The AEAD cipher for encrypting outgoing messages
            read_key: The AEAD cipher for decrypting incoming messages
            on_frame: Callback for handling decrypted frames
        """
        self.fs = fs
        self.write_key = write_key
        self.read_key = read_key
        self.on_frame = on_frame
        self.write_counter = 0
        self.read_counter = 0
        self.write_lock = asyncio.Lock()
        self.destroyed = False
        self.stop_consumer = asyncio.Event()

        # Start the frame consumer task
        self.consumer_task = asyncio.create_task(self._consume_frames())

    async def _consume_frames(self) -> None:
        """
        Consume frames from the underlying FrameSocket.

        This is the equivalent of the Go consumeFrames goroutine.
        """
        try:
            while not self.stop_consumer.is_set():
                # Create tasks explicitly for the coroutines
                frame_task = asyncio.create_task(self.fs.frames.get())
                stop_task = asyncio.create_task(self.stop_consumer.wait())

                # Wait for either a frame or cancellation
                done, pending = await asyncio.wait(
                    [frame_task, stop_task],
                    return_when=asyncio.FIRST_COMPLETED
                )

                # Cancel any pending tasks to avoid warnings
                for task in pending:
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

                # Process completed tasks
                for task in done:
                    if task.exception() is None and not self.stop_consumer.is_set():
                        # Check which task completed
                        if task is frame_task:
                            # If we got a frame and we're not stopping, process it
                            frame = task.result()
                            if isinstance(frame, bytes):
                                await self._receive_encrypted_frame(frame)
                        # If stop_task completed, the loop will exit naturally
                        break
        except asyncio.CancelledError:
            # Task was cancelled, clean up
            pass
        except Exception as e:
            # Log error but don't crash
            print(f"Error in frame consumer: {e}")

    @staticmethod
    def _generate_iv(count: int) -> bytes:
        """
        Generate an initialization vector for AEAD encryption/decryption.

        Args:
            count: The message counter

        Returns:
            A 12-byte IV with the counter in the last 4 bytes
        """
        iv = bytearray(12)
        struct.pack_into('>I', iv, 8, count)
        return bytes(iv)

    async def stop(self, disconnect: bool = True) -> None:
        """
        Stop the NoiseSocket.

        Args:
            disconnect: Whether to also close the underlying connection
        """
        if not self.destroyed:
            self.destroyed = True
            self.stop_consumer.set()

            # Cancel the consumer task
            self.consumer_task.cancel()
            async with contextlib.suppress(asyncio.CancelledError):
                await self.consumer_task

            # Clear the disconnect handler
            self.fs.on_disconnect = None

            if disconnect:
                await self.fs.close()

    async def send_frame(self, plaintext: bytes) -> None:
        """
        Encrypt and send a frame.

        Args:
            plaintext: The plaintext data to send

        Raises:
            ConnectionError: If the socket is closed or encryption fails
        """
        async with self.write_lock:
            iv = self._generate_iv(self.write_counter)
            ciphertext = self.write_key.encrypt(iv, plaintext, None)
            self.write_counter += 1
            await self.fs.send_frame(ciphertext)

    async def _receive_encrypted_frame(self, ciphertext: bytes) -> None:
        """
        Decrypt and process a received frame.

        Args:
            ciphertext: The encrypted frame data
        """
        count = self.read_counter
        self.read_counter += 1

        try:
            iv = self._generate_iv(count)
            plaintext = self.read_key.decrypt(iv, ciphertext, None)

            # Handle both sync and async callbacks
            if asyncio.iscoroutinefunction(self.on_frame):
                await self.on_frame(plaintext)
            else:
                self.on_frame(plaintext)
        except Exception as e:
            # Log error but don't crash
            logger.error(f"Failed to decrypt frame: {e}")

    def is_connected(self) -> bool:
        """
        Check if the socket is connected.

        Returns:
            True if the socket is connected, False otherwise
        """
        return self.fs.is_connected()


async def new_noise_socket(fs: 'FrameSocket', write_key: AESGCM, read_key: AESGCM,
                          frame_handler: Callable[[bytes], Awaitable[None]],
                          disconnect_handler: Callable[["NoiseSocket", bool], Awaitable[None]]) -> NoiseSocket:
    """
    Create a new NoiseSocket.

    Args:
        fs: The underlying FrameSocket
        write_key: The AEAD cipher for encrypting outgoing messages
        read_key: The AEAD cipher for decrypting incoming messages
        frame_handler: Callback for handling decrypted frames
        disconnect_handler: Callback for handling disconnections

    Returns:
        A new NoiseSocket instance
    """
    ns = NoiseSocket(fs, write_key, read_key, frame_handler)

    # Set up disconnect handler on the FrameSocket
    async def on_disconnect(remote: bool) -> None:
        await disconnect_handler(ns, remote)

    fs.on_disconnect = on_disconnect

    return ns
