#!/usr/bin/env python3
"""
PyMeow Client Test Example

Python port of whatsmeow/client_test.go
Demonstrates basic client usage, authentication, and event handling.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from pymeow import Client
from pymeow.qrchan import get_qr_channel
from pymeow.store.sqlstore import Container, SQLStore
from pymeow.types.events import Message
from pymeow.types.events import QR
from pymeow.types.events import Connected, Disconnected

logger = logging.getLogger(__name__)

class ColoredFormatter(logging.Formatter):
    """
    A custom formatter that adds colors to the terminal output based on the log level.
    """
    COLORS = {
        'DEBUG': '\033[94m',  # Blue
        'INFO': '\033[92m',   # Green
        'WARNING': '\033[93m', # Yellow
        'ERROR': '\033[91m',   # Red
        'CRITICAL': '\033[91m\033[1m',  # Bold Red
    }
    RESET = '\033[0m'  # Reset color

    def format(self, record):
        log_message = super().format(record)
        color = self.COLORS.get(record.levelname, self.RESET)
        return f"{color}{log_message}{self.RESET}"

APP_ROOT = Path(__file__).resolve().parent

class ShortPathFormatter(ColoredFormatter):
    """
    A custom formatter that replaces {pathname} with {shortpathname} by trimming
    everything before the project root.
    """
    def format(self, record):
        # Add shortpathname attribute to the record
        if hasattr(record, 'pathname'):
            try:
                # Convert pathname to a Path object
                path = Path(record.pathname)
                # Get the relative path from the project root
                rel_path = path.relative_to(APP_ROOT)
                # Store it as shortpathname
                record.shortpathname = str(rel_path)
            except (ValueError, AttributeError):
                # If the path is not relative to APP_ROOT, use the original pathname
                record.shortpathname = record.pathname

        return super().format(record)
def setup_logging() -> logging.Logger:
    """Set up logging for the client."""
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_formatter = ShortPathFormatter(
        '{levelname} {asctime} {name} {module} {message} ({shortpathname}:{lineno})',
        style='{'
    )
    console_handler.setFormatter(console_formatter)

    # Create file handler with plain formatter (no colors in file)
    file_handler = logging.FileHandler('whatsapp_client.log')
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter(
        '{levelname} {asctime} {name} {module} {message} ({pathname}:{lineno})',
        style='{'
    )
    file_handler.setFormatter(file_formatter)

    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


async def event_handler(event: Any) -> None:
    """
    Handle events from the WhatsApp client.

    Args:
        event: The event object received from WhatsApp
    """
    if isinstance(event, Message):
        # Handle incoming messages
        message_text = event.message.get_conversation() or "No text content"
        print(f"Received a message: {message_text}")
        print(f"From: {event.info.message_source.sender}")
        print(f"Chat: {event.info.message_source.chat}")

    elif isinstance(event, QR):
        # Handle QR code events for authentication
        if event.codes:
            print("QR Codes for pairing:")
            for i, code in enumerate(event.codes):
                print(f"QR {i+1}: {code}")
                # You can render these QR codes using a library like qrcode:
                # import qrcode
                # qr = qrcode.QRCode()
                # qr.add_data(code)
                # qr.make()
                # qr.print_ascii()

    elif isinstance(event, Connected):
        print("✅ Successfully connected to WhatsApp!")

    elif isinstance(event, Disconnected):
        print("❌ Disconnected from WhatsApp")

    else:
        logger.debug(f"client_test event handler ignoring Received event: {type(event).__name__}")


async def main():
    """
    Main example function demonstrating PyMeow client usage.

    This example shows:
    1. Setting up logging
    2. Creating a device store
    3. Initializing the client
    4. Handling authentication (QR code or existing session)
    5. Event handling
    6. Graceful shutdown
    """
    print("PyMeow WhatsApp Client Example")
    print("=" * 40)

    # Set up logging
    setup_logging()
    logger = logging.getLogger(__name__)

    container = None
    client = None
    try:
        # Create data directory if it doesn't exist
        data_dir = Path.home() / ".pymeow"
        data_dir.mkdir(exist_ok=True)

        # Create database path
        db_path = data_dir / "whatsapp_session.db"
        db_url = f"sqlite:///{db_path}"

        print(f"Using database: {db_path}")

        # Create database container
        container = Container(db_url)
        await container.initialize()

        # Create database store with a test JID
        # In a real application, you'd use the actual user's JID
        test_jid = "test@example.com"
        store = SQLStore(container, test_jid)

        # Get or create device store
        device_store = await container.get_first_device()
        if device_store is None:
            print("Creating new device...")
            device_store = await container.new_device(test_jid)

        # Create WhatsApp client
        client = Client(device_store)

        # Add event handler
        await client.add_event_handler(event_handler)

        # Set up signal handling for graceful shutdown
        shutdown_event = asyncio.Event()

        def signal_handler(sig, frame):
            print("\nReceived interrupt signal, shutting down...")
            shutdown_event.set()

        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Check if already logged in
        if device_store.id is None:
            print("No existing session found, starting new login...")

            # Get QR channel for authentication
            qr_channel = await get_qr_channel(client)

            # Connect to WhatsApp
            await client.connect()

            print("Waiting for QR code scan...")
            print("Please scan the QR code with your WhatsApp mobile app:")

            # Wait for QR events or successful authentication
            async for qr_event in qr_channel:
                if qr_event.event == "code":
                    # Display QR codes
                    print(f"\nQR Code: {qr_event.code}")
                    print("Scan this QR code with WhatsApp on your phone")
                    # You could also render this as an actual QR code image

                elif qr_event.event == "success":
                    print("✅ Successfully authenticated!")
                    break

                elif qr_event.event == "timeout":
                    print("❌ QR code timed out, please restart")
                    return

                else:
                    print(f"QR Event: {qr_event.event}")

        else:
            print("Existing session found, connecting...")
            # Already logged in, just connect
            await client.connect()

            # Wait a moment for connection to establish
            await asyncio.sleep(2)

            if client.is_connected():
                print("✅ Successfully connected with existing session!")
            else:
                print("❌ Failed to connect with existing session")
                return

        print("\nClient is now running. Press Ctrl+C to stop.")
        print("Send messages to your WhatsApp to see them appear here.")

        # Keep the client running until interrupted
        try:
            await shutdown_event.wait()
        except KeyboardInterrupt:
            pass

    except Exception as e:
        print(f"❌ Error: {e}")
        logger.exception("Unhandled exception in main")

    finally:
        # Graceful shutdown
        print("Shutting down client...")
        try:
            if client:
                await client.disconnect()
            if container:
                await container.close()
        except Exception as e:
            print(f"Error during shutdown: {e}")

        print("Goodbye!")


if __name__ == "__main__":
    """
    Entry point for the client test example.

    Usage:
        python client_test.py

    The script will:
    1. Try to connect with an existing session
    2. If no session exists, display QR codes for pairing
    3. Handle incoming messages and events
    4. Run until Ctrl+C is pressed
    """
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nProgram interrupted by user")
    # except Exception as e:
    #     print(f"Fatal error: {e}")
    #     sys.exit(1)
