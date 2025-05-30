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
from typing import Any

from pymeow import Client
from pymeow.store.sqlstore import SQLStore
from pymeow.types.events.message import Message
from pymeow.types.events.qr import QR
from pymeow.types.events.connection import Connected, Disconnected


def setup_logging() -> logging.Logger:
    """Set up logging for the client."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(sys.stdout),
            logging.FileHandler('whatsapp_client.log')
        ]
    )
    return logging.getLogger("PyMeow")


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
        print(f"Received event: {type(event).__name__}")


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
    client_log = setup_logging()
    db_log = logging.getLogger("Database")

    try:
        # Create database store
        # NOTE: You may need to adjust the database URL for your setup
        store = SQLStore(
            db_url="sqlite:///whatsapp_session.db",
            logger=db_log
        )
        await store.initialize()

        # Get or create device store
        device_store = await store.get_first_device()
        if device_store is None:
            print("Creating new device...")
            device_store = await store.create_device()

        # Create WhatsApp client
        client = Client(device_store, client_log)

        # Add event handler
        client.add_event_handler(event_handler)

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
            qr_channel = client.get_qr_channel()

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
        client_log.exception("Unhandled exception in main")

    finally:
        # Graceful shutdown
        print("Shutting down client...")
        try:
            if 'client' in locals():
                await client.disconnect()
            if 'store' in locals():
                await store.close()
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
