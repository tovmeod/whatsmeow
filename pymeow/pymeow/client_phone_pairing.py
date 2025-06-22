#!/usr/bin/env python3
"""
PyMeow Client Phone Pairing Example

This script demonstrates how to use the PyMeow library to pair with WhatsApp
using a phone number and a code, instead of scanning a QR code.

Process:
1. The script initializes the WhatsApp client.
2. If no existing session is found, it prompts the user for their full phone number.
3. It calls the `pair_phone` function to request a pairing code from WhatsApp servers.
   - This requires an initial, unauthenticated connection to WhatsApp.
4. A short code (e.g., "ABCD-EFGHJ") is displayed to the user.
5. The user must then go to their primary WhatsApp device (phone) -> Linked Devices -> Link with phone number,
   and enter this code.
6. Once the code is entered on the primary device, WhatsApp servers communicate with this script
   to complete the pairing process in the background.
7. Successful pairing is typically indicated by `LoggedIn` and `PairSuccess` events.
8. After pairing, the session is stored, and subsequent runs should connect automatically.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Any

from client_test import setup_logging
from pymeow.client import Client
from pymeow.datatypes.events import Connected, Disconnected, Message, PairError, PairSuccess

# Make sure pair_phone and PairClientType are correctly imported
from pymeow.pair_code import PairClientType, pair_phone
from pymeow.store.sqlstore.container import Container

# Basic logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(name)s - %(message)s")
logger = logging.getLogger(__name__)

APP_ROOT = Path(__file__).resolve().parent  # Used for potential relative path calculations if needed


async def event_handler(event: Any) -> None:
    """
    Handle events from the WhatsApp client.
    This is a generic handler; you can create more specific handlers for different event types.
    """
    if isinstance(event, Message) and event.message:
        # Attempt to get message content, prioritizing conversation then extended_text
        message_text = ""
        if event.message.conversation:
            message_text = event.message.conversation
        elif event.message.extendedTextMessage and event.message.extendedTextMessage.text:
            message_text = event.message.extendedTextMessage.text
        else:
            message_text = "No text content (possibly media or other type)"
        logger.info(f"Received a message: '{message_text}' from {event.info.message_source.sender}")
    elif isinstance(event, Connected):
        logger.info("✅ Successfully connected to WhatsApp (and is authenticated).")
    elif isinstance(event, PairSuccess):
        logger.info(
            f"📱 Device successfully paired: JID {event.id}, LID {event.lid}, Platform: {event.platform}, Business Name: '{event.business_name}'"
        )
    elif isinstance(event, PairError):
        logger.error(f"❌ Pairing failed: {event.error}")
    elif isinstance(event, Disconnected):
        logger.warning("❌ Disconnected from WhatsApp.")
    else:
        # Log other events at debug level if not specifically handled
        logger.debug(f"Received event: {type(event).__name__}")


async def main() -> None:
    """
    Main example function demonstrating PyMeow client phone pairing.
    """
    logger.info("PyMeow WhatsApp Client Phone Pairing Example")
    logger.info("=" * 40)
    setup_logging()

    container = None
    client = None
    shutdown_event = asyncio.Event()

    # Setup signal handlers for graceful shutdown
    def signal_handler_fn(sig: int, frame: Any) -> None:
        logger.info(f"Signal {sig} received, initiating shutdown...")
        shutdown_event.set()

    signal.signal(signal.SIGINT, signal_handler_fn)
    signal.signal(signal.SIGTERM, signal_handler_fn)

    try:
        # Setup database for storing device session information
        # Using a different directory to avoid conflicts with client_test.py's store
        data_dir = Path.home() / ".pymeow"
        data_dir.mkdir(exist_ok=True)
        db_path = data_dir / "device.db"
        db_url = f"sqlite:///{db_path}"
        logger.info(f"Using database for session storage: {db_path}")

        container = await Container(db_url).ainit()
        device_store = await container.get_first_device()

        if device_store and device_store.id:
            logger.info(f"Existing session found for JID: {device_store.id}. Attempting to connect...")
            client = await Client(device_store).ainit()
        else:
            logger.info("No existing session found. Starting new device pairing process.")
            if device_store is None:
                # A device_store entry is needed. The JID is a placeholder and will be updated on successful pairing.
                device_store = await container.new_device("placeholder.phone@example.com")

            client = await Client(device_store).ainit()

            # Step 1: Connect to WhatsApp (establishes WebSocket and Noise handshake)
            # This is necessary before pairing functions that send IQ stanzas can be called.
            logger.info("Connecting to WhatsApp for pairing...")
            await client.connect()
            if not client.is_connected():
                logger.error("Failed to connect to WhatsApp. Cannot proceed with pairing.")
                return

            # Step 2: Request pairing code
            phone_number_input = input("Enter your full international phone number (e.g., +1234567890): ").strip()
            if not phone_number_input:
                logger.error("Phone number cannot be empty.")
                return

            try:
                logger.info("Requesting pairing code from WhatsApp...")
                # client_type helps WhatsApp identify the type of companion device.
                # client_display_name is shown in the "Linked Devices" section of your WhatsApp app.
                pairing_code = await pair_phone(
                    client=client,
                    phone=phone_number_input,
                    show_push_notification=True,  # Shows a notification on the primary device
                    client_type=PairClientType.CHROME,
                    client_display_name="PyMeow Phone Example",
                )
                logger.info(f"PAIRING CODE: {pairing_code}")
                logger.info("Go to WhatsApp on your phone -> Settings -> Linked Devices -> Link with phone number.")
                logger.info("Enter the above code on your primary WhatsApp device when prompted.")
                logger.info("Waiting for pairing to complete on your phone... (This may take a minute or two)")
                # The script will now wait. Once the code is entered on the phone,
                # the server will send messages to this client to complete the pairing.
                # Success will be indicated by LoggedIn and PairSuccess events.
            except Exception as e:
                logger.error(f"Failed to initiate phone pairing: {e}", exc_info=True)
                return

        # Register the event handler to process incoming events
        client.add_event_handler(event_handler)

        # Step 3: Ensure connection and wait for events or shutdown signal
        # If it's a new pairing, the client is already connected from the pairing step.
        # If it's an existing session, client.connect() handles reconnection.
        if not client.is_connected():
            logger.info("Attempting to connect client...")
            await client.connect()

        if client.is_connected():
            if client.is_logged_in():
                logger.info("Client is connected and logged in.")
                # Example: Send a message to yourself after successful login with existing session
                # own_jid = client.get_own_id()
                # if own_jid and own_jid.user:
                #    from pymeow.send import send_message
                #    from pymeow.generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
                #    logger.info(f"Sending a test message to self ({own_jid.to_string(full=True)})")
                #    await send_message(client, own_jid.to_non_ad(), waE2E_pb2.Message(conversation="Hello from PyMeow (Phone Pairing Example)!"))
            else:
                logger.info(
                    "Client is connected, but not yet logged in. Waiting for pairing confirmation or login events."
                )
        else:
            logger.error("Failed to connect to WhatsApp.")
            # If new pairing failed to complete and connect didn't make it logged_in, exit.
            if not (device_store and device_store.id):  # Check if it was a new pairing attempt
                return

        logger.info("Client is running. Press Ctrl+C to stop.")
        await shutdown_event.wait()  # Keep running until shutdown signal

    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"An unexpected error occurred in main: {e}", exc_info=True)
    finally:
        logger.info("Initiating client shutdown sequence...")
        if client and client.is_connected():
            logger.info("Disconnecting client...")
            await client.disconnect()
        if container:
            logger.info("Closing database container...")
            await container.close()
        logger.info("Shutdown complete. Goodbye!")


if __name__ == "__main__":
    """
    Entry point for the PyMeow Phone Pairing Example.

    To run this example:
    1. Ensure you have PyMeow and its dependencies installed.
    2. Execute this script: `python phone_pairing_example.py`
    3. When prompted, enter your full international WhatsApp phone number (e.g., +1234567890).
    4. The script will display a short code (e.g., ABCD-EFGHJ).
    5. On your primary WhatsApp mobile device, go to:
       - Settings (or three dots menu)
       - Linked Devices
       - Link a device
       - Choose "Link with phone number instead" (or similar option)
       - Enter the code displayed by the script.
    6. The script should then complete the pairing and log in.
       You'll see log messages indicating connection and login status.
    7. To stop the script, press Ctrl+C.
    """
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        # This handles Ctrl+C if it happens before asyncio.run() or during its very early setup
        logger.info("Program interrupted by user (Ctrl+C).")
    except Exception as e:
        # Catch-all for any other unexpected errors during script execution
        logger.critical(f"A fatal error occurred: {e}", exc_info=True)
        sys.exit(1)
