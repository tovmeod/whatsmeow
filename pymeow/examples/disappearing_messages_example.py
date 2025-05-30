"""
Example demonstrating how to use disappearing messages in PyMeow.

This script shows how to:
1. Send disappearing messages with different durations
2. Set disappearing messages for a chat
3. Get the current disappearing messages setting for a chat
4. Send view-once (ephemeral) messages
"""
import asyncio
import logging
from datetime import datetime

from pymeow import Client, MessageUtils, ExpirationType

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Replace with your WhatsApp number in international format
YOUR_NUMBER = "YOUR_WHATSAPP_NUMBER"
# Replace with the recipient's WhatsApp number in international format
RECIPIENT_NUMBER = "RECIPIENT_WHATSAPP_NUMBER"

async def main():
    # Initialize the client
    client = Client()
    
    try:
        # Connect to WhatsApp
        await client.connect()
        
        # Wait for QR code scan
        logger.info("Scan the QR code with your phone to log in")
        await client.wait_until_ready()
        
        # Example 1: Send a message that disappears after 1 week
        logger.info("Sending a message that will disappear after 1 week")
        await client.send_message(
            to=RECIPIENT_NUMBER,
            content="This message will disappear in 1 week!",
            expiration_seconds=ExpirationType.ONE_WEEK
        )
        
        # Example 2: Set disappearing messages for a chat (1 day)
        logger.info("Setting disappearing messages to 1 day for the chat")
        result = await client.set_disappearing_messages(
            chat_jid=RECIPIENT_NUMBER,
            duration_seconds=ExpirationType.ONE_DAY
        )
        logger.info(f"Disappearing messages set: {result}")
        
        # Example 3: Get current disappearing messages setting
        settings = await client.get_disappearing_messages(RECIPIENT_NUMBER)
        logger.info(f"Current disappearing messages settings: {settings}")
        
        # Example 4: Send a view-once (ephemeral) message
        logger.info("Sending a view-once message")
        await client.send_message(
            to=RECIPIENT_NUMBER,
            content="This is a view-once message! It will disappear after being viewed.",
            is_ephemeral=True
        )
        
        # Example 5: Send a message with custom expiration (1 hour)
        logger.info("Sending a message that will disappear after 1 hour")
        await client.send_message(
            to=RECIPIENT_NUMBER,
            content="This message will disappear in 1 hour!",
            expiration_seconds=3600  # 1 hour in seconds
        )
        
    except Exception as e:
        logger.error(f"An error occurred: {e}", exc_info=True)
    finally:
        # Disconnect properly
        await client.disconnect()

if __name__ == "__main__":
    asyncio.run(main())
