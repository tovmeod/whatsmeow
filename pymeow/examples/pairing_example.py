"""
PyMeow Pairing Example

This example demonstrates how to implement WhatsApp Web authentication using QR code scanning.
It shows how to handle the pairing flow, including QR code generation and authentication events.
"""
import asyncio
import logging
import os
from pathlib import Path

from pymeow import Client
from pymeow.models import AuthState

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration
DATA_DIR = Path.home() / ".pymeow_data"
AUTH_FILE = DATA_DIR / "auth.json"
QR_CODE_FILE = DATA_DIR / "qr_code.png"

# Create data directory if it doesn't exist
DATA_DIR.mkdir(parents=True, exist_ok=True)

class PairingExample:
    def __init__(self):
        self.client = None
        self.qr_code = None

    async def on_qr_code(self, qr_data: str) -> None:
        """Handle new QR code received event."""
        self.qr_code = qr_data
        logger.info("New QR code received")
        
        # Generate and display QR code
        qr_path = str(QR_CODE_FILE)
        if self.client.generate_qr_code(qr_data, output_path=qr_path, show_console=True):
            logger.info(f"QR code saved to {qr_path}")
            logger.info(f"Scan the QR code with your phone to authenticate")
            logger.info(f"Or use this link: https://web.whatsapp.com/device {qr_data}")

    async def on_pair_success(self, data: dict) -> None:
        """Handle successful pairing event."""
        logger.info(f"Successfully paired with account: {data}")
        logger.info(f"Phone: {data.get('phone')}")
        logger.info(f"Name: {data.get('name')}")
        
        # Save authentication state for future use
        await self._save_auth()
        
        # You can now start using the client for messaging
        logger.info("Ready to send and receive messages!")

    async def on_authenticated(self) -> None:
        """Handle successful authentication event."""
        logger.info("Successfully authenticated with WhatsApp Web")

    async def on_auth_failure(self, error: dict) -> None:
        """Handle authentication failure event."""
        logger.error(f"Authentication failed: {error}")

    async def _load_auth(self) -> AuthState:
        """Load authentication state from file if it exists."""
        if AUTH_FILE.exists():
            try:
                with open(AUTH_FILE, 'r') as f:
                    return AuthState.from_dict(json.load(f))
            except Exception as e:
                logger.warning(f"Failed to load auth state: {e}")
        return None

    async def _save_auth(self) -> None:
        """Save authentication state to file."""
        if self.client and self.client.auth_state:
            try:
                with open(AUTH_FILE, 'w') as f:
                    json.dump(self.client.auth_state.to_dict(), f)
                logger.info("Authentication state saved")
            except Exception as e:
                logger.error(f"Failed to save auth state: {e}")

    async def run(self) -> None:
        """Run the pairing example."""
        # Load existing auth state if available
        auth_state = await self._load_auth()
        
        # Initialize client
        self.client = Client(auth_state=auth_state)
        
        # Register event handlers
        self.client.on('qr', self.on_qr_code)
        self.client.on('pair_success', self.on_pair_success)
        self.client.on('authenticated', self.on_authenticated)
        self.client.on('auth_failure', self.on_auth_failure)
        
        try:
            # Connect to WhatsApp Web
            logger.info("Connecting to WhatsApp Web...")
            await self.client.connect()
            
            # Keep the connection alive
            while True:
                await asyncio.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Disconnecting...")
        except Exception as e:
            logger.error(f"An error occurred: {e}", exc_info=True)
        finally:
            # Clean up
            if self.client:
                await self.client.disconnect()
            logger.info("Disconnected")

if __name__ == "__main__":
    import json  # Add this import at the top of the file
    
    # Run the example
    example = PairingExample()
    asyncio.run(example.run())
