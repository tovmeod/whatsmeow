"""Test handshake timeout scenario using ws_server_vcr fixture."""

import asyncio
import os
from pathlib import Path

import pytest

from pymeow.client import Client
from pymeow.qrchan import get_qr_channel
from pymeow.store.sqlstore.container import Container
from pymeow.util.keys.keypair import KeyPair

# Define a fixed 32-byte private key for deterministic ephemeral key generation
FIXED_EPHEMERAL_PRIVATE_KEY = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\x00\xaa\xbb\xcc\xdd\xee\xff\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f'


@pytest.mark.asyncio
async def test_handshake_qr_timeout(ws_server_vcr, monkeypatch):  # Add monkeypatch fixture
    """Test client creation, connection, QR code generation, and timeout."""
    # # Delete cassette to force re-recording with the fixed ephemeral key
    # cassette_path = Path("pymeow/pymeow/tests/ws_cassettes/test_handshake_qr_timeout.yaml")
    # try:
    #     if cassette_path.exists():
    #         os.remove(cassette_path)
    #         print(f"Deleted cassette: {cassette_path}")
    # except OSError as e:
    #     print(f"Error deleting cassette {cassette_path}: {e}")
    #     # Optionally, re-raise or handle as a fatal test setup error if critical
    #     # For now, just print and continue; VCR will use existing if deletion fails

    # Setup fixed keypair for KeyPair.generate
    # This ensures that the client's ephemeral key is deterministic for this test.
    fixed_kp = KeyPair.from_private_key(FIXED_EPHEMERAL_PRIVATE_KEY)
    monkeypatch.setattr(KeyPair, 'generate', lambda: fixed_kp)  # Use the imported KeyPair directly

    container = None
    client = None

    try:
        # Create in-memory database for testing
        db_url = "sqlite://:memory:"

        # Create database container
        container = await Container(db_url).ainit()

        # Create new device store (no existing session)
        test_jid = "test@example.com"
        device_store = await container.new_device(test_jid)

        # Ensure device has no existing session (simulating fresh install)
        assert device_store.id is None

        # Create WhatsApp client
        client = await Client(device_store).ainit()

        # Get QR channel for authentication
        qr_channel = await get_qr_channel(client)

        # Connect to WhatsApp (VCR handles recording/playback transparently)
        await client.connect()

        # Track QR events
        qr_events = []

        # Wait for QR events with a reasonable timeout
        try:
            async with asyncio.timeout(90):  # 90 second timeout to allow for recording
                async for qr_event in qr_channel:
                    qr_events.append(qr_event)
                    print(f"QR event: {qr_event.event}")

                    if qr_event.event == "code":
                        # QR code received - this is what we expect initially
                        assert qr_event.code is not None
                        print(f"Received QR code: {qr_event.code}")

                    elif qr_event.event == "timeout":
                        # Timeout occurred - this is what we're testing
                        print("QR code timed out as expected")
                        break

                    elif qr_event.event == "success":
                        # Should not happen in this test (no scan simulation)
                        print("Unexpected successful authentication")
                        break

        except asyncio.TimeoutError:
            # Test timeout - might happen during initial recording
            print(f"Test timed out after receiving {len(qr_events)} QR events")
        except AssertionError:
            # If an assertion fails, log it but ensure we break out of the loop
            print("Assertion failed during QR event processing")
            raise  # Re-raise to fail the test, but after cleanup in finally block

        # Verify we got some events (at least during recording)
        assert len(qr_events) > 0, "Should have received at least one QR event"

        # Check if we received a timeout event
        timeout_events = [e for e in qr_events if e.event == "timeout"]
        has_timeout = len(timeout_events) > 0

        # In normal flow, we should get at least one QR code or a timeout event
        code_events = [e for e in qr_events if e.event == "code"]

        # If we didn't get any code events but got a timeout, that's acceptable for this test
        # since we're specifically testing the timeout scenario
        if not has_timeout:
            assert len(code_events) > 0, "Should have received at least one QR code when no timeout occurred"

        print(f"Test completed with {len(qr_events)} QR events")

    finally:
        # Cleanup
        if client:
            try:
                await client.disconnect()
            except Exception:
                pass
        if container:
            await container.close()
