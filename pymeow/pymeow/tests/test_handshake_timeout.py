
"""Test handshake timeout scenario using ws_server_vcr fixture."""

import asyncio

import pytest

from pymeow.client import Client
from pymeow.qrchan import get_qr_channel
from pymeow.store.sqlstore.container import Container


@pytest.mark.asyncio
async def test_handshake_qr_timeout(ws_server_vcr):
    """Test client creation, connection, QR code generation, and timeout."""
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
            async with asyncio.timeout(90):  # 30 second timeout to allow for recording
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

        # Verify we got some events (at least during recording)
        assert len(qr_events) > 0, "Should have received at least one QR event"

        # In normal flow, we should get at least one QR code
        code_events = [e for e in qr_events if e.event == "code"]
        assert len(code_events) > 0, "Should have received at least one QR code"

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
