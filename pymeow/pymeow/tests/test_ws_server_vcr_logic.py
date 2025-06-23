import asyncio
import yaml
from pathlib import Path
import pytest
import aiohttp
from aiohttp import web, WSMsgType
from unittest.mock import patch
import logging

# Configure logging for tests (optional, but can be helpful for debugging)
logging.basicConfig(level=logging.DEBUG)

# Assuming ws_server_vcr is in the same directory or adjust path accordingly
# For the purpose of this exercise, I'll assume it's importable like this:
from .ws_server_vcr import create_ws_server_from_cassette, ReplayMismatchError, WebSocketProxy


# Helper for dummy WebSocket server (for Test 1 Recording)
async def dummy_websocket_handler(request):
    ws = web.WebSocketResponse()
    await ws.prepare(request)
    logging.debug("Dummy Server: Client connected")
    async for msg in ws:
        if msg.type == WSMsgType.TEXT:
            logging.debug(f"Dummy Server: Received TEXT '{msg.data}', echoing.")
            await ws.send_str(f"echo:{msg.data}")
        elif msg.type == WSMsgType.BINARY:
            logging.debug(f"Dummy Server: Received BINARY data, echoing.")
            await ws.send_bytes(b"echo:" + msg.data)
        elif msg.type == WSMsgType.CLOSE:
            logging.debug("Dummy Server: Received CLOSE from client.")
            break  # Exit loop on client close
        elif msg.type == WSMsgType.ERROR:
            logging.error(f"Dummy Server: WebSocket error: {ws.exception()}")
            break
    logging.debug("Dummy Server: Connection closed.")
    return ws


async def run_dummy_server(host, port):
    app = web.Application()
    app.router.add_get("/ws_real", dummy_websocket_handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, host, port)
    await site.start()
    logging.info(f"Dummy real server started on ws://{host}:{port}/ws_real")
    return runner  # To cleanup later


@pytest.mark.asyncio
async def test_basic_record_and_replay(tmp_path, unused_tcp_port_factory):
    cassette_file = tmp_path / "test_cassette.yaml"
    vcr_port = unused_tcp_port_factory()
    real_server_port = unused_tcp_port_factory()
    real_server_host = "localhost"
    real_server_url = f"ws://{real_server_host}:{real_server_port}/ws_real"

    # Start the dummy "real" server
    real_server_runner = await run_dummy_server(real_server_host, real_server_port)

    server_vcr = None
    server_vcr_replay = None

    try:
        # --- Recording Phase ---
        with patch("pymeow.socket.framesocket.FrameSocket.url", real_server_url):
            # Ensure FrameSocket is loaded after patch if it's module-level
            # For this test, we directly control the target_url for WebSocketProxy if needed
            # or ensure create_ws_server_from_cassette uses the patched FrameSocket.url

            # If create_ws_server_from_cassette relies on FrameSocket.url being set at import time of its module,
            # this patching strategy might be tricky. We assume it reads it dynamically or we can influence it.
            # The provided code for create_ws_server_from_cassette shows:
            # if should_record:
            #     from pymeow.socket.framesocket import FrameSocket
            #     target_url = FrameSocket.url
            # This dynamic import inside the function is good for patching.

            server_vcr = await create_ws_server_from_cassette(cassette_file, vcr_port, record=True)
            assert server_vcr["recording"] is True
            assert server_vcr["target_url"] == real_server_url

            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{vcr_port}/ws") as client_ws:
                    await client_ws.send_str("hello")
                    response = await client_ws.receive_str(timeout=2)
                    assert response == "echo:hello"
                    await client_ws.send_bytes(b"binary_data")
                    response_bytes = await client_ws.receive_bytes(timeout=2)
                    assert response_bytes == b"echo:binary_data"
                    await client_ws.close()

        await server_vcr["shutdown"]()
        assert cassette_file.exists()

        with open(cassette_file, "r") as f:
            cassette_content = yaml.safe_load(f)
            assert len(cassette_content["interactions"]) > 0
            # Example: check first and last message direction/type if necessary
            assert cassette_content["interactions"][0]["direction"] == "client_to_server"
            assert cassette_content["interactions"][0]["type"] == "text"
            assert cassette_content["interactions"][0]["payload"] == "hello"

        # --- Replay Phase ---
        # Stop the real server to ensure we are replaying from cassette
        await real_server_runner.cleanup()
        logging.info("Dummy real server stopped for replay phase.")

        server_vcr_replay = await create_ws_server_from_cassette(cassette_file, vcr_port, record=False)
        assert server_vcr_replay["recording"] is False

        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f"ws://localhost:{vcr_port}/ws") as client_ws:
                await client_ws.send_str("hello")
                response = await client_ws.receive_str(timeout=2)
                assert response == "echo:hello"

                await client_ws.send_bytes(b"binary_data")
                response_bytes = await client_ws.receive_bytes(timeout=2)
                assert response_bytes == b"echo:binary_data"
                await client_ws.close()

    finally:
        if server_vcr:
            await server_vcr["shutdown"]()  # Ensure shutdown if not already called
        if server_vcr_replay:
            await server_vcr_replay["shutdown"]()
        # Ensure real_server_runner is cleaned up if an error occurred before replay phase shutdown
        if real_server_runner:
            # Check if cleanup has already been called
            if real_server_runner.server and real_server_runner.server.sockets:  # Basic check if server is still up
                await real_server_runner.cleanup()


@pytest.mark.asyncio
async def test_strict_replay_match(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "strict_match.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "ping"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "pong"},
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                await ws.send_str("ping")
                response = await ws.receive_str(timeout=1)
                assert response == "pong"
                await ws.close()
        # No ReplayMismatchError should be raised
    finally:
        if server:
            await server["shutdown"]()


@pytest.mark.asyncio
async def test_strict_replay_payload_mismatch(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "strict_mismatch_payload.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "ping"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "pong"},
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        with pytest.raises(ReplayMismatchError) as excinfo:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    await ws.send_str("pinnng")  # Mismatched payload
                    # The error might occur here or on next receive, depending on server logic
                    # For current _replay_interactions, error is raised after ws.receive() gets unexpected msg
                    # and then tries to match.
                    # If server sends "pong" before client sends anything else, this test would need adjustment.
                    # The current logic expects "ping", then server sends "pong".
                    # If client sends "pinnng", the server's receive() gets it, compares, and raises.
                    await ws.receive_str(timeout=1)  # Attempt to receive, may not be reached if send already failed

        assert "Expected: type=text, payload=ping" in str(excinfo.value)
        assert "Got: type=TEXT, payload=pinnng" in str(excinfo.value)

    finally:
        if server:
            await server["shutdown"]()


@pytest.mark.asyncio
async def test_strict_replay_type_mismatch(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "strict_mismatch_type.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "ping"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "pong"},
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        with pytest.raises(ReplayMismatchError) as excinfo:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    await ws.send_bytes(b"ping_bytes")  # Mismatched type (BINARY instead of TEXT)
                    await ws.receive_str(timeout=1)  # May not be reached

        assert "Expected: type=text, payload=ping" in str(excinfo.value)
        assert "Got: type=BINARY" in str(excinfo.value)  # Payload will be hex of "ping_bytes"
    finally:
        if server:
            await server["shutdown"]()


@pytest.mark.asyncio
async def test_strict_replay_timeout(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "strict_timeout.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "ping"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "pong"},
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        # Reduce timeout in _replay_interactions for this test if possible, or use a client that just connects and waits.
        # For now, we assume the 10s timeout in _replay_interactions. This test will be slow.
        # To make it faster, one might need to pass timeout to create_ws_server_from_cassette.

        with pytest.raises(ReplayMismatchError) as excinfo:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    # Client connects but sends nothing, server expects "ping"
                    # Server's ws.receive(timeout=10) will eventually timeout.
                    # We need to ensure the client stays connected long enough for the server to timeout.
                    await asyncio.sleep(0.2)  # Give server time to start expecting
                    # The ReplayMismatchError for timeout is raised by _replay_interactions
                    # when it calls ws.receive(timeout=10) and it times out.
                    # The client doesn't need to do anything else to trigger this.
                    # The test itself will hang until the server's timeout logic completes.
                    # To prevent test hanging too long if logic is wrong, we can wrap client part in timeout
                    try:
                        await asyncio.wait_for(
                            ws.receive_str(), timeout=0.5
                        )  # client waits for server (won't get if server expects client msg)
                    except asyncio.TimeoutError:
                        logging.debug(
                            "Client timed out waiting for server message, this is expected if server is waiting for client."
                        )
                        pass  # This is expected if server is waiting for client message

        assert "Timeout waiting for client message 0" in str(excinfo.value)
        assert "expected type=text" in str(excinfo.value)

    finally:
        if server:
            await server["shutdown"]()


@pytest.mark.asyncio
async def test_replay_unsolicited_server_message(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "unsolicited.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "init"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "ack"},
        {"timestamp": 1.2, "direction": "server_to_client", "type": "text", "payload": "unsolicited_msg"},
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, record=False)
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                await ws.send_str("init")

                response1 = await ws.receive_str(timeout=1)
                assert response1 == "ack"

                response2 = await ws.receive_str(timeout=1)  # Expecting the unsolicited message
                assert response2 == "unsolicited_msg"

                await ws.close()
    finally:
        if server:
            await server["shutdown"]()


@pytest.mark.asyncio
async def test_strict_replay_client_closes_unexpectedly(tmp_path, unused_tcp_port):
    cassette_file = tmp_path / "strict_client_closes.yaml"
    port = unused_tcp_port
    interactions = [
        {"timestamp": 1.0, "direction": "client_to_server", "type": "text", "payload": "ping"},
        {"timestamp": 1.1, "direction": "server_to_client", "type": "text", "payload": "pong"},
        {"timestamp": 1.2, "direction": "client_to_server", "type": "text", "payload": "another_ping"},
        # Server expects this
    ]
    with open(cassette_file, "w") as f:
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        with pytest.raises(ReplayMismatchError) as excinfo:
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    await ws.send_str("ping")
                    response = await ws.receive_str(timeout=1)
                    assert response == "pong"
                    # Client closes connection here, but server expects "another_ping"
                    await ws.close()
                    # The error should be raised when the server tries to receive next message
                    # and finds the client has closed.

        # The error message might be "Client message 2 mismatch. Expected: type=text, payload=another_ping. Got: type=CLOSE..."
        # Or it could be a more specific "client closed unexpectedly" if that logic path is hit first.
        # Based on current _replay_interactions, it's likely the generic mismatch.
        assert "Client message 2 mismatch" in str(excinfo.value)
        assert "Expected: type=text, payload=another_ping" in str(excinfo.value)
        assert "Got: type=CLOSE" in str(excinfo.value)
    finally:
        if server:
            await server["shutdown"]()
