import asyncio
import logging
from unittest.mock import patch

import aiohttp
import pytest
import yaml
from aiohttp import WSMsgType, web

# Assuming ws_server_vcr is in the same directory or adjust path accordingly
# For the purpose of this exercise, I'll assume it's importable like this:
from .ws_server_vcr import create_ws_server_from_cassette

# Configure logging for tests (optional, but can be helpful for debugging)
logging.basicConfig(level=logging.DEBUG)


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
            logging.debug("Dummy Server: Received BINARY data, echoing.")
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

        with open(cassette_file, "r") as f:  # noqa: ASYNC230
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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        # Expect WSMessageTypeError because server will close connection upon mismatch,
        # and client's receive_str will get a close message instead of TEXT.
        with pytest.raises(aiohttp.client_exceptions.WSMessageTypeError):
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    await ws.send_str("pinnng")  # Mismatched payload
                    # The VCR server will detect the mismatch, log ReplayMismatchError,
                    # and send a WebSocket close frame.
                    await ws.receive_str(timeout=1)  # This will raise WSMessageTypeError

        # No need to check excinfo.value for ReplayMismatchError content,
        # as that's a server-side exception. We're checking client's observation.

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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        # Expect WSMessageTypeError because server will close connection upon mismatch,
        # and client's receive_str will get a close message instead of TEXT.
        with pytest.raises(aiohttp.client_exceptions.WSMessageTypeError):
            async with aiohttp.ClientSession() as session:
                async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                    await ws.send_bytes(b"ping_bytes")  # Mismatched type (BINARY instead of TEXT)
                    # The VCR server will detect the mismatch, log ReplayMismatchError,
                    # and send a WebSocket close frame.
                    await ws.receive_str(timeout=1)  # This will raise WSMessageTypeError

        # No need to check excinfo.value for ReplayMismatchError content,
        # as that's a server-side exception. We're checking client's observation.
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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        # Reduce timeout in _replay_interactions for this test if possible, or use a client that just connects and waits.
        # For now, we assume the 10s timeout in _replay_interactions in ws_server_vcr.py.
        # This test will make the client wait longer than that.
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                # Client connects but sends nothing initially.
                # Server expects "ping". Server should timeout after ~10s (client_receive_timeout in VCR).
                logging.info(f"Client connected to ws://localhost:{port}/ws, now sleeping for 10.5 seconds...")
                await asyncio.sleep(10.5)  # Wait longer than server's client_receive_timeout

                # By now, server should have closed the connection due to client_receive_timeout.
                logging.info("Client woke up, attempting to send a late message.")
                await ws.send_str("late_message")  # This might succeed if send is buffered
                logging.info("Client sent late_message; server should have already closed. Expecting error on receive.")
                # Attempting to receive should now fail as server has closed connection.
                # Server should send a CLOSE frame when it times out the client.
                # So, client should receive a CLOSE message.
                msg = await ws.receive(timeout=1.0)
                assert msg.type == aiohttp.WSMsgType.CLOSE, f"Expected CLOSE message, got {msg.type}"
                logging.info(f"Client received message of type {msg.type}, confirming server closure.")

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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
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
    with open(cassette_file, "w") as f:  # noqa: ASYNC230
        yaml.dump({"interactions": interactions}, f)

    server = None
    try:
        server = await create_ws_server_from_cassette(cassette_file, port, strict_replay=True)
        # The server expects "another_ping" after "pong".
        # If client closes instead, server logs ReplayMismatchError and closes the connection from its side.
        # The client should be able to perform its close operation without a client-side error.
        async with aiohttp.ClientSession() as session:
            async with session.ws_connect(f"ws://localhost:{port}/ws") as ws:
                await ws.send_str("ping")
                response = await ws.receive_str(timeout=1)
                assert response == "pong"
                # Client closes connection here. Server expects "another_ping".
                # Server will see this close as a mismatch. Client's close should succeed.
                await ws.close()
                logging.info("Client closed connection. Server should have logged a mismatch.")
        # No client-side exception is expected here. The mismatch is a server-side protocol observation.
    finally:
        if server:
            await server["shutdown"]()

    # Add a small delay to allow server to process and close if necessary
    await asyncio.sleep(0.1)
