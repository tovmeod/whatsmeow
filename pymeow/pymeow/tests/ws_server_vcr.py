import asyncio
import logging

import aiohttp
import yaml
from aiohttp import WSMsgType, web

logger = logging.getLogger(__name__)


class WebSocketProxy:
    def __init__(self, target_url):
        self.target_url = target_url
        self.recorded_interactions = []

    async def proxy_connection(self, client_ws):
        """Create proxy connection to target server and relay messages both ways."""
        session = aiohttp.ClientSession()

        try:
            # Connect to the real target server
            logger.info(f"Connecting to target server: {self.target_url}")
            async with session.ws_connect(self.target_url) as server_ws:
                logger.info("Connected to target server, starting proxy relay")

                # Create tasks for both directions
                client_to_server_task = asyncio.create_task(
                    self._relay_messages(client_ws, server_ws, "client_to_server")
                )
                server_to_client_task = asyncio.create_task(
                    self._relay_messages(server_ws, client_ws, "server_to_client")
                )

                # Wait for either direction to close
                done, pending = await asyncio.wait(
                    [client_to_server_task, server_to_client_task], return_when=asyncio.FIRST_COMPLETED
                )

                # Cancel remaining tasks
                for task in pending:
                    task.cancel()

        except Exception as e:
            logger.error(f"Proxy connection failed: {e}")
            raise
        finally:
            await session.close()

    async def _relay_messages(self, from_ws, to_ws, direction):
        """Relay messages from one WebSocket to another while recording."""
        try:
            async for msg in from_ws:
                if msg.type == WSMsgType.TEXT:
                    await to_ws.send_str(msg.data)
                    self._record_message(direction, "text", msg.data)
                elif msg.type == WSMsgType.BINARY:
                    await to_ws.send_bytes(msg.data)
                    self._record_message(direction, "binary", msg.data.hex())
                elif msg.type == WSMsgType.CLOSE:
                    await to_ws.close()
                    self._record_message(direction, "close", None)
                    break
                elif msg.type == WSMsgType.ERROR:
                    logger.error(f"WebSocket error in {direction}: {msg.data}")
                    break
        except Exception as e:
            logger.error(f"Error in {direction} relay: {e}")

    def _record_message(self, direction, msg_type, payload):
        """Record a message interaction."""
        interaction = {
            "timestamp": asyncio.get_event_loop().time(),
            "direction": direction,  # "client_to_server" or "server_to_client"
            "type": msg_type,
            "payload": payload,
        }
        self.recorded_interactions.append(interaction)
        logger.debug(f"Recorded {direction} {msg_type} message")


async def create_ws_server_from_cassette(cassette_file, port, *, record=False):
    """
    Create WebSocket server that can either:
    1. Replay recorded interactions (normal mode)
    2. Act as proxy to real server while recording (record mode)

    Args:
        cassette_file: Path to YAML file containing recorded interactions
        port: Port to run the proxy server on
        record: If True, act as proxy and record interactions
    """

    # Determine recording mode automatically if no cassette exists
    should_record = record or not cassette_file.exists()

    if cassette_file.exists() and not should_record:
        # Load existing cassette for playback
        with cassette_file.open("r") as f:
            cassette = yaml.safe_load(f)
        interactions = cassette.get("interactions", [])
        logger.info(f"Loaded {len(interactions)} interactions from {cassette_file}")
    else:
        # Recording mode or no existing cassette
        interactions = []
        cassette = {"interactions": []}
        logger.info(f"Recording mode: will create new cassette at {cassette_file}")

    # For recording mode, get target URL from FrameSocket
    target_url = None
    proxy = None
    if should_record:
        from pymeow.socket.framesocket import FrameSocket

        target_url = FrameSocket.url
        proxy = WebSocketProxy(target_url)
        logger.info(f"Auto-detected target URL from FrameSocket: {target_url}")

    async def handler(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)

        if should_record and proxy:
            # Proxy mode: relay to real server while recording
            logger.info(f"Recording mode: proxying to {target_url}")
            try:
                await proxy.proxy_connection(ws)
            except Exception as e:
                logger.error(f"Proxy connection failed: {e}")
                # Close the client connection
                if not ws.closed:
                    await ws.close()
        else:
            # Playback mode: replay recorded interactions
            logger.info(f"Playback mode: using {len(interactions)} recorded interactions")
            await _replay_interactions(ws, interactions)

        return ws

    async def _replay_interactions(ws, interactions):
        """Replay recorded interactions with the client."""
        client_messages = []
        server_messages = []

        # Separate messages by direction
        for interaction in interactions:
            if interaction["direction"] == "server_to_client":
                server_messages.append(interaction)
            else:
                client_messages.append(interaction)

        logger.info(
            f"Replaying {len(server_messages)} server messages, expecting {len(client_messages)} client messages"
        )

        # Start background task to send server messages
        server_task = asyncio.create_task(_send_server_messages(ws, server_messages))

        try:
            # Receive and verify client messages
            expected_client_idx = 0
            async for msg in ws:
                if msg.type == WSMsgType.TEXT:
                    if expected_client_idx < len(client_messages):
                        expected = client_messages[expected_client_idx]
                        if expected["type"] == "text" and expected["payload"] == msg.data:
                            logger.debug(f"Client message {expected_client_idx} matches recording")
                        else:
                            logger.warning(f"Client message {expected_client_idx} differs from recording")
                        expected_client_idx += 1
                elif msg.type == WSMsgType.BINARY:
                    if expected_client_idx < len(client_messages):
                        expected = client_messages[expected_client_idx]
                        if expected["type"] == "binary" and expected["payload"] == msg.data.hex():
                            logger.debug(f"Client message {expected_client_idx} matches recording")
                        else:
                            logger.warning(f"Client message {expected_client_idx} differs from recording")
                        expected_client_idx += 1
                elif msg.type == WSMsgType.CLOSE:
                    logger.info("Client closed WebSocket connection during replay.")
                    break
        except Exception as e:
            logger.error(f"Error in replay while handling client messages: {e}")
        finally:
            # Ensure server messages are processed or server_task is cancelled
            if not server_task.done():
                try:
                    logger.debug("Waiting for server_task to complete...")
                    await asyncio.wait_for(server_task, timeout=5.0)  # Wait for task to complete
                except asyncio.TimeoutError:
                    logger.warning("Timeout waiting for server_task to complete, cancelling.")
                    server_task.cancel()
                except Exception as e:
                    logger.error(f"Error awaiting server_task: {e}")
                    server_task.cancel()  # Ensure cancellation on other errors
            else:
                # If task is done, retrieve exception if any to log it
                try:
                    server_task.result()
                except Exception as e:
                    logger.error(f"Server_task completed with an error: {e}")

            logger.info("All server messages replayed or client disconnected, closing connection to client.")
            if not ws.closed:
                await ws.close()

    async def _send_server_messages(ws, server_messages):
        """Send server messages to client with appropriate timing."""
        for i, msg in enumerate(server_messages):
            try:
                if ws.closed:
                    logger.warning(f"WebSocket closed before sending server message {i}, stopping.")
                    break
                if msg["type"] == "text":
                    await ws.send_str(msg["payload"])
                    logger.debug(f"Sent server text message {i}")
                elif msg["type"] == "binary":
                    await ws.send_bytes(bytes.fromhex(msg["payload"]))
                    logger.debug(f"Sent server binary message {i}")
                elif msg["type"] == "close":
                    if not ws.closed:
                        await ws.close()
                    logger.debug("Sent server close message")
                    break

                # Add small delay between messages to simulate real timing
                await asyncio.sleep(0.1)
            except ConnectionResetError:
                logger.warning(f"Connection reset while sending server message {i}. Client likely disconnected.")
                break
            except Exception as e:  # Broad exception to catch errors like sending on closed socket
                logger.error(f"Error sending server message {i} ('{msg.get('type', 'unknown')}') type: {e}")
                break
        logger.debug(f"Finished sending all {len(server_messages)} server messages.")

    app = web.Application()
    app.router.add_get("/ws", handler)

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "localhost", port)
    await site.start()

    logger.info(f"WebSocket VCR server started on ws://localhost:{port}/ws")

    async def shutdown():
        await runner.cleanup()

        if should_record and proxy and proxy.recorded_interactions:
            # Save recorded interactions
            cassette["interactions"] = proxy.recorded_interactions

            # Create directory if it doesn't exist
            cassette_file.parent.mkdir(parents=True, exist_ok=True)

            with cassette_file.open("w") as f:
                yaml.safe_dump(cassette, f, sort_keys=False, default_flow_style=False)

            logger.info(f"Recorded {len(proxy.recorded_interactions)} interactions to {cassette_file}")

    return {
        "app": app,
        "runner": runner,
        "site": site,
        "proxy": proxy,
        "recording": should_record,
        "target_url": target_url,
        "shutdown": shutdown,
    }
