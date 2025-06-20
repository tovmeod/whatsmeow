"""Test configuration for pymeow."""
import logging
import os
from pathlib import Path
from unittest.mock import patch

from tortoise.contrib.test import finalizer, initializer
import pytest
import pytest_asyncio

from pymeow.store.sqlstore.config import get_tortoise_config
from .ws_server_vcr import create_ws_server_from_cassette

@pytest.fixture(scope="session", autouse=True)
def configure_logging():
    logging.getLogger('tortoise').setLevel(logging.ERROR)
    logging.getLogger('aiosqlite').setLevel(logging.ERROR)


def pytest_addoption(parser):
    parser.addoption(
        "--ws-record",
        action="store_true",
        default=False,
        help="Force recording mode even if cassette file exists"
    )

@pytest_asyncio.fixture
async def ws_server_vcr(request, unused_tcp_port):
    """WebSocket VCR fixture that automatically records or replays."""
    test_name = request.node.name
    test_file = Path(request.node.fspath)
    cassette_file = test_file.parent / "ws_cassettes" / f"{test_name}.yaml"

    port = unused_tcp_port
    force_record = request.config.getoption("--ws-record", default=False)

    # Get original URL before patching
    from pymeow.socket.framesocket import FrameSocket
    original_url = FrameSocket.url

    server = await create_ws_server_from_cassette(
        cassette_file,
        port,
        record=force_record
    )

    # Patch FrameSocket to use our VCR server
    test_url = f"ws://localhost:{port}/ws"

    with patch.object(FrameSocket, 'url', test_url):
        # Return the data directly instead of yielding
        server_info = {
            "url": test_url,
            "cassette": cassette_file,
            "recording": server["recording"],
            "target_url": server["target_url"],
            "original_url": original_url,
        }

        # Use try/finally to ensure cleanup
        try:
            yield server_info
        finally:
            await server["shutdown"]()

@pytest.fixture(scope="session", autouse=True)
def initialize_tests(request):
    """Initialize Tortoise ORM for testing."""
    db_url = os.environ.get("TORTOISE_TEST_DB", "sqlite://:memory:")

    config = get_tortoise_config(db_url)
    models = config["apps"]["models"]["models"]

    initializer(models, db_url=db_url, app_label="models")
    request.addfinalizer(finalizer)
