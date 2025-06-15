"""Test configuration for pymeow."""
import os

import pytest
from tortoise.contrib.test import finalizer, initializer


@pytest.fixture(scope="session", autouse=True)
def initialize_tests(request):
    """Initialize Tortoise ORM for testing."""
    db_url = os.environ.get("TORTOISE_TEST_DB", "sqlite://:memory:")

    # The models seem to exist based on the successful table creation
    models = [
        "pymeow.pymeow.store.sqlstore.models.device",
        "pymeow.pymeow.store.sqlstore.models.session",
        "pymeow.pymeow.store.sqlstore.models.contacts",
        "pymeow.pymeow.store.sqlstore.models.appstate",
        "pymeow.pymeow.store.sqlstore.models.messages",
    ]

    initializer(models, db_url=db_url, app_label="models")
    request.addfinalizer(finalizer)

@pytest.fixture
def mock_socket():
    """Mock websocket connection."""
    class MockWebSocket:
        async def connect(self):
            pass
        async def send(self, data: bytes):
            pass
        async def receive(self):
            pass
        async def close(self):
            pass
    return MockWebSocket()

@pytest.fixture
def mock_store():
    """Mock store implementation."""
    class MockStore:
        async def save_message(self, msg):
            pass
        async def get_message(self, msg_id):
            pass
    return MockStore()
