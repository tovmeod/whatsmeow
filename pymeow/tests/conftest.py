"""Test configuration for pymeow."""
import pytest

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
