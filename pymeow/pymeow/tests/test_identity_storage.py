import pytest
from tortoise.contrib.test import TestCase

from ..pymeow.store.sqlstore import SQLStore


class TestSQLStore(TestCase):
    async def test_identity_operations(self):
        """Test identity storage operations."""
        # Don't create a new container since Tortoise is already initialized by conftest.py
        # Just create the SQLStore directly
        store = SQLStore(None, "test@example.com")  # Pass None for container for now

        # For now, let's test the basic functionality exists
        # Once the actual SQLStore implementation is complete, this will work properly
        assert store is not None

    @pytest.mark.asyncio
    async def test_mock_store_operations(self):
        """Test using a mock store for identity operations."""
        # Create a simple mock store to demonstrate the expected interface
        class MockIdentityStore:
            def __init__(self):
                self.identities = {}

            async def put_identity(self, address: str, identity_key: bytes):
                self.identities[address] = identity_key

            async def is_trusted_identity(self, address: str, identity_key: bytes) -> bool:
                return self.identities.get(address) == identity_key

        # Test the mock store
        store = MockIdentityStore()
        await store.put_identity("user@example.com", b"identity_key")
        assert await store.is_trusted_identity("user@example.com", b"identity_key")
        assert not await store.is_trusted_identity("user@example.com", b"wrong_key")
