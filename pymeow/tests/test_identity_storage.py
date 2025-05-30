import pytest
from tortoise.contrib.test import TestCase

from ..pymeow.store.sqlstore import Container, SQLStore


class TestSQLStore(TestCase):
    async def test_identity_operations(self):
        container = Container("sqlite://:memory:")
        await container.initialize()

        store = SQLStore(container, "test@example.com")

        # Test identity storage
        await store.put_identity("user@example.com", b"identity_key")
        assert await store.is_trusted_identity("user@example.com", b"identity_key")

