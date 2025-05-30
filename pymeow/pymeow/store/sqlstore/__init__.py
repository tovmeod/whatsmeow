"""
Tortoise ORM-based SQLStore implementation for WhatsApp

Maintains the same interface as the Go version while using
Python-native async ORM patterns.
"""

from .container import Container
from .store import SQLStore

__all__ = ["Container", "SQLStore"]

# For backward compatibility
async def new_container(db_url: str, logger=None) -> Container:
    """Create and initialize a new database container"""
    container = Container(db_url, logger)
    await container.initialize()
    return container
