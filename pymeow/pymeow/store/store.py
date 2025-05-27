"""
Store interface for WhatsApp data.

Port of whatsmeow/store/store.go
"""
from abc import ABC, abstractmethod
from typing import Optional, Dict, Any, List
from datetime import datetime

from ..generated import WAMsgTransport_pb2
from ..generated.waE2E import WAWebProtobufsE2E_pb2
from ..types.message import MessageSource

class Store(ABC):
    """Base interface for WhatsApp data storage."""

    @abstractmethod
    async def save_message(self, msg: WAMsgTransport_pb2.MessageTransport) -> None:
        """Save a message to the store."""
        pass

    @abstractmethod
    async def get_message(self, message_id: str) -> Optional[WAMsgTransport_pb2.MessageTransport]:
        """Retrieve a message from the store."""
        pass

    @abstractmethod
    async def get_contact_name(self, jid: str) -> Optional[str]:
        """Get the name of a contact."""
        pass

    @abstractmethod
    async def save_contact_name(self, jid: str, name: str) -> None:
        """Save a contact's name."""
        pass

    @abstractmethod
    async def save_group_participant(self, group_id: str, participant_jid: str) -> None:
        """Save a group participant."""
        pass

    @abstractmethod
    async def get_group_participants(self, group_id: str) -> List[str]:
        """Get all participants in a group."""
        pass
