"""
WhatsApp push notification handling.

Port of whatsmeow/push.go
"""

import base64
import logging
import secrets
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from . import request
from .binary.node import Node
from .client import Client
from .request import InfoQuery, InfoQueryType

logger = logging.getLogger(__name__)


class PushConfig(ABC):
    """Interface for push notification configurations."""

    @abstractmethod
    def get_push_config_attrs(self) -> Dict[str, Any]:
        """Returns attributes for push notification configuration."""
        pass


@dataclass
class FCMPushConfig(PushConfig):
    """Firebase Cloud Messaging configuration."""

    token: str

    def get_push_config_attrs(self) -> Dict[str, Any]:
        """Returns attributes for FCM configuration."""
        return {
            "id": self.token,
            "num_acc": 1,
            "platform": "gcm",
        }


@dataclass
class APNsPushConfig(PushConfig):
    """Apple Push Notification service configuration."""

    token: str
    voip_token: str = ""
    msg_id_enc_key: bytes = b""

    def __post_init__(self) -> None:
        if self.msg_id_enc_key is None or len(self.msg_id_enc_key) != 32:
            self.msg_id_enc_key = secrets.token_bytes(32)

    def get_push_config_attrs(self) -> Dict[str, Any]:
        """Returns attributes for APNs configuration."""
        attrs = {
            "id": self.token,
            "platform": "apple",
            "version": 2,
            "reg_push": 1,
            "preview": 1,
            "pkey": base64.urlsafe_b64encode(self.msg_id_enc_key).decode().rstrip("="),
            "background_location": 1,  # or 0
            "call": "Opening.m4r",
            "default": "note.m4r",
            "groups": "note.m4r",
            "lg": "en",
            "lc": "US",
            "nse_call": 0,
            "nse_ver": 2,
            "nse_read": 0,
            "voip_payload_type": 2,
        }
        if self.voip_token:
            attrs["voip"] = self.voip_token
        return attrs


@dataclass
class WebPushConfig(PushConfig):
    """Web Push configuration."""

    endpoint: str
    auth: bytes
    p256dh: bytes

    def get_push_config_attrs(self) -> Dict[str, Any]:
        """Returns attributes for Web Push configuration."""
        return {
            "platform": "web",
            "endpoint": self.endpoint,
            "auth": base64.b64encode(self.auth).decode(),
            "p256dh": base64.b64encode(self.p256dh).decode(),
        }


async def get_server_push_notification_config(client: "Client") -> Optional[Node]:
    """Retrieves server push notification settings."""
    resp = await request.send_iq(
        client,
        InfoQuery(
            namespace="urn:xmpp:whatsapp:push",
            type=InfoQueryType.GET,
            to=client.server_jid,
            content=[Node(tag="settings")],
        ),
    )
    return resp


async def register_for_push_notifications(client: "Client", pc: PushConfig) -> None:
    """
    Registers a device for push notifications.

    This is generally not necessary for anything. Don't use this if you don't know what you're doing.

    Args:
        client: The client instance. This is required to send the IQ.
        pc: The push configuration to register

    Raises:
        ElementMissingError: If the client is nil
        Exception: If there's an error registering for push notifications
    """
    _ = await request.send_iq(
        client,
        InfoQuery(
            namespace="urn:xmpp:whatsapp:push",
            type=InfoQueryType.SET,
            to=client.server_jid,
            content=[Node(tag="config", attrs=pc.get_push_config_attrs())],
        ),
    )
