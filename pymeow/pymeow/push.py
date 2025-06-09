"""
WhatsApp push notification handling.

Port of whatsmeow/push.go
"""
import logging
from abc import ABC, abstractmethod
import base64
import secrets
from typing import Dict, Any, Optional
from dataclasses import dataclass

from .binary.node import Node

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
    msg_id_enc_key: bytes = None

    def __post_init__(self):
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


async def get_server_push_notification_config(self) -> Optional[Node]:
    """Retrieves server push notification settings."""
    if not self:
        return None

    from .request import InfoQuery, InfoQueryType

    resp, err = await self.send_iq(InfoQuery(
        namespace="urn:xmpp:whatsapp:push",
        type=InfoQueryType.GET,
        to=self.server_jid,
        content=[Node(tag="settings")]
    ))

    if err:
        logger.error(f"Failed to get server push notification config: {err}")
        return None

    return resp

async def register_for_push_notifications(self, pc: PushConfig) -> None:
    """
    Registers a device for push notifications.

    This is generally not necessary for anything. Don't use this if you don't know what you're doing.

    Args:
        pc: The push configuration to register

    Raises:
        ElementMissingError: If the client is nil
        Exception: If there's an error registering for push notifications
    """
    if not self:
        raise Exception("Element missing")

    from .request import InfoQuery, InfoQueryType

    _, err = await self.send_iq(InfoQuery(
        namespace="urn:xmpp:whatsapp:push",
        type=InfoQueryType.SET,
        to=self.server_jid,
        content=[Node(tag="config", attributes=pc.get_push_config_attrs())]
    ))

    if err:
        raise Exception(f"Failed to register for push notifications: {err}")
