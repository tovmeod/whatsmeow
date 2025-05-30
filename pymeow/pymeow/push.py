"""
WhatsApp push notification handling.

Port of whatsmeow/push.go
"""
from abc import ABC, abstractmethod
import base64
import secrets
from typing import Dict, Any
from dataclasses import dataclass

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

