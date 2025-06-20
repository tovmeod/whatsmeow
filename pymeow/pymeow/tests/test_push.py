"""
Tests for the push notification implementation.
"""
import base64
import unittest
from unittest.mock import AsyncMock, MagicMock

from py.pymeow.binary import node as binary_node
from py.pymeow.push import (
    APNsPushConfig,
    FCMPushConfig,
    PushNotificationHandler,
    WebPushConfig,
)


class TestPushConfigs(unittest.TestCase):
    """Test the push configuration classes."""

    def test_fcm_push_config(self):
        """Test FCM push configuration."""
        config = FCMPushConfig(token="test_token")
        attrs = config.get_push_config_attrs()

        self.assertEqual(attrs["id"], "test_token")
        self.assertEqual(attrs["num_acc"], 1)
        self.assertEqual(attrs["platform"], "gcm")

    def test_apns_push_config(self):
        """Test APNs push configuration."""
        # Test with default msg_id_enc_key
        config = APNsPushConfig(token="test_token")
        attrs = config.get_push_config_attrs()

        self.assertEqual(attrs["id"], "test_token")
        self.assertEqual(attrs["platform"], "apple")
        self.assertEqual(attrs["version"], 2)
        self.assertEqual(len(base64.urlsafe_b64decode(attrs["pkey"] + "==")), 32)

        # Test with custom msg_id_enc_key
        custom_key = b"0" * 32
        config = APNsPushConfig(token="test_token", msg_id_enc_key=custom_key)
        attrs = config.get_push_config_attrs()

        self.assertEqual(attrs["pkey"], base64.urlsafe_b64encode(custom_key).decode().rstrip("="))

        # Test with voip_token
        config = APNsPushConfig(token="test_token", voip_token="voip_token")
        attrs = config.get_push_config_attrs()

        self.assertEqual(attrs["voip"], "voip_token")

    def test_web_push_config(self):
        """Test Web Push configuration."""
        config = WebPushConfig(
            endpoint="https://example.com/push",
            auth=b"auth_bytes",
            p256dh=b"p256dh_bytes"
        )
        attrs = config.get_push_config_attrs()

        self.assertEqual(attrs["platform"], "web")
        self.assertEqual(attrs["endpoint"], "https://example.com/push")
        self.assertEqual(attrs["auth"], base64.b64encode(b"auth_bytes").decode())
        self.assertEqual(attrs["p256dh"], base64.b64encode(b"p256dh_bytes").decode())

class TestPushNotificationHandler(unittest.IsolatedAsyncioTestCase):
    """Test the push notification handler."""

    async def test_get_server_push_notification_config(self):
        """Test getting server push notification config."""
        mock_client = MagicMock()
        mock_client.send_iq = AsyncMock(return_value=(binary_node.Node("result", {}), None))

        handler = PushNotificationHandler(mock_client)
        result = await handler.get_server_push_notification_config()

        self.assertEqual(result.tag, "result")
        mock_client.send_iq.assert_called_once()
        call_args = mock_client.send_iq.call_args[0][0]
        self.assertEqual(call_args["namespace"], "urn:xmpp:whatsapp:push")
        self.assertEqual(call_args["type"], "get")

    async def test_register_for_push_notifications(self):
        """Test registering for push notifications."""
        mock_client = MagicMock()
        mock_client.send_iq = AsyncMock(return_value=(None, None))

        handler = PushNotificationHandler(mock_client)
        config = FCMPushConfig(token="test_token")
        await handler.register_for_push_notifications(config)

        mock_client.send_iq.assert_called_once()
        call_args = mock_client.send_iq.call_args[0][0]
        self.assertEqual(call_args["namespace"], "urn:xmpp:whatsapp:push")
        self.assertEqual(call_args["type"], "set")
        self.assertEqual(call_args["content"][0].tag, "config")
        self.assertEqual(call_args["content"][0].attributes["id"], "test_token")

    async def test_error_handling(self):
        """Test error handling in push notification methods."""
        mock_client = MagicMock()
        mock_error = Exception("Test error")
        mock_client.send_iq = AsyncMock(return_value=(None, mock_error))

        handler = PushNotificationHandler(mock_client)
        config = FCMPushConfig(token="test_token")

        with self.assertRaises(Exception) as context:
            await handler.register_for_push_notifications(config)

        self.assertEqual(str(context.exception), "Test error")

if __name__ == "__main__":
    unittest.main()
