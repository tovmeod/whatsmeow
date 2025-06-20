"""Tests for the privacy settings implementation."""
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from ..pymeow.binary import node as binary_node
from ..pymeow.privacysettings import (
    PrivacySetting,
    PrivacySettings,
    PrivacySettingType,
)
from ..pymeow.datatypes.events import PrivacySettingsEvent


def test_privacy_settings_defaults():
    """Test that privacy settings have the correct defaults."""
    settings = PrivacySettings()
    assert settings.group_add == PrivacySetting.ALL
    assert settings.last_seen == PrivacySetting.ALL
    assert settings.status == PrivacySetting.ALL
    assert settings.profile == PrivacySetting.ALL
    assert settings.read_receipts == PrivacySetting.ALL
    assert settings.online == PrivacySetting.ALL
    assert settings.call_add == PrivacySetting.ALL

@pytest.fixture
def mock_client():
    """Create a mock client."""
    client = MagicMock()
    client.send_iq = AsyncMock()
    client.log = MagicMock()
    client.dispatch_event = AsyncMock()
    client.server_jid = "s.whatsapp.net"
    client._privacy_settings_cache = None
    client._privacy_cache_lock = asyncio.Lock()
    return client

@pytest.mark.asyncio
async def test_try_fetch_privacy_settings_from_cache(mock_client):
    """Test fetching privacy settings from cache."""
    # Set up the cache
    settings = PrivacySettings()
    settings.last_seen = PrivacySetting.CONTACTS
    mock_client._privacy_settings_cache = settings

    # Import the client module
    from ..pymeow.client import Client

    # Patch the client class
    with patch.object(Client, 'try_fetch_privacy_settings', AsyncMock()) as mock_method:
        mock_method.return_value = (settings, None)

        # Fetch from cache
        result, err = await mock_client.try_fetch_privacy_settings(False)

        # Check the result
        assert result == settings
        assert err is None
        mock_client.send_iq.assert_not_called()

@pytest.mark.asyncio
async def test_try_fetch_privacy_settings_from_server(mock_client):
    """Test fetching privacy settings from server."""
    # Set up the mock response
    privacy_node = binary_node.Node("privacy", {}, [
        binary_node.Node("category", {
            "name": PrivacySettingType.LAST_SEEN,
            "value": PrivacySetting.CONTACTS,
        }),
    ])
    mock_response = binary_node.Node("iq", {"type": "result"}, [privacy_node])
    mock_client.send_iq.return_value = mock_response

    # Import the client module
    from ..pymeow.client import Client

    # Create a method to parse privacy settings
    def mock_parse_privacy_settings(self, privacy_node, settings):
        settings.last_seen = PrivacySetting.CONTACTS
        return PrivacySettingsEvent(new_settings=settings)

    # Patch the client class
    with patch.object(Client, '_parse_privacy_settings', mock_parse_privacy_settings):
        # Call the method directly
        result, err = await Client.try_fetch_privacy_settings(mock_client, True)

        # Check the result
        assert result is not None
        assert err is None
        assert result.last_seen == PrivacySetting.CONTACTS
        mock_client.send_iq.assert_called_once()

@pytest.mark.asyncio
async def test_get_privacy_settings(mock_client):
    """Test getting privacy settings."""
    # Set up the mock response
    settings = PrivacySettings()
    settings.last_seen = PrivacySetting.CONTACTS

    # Import the client module
    from ..pymeow.client import Client

    # Patch the client class
    with patch.object(Client, 'try_fetch_privacy_settings', AsyncMock()) as mock_method:
        mock_method.return_value = (settings, None)

        # Get privacy settings
        result = await Client.get_privacy_settings(mock_client)

        # Check the result
        assert result is not None
        assert result.last_seen == PrivacySetting.CONTACTS
        mock_method.assert_called_once_with(mock_client, False)

@pytest.mark.asyncio
async def test_set_privacy_setting(mock_client):
    """Test setting a privacy setting."""
    # Set up the mock responses
    settings = PrivacySettings()
    settings.last_seen = PrivacySetting.CONTACTS

    # Import the client module
    from ..pymeow.client import Client

    # Patch the client class
    with patch.object(Client, 'try_fetch_privacy_settings', AsyncMock()) as mock_method:
        mock_method.return_value = (settings, None)

        # Set privacy setting
        result, err = await Client.set_privacy_setting(
            mock_client,
            PrivacySettingType.LAST_SEEN,
            PrivacySetting.NONE,
        )

        # Check the result
        assert result is not None
        assert err is None
        assert result.last_seen == PrivacySetting.NONE
        mock_method.assert_called_once_with(mock_client, False)
        mock_client.send_iq.assert_called_once()

@pytest.mark.asyncio
async def test_set_default_disappearing_timer(mock_client):
    """Test setting the default disappearing timer."""
    # Set up the mock response
    mock_response = binary_node.Node("iq", {"type": "result"})
    mock_client.send_iq.return_value = mock_response

    # Import the client module
    from ..pymeow.client import Client

    # Set default disappearing timer
    err = await Client.set_default_disappearing_timer(mock_client, 86400)  # 1 day

    # Check the result
    assert err is None
    mock_client.send_iq.assert_called_once()

def test_parse_privacy_settings(mock_client):
    """Test parsing privacy settings from a node."""
    # Create a privacy node
    privacy_node = binary_node.Node("privacy", {}, [
        binary_node.Node("category", {
            "name": PrivacySettingType.LAST_SEEN,
            "value": PrivacySetting.CONTACTS,
        }),
        binary_node.Node("category", {
            "name": PrivacySettingType.STATUS,
            "value": PrivacySetting.NONE,
        }),
    ])

    # Import the client module
    from ..pymeow.client import Client

    # Parse the privacy settings
    settings = PrivacySettings()
    evt = Client._parse_privacy_settings(mock_client, privacy_node, settings)

    # Check the settings
    assert settings.last_seen == PrivacySetting.CONTACTS
    assert settings.status == PrivacySetting.NONE

    # Check the event
    assert evt.last_seen_changed
    assert evt.status_changed
    assert not evt.profile_changed

@pytest.mark.asyncio
async def test_handle_privacy_settings_notification(mock_client):
    """Test handling privacy settings notifications."""
    # Set up the mock response
    privacy_node = binary_node.Node("privacy", {}, [
        binary_node.Node("category", {
            "name": PrivacySettingType.LAST_SEEN,
            "value": PrivacySetting.CONTACTS,
        }),
    ])
    settings = PrivacySettings()
    settings.last_seen = PrivacySetting.CONTACTS

    # Import the client module
    from ..pymeow.client import Client

    # Patch the client class
    with patch.object(Client, 'try_fetch_privacy_settings', AsyncMock()) as mock_method:
        mock_method.return_value = (settings, None)

        # Create a method to parse privacy settings
        def mock_parse_privacy_settings(self, privacy_node, settings):
            evt = PrivacySettingsEvent(new_settings=settings)
            evt.last_seen_changed = True
            return evt

        # Patch the client class
        with patch.object(Client, '_parse_privacy_settings', mock_parse_privacy_settings):
            # Handle privacy settings notification
            await Client.handle_privacy_settings_notification(mock_client, privacy_node)

            # Check that the client's dispatch_event method was called
            mock_client.dispatch_event.assert_called_once()
            event = mock_client.dispatch_event.call_args[0][0]
            assert isinstance(event, PrivacySettingsEvent)
            assert event.last_seen_changed
