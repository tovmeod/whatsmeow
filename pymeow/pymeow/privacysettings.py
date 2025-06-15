"""
WhatsApp privacy settings handling.

Port of whatsmeow/privacysettings.go
"""
import logging
from dataclasses import dataclass
from datetime import timedelta
from enum import Enum
from typing import TYPE_CHECKING, Optional, Tuple

from . import request
from .exceptions import ElementMissingError, ErrClientIsNil
from .request import InfoQuery, InfoQueryType
from .types.events import PrivacySettingsEvent
from .types.jid import SERVER_JID

if TYPE_CHECKING:
    from .binary.node import Node
    from .client import Client

class PrivacySettingType(str, Enum):
    """Types of WhatsApp privacy settings."""
    GROUP_ADD = "groupadd"
    LAST_SEEN = "last"
    STATUS = "status"
    PROFILE = "profile"
    READ_RECEIPTS = "readreceipts"
    ONLINE = "online"
    CALL_ADD = "calladd"

class PrivacySetting(str, Enum):
    """Values for privacy settings."""
    ALL = "all"
    CONTACTS = "contacts"
    CONTACT_BLACKLIST = "contact-blacklist"
    NONE = "none"
    MATCH_LAST_SEEN = "match-last-seen"

@dataclass
class PrivacySettings:
    """Represents the privacy settings for an account."""
    group_add: PrivacySetting = PrivacySetting.ALL
    last_seen: PrivacySetting = PrivacySetting.ALL
    status: PrivacySetting = PrivacySetting.ALL
    profile: PrivacySetting = PrivacySetting.ALL
    read_receipts: PrivacySetting = PrivacySetting.ALL
    online: PrivacySetting = PrivacySetting.ALL
    call_add: PrivacySetting = PrivacySetting.ALL

logger = logging.getLogger(__name__)

async def try_fetch_privacy_settings(
    client: 'Client',
    ignore_cache: bool
) -> Tuple[Optional[PrivacySettings], Optional[Exception]]:
    """
    Port of Go method TryFetchPrivacySettings from privacy.go.

    Fetch the user's privacy settings, either from the in-memory cache or from the server.

    Args:
        client: The WhatsApp client instance
        ignore_cache: Whether to ignore the cached settings and fetch from server

    Returns:
        Tuple containing (PrivacySettings or None, error or None)
    """
    # TODO: Review PrivacySettings implementation
    # TODO: Review ErrClientIsNil implementation
    # TODO: Review privacy_settings_cache implementation
    # TODO: Review send_iq implementation
    # TODO: Review info_query implementation
    # TODO: Review IQ_GET constant implementation
    # TODO: Review SERVER_JID constant implementation
    # TODO: Review Node implementation
    # TODO: Review ElementMissingError implementation
    # TODO: Review parse_privacy_settings implementation
    from .binary.node import Node

    if client is None:
        return None, ErrClientIsNil

    if not ignore_cache:
        val = client._privacy_settings_cache.load()
        if val is not None:
            return val, None

    resp, err = await request.send_iq(client, InfoQuery(
        namespace="privacy",
        type=InfoQueryType.GET,
        to=SERVER_JID,
        content=[Node(tag="privacy")]
    ))

    if err is not None:
        return None, err

    privacy_node, ok = resp.get_optional_child_by_tag("privacy")
    if not ok:
        return None, ElementMissingError(
            tag="privacy",
            in_location="response to privacy settings query"
        )

    settings = PrivacySettings()
    parse_privacy_settings(client, privacy_node, settings)
    client._privacy_settings_cache.store(settings)
    return settings, None


async def get_privacy_settings(client: 'Client') -> PrivacySettings:
    """
    Port of Go method GetPrivacySettings from privacy.go.

    Get the user's privacy settings. If an error occurs while fetching them, the error will be
    logged, but the method will just return an empty struct.

    Args:
        client: The WhatsApp client instance

    Returns:
        PrivacySettings object (empty if error occurred)
    """
    # TODO: Review PrivacySettings implementation
    # TODO: Review try_fetch_privacy_settings implementation
    # TODO: Review MessengerConfig implementation
    # TODO: Review Log.errorf implementation

    settings = PrivacySettings()

    if client is None or client.messenger_config is not None:
        return settings

    settings_ptr, err = await try_fetch_privacy_settings(client, False)
    if err is not None:
        logger.error("Failed to fetch privacy settings: %v", err)
    else:
        settings = settings_ptr

    return settings


async def set_privacy_setting(
    client: 'Client',
    name: PrivacySettingType,
    value: PrivacySetting
) -> Tuple[PrivacySettings, Optional[Exception]]:
    """
    Port of Go method SetPrivacySetting from privacy.go.

    Set the given privacy setting to the given value.
    The privacy settings will be fetched from the server after the change and the new settings will be returned.
    If an error occurs while fetching the new settings, will return an empty struct.

    Args:
        client: The WhatsApp client instance
        name: The privacy setting type to change
        value: The new value for the privacy setting

    Returns:
        Tuple containing (PrivacySettings, error, or None)
    """
    # TODO: Review PrivacySettings implementation
    # TODO: Review PrivacySettingType implementation
    # TODO: Review PrivacySetting implementation
    # TODO: Review try_fetch_privacy_settings implementation
    # TODO: Review send_iq implementation
    # TODO: Review info_query implementation
    # TODO: Review IQ_SET constant implementation
    # TODO: Review SERVER_JID constant implementation
    # TODO: Review Node implementation
    # TODO: Review Attrs implementation
    # TODO: Review PRIVACY_SETTING_TYPE_* constants implementation
    # TODO: Review privacy_settings_cache implementation
    from .binary.attrs import Attrs
    from .binary.node import Node

    settings = PrivacySettings()

    settings_ptr, err = await try_fetch_privacy_settings(client, False)
    if err is not None:
        return settings, err

    _, err = await request.send_iq(client, InfoQuery(
        namespace="privacy",
        type=InfoQueryType.SET,
        to=SERVER_JID,
        content=[Node(
            tag="privacy",
            content=[Node(
                tag="category",
                attrs=Attrs({
                    "name": str(name),
                    "value": str(value),
                })
            )]
        )]
    ))

    if err is not None:
        return settings, err

    settings = settings_ptr

    if name == PrivacySettingType.GROUP_ADD:
        settings.group_add = value
    elif name == PrivacySettingType.LAST_SEEN:
        settings.last_seen = value
    elif name == PrivacySettingType.STATUS:
        settings.status = value
    elif name == PrivacySettingType.PROFILE:
        settings.profile = value
    elif name == PrivacySettingType.READ_RECEIPTS:
        settings.read_receipts = value
    elif name == PrivacySettingType.ONLINE:
        settings.online = value
    elif name == PrivacySettingType.CALL_ADD:
        settings.call_add = value

    client._privacy_settings_cache.store(settings)
    return settings, None


async def set_default_disappearing_timer(
    client: 'Client',
    timer: timedelta
) -> Optional[Exception]:
    """
    Port of Go method SetDefaultDisappearingTimer from disappearing.go.

    Set the default disappearing message timer.

    Args:
        client: The WhatsApp client instance
        timer: The duration for the disappearing message timer

    Returns:
        Exception if error occurred, None if successful
    """
    # TODO: Review send_iq implementation
    # TODO: Review info_query implementation
    # TODO: Review IQ_SET constant implementation
    # TODO: Review SERVER_JID constant implementation
    # TODO: Review Node implementation
    # TODO: Review Attrs implementation
    from .binary.attrs import Attrs
    from .binary.node import Node

    _, err = await request.send_iq(client, InfoQuery(
        namespace="disappearing_mode",
        type=InfoQueryType.SET,
        to=SERVER_JID,
        content=[Node(
            tag="disappearing_mode",
            attrs=Attrs({
                "duration": str(int(timer.total_seconds())),
            })
        )]
    ))

    return err


def parse_privacy_settings(
    client: 'Client',
    privacy_node: 'Node',
    settings: PrivacySettings
) -> PrivacySettingsEvent:
    """
    Port of Go method parsePrivacySettings from privacy.go.

    Parse privacy settings from a privacy node and update the settings object.
    Returns an event object indicating which settings were changed.

    Args:
        client: The WhatsApp client instance
        privacy_node: The privacy XML node to parse
        settings: The privacy settings object to update (modified in-place)

    Returns:
        PrivacySettingsEvent object indicating which settings were changed
    """
    # TODO: Review PrivacySettingsEvent implementation
    # TODO: Review Node.get_children implementation
    # TODO: Review Node.attr_getter implementation
    # TODO: Review AttrGetter.string implementation
    # TODO: Review PrivacySettingType implementation
    # TODO: Review PrivacySetting implementation
    # TODO: Review PRIVACY_SETTING_TYPE_* constants implementation

    evt = PrivacySettingsEvent()

    for child in privacy_node.get_children():
        if child.tag != "category":
            continue

        ag = child.attr_getter()
        name = PrivacySettingType(ag.string("name"))
        value = PrivacySetting(ag.string("value"))

        if name == PrivacySettingType.GROUP_ADD:
            settings.group_add = value
            evt.group_add_changed = True
        elif name == PrivacySettingType.LAST_SEEN:
            settings.last_seen = value
            evt.last_seen_changed = True
        elif name == PrivacySettingType.STATUS:
            settings.status = value
            evt.status_changed = True
        elif name == PrivacySettingType.PROFILE:
            settings.profile = value
            evt.profile_changed = True
        elif name == PrivacySettingType.READ_RECEIPTS:
            settings.read_receipts = value
            evt.read_receipts_changed = True
        elif name == PrivacySettingType.ONLINE:
            settings.online = value
            evt.online_changed = True
        elif name == PrivacySettingType.CALL_ADD:
            settings.call_add = value
            evt.call_add_changed = True

    return evt


async def handle_privacy_settings_notification(
    client: 'Client',
    privacy_node: 'Node'
) -> None:
    """
    Port of Go method handlePrivacySettingsNotification from privacy.go.

    Handle privacy settings change notification by parsing the notification,
    updating cached settings, and dispatching an event.

    Args:
        client: The WhatsApp client instance
        privacy_node: The privacy XML node containing the notification

    Returns:
        None
    """
    # TODO: Review try_fetch_privacy_settings implementation
    # TODO: Review parse_privacy_settings implementation
    # TODO: Review privacy_settings_cache implementation
    # TODO: Review dispatch_event implementation

    logger.debug("Parsing privacy settings change notification")

    settings, err = await try_fetch_privacy_settings(client, False)
    if err is not None:
        logger.error("Failed to fetch privacy settings when handling change: %v", err)
        return

    evt = parse_privacy_settings(client, privacy_node, settings)
    client._privacy_settings_cache.store(settings)
    await client.dispatch_event(evt)
