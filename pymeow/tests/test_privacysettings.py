"""Test privacy settings handling."""
import pytest
from pymeow.privacysettings import PrivacySettings, PrivacySettingType, PrivacyValue

def test_set_and_get_privacy():
    """Test setting and getting privacy settings."""
    settings = PrivacySettings()

    # Set a basic privacy setting
    settings.set_privacy(PrivacySettingType.LAST_SEEN, PrivacyValue.CONTACTS)
    value, excluded = settings.get_privacy(PrivacySettingType.LAST_SEEN)
    assert value == PrivacyValue.CONTACTS
    assert excluded == []

def test_privacy_with_exclusions():
    """Test privacy settings with excluded JIDs."""
    settings = PrivacySettings()
    excluded_jids = ["123@s.whatsapp.net", "456@s.whatsapp.net"]

    settings.set_privacy(
        PrivacySettingType.GROUPS,
        PrivacyValue.CONTACT_BLACKLIST,
        excluded_jids
    )

    value, excluded = settings.get_privacy(PrivacySettingType.GROUPS)
    assert value == PrivacyValue.CONTACT_BLACKLIST
    assert excluded == excluded_jids

def test_undefined_privacy():
    """Test getting undefined privacy settings."""
    settings = PrivacySettings()

    # Getting an unset privacy setting should return None
    value, excluded = settings.get_privacy(PrivacySettingType.STATUS)
    assert value is None
    assert excluded == []

def test_update_privacy():
    """Test updating existing privacy settings."""
    settings = PrivacySettings()

    # Set initial value
    settings.set_privacy(PrivacySettingType.PROFILE_PHOTO, PrivacyValue.ALL)

    # Update to new value
    settings.set_privacy(PrivacySettingType.PROFILE_PHOTO, PrivacyValue.NONE)

    value, _ = settings.get_privacy(PrivacySettingType.PROFILE_PHOTO)
    assert value == PrivacyValue.NONE
