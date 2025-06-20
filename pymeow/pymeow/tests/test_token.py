"""Test token handling for WhatsApp binary protocol."""

from ..pymeow.binary.token import (
    DICT_VERSION,
    DOUBLE_BYTE_TOKENS,
    SINGLE_BYTE_TOKENS,
    get_double_token,
    index_of_double_byte_token,
    index_of_single_token,
)


def test_dict_version():
    """Test that the dictionary version is set correctly."""
    assert DICT_VERSION == 3

def test_single_byte_tokens():
    """Test that single byte tokens are defined."""
    assert len(SINGLE_BYTE_TOKENS) > 0
    assert SINGLE_BYTE_TOKENS[0] == ""  # First token is always empty
    assert "xmlstreamstart" in SINGLE_BYTE_TOKENS
    assert "xmlstreamend" in SINGLE_BYTE_TOKENS
    assert "s.whatsapp.net" in SINGLE_BYTE_TOKENS
    assert "type" in SINGLE_BYTE_TOKENS

def test_double_byte_tokens():
    """Test that double byte tokens are defined."""
    assert len(DOUBLE_BYTE_TOKENS) > 0
    assert len(DOUBLE_BYTE_TOKENS[0]) > 0
    # Check first dictionary
    assert "read-self" in DOUBLE_BYTE_TOKENS[0]
    assert "active" in DOUBLE_BYTE_TOKENS[0]
    # Check second dictionary
    assert "reject" in DOUBLE_BYTE_TOKENS[1]
    assert "dirty" in DOUBLE_BYTE_TOKENS[1]
    # Check third dictionary
    assert "64" in DOUBLE_BYTE_TOKENS[2]
    assert "ptt_playback_speed" in DOUBLE_BYTE_TOKENS[2]
    # Check fourth dictionary
    assert "1724" in DOUBLE_BYTE_TOKENS[3]
    assert "profile_picture" in DOUBLE_BYTE_TOKENS[3]

def test_get_double_token():
    """Test getting double byte tokens."""
    # Valid token
    token, err = get_double_token(0, 0)
    assert err is None
    assert token == "read-self"

    # Invalid dictionary index
    token, err = get_double_token(99, 0)
    assert err is not None
    assert token == ""

    # Invalid token index
    token, err = get_double_token(0, 999)
    assert err is not None
    assert token == ""

def test_index_of_single_token():
    """Test finding index of single byte tokens."""
    # Valid token
    index, found = index_of_single_token("xmlstreamstart")
    assert found is True
    assert index > 0
    assert SINGLE_BYTE_TOKENS[index] == "xmlstreamstart"

    # Invalid token
    index, found = index_of_single_token("nonexistent_token")
    assert found is False
    assert index == 0

def test_index_of_double_byte_token():
    """Test finding index of double byte tokens."""
    # Valid token
    dict_index, token_index, found = index_of_double_byte_token("read-self")
    assert found is True
    assert dict_index == 0
    assert token_index == 0
    assert DOUBLE_BYTE_TOKENS[dict_index][token_index] == "read-self"

    # Invalid token
    dict_index, token_index, found = index_of_double_byte_token("nonexistent_token")
    assert found is False
    assert dict_index == 0
    assert token_index == 0
