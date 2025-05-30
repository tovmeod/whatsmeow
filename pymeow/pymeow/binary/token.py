"""
Token handling for WhatsApp binary protocol.

Port of whatsmeow/binary/token/token.go
"""
from typing import Dict, Tuple, Optional, List

# All the currently known string tokens.
# Note: These arrays are placeholders and need to be filled with the actual tokens
# from the Go file.
SINGLE_BYTE_TOKENS = ["", "xmlstreamstart", "xmlstreamend", "s.whatsapp.net", "type"]  # Placeholder
DOUBLE_BYTE_TOKENS = [
    ["read-self", "active"],  # Placeholder for dictionary 0
    ["reject", "dirty"],      # Placeholder for dictionary 1
    ["64", "ptt_playback_speed"],  # Placeholder for dictionary 2
    ["1724", "profile_picture"],   # Placeholder for dictionary 3
]

# DictVersion is the version number of the token lists above.
# It's sent when connecting to the websocket so the server knows which tokens are supported.
DICT_VERSION = 3

# Maps for efficient token lookup
_md_single_byte_token_index: Dict[str, int] = {}
_md_double_byte_token_index: Dict[str, Tuple[int, int]] = {}

# Initialize the maps
for index, token in enumerate(SINGLE_BYTE_TOKENS):
    if token:
        _md_single_byte_token_index[token] = index

for dict_index, tokens in enumerate(DOUBLE_BYTE_TOKENS):
    for index, token in enumerate(tokens):
        _md_double_byte_token_index[token] = (dict_index, index)

def get_double_token(index1: int, index2: int) -> Tuple[str, Optional[Exception]]:
    """
    Get the string value of the double-byte token at the given index.

    Args:
        index1: The dictionary index
        index2: The token index within the dictionary

    Returns:
        A tuple containing the token string and an optional error
    """
    if index1 < 0 or index1 >= len(DOUBLE_BYTE_TOKENS):
        return "", ValueError(f"index out of double byte token bounds {index1}-{index2}")
    elif index2 < 0 or index2 >= len(DOUBLE_BYTE_TOKENS[index1]):
        return "", ValueError(f"index out of double byte token index {index1} bounds {index2}")

    return DOUBLE_BYTE_TOKENS[index1][index2], None

def index_of_single_token(token: str) -> Tuple[int, bool]:
    """
    Get the index of the single-byte token with the given string value.

    Args:
        token: The token string to look up

    Returns:
        A tuple containing the token index and a boolean indicating if the token was found
    """
    val = _md_single_byte_token_index.get(token)
    return val if val is not None else 0, val is not None

def index_of_double_byte_token(token: str) -> Tuple[int, int, bool]:
    """
    Get the index of the double-byte token with the given string value.

    Args:
        token: The token string to look up

    Returns:
        A tuple containing the dictionary index, token index, and a boolean indicating if the token was found
    """
    val = _md_double_byte_token_index.get(token)
    if val is not None:
        return val[0], val[1], True
    else:
        return 0, 0, False

# Type tokens used in the binary XML representation.
LIST_EMPTY = 0
DICTIONARY_0 = 236
DICTIONARY_1 = 237
DICTIONARY_2 = 238
DICTIONARY_3 = 239
INTEROP_JID = 245
FB_JID = 246
AD_JID = 247
LIST_8 = 248
LIST_16 = 249
JID_PAIR = 250
HEX_8 = 251
BINARY_8 = 252
BINARY_20 = 253
BINARY_32 = 254
NIBBLE_8 = 255

# Other constants
PACKED_MAX = 127
SINGLE_BYTE_MAX = 256
