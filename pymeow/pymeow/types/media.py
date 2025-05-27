"""
Media-related types for PyMeow.
"""
from enum import Enum
from typing import Optional, Dict, Any, Union, List
from dataclasses import dataclass, field

class MediaType(str, Enum):
    """Types of media that can be sent in messages."""
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    DOCUMENT = "document"
    STICKER = "sticker"
    GIF = "gif"

@dataclass
class MediaInfo:
    """Information about a media file."""
    media_type: MediaType
    url: Optional[str] = None
    mimetype: Optional[str] = None
    file_sha256: Optional[bytes] = None
    file_enc_sha256: Optional[bytes] = None
    file_length: Optional[int] = None
    media_key: Optional[bytes] = None
    width: Optional[int] = None
    height: Optional[int] = None
    direct_path: Optional[str] = None
    media_key_timestamp: Optional[int] = None
    file_name: Optional[str] = None
    file_hash: Optional[bytes] = None
    jpeg_thumbnail: Optional[bytes] = None
    context_info: Optional[Dict[str, Any]] = field(default_factory=dict)
    caption: Optional[str] = None
    seconds: Optional[int] = None  # For audio/video
    gif_playback: Optional[bool] = None
    gif_attribution: Optional[int] = None
    streaming_sidecar: Optional[bytes] = None
    animated_gif_playback: Optional[bool] = None
    first_frame_sidecar: Optional[bytes] = None
    first_frame_sidecar_rotation: Optional[int] = None
    view_once: Optional[bool] = None
    is_animated: Optional[bool] = None
