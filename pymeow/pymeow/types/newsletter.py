"""
Newsletter types for PyMeow.

Port of types/newsletter.go
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from .jid import JID
from .message import MessageServerID, MessageID
from .user import ProfilePictureInfo
from ..generated.waE2E import Message

# TODO: Verify import when util/jsontime is ported
# In Go: "go.mau.fi/util/jsontime"


class NewsletterVerificationState(str, Enum):
    """
    Verification state of a newsletter.

    Port of NewsletterVerificationState in Go.
    """
    VERIFIED = "verified"
    UNVERIFIED = "unverified"

    @classmethod
    def from_text(cls, text: str) -> 'NewsletterVerificationState':
        """Case-insensitive parsing like Go's UnmarshalText."""
        return cls(text.lower())


class NewsletterPrivacy(str, Enum):
    """
    Privacy setting of a newsletter.

    Port of NewsletterPrivacy in Go.
    """
    PRIVATE = "private"
    PUBLIC = "public"

    @classmethod
    def from_text(cls, text: str) -> 'NewsletterPrivacy':
        """Case-insensitive parsing like Go's UnmarshalText."""
        return cls(text.lower())


class NewsletterReactionsMode(str, Enum):
    """
    Reactions mode for a newsletter.

    Port of NewsletterReactionsMode in Go.
    """
    ALL = "all"
    BASIC = "basic"
    NONE = "none"
    BLOCKLIST = "blocklist"


class NewsletterState(str, Enum):
    """
    State of a newsletter.

    Port of NewsletterState in Go.
    """
    ACTIVE = "active"
    SUSPENDED = "suspended"
    GEO_SUSPENDED = "geosuspended"

    @classmethod
    def from_text(cls, text: str) -> 'NewsletterState':
        """Case-insensitive parsing like Go's UnmarshalText."""
        return cls(text.lower())


@dataclass
class NewsletterMuted:
    """
    Mute state of a newsletter.

    Port of NewsletterMuted in Go.
    """
    muted: bool


@dataclass
class WrappedNewsletterState:
    """
    Wrapped newsletter state.

    Port of WrappedNewsletterState in Go.
    """
    type: NewsletterState


class NewsletterMuteState(str, Enum):
    """
    Mute state of a newsletter.

    Port of NewsletterMuteState in Go.
    """
    ON = "on"
    OFF = "off"

    @classmethod
    def from_text(cls, text: str) -> 'NewsletterMuteState':
        """Case-insensitive parsing like Go's UnmarshalText."""
        return cls(text.lower())


class NewsletterRole(str, Enum):
    """
    Role in a newsletter.

    Port of NewsletterRole in Go.
    """
    SUBSCRIBER = "subscriber"
    GUEST = "guest"
    ADMIN = "admin"
    OWNER = "owner"

    @classmethod
    def from_text(cls, text: str) -> 'NewsletterRole':
        """Case-insensitive parsing like Go's UnmarshalText."""
        return cls(text.lower())


@dataclass
class NewsletterText:
    """
    Text content in a newsletter.

    Port of NewsletterText in Go.
    """
    text: str
    id: str
    update_time: datetime  # In Go: jsontime.UnixMicroString


@dataclass
class NewsletterReactionSettings:
    """
    Reaction settings for a newsletter.

    Port of NewsletterReactionSettings in Go.
    """
    value: NewsletterReactionsMode


@dataclass
class NewsletterSettings:
    """
    Settings for a newsletter.

    Port of NewsletterSettings in Go.
    """
    reaction_codes: NewsletterReactionSettings


@dataclass
class NewsletterThreadMetadata:
    """
    Metadata for a newsletter thread.

    Port of NewsletterThreadMetadata in Go.
    """
    creation_time: datetime  # In Go: jsontime.UnixString
    invite_code: str
    name: NewsletterText
    description: NewsletterText
    subscriber_count: int
    verification_state: NewsletterVerificationState
    preview: ProfilePictureInfo  # In Go: ProfilePictureInfo
    settings: NewsletterSettings
    picture: Optional[ProfilePictureInfo] = None  # In Go: *ProfilePictureInfo

    @classmethod
    def from_json(cls, data: dict) -> 'NewsletterThreadMetadata':
        """Handle JSON parsing with proper field mapping."""
        # Handle subscribers_count as string -> int conversion
        if 'subscribers_count' in data:
            data['subscriber_count'] = int(data.pop('subscribers_count'))
        return cls(**data)


@dataclass
class NewsletterViewerMetadata:
    """
    Metadata for a newsletter viewer.

    Port of NewsletterViewerMetadata in Go.
    """
    mute: NewsletterMuteState
    role: NewsletterRole


@dataclass
class NewsletterMetadata:
    """
    Metadata for a newsletter.

    Port of NewsletterMetadata in Go.
    """
    id: JID
    state: WrappedNewsletterState
    thread_meta: NewsletterThreadMetadata
    viewer_meta: Optional[NewsletterViewerMetadata] = None


class NewsletterKeyType(str, Enum):
    """
    Type of newsletter key.

    Port of NewsletterKeyType in Go.
    """
    JID = "JID"
    INVITE = "INVITE"


@dataclass
class NewsletterMessage:
    """
    A message in a newsletter.

    Port of NewsletterMessage in Go.
    """
    message_server_id: MessageServerID
    message_id: MessageID
    type: str
    timestamp: datetime
    views_count: int
    reaction_counts: Dict[str, int]
    message: Optional[Message] = None  # From protobuf


@dataclass
class GraphQLErrorExtensions:
    """
    Extensions for a GraphQL error.

    Port of GraphQLErrorExtensions in Go.
    """
    error_code: int
    is_retryable: bool
    severity: str


@dataclass
class GraphQLError:
    """
    A GraphQL error.

    Port of GraphQLError in Go.
    """
    extensions: GraphQLErrorExtensions
    message: str
    path: List[str]

    def __str__(self) -> str:
        """
        String representation of the error.

        Port of Error() method in Go.
        """
        return f"{self.extensions.error_code} {self.message} ({self.extensions.severity})"


class GraphQLErrors(Exception):
    """
    A list of GraphQL errors that can be raised as an exception.

    Port of GraphQLErrors in Go.
    """

    def __init__(self, errors: List[GraphQLError]):
        """Initialize with a list of GraphQL errors."""
        self.errors = errors
        super().__init__(str(self))

    def unwrap(self) -> List[Exception]:
        """
        Unwrap the errors into a list of exceptions.

        Port of Unwrap() method in Go.
        """
        return [Exception(str(err)) for err in self.errors]

    def __str__(self) -> str:
        """
        String representation of the errors.

        Port of Error() method in Go.
        """
        if not self.errors:
            return ""
        elif len(self.errors) == 1:
            return str(self.errors[0])
        else:
            return f"{self.errors[0]} (and {len(self.errors)-1} other errors)"

    def __len__(self) -> int:
        """Return the number of errors."""
        return len(self.errors)

    def __getitem__(self, index: int) -> GraphQLError:
        """Allow indexing into the errors."""
        return self.errors[index]

    def __iter__(self):
        """Allow iteration over the errors."""
        return iter(self.errors)


@dataclass
class GraphQLResponse:
    """
    A response from a GraphQL API.

    Port of GraphQLResponse in Go.
    """
    data: Any  # In Go: json.RawMessage
    errors: GraphQLErrors
