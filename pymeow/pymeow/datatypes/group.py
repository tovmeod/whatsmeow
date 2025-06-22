"""
Group-related types for PyMeow.

Port of whatsmeow/types/group.go
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional

from .jid import JID
from .message import AddressingMode


class GroupMemberAddMode(str, Enum):
    """Modes for adding members to a group."""

    ADMIN = "admin_add"
    ALL_MEMBER = "all_member_add"


@dataclass
class GroupMembershipApprovalMode:
    """Settings for group membership approval."""

    is_join_approval_required: bool = False


@dataclass
class GroupParent:
    """Information about a parent group."""

    is_parent: bool = False
    default_membership_approval_mode: str = ""


@dataclass
class GroupLinkedParent:
    """Information about a linked parent group."""

    linked_parent_jid: Optional[JID] = None


@dataclass
class GroupIsDefaultSub:
    """Information about whether a group is a default subgroup."""

    is_default_sub_group: bool = False


@dataclass
class GroupName:
    """Contains the name of a group along with metadata of who set it and when."""

    name: str = ""
    name_set_at: Optional[datetime] = None
    name_set_by: Optional[JID] = None
    name_set_by_pn: Optional[JID] = None


@dataclass
class GroupTopic:
    """Contains the topic (description) of a group along with metadata of who set it and when."""

    topic: str = ""
    topic_id: str = ""
    topic_set_at: Optional[datetime] = None
    topic_set_by: Optional[JID] = None
    topic_set_by_pn: Optional[JID] = None
    topic_deleted: bool = False


@dataclass
class GroupLocked:
    """Specifies whether the group info can only be edited by admins."""

    is_locked: bool = False


@dataclass
class GroupAnnounce:
    """Specifies whether only admins can send messages in the group."""

    is_announce: bool = False
    announce_version_id: str = ""


@dataclass
class GroupIncognito:
    """Specifies whether the group is in incognito mode."""

    is_incognito: bool = False


@dataclass
class GroupParticipantAddRequest:
    """Information about a request to add a participant to a group."""

    code: str = ""
    expiration: Optional[datetime] = None


@dataclass
class GroupParticipant:
    """Contains info about a participant of a WhatsApp group chat."""

    jid: JID
    phone_number: Optional[JID] = None
    lid: Optional[JID] = None

    is_admin: bool = False
    is_super_admin: bool = False

    display_name: str = ""

    error: int = 0
    add_request: Optional[GroupParticipantAddRequest] = None


@dataclass
class GroupEphemeral:
    """Contains the group's disappearing messages settings."""

    is_ephemeral: bool = False
    disappearing_timer: int = 0


@dataclass
class GroupDelete:
    """Information about a deleted group."""

    deleted: bool = False
    delete_reason: str = ""


class GroupLinkChangeType(str, Enum):
    """Types of group link changes."""

    PARENT = "parent_group"
    SUB = "sub_group"
    SIBLING = "sibling_group"


class GroupUnlinkReason(str, Enum):
    """Reasons for unlinking a group."""

    DEFAULT = "unlink_group"
    DELETE = "delete_parent"


@dataclass
class GroupLinkTarget:
    """Target information for group linking."""

    jid: Optional[JID] = None
    group_name: Optional[GroupName] = None
    group_is_default_sub: Optional[GroupIsDefaultSub] = None


@dataclass
class GroupLinkChange:
    """Information about a change in group linking."""

    type: Optional[GroupLinkChangeType] = None
    unlink_reason: Optional[GroupUnlinkReason] = None
    group: Optional[GroupLinkTarget] = None


@dataclass
class GroupParticipantRequest:
    """Information about a request to join a group."""

    jid: Optional[JID] = None
    requested_at: Optional[datetime] = None


@dataclass
class GroupInfo:
    """Contains basic information about a group chat on WhatsApp."""

    jid: Optional[JID] = None
    owner_jid: Optional[JID] = None
    owner_pn: Optional[JID] = None

    group_name: GroupName = field(default_factory=GroupName)
    group_topic: GroupTopic = field(default_factory=GroupTopic)
    group_locked: GroupLocked = field(default_factory=GroupLocked)
    group_announce: GroupAnnounce = field(default_factory=GroupAnnounce)
    group_ephemeral: GroupEphemeral = field(default_factory=GroupEphemeral)
    group_incognito: GroupIncognito = field(default_factory=GroupIncognito)

    group_parent: GroupParent = field(default_factory=GroupParent)
    group_linked_parent: GroupLinkedParent = field(default_factory=GroupLinkedParent)
    group_is_default_sub: GroupIsDefaultSub = field(default_factory=GroupIsDefaultSub)
    group_membership_approval_mode: GroupMembershipApprovalMode = field(default_factory=GroupMembershipApprovalMode)

    addressing_mode: Optional[AddressingMode] = None
    group_created: Optional[datetime] = None
    creator_country_code: str = ""

    participant_version_id: str = ""
    participants: List[GroupParticipant] = field(default_factory=list)

    member_add_mode: Optional[GroupMemberAddMode] = None
