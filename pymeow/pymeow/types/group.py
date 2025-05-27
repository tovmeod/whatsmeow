"""
Group-related types for PyMeow.
"""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any

from .jid import JID

class GroupLinkChangeType(str, Enum):
    """Types of group link changes."""
    PARENT = "parent"
    SIBLING = "sibling"
    SUB = "sub"
    DEFAULT = ""

class GroupUnlinkReason(str, Enum):
    """Reasons for unlinking a group."""
    DEFAULT = ""
    DELETE = "delete"

@dataclass
class GroupParticipant:
    """Represents a participant in a group."""
    jid: JID
    is_admin: bool = False
    is_super_admin: bool = False
    is_creator: bool = False
    is_announce: bool = False
    is_locked: bool = False

@dataclass
class GroupInfo:
    """Contains information about a group."""
    jid: JID
    owner_jid: JID
    subject: str
    subject_owner: Optional[JID] = None
    subject_time: Optional[datetime] = None
    creation: Optional[datetime] = None
    participants: List[GroupParticipant] = None
    description: Optional[str] = None
    description_id: Optional[str] = None
    description_time: Optional[datetime] = None
    description_owner: Optional[JID] = None
    locked: bool = False
    announce: bool = True
    restrict: bool = False
    no_frequently_forwarded: bool = False
    ephemeral_duration: Optional[int] = None
    size: Optional[int] = None
    support: bool = False
    is_parent: bool = False
    is_default_sub_group: bool = False
    default_sub_group_jid: Optional[JID] = None
    is_main_sub_group: bool = False
    parent_group_jids: List[JID] = None
    linked_parent_jid: Optional[JID] = None
    linked_parent_name: Optional[str] = None
    linked_children: List[Dict[str, Any]] = None
    membership_approval_mode: bool = False
    member_add_mode: str = "all"  # 'all', 'admin_add', 'unknown'
    join_approval_mode: bool = False
    join_approval_requests_pending: int = 0
    is_community: bool = False
    is_community_verified: bool = False
    community_restricted: bool = False
    community_default: bool = False
    community_parent: bool = False
    community_id: Optional[str] = None
    community_announce: bool = False
    community_restrict: bool = False
    community_no_frequently_forwarded: bool = False
    community_ephemeral: Optional[int] = None
    community_default_membership_approval: bool = False
    community_default_add_mode: str = "all"
    community_default_join_approval_mode: bool = False
    community_default_join_approval_requests_pending: int = 0
    community_default_join_approval_requests_pending_count: int = 0
    community_default_join_approval_requests_pending_up_to: Optional[datetime] = None
    community_default_join_approval_requests_pending_since: Optional[datetime] = None
    community_default_join_approval_requests_pending_sender: Optional[JID] = None
    community_default_join_approval_requests_pending_name: Optional[str] = None
    community_default_join_approval_requests_pending_count: int = 0
    community_default_join_approval_requests_pending_up_to: Optional[datetime] = None
    community_default_join_approval_requests_pending_since: Optional[datetime] = None
    community_default_join_approval_requests_pending_sender: Optional[JID] = None
    community_default_join_approval_requests_pending_name: Optional[str] = None
    community_default_join_approval_requests_pending_count: int = 0
    community_default_join_approval_requests_pending_up_to: Optional[datetime] = None
    community_default_join_approval_requests_pending_since: Optional[datetime] = None
    community_default_join_approval_requests_pending_sender: Optional[JID] = None
    community_default_join_approval_requests_pending_name: Optional[str] = None

    def __post_init__(self):
        if self.participants is None:
            self.participants = []
        if self.parent_group_jids is None:
            self.parent_group_jids = []
        if self.linked_children is None:
            self.linked_children = []

@dataclass
class GroupLinkInfo:
    """Information about a group's invite link."""
    code: str
    group_jid: JID
    group_name: str
    group_is_default_sub_group: bool
    group_size: int
    approval_required: bool
    invite_code: str
    invite_expiration: Optional[datetime] = None
    invite_link: Optional[str] = None
    invite_link_parent_group: Optional[bool] = None
    invite_link_parent_group_pending_admin_approval: Optional[bool] = None
    invite_link_parent_group_pending_admin_approval_count: Optional[int] = None
    invite_link_parent_group_pending_admin_approval_up_to: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_since: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_sender: Optional[JID] = None
    invite_link_parent_group_pending_admin_approval_name: Optional[str] = None
    invite_link_parent_group_pending_admin_approval_count: Optional[int] = None
    invite_link_parent_group_pending_admin_approval_up_to: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_since: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_sender: Optional[JID] = None
    invite_link_parent_group_pending_admin_approval_name: Optional[str] = None
    invite_link_parent_group_pending_admin_approval_count: Optional[int] = None
    invite_link_parent_group_pending_admin_approval_up_to: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_since: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_sender: Optional[JID] = None
    invite_link_parent_group_pending_admin_approval_name: Optional[str] = None
    invite_link_parent_group_pending_admin_approval_count: Optional[int] = None
    invite_link_parent_group_pending_admin_approval_up_to: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_since: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_sender: Optional[JID] = None
    invite_link_parent_group_pending_admin_approval_name: Optional[str] = None
    invite_link_parent_group_pending_admin_approval_count: Optional[int] = None
    invite_link_parent_group_pending_admin_approval_up_to: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_since: Optional[datetime] = None
    invite_link_parent_group_pending_admin_approval_sender: Optional[JID] = None
    invite_link_parent_group_pending_admin_approval_name: Optional[str] = None
