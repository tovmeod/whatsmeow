"""
Contact-related types for PyMeow.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Union, Any

from .jid import JID

class ContactStatus(str, Enum):
    """Possible statuses for a contact."""
    UNKNOWN = "unknown"
    NOT_CONTACT = "not_contact"
    USER = "user"
    IN_CONTACTS = "in_contacts"
    IN_CONTACTS_BLOCKED = "in_contacts_blocked"
    IN_CONTACTS_BLOCKED_REVERSE = "in_contacts_blocked_reverse"
    IN_CONTACTS_BLOCKED_BOTH = "in_contacts_blocked_both"
    IN_CONTACTS_BLOCKED_SELF = "in_contacts_blocked_self"

class ContactAction(str, Enum):
    """Possible actions for contact updates."""
    ADD = "add"
    REMOVE = "remove"
    UPDATE = "update"
    BLOCK = "block"
    UNBLOCK = "unblock"

@dataclass
class Contact:
    """Contains information about a contact."""
    jid: JID
    first_name: str = ""
    full_name: str = ""
    push_name: str = ""
    business_name: str = ""
    status: ContactStatus = ContactStatus.UNKNOWN
    is_contact: bool = False
    is_blocked: bool = False
    is_me: bool = False
    is_wa_user: bool = True
    is_enterprise: bool = False
    is_verified: bool = False
    is_in_contact_list: bool = False
    is_contact_blocked: bool = False
    is_contact_blocked_reverse: bool = False
    is_contact_blocked_both: bool = False
    is_contact_blocked_self: bool = False
    is_contact_blocked_unknown: bool = False
    is_contact_blocked_any: bool = False
    is_contact_blocked_none: bool = False
    labels: List[str] = field(default_factory=list)

    # Timestamps
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Profile information
    profile_pic_id: Optional[str] = None
    profile_pic_url: Optional[str] = None
    status_text: Optional[str] = None
    status_timestamp: Optional[datetime] = None

    # Business information
    business_hours_enabled: bool = False
    business_hours_timezone: Optional[str] = None
    business_hours_config: Optional[Dict[str, Any]] = None
    business_description: Optional[str] = None
    business_website: Optional[str] = None
    business_email: Optional[str] = None
    business_address: Optional[str] = None
    business_category: Optional[str] = None
    business_subcategory: Optional[str] = None

    def __post_init__(self):
        if isinstance(self.jid, str):
            self.jid = JID.from_string(self.jid)

    @property
    def display_name(self) -> str:
        """Get the best available display name."""
        return (
            self.business_name
            or self.push_name
            or self.full_name
            or self.first_name
            or str(self.jid.user)
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'jid': str(self.jid),
            'first_name': self.first_name,
            'full_name': self.full_name,
            'push_name': self.push_name,
            'business_name': self.business_name,
            'status': self.status.value,
            'is_contact': self.is_contact,
            'is_blocked': self.is_blocked,
            'is_wa_user': self.is_wa_user,
            'is_enterprise': self.is_enterprise,
            'is_verified': self.is_verified,
            'display_name': self.display_name,
            'profile_pic_url': self.profile_pic_url,
            'status_text': self.status_text,
        }
