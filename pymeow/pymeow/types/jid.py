"""
JID (Jabber ID) type for PyMeow.

Port of whatsmeow/types/jid.go
"""
import re
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from signal_protocol import address

# Known JID servers on WhatsApp
DEFAULT_USER_SERVER = "s.whatsapp.net"
GROUP_SERVER = "g.us"
LEGACY_USER_SERVER = "c.us"
BROADCAST_SERVER = "broadcast"
HIDDEN_USER_SERVER = "lid"
MESSENGER_SERVER = "msgr"
INTEROP_SERVER = "interop"
NEWSLETTER_SERVER = "newsletter"
HOSTED_SERVER = "hosted"
BOT_SERVER = "bot"


# JID types for classification
class JIDType:
    """Types of JIDs for classification."""
    USER = "user"
    GROUP = "group"
    BROADCAST = "broadcast"
    STATUS_BROADCAST = "status_broadcast"
    NEWSLETTER = "newsletter"
    OTHER = "other"


# Bot user regex pattern
BOT_USER_REGEX = re.compile(r'^1313555\d{4}$|^131655500\d{2}$')


@dataclass(frozen=True)
class JID:
    """Represents a Jabber ID (JID) used in WhatsApp.

    There are two types of JIDs: regular JID pairs (user and server) and AD-JIDs (user, agent and device).
    AD JIDs are only used to refer to specific devices of users, so the server is always s.whatsapp.net (DEFAULT_USER_SERVER).
    Regular JIDs can be used for entities on any servers (users, groups, broadcasts).
    """
    user: str = ""
    server: str = ""
    raw_agent: int = 0
    device: int = 0
    integrator: int = 0

    @classmethod
    def server_jid(cls) -> 'JID':
        """Returns the WhatsApp server JID."""
        return cls(user="", server="s.whatsapp.net")

    def actual_agent(self) -> int:
        """Returns the actual agent value based on the server type."""
        if self.server == DEFAULT_USER_SERVER:
            return 0
        elif self.server == HIDDEN_USER_SERVER:
            return 1
        else:
            return self.raw_agent

    def user_int(self) -> int:
        """Returns the user as an integer. Only safe for normal users, not groups or broadcasts."""
        try:
            return int(self.user)
        except (ValueError, TypeError):
            return 0

    def to_non_ad(self) -> 'JID':
        """Returns a version of the JID struct that doesn't have the agent and device set."""
        return JID(
            user=self.user,
            server=self.server,
            integrator=self.integrator
        )

    def signal_address_user(self) -> str:
        """Returns the user part of the Signal protocol address."""
        user = self.user
        agent = self.actual_agent()
        if agent != 0:
            user = f"{self.user}_{agent}"
        return user

    def is_broadcast_list(self) -> bool:
        """Returns true if the JID is a broadcast list, but not the status broadcast."""
        return self.server == BROADCAST_SERVER and self.user != STATUS_BROADCAST_JID.user

    def is_bot(self) -> bool:
        """Returns true if the JID is a bot."""
        return ((self.server == DEFAULT_USER_SERVER and
                BOT_USER_REGEX.match(self.user) and
                self.device == 0) or
                self.server == BOT_SERVER)

    def ad_string(self) -> str:
        """Returns the AD string representation of the JID."""
        return f"{self.user}.{self.raw_agent}:{self.device}@{self.server}"

    def __str__(self) -> str:
        """Convert JID to string representation."""
        if self.raw_agent > 0:
            return f"{self.user}.{self.raw_agent}:{self.device}@{self.server}"
        elif self.device > 0:
            return f"{self.user}:{self.device}@{self.server}"
        elif self.user:
            return f"{self.user}@{self.server}"
        else:
            return self.server

    def is_empty(self) -> bool:
        """Returns true if the JID has no server (which is required for all JIDs)."""
        return not self.server

    def get_type(self) -> str:
        """Get the type of JID (user, group, broadcast, etc.)."""
        if self.server == DEFAULT_USER_SERVER or self.server == LEGACY_USER_SERVER:
            return JIDType.USER
        elif self.server == GROUP_SERVER:
            return JIDType.GROUP
        elif self.server == BROADCAST_SERVER:
            if self.user == "status":
                return JIDType.STATUS_BROADCAST
            return JIDType.BROADCAST
        elif self.server == NEWSLETTER_SERVER:
            return JIDType.NEWSLETTER
        return JIDType.OTHER

    # Convenience methods for checking JID types
    def is_user(self) -> bool:
        """Returns true if the JID is a user."""
        return self.server == DEFAULT_USER_SERVER or self.server == LEGACY_USER_SERVER

    def is_group(self) -> bool:
        """Returns true if the JID is a group."""
        return self.server == GROUP_SERVER

    def is_broadcast(self) -> bool:
        """Returns true if the JID is a broadcast."""
        return self.server == BROADCAST_SERVER

    def is_status_broadcast(self) -> bool:
        """Returns true if the JID is the status broadcast."""
        return self.server == BROADCAST_SERVER and self.user == "status"

    def is_newsletter(self) -> bool:
        """Returns true if the JID is a newsletter."""
        return self.server == NEWSLETTER_SERVER

    @classmethod
    def new_jid(cls, user: str, server: str) -> 'JID':
        """Creates a new regular JID."""
        return cls(user=user, server=server)

    @classmethod
    def new_ad_jid(cls, user: str, agent: int, device: int) -> 'JID':
        """Creates a new AD JID."""
        server = DEFAULT_USER_SERVER
        raw_agent = agent

        if agent == 0:
            server = DEFAULT_USER_SERVER
        elif agent == 1:
            server = HIDDEN_USER_SERVER
            raw_agent = 0
        else:
            # In Go: if (agent&0x01) != 0 || (agent&0x80) == 0 { /* TODO invalid JID? */ }
            if (agent & 0x01) != 0 or (agent & 0x80) == 0:
                # TODO: Handle invalid JID?
                pass
            server = HOSTED_SERVER

        return cls(user=user, server=server, raw_agent=raw_agent, device=device)

    @classmethod
    def parse_jid(cls, jid_str: str) -> 'JID':
        """Parses a JID out of the given string. Supports both regular and AD JIDs.
        Raises:
            ValueError:
        """
        parts = jid_str.split('@')
        if len(parts) == 1:
            return cls.new_jid("", parts[0])

        parsed_jid = cls.new_jid(parts[0], parts[1])

        if '.' in parsed_jid.user:
            user_parts = parsed_jid.user.split('.')
            if len(user_parts) != 2:
                raise ValueError("Unexpected number of dots in JID")

            parsed_jid = cls(
                user=user_parts[0],
                server=parsed_jid.server,
                integrator=parsed_jid.integrator
            )

            ad = user_parts[1]
            ad_parts = ad.split(':')

            if len(ad_parts) > 2:
                raise ValueError("Unexpected number of colons in JID")

            try:
                agent = int(ad_parts[0])
                parsed_jid = cls(
                    user=parsed_jid.user,
                    server=parsed_jid.server,
                    raw_agent=agent,
                    integrator=parsed_jid.integrator
                )

                if len(ad_parts) == 2:
                    device = int(ad_parts[1])
                    parsed_jid = cls(
                        user=parsed_jid.user,
                        server=parsed_jid.server,
                        raw_agent=parsed_jid.raw_agent,
                        device=device,
                        integrator=parsed_jid.integrator
                    )
            except ValueError as e:
                raise ValueError(f"Failed to parse device from JID: {e}")

        elif ':' in parsed_jid.user:
            user_parts = parsed_jid.user.split(':')
            if len(user_parts) != 2:
                raise ValueError("Unexpected number of colons in JID")

            parsed_jid = cls(
                user=user_parts[0],
                server=parsed_jid.server,
                integrator=parsed_jid.integrator
            )

            try:
                device = int(user_parts[1])
                parsed_jid = cls(
                    user=parsed_jid.user,
                    server=parsed_jid.server,
                    raw_agent=parsed_jid.raw_agent,
                    device=device,
                    integrator=parsed_jid.integrator
                )
            except ValueError as e:
                raise ValueError(f"Failed to parse device from JID: {e}")

        return parsed_jid

    @classmethod
    def from_string(cls, jid: Optional[Union[str, 'JID']]) -> Optional['JID']:
        """Create a JID from a string."""
        if not jid:
            return None
        if isinstance(jid, JID):
            return jid
        return cls.parse_jid(jid)

    @classmethod
    def from_user_id(cls, user_id: str, device: int = 0, agent: int = 0) -> 'JID':
        """Create a JID from a user ID."""
        if '@' in user_id:
            user, server = user_id.split('@', 1)
            return cls(user=user, server=server, device=device, raw_agent=agent)
        return cls(user="", server=user_id, device=device, raw_agent=agent)

    @classmethod
    def new_user_jid(cls, user: str, device: int = 0) -> 'JID':
        """Creates a new user JID."""
        return cls(user=user, server=DEFAULT_USER_SERVER, device=device)

    @classmethod
    def new_group_jid(cls, group_id: str) -> 'JID':
        """Creates a new group JID."""
        return cls(user=group_id, server=GROUP_SERVER)

    @classmethod
    def new_broadcast_jid(cls, broadcast_id: str) -> 'JID':
        """Creates a new broadcast JID."""
        return cls(user=broadcast_id, server=BROADCAST_SERVER)

    @classmethod
    def new_status_broadcast_jid(cls) -> 'JID':
        """Creates a new status broadcast JID."""
        return cls(user="status", server=BROADCAST_SERVER)

    @classmethod
    def new_newsletter_jid(cls, newsletter_id: str) -> 'JID':
        """Creates a new newsletter JID."""
        return cls(user=newsletter_id, server=NEWSLETTER_SERVER)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'user': self.user,
            'server': self.server,
            'raw_agent': self.raw_agent,
            'device': self.device,
            'integrator': self.integrator
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JID':
        """Create from a dictionary."""
        return cls(
            user=data.get('user', ''),
            server=data.get('server', ''),
            raw_agent=data.get('raw_agent', 0),
            device=data.get('device', 0),
            integrator=data.get('integrator', 0)
        )

    def __eq__(self, other: object) -> bool:
        """Check if two JIDs are equal."""
        if not isinstance(other, JID):
            return False
        return (self.user == other.user and
                self.server == other.server and
                self.raw_agent == other.raw_agent and
                self.device == other.device and
                self.integrator == other.integrator)

    def __hash__(self) -> int:
        """Hash function for JID."""
        return hash((self.user, self.server, self.raw_agent, self.device, self.integrator))

    def signal_address(self) -> address.ProtocolAddress:
        """Returns the Signal protocol address for the user.

        Returns an Address object from the signal_protocol package, which is the Python
        equivalent of protocol.SignalAddress in the Go implementation.
        """
        return address.ProtocolAddress(self.signal_address_user(), self.device)


# Initialize predefined JIDs
EMPTY_JID = JID(user="", server="")
GROUP_SERVER_JID = JID(user="", server=GROUP_SERVER)
SERVER_JID = JID(user="", server=DEFAULT_USER_SERVER)
BROADCAST_SERVER_JID = JID(user="", server=BROADCAST_SERVER)
STATUS_BROADCAST_JID = JID(user="status", server=BROADCAST_SERVER)
PSA_JID = JID(user="0", server=LEGACY_USER_SERVER)
OFFICIAL_BUSINESS_JID = JID(user="16505361212", server=LEGACY_USER_SERVER)
META_AI_JID = JID(user="13135550002", server=DEFAULT_USER_SERVER)
NEW_META_AI_JID = JID(user="867051314767696", server=BOT_SERVER)
