"""
JID (Jabber ID) type for PyMeow.
"""
from dataclasses import dataclass
from typing import Optional, Union, Tuple, Dict, Any
import re


@dataclass(frozen=True)
class JID:
    """Represents a Jabber ID (JID) used in WhatsApp.
    
    A JID typically follows the format: [user@]domain[/resource]
    """
    user: Optional[str]
    server: str
    device: int = 0
    agent: int = 0
    _regex = re.compile(r'^(([^@/]*)@)?([^@/]+)(?::([0-9]+))?(?::([0-9]+))?(?:/([^@]+))?$')

    def __str__(self) -> str:
        """Convert JID to string representation."""
        result = ''
        if self.user is not None:
            result += f"{self.user}@"
        result += self.server
        if self.device > 0:
            result += f":{self.device}"
        if self.agent > 0:
            result += f":{self.agent}"
        return result

    def to_string(self, include_agent: bool = False) -> str:
        """Convert JID to string with optional agent inclusion."""
        result = str(self)
        if self.agent > 0 and include_agent:
            result += f":{self.agent}"
        return result

    def to_user_id(self) -> str:
        """Convert to a user ID string (without server)."""
        if self.user is None:
            return self.server
        return f"{self.user}@{self.server}"

    def to_non_ad(self) -> 'JID':
        """Convert to a non-AD JID (removes agent)."""
        return JID(user=self.user, server=self.server, device=self.device)

    def to_string_unsafe(self) -> str:
        """Convert to string without any escaping (use with caution)."""
        return str(self)

    def get_type(self) -> str:
        """Get the type of JID (user, group, broadcast, etc.)."""
        if self.server == 's.whatsapp.net':
            return 'user'
        elif self.server.endswith('.broadcast'):
            return 'broadcast'
        elif self.server.endswith('.g.us'):
            return 'group'
        elif self.server.endswith('.call'):
            return 'call'
        elif self.server.endswith('.newsletter'):
            return 'newsletter'
        return 'other'

    def is_empty(self) -> bool:
        """Check if the JID is empty."""
        return not self.server

    def is_linked(self) -> bool:
        """Check if this is a linked JID (has a device)."""
        return self.device > 0

    @classmethod
    def from_string(cls, jid: Optional[Union[str, 'JID']]) -> Optional['JID']:
        """Create a JID from a string."""
        if not jid:
            return None
        if isinstance(jid, JID):
            return jid
            
        match = cls._regex.match(jid)
        if not match:
            return None
            
        user = match.group(2)
        server = match.group(3)
        device = int(match.group(4) or 0)
        agent = int(match.group(5) or 0)
        
        return cls(user=user, server=server, device=device, agent=agent)

    @classmethod
    def from_user_id(cls, user_id: str, device: int = 0, agent: int = 0) -> 'JID':
        """Create a JID from a user ID (user@server)."""
        if '@' in user_id:
            user, server = user_id.split('@', 1)
            return cls(user=user, server=server, device=device, agent=agent)
        return cls(user=None, server=user_id, device=device, agent=agent)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a dictionary."""
        return {
            'user': self.user,
            'server': self.server,
            'device': self.device,
            'agent': self.agent
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JID':
        """Create from a dictionary."""
        return cls(
            user=data.get('user'),
            server=data.get('server', ''),
            device=data.get('device', 0),
            agent=data.get('agent', 0)
        )

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, JID):
            return False
        return (self.user == other.user and 
                self.server == other.server and 
                self.device == other.device and 
                self.agent == other.agent)

    def __hash__(self) -> int:
        return hash((self.user, self.server, self.device, self.agent))
