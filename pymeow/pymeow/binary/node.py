"""
Node handling for WhatsApp binary protocol.

Port of whatsmeow/binary/node.go
"""
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple, TypeVar

from ..types.jid import JID, DEFAULT_USER_SERVER, GROUP_SERVER, NEWSLETTER_SERVER, BROADCAST_SERVER

# Type alias for attributes
Attrs = Dict[str, Any]

T = TypeVar('T')

class AttrGetter:
    """
    Helper class for safely extracting attributes from a Node with type conversion.
    """
    def __init__(self, attrs: Attrs):
        self.attrs = attrs

    def string(self, key: str) -> str:
        """Get a string attribute or empty string if not found."""
        return str(self.attrs.get(key, ""))

    def optional_string(self, key: str) -> Optional[str]:
        """Get a string attribute or None if not found."""
        value = self.attrs.get(key)
        return str(value) if value is not None else None

    def int(self, key: str) -> int:
        """Get an integer attribute or 0 if not found or not convertible."""
        try:
            return int(self.attrs.get(key, 0))
        except (ValueError, TypeError):
            return 0

    def optional_int(self, key: str) -> Optional[int]:
        """Get an integer attribute or None if not found or not convertible."""
        value = self.attrs.get(key)
        if value is None:
            return None
        try:
            return int(value)
        except (ValueError, TypeError):
            return None

    def jid(self, key: str) -> JID:
        """Get a JID attribute or empty JID if not found."""
        value = self.attrs.get(key, "")
        if isinstance(value, JID):
            return value
        return JID.from_string(str(value))

    def optional_jid(self, key: str) -> Optional[JID]:
        """Get a JID attribute or None if not found."""
        value = self.attrs.get(key)
        if value is None:
            return None
        if isinstance(value, JID):
            return value
        return JID.from_string(str(value))

    def unix_time(self, key: str) -> datetime:
        """Get a unix timestamp attribute as datetime or epoch if not found or not convertible."""
        try:
            timestamp = int(self.attrs.get(key, 0))
            return datetime.fromtimestamp(timestamp)
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0)

    def unix_milli(self, key: str) -> datetime:
        """Get a unix millisecond timestamp attribute as datetime or epoch if not found or not convertible."""
        try:
            timestamp = int(self.attrs.get(key, 0)) / 1000
            return datetime.fromtimestamp(timestamp)
        except (ValueError, TypeError):
            return datetime.fromtimestamp(0)

    def get_string(self, key: str, required: bool = False) -> Tuple[str, bool]:
        """Get a string attribute with existence check."""
        value = self.attrs.get(key)
        if value is None:
            return "", False
        return str(value), True

    def get_int(self, key: str, required: bool = False) -> Tuple[int, bool]:
        """Get an integer attribute with existence and conversion check."""
        value = self.attrs.get(key)
        if value is None:
            return 0, False
        try:
            return int(value), True
        except (ValueError, TypeError):
            return 0, False

    def get_jid(self, key: str, required: bool = False) -> Tuple[JID, bool]:
        """Get a JID attribute with existence check."""
        value = self.attrs.get(key)
        if value is None:
            return JID(), False
        if isinstance(value, JID):
            return value, True
        return JID.from_string(str(value)), True

@dataclass
class Node:
    """
    Represents an XML element in WhatsApp's binary protocol.

    This class is the core data structure for WhatsApp's binary XML format,
    containing a tag, attributes, and optional content.
    """
    tag: str
    attributes: Optional[Attrs] = field(default_factory=dict)
    content: Optional[Any] = None

    @property
    def attrs(self) -> Attrs:
        """Alias for attributes for compatibility with Go code."""
        return self.attributes

    def attr_getter(self) -> AttrGetter:
        """
        Returns an AttrGetter for this node's attributes.

        This provides type-safe attribute extraction methods.

        Returns:
            An AttrGetter instance for this node's attributes
        """
        return AttrGetter(self.attributes)

    def xml_string(self) -> str:
        """
        Returns a string representation of the node in XML format.

        This is primarily used for debugging purposes.

        Returns:
            String representation of the node
        """
        attrs_str = " ".join(f'{k}="{v}"' for k, v in self.attributes.items())
        if attrs_str:
            attrs_str = " " + attrs_str

        if self.content is None:
            return f"<{self.tag}{attrs_str}/>"
        elif isinstance(self.content, bytes):
            return f"<{self.tag}{attrs_str}>[binary data]</{self.tag}>"
        elif isinstance(self.content, list):
            children = []
            for child in self.content:
                if isinstance(child, Node):
                    children.append(child.xml_string())
                else:
                    children.append(str(child))
            content_str = "".join(children)
            return f"<{self.tag}{attrs_str}>{content_str}</{self.tag}>"
        else:
            return f"<{self.tag}{attrs_str}>{self.content}</{self.tag}>"

    def marshal(self) -> bytes:
        """
        Encodes this node into WhatsApp's binary XML representation.

        Returns:
            Binary XML representation of the node

        Raises:
            Exception: If encoding fails
        """
        from .encoder import new_encoder

        w = new_encoder()
        w.write_node(self)
        return w.get_data()

    @staticmethod
    def unmarshal(data: bytes) -> Tuple[Optional['Node'], Optional[Exception]]:
        """
        Decodes WhatsApp's binary XML representation into a Node.

        Args:
            data: Binary XML data to decode

        Returns:
            Tuple of (node, error) where error is None if decoding was successful
        """
        from .decoder import unmarshal as decoder_unmarshal

        return decoder_unmarshal(data)

    @staticmethod
    def unpack(data: bytes) -> bytes:
        """
        Unpack the given decrypted data from the WhatsApp web API.

        Args:
            data: The encrypted data to unpack

        Returns:
            The unpacked data

        Raises:
            ValueError: If the data is compressed but cannot be decompressed
        """
        from .unpack import unpack as unpack_data

        return unpack_data(data)

    def get_children(self) -> List['Node']:
        """
        Returns the Content of the node as a list of nodes.

        If the content is not a list of nodes, this returns an empty list.

        Returns:
            List of child nodes or empty list if content is not a list of nodes
        """
        if self.content is None:
            return []

        children = self.content if isinstance(self.content, list) else []
        return [child for child in children if isinstance(child, Node)]

    def get_children_by_tag(self, tag: str) -> List['Node']:
        """
        Returns the same list as get_children, but filters it by tag first.

        Args:
            tag: The tag to filter by

        Returns:
            List of child nodes with the specified tag
        """
        return [node for node in self.get_children() if node.tag == tag]

    def get_optional_child_by_tag(self, *tags: str) -> Tuple['Node', bool]:
        """
        Finds the first child with the given tag and returns it.

        Each provided tag will recurse in, so this is useful for getting
        a specific nested element.

        Args:
            *tags: Variable number of tags to navigate through

        Returns:
            Tuple containing (node, found) where found is True if the node was found
        """
        val = self

        for tag in tags:
            found = False
            for child in val.get_children():
                if child.tag == tag:
                    val = child
                    found = True
                    break

            if not found:
                # If no matching children are found, return false
                return val, False

        # All iterations of loop found a matching child, return it
        return val, True

    def get_child_by_tag(self, *tags: str) -> 'Node':
        """
        Does the same thing as get_optional_child_by_tag, but returns the Node directly.

        Args:
            *tags: Variable number of tags to navigate through

        Returns:
            The found node or an empty node if not found
        """
        node, _ = self.get_optional_child_by_tag(*tags)
        return node

    def unmarshal_json(self, data: bytes) -> None:
        """
        Unmarshal JSON data into this Node.

        Args:
            data: JSON data to unmarshal

        Raises:
            ValueError: If the JSON data is invalid
        """
        mn = json.loads(data)

        # Process attributes
        for key, val in mn.get('attrs', {}).items():
            if isinstance(val, str):
                # Try to parse JIDs
                try:
                    parsed = JID.from_string(val)
                    if (parsed and (parsed.server == DEFAULT_USER_SERVER or
                                   parsed.server == NEWSLETTER_SERVER or
                                   parsed.server == GROUP_SERVER or
                                   parsed.server == BROADCAST_SERVER)):
                        mn['attrs'][key] = parsed
                except:
                    pass
            elif isinstance(val, float):
                # Convert floats to ints
                mn['attrs'][key] = int(val)

        self.tag = mn.get('tag', '')
        self.attributes = mn.get('attrs', {})

        # Process content
        content = mn.get('content')
        if content:
            if isinstance(content, list):
                # Content is a list of nodes
                self.content = [Node(tag=n.get('tag', ''),
                                    attributes=n.get('attrs', {}),
                                    content=n.get('content'))
                               for n in content]
            elif isinstance(content, str):
                # Content is a binary string
                self.content = content.encode('utf-8')
            else:
                raise ValueError("node content must be an array of nodes or a base64 string")


def marshal(n: Node) -> bytes:
    """
    Encodes an XML element (Node) into WhatsApp's binary XML representation.

    Args:
        n: The node to marshal

    Returns:
        Binary XML representation of the node

    Raises:
        Exception: If encoding fails
    """
    from .encoder import new_encoder

    w = new_encoder()
    w.write_node(n)
    return w.get_data()


def unmarshal(data: bytes) -> Tuple[Optional[Node], Optional[Exception]]:
    """
    Decodes WhatsApp's binary XML representation into a Node.

    Args:
        data: Binary XML data to decode

    Returns:
        Tuple of (node, error) where error is None if decoding was successful
    """
    from .decoder import unmarshal as decoder_unmarshal

    return decoder_unmarshal(data)
