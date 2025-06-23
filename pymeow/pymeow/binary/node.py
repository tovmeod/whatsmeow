"""
Node handling for WhatsApp binary protocol.

Port of whatsmeow/binary/node.go
"""

import json
import logging
from dataclasses import dataclass, field
from typing import List, Optional, Union

from .decoder import BinaryDecoder, DecodingError
from ..datatypes.jid import BROADCAST_SERVER, DEFAULT_USER_SERVER, GROUP_SERVER, JID, NEWSLETTER_SERVER
from .attrs import Attrs, AttrUtility

logger = logging.getLogger(__name__)


@dataclass
class Node:
    """
    Represents an XML element in WhatsApp's binary protocol.

    This class is the core data structure for WhatsApp's binary XML format,
    containing a tag, attributes, and optional content.
    """

    tag: str
    attrs: Attrs = field(default_factory=dict)
    content: Optional[Union[List["Node"], bytes]] = None

    def attr_getter(self) -> AttrUtility:
        """
        Returns the AttrUtility for this Node.

        This is equivalent to Go's (n *Node) AttrGetter() *AttrUtility
        """
        return AttrUtility(self.attrs)

    def xml_string(self) -> str:
        """
        Returns a string representation of the node in XML format.

        This is primarily used for debugging purposes.

        Returns:
            String representation of the node
        """
        attrs_str = " ".join(f'{k}="{v}"' for k, v in self.attrs.items())
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

    def get_children(self) -> List["Node"]:
        """
        Returns the Content of the node as a list of nodes.

        If the content is not a list of nodes, this returns an empty list.

        Returns:
            List of child nodes or empty list if content is not a list of nodes
        """
        if self.content is None:
            return []

        if isinstance(self.content, list):
            return [child for child in self.content if isinstance(child, Node)]

        return []

    def get_children_by_tag(self, tag: str) -> List["Node"]:
        """
        Returns the same list as get_children, but filters it by tag first.

        Args:
            tag: The tag to filter by

        Returns:
            List of child nodes with the specified tag
        """
        return [node for node in self.get_children() if node.tag == tag]

    def get_optional_child_by_tag(self, *tags: str) -> tuple["Node", bool]:
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

    def get_child_by_tag(self, *tags: str) -> "Node":
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
        attrs = mn.get("attrs", {})
        for key, val in attrs.items():
            if isinstance(val, str):
                # Try to parse JIDs
                try:
                    parsed = JID.from_string(val)
                    if parsed and (
                        parsed.server == DEFAULT_USER_SERVER
                        or parsed.server == NEWSLETTER_SERVER
                        or parsed.server == GROUP_SERVER
                        or parsed.server == BROADCAST_SERVER
                    ):
                        attrs[key] = parsed
                except Exception as e:
                    logger.exception(e)
                    pass
            elif isinstance(val, float):
                # Convert floats to ints
                attrs[key] = int(val)

        self.tag = mn.get("tag", "")
        self.attrs = attrs

        # Process content
        content = mn.get("content")
        if content:
            if isinstance(content, list):
                # Content is a list of nodes
                nodes = []
                for n in content:
                    node = Node(tag=n.get("tag", ""), attrs=n.get("attrs", {}), content=n.get("content"))
                    nodes.append(node)
                self.content = nodes
            elif isinstance(content, str):
                # Content is a binary string
                self.content = content.encode("utf-8")
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


def unmarshal(data: bytes) -> Node:
    """
    Decodes WhatsApp's binary XML representation into a Node.

    Args:
        data: Binary XML data to decode

    Returns:
        Tuple of (node, error) where error is None if decoding was successful
    Raises:
        DecodingError: if r.index != len(r.data): leftover bytes after decoding
    """
    r = BinaryDecoder.new_decoder(data)
    n = r.read_node()
    if r.index != len(r.data):
        raise DecodingError(f"{len(r.data) - r.index} leftover bytes after decoding")
    return n
