"""
Media connection management for WhatsApp Web.

This module handles querying and caching media server connection information.
Port of whatsmeow/mediaconn.go
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, List

from .datatypes.jid import JID
from .exceptions import ErrClientIsNil

if TYPE_CHECKING:
    from .client import Client

logger = logging.getLogger(__name__)


@dataclass
class MediaConnHost:
    """Represents a single host to download media from."""

    hostname: str
    # Note: IPs field commented out in Go version
    # ips: List[MediaConnIP] = field(default_factory=list)


@dataclass
class MediaConn:
    """Contains a list of WhatsApp servers from which attachments can be downloaded."""

    auth: str
    auth_ttl: int
    ttl: int
    max_buckets: int
    fetched_at: datetime
    hosts: List[MediaConnHost]

    def expiry(self) -> datetime:
        """Returns the time when the MediaConn expires."""
        return self.fetched_at + timedelta(seconds=self.ttl)


async def refresh_media_conn(client: "Client", force: bool = False) -> MediaConn:
    """
    Refresh the media connection cache if needed.

    Args:
        client: The client instance
        force: If True, force refresh even if cache is still valid

    Returns:
        MediaConn: Current media connection info

    Raises:
        ErrClientIsNil: If client is None
        Various exceptions: If query fails
    """
    if client is None:
        raise ErrClientIsNil()

    async with client.media_conn_lock:
        if client.media_conn_cache is None or force or datetime.now() >= client.media_conn_cache.expiry():
            client.media_conn_cache = await query_media_conn(client)

    return client.media_conn_cache


async def query_media_conn(client: "Client") -> MediaConn:
    """
    Query WhatsApp servers for media connection information.

    Args:
        client: The client instance

    Returns:
        MediaConn: Fresh media connection info from server

    Raises:
        Various exceptions: If the query fails or response is invalid
    """
    from .binary.node import Node
    from .request import InfoQuery, InfoQueryType, send_iq

    # Create info query for media connections
    query = InfoQuery(namespace="w:m", type=InfoQueryType.SET, to=JID.server_jid(), content=[Node(tag="media_conn")])

    resp = await send_iq(client, query)

    # Validate response structure - use get_children() method
    children = resp.get_children()
    if not children or children[0].tag != "media_conn":
        raise ValueError("Failed to query media connections: unexpected child tag")

    resp_mc = children[0]

    # Parse response attributes using attr_getter like Go version
    ag = resp_mc.attr_getter()
    auth = ag.string("auth")
    ttl = ag.int("ttl")
    auth_ttl = ag.int("auth_ttl")
    max_buckets = ag.int("max_buckets")

    # Validate required attributes
    if not auth or ttl <= 0:
        raise ValueError("Failed to parse media connections: missing required attributes")

    # Parse host list
    hosts = []
    for child in resp_mc.get_children():
        if child.tag != "host":
            logger.warning(f"Unexpected child in media_conn element: {child.xml_string()}")
            continue

        cag = child.attr_getter()
        hostname = cag.string("hostname")
        if not hostname:
            raise ValueError("Missing hostname in media connection host")

        hosts.append(MediaConnHost(hostname=hostname))

    if not hosts:
        raise ValueError("No media hosts received from server")

    return MediaConn(
        auth=auth, auth_ttl=auth_ttl, ttl=ttl, max_buckets=max_buckets, fetched_at=datetime.now(), hosts=hosts
    )
