"""
Media connection management for WhatsApp Web.

This module handles querying and caching media server connection information.
Port of whatsmeow/mediaconn.go
"""
import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from .binary.node import Node
from .request import InfoQuery, InfoQueryType
from .types.jid import JID
from .exceptions import ClientError

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


class MediaConnMixin:
    """
    Mixin class providing media connection management functionality.

    This should be mixed into the Client class to provide mediaconn functionality.
    """

    def __init__(self):
        self.media_conn_cache: Optional[MediaConn] = None
        self.media_conn_lock = asyncio.Lock()

    async def refresh_media_conn(self, force: bool = False) -> MediaConn:
        """
        Refresh the media connection cache if needed.

        Args:
            force: If True, force refresh even if cache is still valid

        Returns:
            MediaConn: Current media connection info

        Raises:
            ClientError: If client is not initialized or query fails
        """
        if not hasattr(self, 'store') or self.store is None:
            raise ClientError("Client is not initialized")

        async with self.media_conn_lock:
            if (self.media_conn_cache is None or
                force or
                datetime.now() >= self.media_conn_cache.expiry()):

                self.media_conn_cache = await self.query_media_conn()

        return self.media_conn_cache

    async def query_media_conn(self) -> MediaConn:
        """
        Query WhatsApp servers for media connection information.

        Returns:
            MediaConn: Fresh media connection info from server

        Raises:
            ClientError: If the query fails or response is invalid
        """
        try:
            # Send media_conn query
            resp = await self.send_iq(InfoQuery(
                namespace="w:m",
                type=InfoQueryType.SET,
                to=JID.server_jid(),
                content=[Node(tag="media_conn")]
            ))

            if not resp.children or resp.children[0].tag != "media_conn":
                raise ClientError("Failed to query media connections: unexpected response structure")

            resp_mc = resp.children[0]

            # Parse response attributes
            try:
                auth = resp_mc.attrs.get("auth", "")
                ttl = int(resp_mc.attrs.get("ttl", "0"))
                auth_ttl = int(resp_mc.attrs.get("auth_ttl", "0"))
                max_buckets = int(resp_mc.attrs.get("max_buckets", "0"))

                if not auth or ttl <= 0:
                    raise ValueError("Missing required attributes")

            except (ValueError, KeyError) as e:
                raise ClientError(f"Failed to parse media connection attributes: {e}")

            # Parse host list
            hosts = []
            for child in resp_mc.children:
                if child.tag != "host":
                    logger.warning(f"Unexpected child in media_conn element: {child}")
                    continue

                hostname = child.attrs.get("hostname", "")
                if not hostname:
                    raise ClientError("Missing hostname in media connection host")

                hosts.append(MediaConnHost(hostname=hostname))

            if not hosts:
                raise ClientError("No media hosts received from server")

            return MediaConn(
                auth=auth,
                auth_ttl=auth_ttl,
                ttl=ttl,
                max_buckets=max_buckets,
                fetched_at=datetime.now(),
                hosts=hosts
            )

        except Exception as e:
            if isinstance(e, ClientError):
                raise
            raise ClientError(f"Failed to query media connections: {e}")


# For backwards compatibility with existing code
class Client(MediaConnMixin):
    """
    Partial Client class showing mediaconn integration.

    In the actual implementation, MediaConnMixin would be mixed into
    the main Client class in client.py.
    """

    def __init__(self):
        super().__init__()
        self.store = None  # Placeholder

    async def send_iq(self, query: InfoQuery) -> Node:
        """Send IQ query. Implementation would be in request.py"""
        raise NotImplementedError("Implemented in request.py")
