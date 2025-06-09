"""
Cached LID mapping implementation.

Port of whatsmeow/store/sqlstore/lidmap.go
"""
import asyncio
import logging
from typing import Dict, Optional, Tuple, List

# Internal imports
from ...types.jid import JID
from .. import store

# TODO: Verify import when dbutil is ported
from ...util import dbutil

logger = logging.getLogger(__name__)
# SQL query constants
DELETE_EXISTING_LID_MAPPING_QUERY = "DELETE FROM whatsmeow_lid_map WHERE (lid<>$1 AND pn=$2)"
PUT_LID_MAPPING_QUERY = """
    INSERT INTO whatsmeow_lid_map (lid, pn)
    VALUES ($1, $2)
    ON CONFLICT (lid) DO UPDATE SET pn=excluded.pn WHERE whatsmeow_lid_map.pn<>excluded.pn
"""
GET_LID_FOR_PN_QUERY = "SELECT lid FROM whatsmeow_lid_map WHERE pn=$1"
GET_PN_FOR_LID_QUERY = "SELECT pn FROM whatsmeow_lid_map WHERE lid=$1"
GET_ALL_LID_MAPPINGS_QUERY = "SELECT lid, pn FROM whatsmeow_lid_map"


class CachedLIDMap:
    """
    Cached implementation of the LIDStore interface.

    This class provides methods for mapping between phone numbers (PN) and long IDs (LID).
    It uses a cache to improve performance.
    """

    def __init__(self, db: 'dbutil.Database'):
        """
        Create a new CachedLIDMap with the given database.

        Args:
            db: The database connection
        """
        self.db = db
        self.pn_to_lid_cache: Dict[str, str] = {}
        self.lid_to_pn_cache: Dict[str, str] = {}
        self.cache_filled = False
        self.lid_cache_lock = asyncio.Lock()

    async def fill_cache(self) -> None:
        """
        Fill the cache with all LID mappings from the database.

        Raises:
            Exception: If query fails
        """
        async with self.lid_cache_lock:
            rows = await self.db.fetch_all(GET_ALL_LID_MAPPINGS_QUERY)

            for row in rows:
                lid, pn = row
                self.pn_to_lid_cache[pn] = lid
                self.lid_to_pn_cache[lid] = pn

            self.cache_filled = True

    async def _get_lid_mapping(self, source: JID, target_server: str, query: str,
                              source_to_target: Dict[str, str], target_to_source: Dict[str, str]) -> JID:
        """
        Internal method to get a LID mapping.

        Args:
            source: Source JID
            target_server: Target server
            query: SQL query to execute
            source_to_target: Source to target mapping cache
            target_to_source: Target to source mapping cache

        Returns:
            Target JID or empty JID if not found

        Raises:
            Exception: If query fails
        """
        # Check cache first
        async with self.lid_cache_lock.reader:
            target_user = source_to_target.get(source.user)
            cache_filled = self.cache_filled

        if target_user is not None or cache_filled:
            if not target_user:
                return JID()
            return JID(user=target_user, device=source.device, server=target_server)

        # Not in cache, query database
        async with self.lid_cache_lock:
            row = await self.db.fetch_one(query, source.user)
            target_user = row[0] if row else ""

            source_to_target[source.user] = target_user
            if target_user:
                target_to_source[target_user] = source.user
                return JID(user=target_user, device=source.device, server=target_server)

            return JID()

    async def get_lid_for_pn(self, pn: JID) -> Tuple[JID, Optional[Exception]]:
        """
        Get a LID for a phone number.

        Args:
            pn: Phone number JID

        Returns:
            LID JID and None, or empty JID and error

        Raises:
            Exception: If pn is not a phone number JID
        """
        if pn.server != "s.whatsapp.net":
            return JID(), Exception(f"invalid GetLIDForPN call with non-PN JID {pn}")

        try:
            jid = await self._get_lid_mapping(
                pn, "lid.whatsapp.net", GET_LID_FOR_PN_QUERY,
                self.pn_to_lid_cache, self.lid_to_pn_cache
            )
            return jid, None
        except Exception as e:
            return JID(), e

    async def get_pn_for_lid(self, lid: JID) -> Tuple[JID, Optional[Exception]]:
        """
        Get a phone number for a LID.

        Args:
            lid: LID JID

        Returns:
            Phone number JID and None, or empty JID and error

        Raises:
            Exception: If lid is not a LID JID
        """
        if lid.server != "lid.whatsapp.net":
            return JID(), Exception(f"invalid GetPNForLID call with non-LID JID {lid}")

        try:
            jid = await self._get_lid_mapping(
                lid, "s.whatsapp.net", GET_PN_FOR_LID_QUERY,
                self.lid_to_pn_cache, self.pn_to_lid_cache
            )
            return jid, None
        except Exception as e:
            return JID(), e

    async def _unlocked_put_lid_mapping(self, lid: JID, pn: JID) -> None:
        """
        Internal method to store a LID mapping without locking.

        Args:
            lid: LID JID
            pn: Phone number JID

        Raises:
            Exception: If lid is not a LID JID or pn is not a phone number JID
        """
        if lid.server != "lid.whatsapp.net" or pn.server != "s.whatsapp.net":
            raise Exception(f"invalid PutLIDMapping call {lid}/{pn}")

        # Delete any existing mappings for this phone number
        await self.db.execute(DELETE_EXISTING_LID_MAPPING_QUERY, lid.user, pn.user)

        # Insert the new mapping
        await self.db.execute(PUT_LID_MAPPING_QUERY, lid.user, pn.user)

        # Update cache
        self.pn_to_lid_cache[pn.user] = lid.user
        self.lid_to_pn_cache[lid.user] = pn.user

    async def put_lid_mapping(self, lid: JID, pn: JID) -> None:
        """
        Store a LID mapping.

        Args:
            lid: LID JID
            pn: Phone number JID

        Raises:
            Exception: If lid is not a LID JID or pn is not a phone number JID
        """
        if lid.server != "lid.whatsapp.net" or pn.server != "s.whatsapp.net":
            raise Exception(f"invalid PutLIDMapping call {lid}/{pn}")

        async with self.lid_cache_lock:
            # Check if mapping already exists
            cached_lid = self.pn_to_lid_cache.get(pn.user)
            if cached_lid == lid.user:
                return

            # Store in database within a transaction
            async def _do_mapping() -> None:
                await self._unlocked_put_lid_mapping(lid, pn)

            await self.db.transaction(_do_mapping)

    async def put_many_lid_mappings(self, mappings: List[store.LIDMapping]) -> None:
        """
        Store multiple LID mappings.

        Args:
            mappings: List of LID mappings

        Raises:
            Exception: If any mapping is invalid
        """
        if not mappings:
            return

        async with self.lid_cache_lock:
            # Filter out invalid and already existing mappings
            valid_mappings = []
            for mapping in mappings:
                if mapping.lid.server != "lid.whatsapp.net" or mapping.pn.server != "s.whatsapp.net":
                    logger.debug(
                        f"Ignoring invalid entry in PutManyLIDMappings: {mapping.lid}/{mapping.pn}"
                    )
                    continue

                cached_lid = self.pn_to_lid_cache.get(mapping.pn.user)
                if cached_lid == mapping.lid.user:
                    continue

                valid_mappings.append(mapping)

            if not valid_mappings:
                return

            # Store in database within a transaction
            async def _do_mappings() -> None:
                for mapping in valid_mappings:
                    await self._unlocked_put_lid_mapping(mapping.lid, mapping.pn)

            await self.db.transaction(_do_mappings)

# Register the CachedLIDMap class as implementing the LIDStore interface
store.LIDStore.register(CachedLIDMap)
