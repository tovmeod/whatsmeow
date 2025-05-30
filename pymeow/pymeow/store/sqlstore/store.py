import asyncio
from typing import Optional, List, Dict, Set
import logging

from .container import Container
from .models.session import IdentityKey, Session, PreKey, SenderKey
from .models.contacts import Contact
from .models.appstate import AppStateSyncKey, AppStateVersion
from ..store import (
    IdentityStore, SessionStore, PreKeyStore, SenderKeyStore,
    ContactStore, AppStateStore
)

class SQLStore:
    """Tortoise ORM-based WhatsApp store implementation"""

    def __init__(self, container: Container, jid: str):
        self.container = container
        self.jid = jid
        self.log = container.log

        # Async locks for thread safety
        self.pre_key_lock = asyncio.Lock()
        self.contact_cache_lock = asyncio.Lock()

        # In-memory caches
        self.contact_cache: Dict[str, Contact] = {}
        self.migrated_pn_sessions_cache: Set[str] = set()

    # === Identity Store Implementation ===

    async def put_identity(self, address: str, key: bytes) -> None:
        """Store identity key for an address"""
        await IdentityKey.update_or_create(
            our_jid=self.jid,
            their_id=address,
            defaults={"identity": key}
        )

    async def delete_all_identities(self, phone: str) -> None:
        """Delete all identity keys for a phone number"""
        await IdentityKey.filter(
            our_jid=self.jid,
            their_id__startswith=f"{phone}:"
        ).delete()

    async def delete_identity(self, address: str) -> None:
        """Delete identity key for an address"""
        await IdentityKey.filter(
            our_jid=self.jid,
            their_id=address
        ).delete()

    async def is_trusted_identity(self, address: str, key: bytes) -> bool:
        """Check if identity key is trusted"""
        try:
            identity = await IdentityKey.get(
                our_jid=self.jid,
                their_id=address
            )
            return identity.identity == key
        except:
            # Trust if not known, it'll be saved automatically later
            return True

    # === Session Store Implementation ===

    async def get_session(self, address: str) -> Optional[bytes]:
        """Get session data for an address"""
        try:
            session = await Session.get(
                our_jid=self.jid,
                their_id=address
            )
            return session.session
        except:
            return None

    async def has_session(self, address: str) -> bool:
        """Check if session exists for an address"""
        return await Session.filter(
            our_jid=self.jid,
            their_id=address
        ).exists()

    async def put_session(self, address: str, session_data: bytes) -> None:
        """Store session data for an address"""
        await Session.update_or_create(
            our_jid=self.jid,
            their_id=address,
            defaults={"session": session_data}
        )

    async def delete_session(self, address: str) -> None:
        """Delete session for an address"""
        await Session.filter(
            our_jid=self.jid,
            their_id=address
        ).delete()

    # === PreKey Store Implementation ===

    async def gen_one_pre_key(self) -> 'PreKey':
        """Generate a single pre-key"""
        async with self.pre_key_lock:
            # Get next key ID
            last_key = await PreKey.filter(jid=self.jid).order_by('-key_id').first()
            next_id = (last_key.key_id + 1) if last_key else 1

            # Generate new pre-key
            from ...util.keys import generate_pre_key
            key_data = generate_pre_key(next_id)

            # Store in database
            await PreKey.create(
                jid=self.jid,
                key_id=next_id,
                key=key_data.private_key,
                uploaded=True
            )

            return key_data

    async def get_or_gen_pre_keys(self, count: int) -> List['PreKey']:
        """Get existing unuploaded pre-keys or generate new ones"""
        async with self.pre_key_lock:
            # Get existing unuploaded keys
            existing = await PreKey.filter(
                jid=self.jid,
                uploaded=False
            ).order_by('key_id').limit(count)

            keys = []
            for pre_key in existing:
                # Convert to PreKey object
                from ...util.keys import PreKey as PreKeyObj
                key_obj = PreKeyObj.from_private_key(pre_key.key, pre_key.key_id)
                keys.append(key_obj)

            # Generate additional keys if needed
            if len(keys) < count:
                needed = count - len(keys)
                last_key = await PreKey.filter(jid=self.jid).order_by('-key_id').first()
                next_id = (last_key.key_id + 1) if last_key else 1

                for i in range(needed):
                    from ...util.keys import generate_pre_key
                    key_data = generate_pre_key(next_id + i)

                    await PreKey.create(
                        jid=self.jid,
                        key_id=next_id + i,
                        key=key_data.private_key,
                        uploaded=False
                    )

                    keys.append(key_data)

            return keys

    # === Contact Store Implementation ===

    async def put_contact_name(self, jid: str, first_name: str, full_name: str) -> None:
        """Store contact name"""
        async with self.contact_cache_lock:
            await Contact.update_or_create(
                our_jid=self.jid,
                their_jid=jid,
                defaults={
                    "first_name": first_name,
                    "full_name": full_name
                }
            )
            # Update cache
            self.contact_cache.pop(jid, None)

    async def get_contact(self, jid: str) -> Optional['ContactInfo']:
        """Get contact information"""
        async with self.contact_cache_lock:
            # Check cache first
            if jid in self.contact_cache:
                return self.contact_cache[jid]

            try:
                contact = await Contact.get(
                    our_jid=self.jid,
                    their_jid=jid
                )
                # Convert to ContactInfo and cache
                from ...types.contact import ContactInfo
                info = ContactInfo(
                    first_name=contact.first_name,
                    full_name=contact.full_name,
                    push_name=contact.push_name,
                    business_name=contact.business_name
                )
                self.contact_cache[jid] = info
                return info
            except:
                return None
