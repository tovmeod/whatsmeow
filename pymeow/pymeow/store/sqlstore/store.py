"""
Port of whatsmeow/store/sqlstore/store.go
"""
import asyncio
from typing import Optional, List, Dict, Set, Tuple, TYPE_CHECKING
import logging
from typing import Any
import time

from .container import Container
from .models.session import IdentityKey, Session, PreKeyModel, SenderKey
from .models.contacts import Contact
from .models.appstate import AppStateSyncKey, AppStateVersion, AppStateMutationMACModel
from .. import store
from ..store import (
    IdentityStore, SessionStore, PreKeyStore, SenderKeyStore,
    ContactStore, AppStateStore, AllSessionSpecificStores
)
from ...util.keys import keypair
from ...util.keys.keypair import PreKey, KeyPair

if TYPE_CHECKING:
    from ...types.user import ContactInfo

class SQLStore(AllSessionSpecificStores):
    """Tortoise ORM-based WhatsApp store implementation"""

    def __init__(self, container: Container, jid: str):
        self.container = container
        self.jid = jid

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

    async def delete_all_sessions(self, phone: str) -> None:
        """Delete all sessions for a phone number"""
        await Session.filter(
            our_jid=self.jid,
            their_id__startswith=f"{phone}:"
        ).delete()

    async def migrate_pn_to_lid(self, pn_signal: str, lid_signal: str) -> None:
        """Migrate sessions, identity keys, and sender keys from phone number to LID"""
        if pn_signal in self.migrated_pn_sessions_cache:
            return

        self.migrated_pn_sessions_cache.add(pn_signal)

        # Migrate sessions
        sessions = await Session.filter(
            our_jid=self.jid,
            their_id__startswith=f"{pn_signal}:"
        )

        sessions_updated = 0
        for session in sessions:
            new_id = session.their_id.replace(pn_signal, lid_signal, 1)
            await Session.update_or_create(
                our_jid=self.jid,
                their_id=new_id,
                defaults={"session": session.session}
            )
            sessions_updated += 1

        await Session.filter(
            our_jid=self.jid,
            their_id__startswith=f"{pn_signal}:"
        ).delete()

        # Migrate identity keys
        identity_keys = await IdentityKey.filter(
            our_jid=self.jid,
            their_id__startswith=f"{pn_signal}:"
        )

        identity_keys_updated = 0
        for identity in identity_keys:
            new_id = identity.their_id.replace(pn_signal, lid_signal, 1)
            await IdentityKey.update_or_create(
                our_jid=self.jid,
                their_id=new_id,
                defaults={"identity": identity.identity}
            )
            identity_keys_updated += 1

        await IdentityKey.filter(
            our_jid=self.jid,
            their_id__startswith=f"{pn_signal}:"
        ).delete()

        # Migrate sender keys
        sender_keys = await SenderKey.filter(
            our_jid=self.jid,
            sender_id__startswith=f"{pn_signal}:"
        )

        sender_keys_updated = 0
        for sender_key in sender_keys:
            new_id = sender_key.sender_id.replace(pn_signal, lid_signal, 1)
            await SenderKey.update_or_create(
                our_jid=self.jid,
                chat_id=sender_key.chat_id,
                sender_id=new_id,
                defaults={"sender_key": sender_key.sender_key}
            )
            sender_keys_updated += 1

        await SenderKey.filter(
            our_jid=self.jid,
            sender_id__startswith=f"{pn_signal}:"
        ).delete()

        if sessions_updated > 0 or sender_keys_updated > 0 or identity_keys_updated > 0:
            logging.info(f"Migrated {sessions_updated} sessions, {identity_keys_updated} identity keys and {sender_keys_updated} sender keys from {pn_signal} to {lid_signal}")

    # === PreKey Store Implementation ===

    async def _get_next_pre_key_id(self) -> int:
        """Get the next available pre-key ID"""
        last_key = await PreKeyModel.filter(jid=self.jid).order_by('-key_id').first()
        return (last_key.key_id + 1) if last_key else 1

    async def _gen_one_pre_key(self, key_id: int, mark_uploaded: bool = False) -> 'PreKey':
        """Generate a single pre-key"""
        # Generate a new PreKey directly (matches Go's keys.NewPreKey(id))
        key_data = PreKey.generate(key_id)

        await PreKeyModel.create(
            jid=self.jid,
            key_id=key_id,
            key=key_data.priv,  # Store the private key bytes
            uploaded=mark_uploaded
        )

        return key_data

    async def gen_one_pre_key(self) -> 'PreKey':
        """Generate a single pre-key (public method)"""
        async with self.pre_key_lock:
            next_id = await self._get_next_pre_key_id()
            return await self._gen_one_pre_key(next_id, True)

    async def get_or_gen_pre_keys(self, count: int) -> List['PreKey']:
        """Get existing unuploaded pre-keys or generate new ones"""
        async with self.pre_key_lock:
            # Get existing unuploaded keys
            existing = await PreKeyModel.filter(
                jid=self.jid,
                uploaded=False
            ).order_by('key_id').limit(count)

            keys = []
            for pre_key in existing:
                # Convert to PreKey object by reconstructing from private key
                from ...util.keys.keypair import PreKey as PreKeyObj, KeyPair

                # Create KeyPair from private key (like Go's NewKeyPairFromPrivateKey)
                key_pair = KeyPair.from_private_key(pre_key.key)

                # Create PreKey with the reconstructed KeyPair
                key_obj = PreKeyObj(key_pair=key_pair, key_id=pre_key.key_id)
                keys.append(key_obj)

        # Generate additional keys if needed
        if len(keys) < count:
            needed = count - len(keys)
            next_id = await self._get_next_pre_key_id()

            for i in range(needed):
                key_data = await self._gen_one_pre_key(next_id + i, False)
                keys.append(key_data)

        return keys

    async def get_pre_key(self, key_id: int) -> Optional['PreKey']:
        """Get a specific pre-key by ID"""
        try:
            pre_key = await PreKeyModel.get(jid=self.jid, key_id=key_id)

            # Create KeyPair from private key (like Go's NewKeyPairFromPrivateKey)
            key_pair = KeyPair.from_private_key(pre_key.key)

            # Create PreKey with the reconstructed KeyPair
            return PreKey(key_pair=key_pair, key_id=pre_key.key_id)
        except:
            return None

    async def remove_pre_key(self, key_id: int) -> None:
        """Remove a pre-key by ID"""
        await PreKeyModel.filter(jid=self.jid, key_id=key_id).delete()

    async def mark_pre_keys_as_uploaded(self, up_to_id: int) -> None:
        """Mark pre-keys as uploaded up to a certain ID"""
        await PreKeyModel.filter(jid=self.jid, key_id__lte=up_to_id).update(uploaded=True)

    async def uploaded_prekey_count(self, ctx: Any = None) -> int:
        """Get the count of uploaded pre-keys."""
        try:
            count = await PreKeyModel.filter(
                jid=self.jid,
                uploaded=True
            ).count()
            return count
        except Exception as e:
            # Log the error and return 0 as fallback
            logging.error(f"Failed to get uploaded pre-key count: {e}")
            return 0

    # === Sender Key Store Implementation ===

    async def put_sender_key(self, group: str, user: str, session: bytes) -> None:
        """Store sender key for a group chat user"""
        await SenderKey.update_or_create(
            our_jid=self.jid,
            chat_id=group,
            sender_id=user,
            defaults={"sender_key": session}
        )

    async def get_sender_key(self, group: str, user: str) -> Optional[bytes]:
        """Get sender key for a group chat user"""
        try:
            sender_key = await SenderKey.get(
                our_jid=self.jid,
                chat_id=group,
                sender_id=user
            )
            return sender_key.sender_key
        except:
            return None

    # === App State Store Implementation ===

    async def put_app_state_sync_key(self, key_id: bytes, key_data: 'store.AppStateSyncKey') -> None:
        """Store app state sync key"""
        await AppStateSyncKey.update_or_create(
            jid=self.jid,
            key_id=key_id,
            defaults={
                "key_data": key_data.data,
                "timestamp": key_data.timestamp,
                "fingerprint": key_data.fingerprint
            }
        )

    async def get_app_state_sync_key(self, key_id: bytes) -> Optional['AppStateSyncKey']:
        """Get app state sync key by ID"""
        try:
            key = await AppStateSyncKey.get(jid=self.jid, key_id=key_id)
            from ...store import AppStateSyncKey as AppStateSyncKeyObj
            return AppStateSyncKeyObj(
                data=key.key_data,
                timestamp=key.timestamp,
                fingerprint=key.fingerprint
            )
        except:
            return None

    async def get_latest_app_state_sync_key_id(self) -> Optional[bytes]:
        """Get the latest app state sync key ID"""
        try:
            key = await AppStateSyncKey.filter(jid=self.jid).order_by('-timestamp').first()
            return key.key_id if key else None
        except:
            return None

    async def put_app_state_version(self, name: str, version: int, hash_bytes: bytes) -> None:
        """Store app state version"""
        await AppStateVersion.update_or_create(
            jid=self.jid,
            name=name,
            defaults={"version": version, "hash": hash_bytes}
        )

    async def get_app_state_version(self, name: str) -> Tuple[int, bytes]:
        """Get app state version and hash"""
        try:
            state = await AppStateVersion.get(jid=self.jid, name=name)
            return state.version, state.hash
        except:
            return 0, b'\x00' * 128

    async def delete_app_state_version(self, name: str) -> None:
        """Delete app state version"""
        await AppStateVersion.filter(jid=self.jid, name=name).delete()

    async def put_app_state_mutation_macs(self, name: str, version: int, mutations: List['AppStateMutationMACModel']) -> None:
        """Store app state mutation MACs"""
        if not mutations:
            return

        # Process in batches to avoid too many parameters
        batch_size = 400
        for i in range(0, len(mutations), batch_size):
            batch = mutations[i:i + batch_size]
            mac_objects = []
            for mutation in batch:
                mac_objects.append(AppStateMutationMACModel(
                    jid=self.jid,
                    name=name,
                    version=version,
                    index_mac=mutation.index_mac,
                    value_mac=mutation.value_mac
                ))
            await AppStateMutationMACModel.bulk_create(mac_objects)

    async def delete_app_state_mutation_macs(self, name: str, index_macs: List[bytes]) -> None:
        """Delete app state mutation MACs by index MAC"""
        if not index_macs:
            return

        await AppStateMutationMACModel.filter(
            jid=self.jid,
            name=name,
            index_mac__in=index_macs
        ).delete()

    async def get_app_state_mutation_mac(self, name: str, index_mac: bytes) -> Optional[bytes]:
        """Get app state mutation MAC by index MAC"""
        try:
            mac = await AppStateMutationMACModel.filter(
                jid=self.jid,
                name=name,
                index_mac=index_mac
            ).order_by('-version').first()
            return mac.value_mac if mac else None
        except:
            return None

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
            await self.contact_cache.pop(jid, None)

    async def put_many_contact_names(self, contacts: List[Tuple[str, str, str]]) -> None:
        """Store multiple contact names efficiently"""
        if not contacts:
            return

        async with self.contact_cache_lock:
            contact_objects = []
            for jid, first_name, full_name in contacts:
                contact_objects.append(Contact(
                    our_jid=self.jid,
                    their_jid=jid,
                    first_name=first_name,
                    full_name=full_name
                ))

            # Clear cache for all updated contacts
            for jid, _, _ in contacts:
                await self.contact_cache.pop(jid, None)

            for contact in contact_objects:
                await Contact.update_or_create(
                    defaults={
                        'first_name': contact.first_name,
                        'full_name': contact.full_name,
                    },
                    our_jid=contact.our_jid,
                    their_jid=contact.their_jid
                )

    async def put_push_name(self, user_jid: str, push_name: str) -> Tuple[bool, str]:
        """Store push name and return if changed and previous name"""
        async with self.contact_cache_lock:
            try:
                contact = await Contact.get(our_jid=self.jid, their_jid=user_jid)
                previous_name = contact.push_name or ""
                if contact.push_name != push_name:
                    contact.push_name = push_name
                    await contact.save()
                    # Clear cache
                    await self.contact_cache.pop(user_jid, None)
                    return True, previous_name
                return False, ""
            except:
                # Create new contact
                await Contact.create(
                    our_jid=self.jid,
                    their_jid=user_jid,
                    push_name=push_name
                )
                return True, ""

    async def put_business_name(self, user_jid: str, business_name: str) -> Tuple[bool, str]:
        """Store business name and return if changed and previous name"""
        async with self.contact_cache_lock:
            try:
                contact = await Contact.get(our_jid=self.jid, their_jid=user_jid)
                previous_name = contact.business_name or ""
                if contact.business_name != business_name:
                    contact.business_name = business_name
                    await contact.save()
                    # Clear cache
                    await self.contact_cache.pop(user_jid, None)
                    return True, previous_name
                return False, ""
            except:
                # Create new contact
                await Contact.create(
                    our_jid=self.jid,
                    their_jid=user_jid,
                    business_name=business_name
                )
                return True, ""

    async def get_contact(self, jid: str) -> Optional['ContactInfo']:
        """Get contact information"""
        from ...types.user import ContactInfo
        async with self.contact_cache_lock:
            # Check cache first
            if jid in self.contact_cache:
                contact = self.contact_cache[jid]

                return ContactInfo(
                    first_name=contact.first_name,
                    full_name=contact.full_name,
                    push_name=contact.push_name,
                    business_name=contact.business_name,
                    found=True
                )

            try:
                contact = await Contact.get(
                    our_jid=self.jid,
                    their_jid=jid
                )
                # Cache the contact
                self.contact_cache[jid] = contact

                # Convert to ContactInfo
                info = ContactInfo(
                    first_name=contact.first_name,
                    full_name=contact.full_name,
                    push_name=contact.push_name,
                    business_name=contact.business_name,
                    found=True
                )
                return info
            except:
                # Return empty contact info
                return ContactInfo(found=False)

    async def get_all_contacts(self) -> Dict[str, 'ContactInfo']:
        """Get all contacts"""
        contacts = await Contact.filter(our_jid=self.jid)
        result = {}

        from ...types.user import ContactInfo
        for contact in contacts:
            info = ContactInfo(
                first_name=contact.first_name,
                full_name=contact.full_name,
                push_name=contact.push_name,
                business_name=contact.business_name,
                found=True
            )
            result[contact.their_jid] = info
            # Update cache
            self.contact_cache[contact.their_jid] = contact

        return result
