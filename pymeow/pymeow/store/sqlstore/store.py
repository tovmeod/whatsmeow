"""
SQL-backed store implementation using Tortoise ORM.

Port of whatsmeow/store/sqlstore/store.go
"""
import asyncio
from typing import Dict, List, Optional, Tuple, Set
from tortoise.transactions import in_transaction

from ...types import JID, ContactInfo
from ...util.keys.keypair import PreKey, KeyPair
from ..store import ContactEntry, AppStateMutationMAC, AppStateSyncKey
from .container import Container
from .models.session import IdentityKeyModel, SessionModel, PreKeyModel, SenderKeyModel
from .models.appstate import AppStateSyncKeyModel, AppStateVersionModel, AppStateMutationMACModel
from .models.contacts import ContactModel


class SQLStore:
    """
    SQL-backed store implementation for WhatsApp client data.

    Port of SQLStore from Go whatsmeow/store/sqlstore/store.go
    """

    def __init__(self, container: Container, jid: str):
        """
        Args:
            container: Database container
            jid: User JID string
        """
        self.container = container
        self.jid = jid

        # Thread safety for pre-key operations
        self.pre_key_lock = asyncio.Lock()

        # Contact cache
        self.contact_cache: Dict[JID, ContactInfo] = {}
        self.contact_cache_lock = asyncio.Lock()

        # Cache for migrated PN sessions
        self.migrated_pn_sessions_cache: Set[str] = set()

    # Identity Key methods
    async def put_identity(self, address: str, key: bytes) -> None:
        """Put an identity key in the store."""
        await IdentityKeyModel.update_or_create(
            our_jid=self.jid,
            their_id=address,
            defaults={'identity': key}
        )

    async def delete_all_identities(self, phone: str) -> None:
        """Delete all identity keys for a phone number."""
        await IdentityKeyModel.filter(
            our_jid=self.jid,
            their_id__startswith=f"{phone}:"
        ).delete()

    async def delete_identity(self, address: str) -> None:
        """Delete a specific identity key."""
        await IdentityKeyModel.filter(
            our_jid=self.jid,
            their_id=address
        ).delete()

    async def is_trusted_identity(self, address: str, key: bytes) -> bool:
        """Check if an identity key is trusted."""
        try:
            identity = await IdentityKeyModel.get(our_jid=self.jid, their_id=address)
            return identity.identity == key
        except:
            # Trust if not known, it'll be saved automatically later
            return True

    # Session methods
    async def get_session(self, address: str) -> Optional[bytes]:
        """Get a session for an address."""
        try:
            session = await SessionModel.get(our_jid=self.jid, their_id=address)
            return session.session
        except:
            return None

    async def has_session(self, address: str) -> bool:
        """Check if a session exists for an address."""
        return await SessionModel.filter(our_jid=self.jid, their_id=address).exists()

    async def put_session(self, address: str, session: bytes) -> None:
        """Put a session in the store."""
        await SessionModel.update_or_create(
            our_jid=self.jid,
            their_id=address,
            defaults={'session': session}
        )

    async def delete_session(self, address: str) -> None:
        """Delete a specific session."""
        await SessionModel.filter(our_jid=self.jid, their_id=address).delete()

    async def delete_all_sessions(self, phone: str) -> None:
        """Delete all sessions for a phone number."""
        await SessionModel.filter(
            our_jid=self.jid,
            their_id__startswith=f"{phone}:"
        ).delete()

    async def migrate_pn_to_lid(self, pn: JID, lid: JID) -> None:
        """
        Migrate sessions, identity keys, and sender keys from phone number to LID.

        Args:
            pn: Phone number JID
            lid: LID JID
        """
        pn_signal = pn.signal_address_user()

        # Skip if already migrated
        if pn_signal in self.migrated_pn_sessions_cache:
            return

        self.migrated_pn_sessions_cache.add(pn_signal)

        lid_signal = lid.signal_address_user()

        async with in_transaction() as connection:
            # Migrate sessions
            sessions_updated = 0
            sessions = await SessionModel.filter(
                our_jid=self.jid,
                their_id__startswith=f"{pn_signal}:"
            ).using_db(connection).all()
            for session in sessions:
                new_id = session.their_id.replace(pn_signal, lid_signal, 1)
                await SessionModel.update_or_create(
                    our_jid=self.jid,
                    their_id=new_id,
                    defaults={'session': session.session},
                    using_db=connection
                )
                sessions_updated += 1

            # Delete old sessions
            await SessionModel.filter(
                our_jid=self.jid,
                their_id__startswith=f"{pn_signal}:"
            ).using_db(connection).delete()

            # Migrate identity keys
            identity_keys_updated = 0
            identities = await IdentityKeyModel.filter(
                our_jid=self.jid,
                their_id__startswith=f"{pn_signal}:"
            ).using_db(connection)
            for identity in identities:
                new_id = identity.their_id.replace(pn_signal, lid_signal, 1)
                await IdentityKeyModel.update_or_create(
                    our_jid=self.jid,
                    their_id=new_id,
                    defaults={'identity': identity.identity},
                    using_db=connection
                )
                identity_keys_updated += 1

            # Delete old identity keys
            await IdentityKeyModel.filter(
                our_jid=self.jid,
                their_id__startswith=f"{pn_signal}:"
            ).using_db(connection).delete()

            # Migrate sender keys
            sender_keys_updated = 0
            sender_keys = await SenderKeyModel.filter(
                our_jid=self.jid,
                sender_id__startswith=f"{pn_signal}:"
            ).using_db(connection)
            for sender_key in sender_keys:
                new_id = sender_key.sender_id.replace(pn_signal, lid_signal, 1)
                await SenderKeyModel.update_or_create(
                    our_jid=self.jid,
                    chat_id=sender_key.chat_id,
                    sender_id=new_id,
                    defaults={'sender_key': sender_key.sender_key},
                    using_db=connection
                )
                sender_keys_updated += 1

            # Delete old sender keys
            await SenderKeyModel.filter(
                our_jid=self.jid,
                sender_id__startswith=f"{pn_signal}:"
            ).using_db(connection).delete()

        if sessions_updated > 0 or sender_keys_updated > 0 or identity_keys_updated > 0:
            print(f"Migrated {sessions_updated} sessions, {identity_keys_updated} identity keys and {sender_keys_updated} sender keys from {pn_signal} to {lid_signal}")

    # Pre-key methods
    async def _get_next_pre_key_id(self) -> int:
        """Get the next available pre-key ID."""
        max_key = await PreKeyModel.filter(jid=self.jid).only('key_id').order_by('-key_id').first()
        return (max_key.key_id + 1) if max_key else 1

    async def _gen_one_pre_key(self, key_id: int, mark_uploaded: bool = False) -> PreKey:
        """Generate and store one pre-key."""
        key = PreKey.generate(key_id)
        await PreKeyModel.create(
            jid=self.jid,
            key_id=key.key_id,
            key=key.priv,
            uploaded=mark_uploaded
        )
        return key

    async def gen_one_pre_key(self) -> PreKey:
        """Generate one pre-key marked as uploaded."""
        async with self.pre_key_lock:
            next_key_id = await self._get_next_pre_key_id()
            return await self._gen_one_pre_key(next_key_id, True)

    async def get_or_gen_pre_keys(self, count: int) -> List[PreKey]:
        """Get or generate the requested number of pre-keys."""
        async with self.pre_key_lock:
            # Get existing unuploaded keys
            existing_keys = []
            prekeys = await PreKeyModel.filter(
                jid=self.jid,
                uploaded=False
            ).order_by('key_id').limit(count)
            for pre_key_model in prekeys:
                key_pair = KeyPair.from_private_key(pre_key_model.key)
                pre_key = PreKey(key_pair, pre_key_model.key_id)
                existing_keys.append(pre_key)

            # Generate additional keys if needed
            if len(existing_keys) < count:
                next_key_id = await self._get_next_pre_key_id()
                for i in range(len(existing_keys), count):
                    new_key = await self._gen_one_pre_key(next_key_id + i - len(existing_keys), False)
                    existing_keys.append(new_key)

            return existing_keys

    async def get_pre_key(self, key_id: int) -> Optional[PreKey]:
        """Get a specific pre-key by ID."""
        try:
            pre_key_model = await PreKeyModel.get(jid=self.jid, key_id=key_id)
            key_pair = KeyPair.from_private_key(pre_key_model.key)
            return PreKey(key_pair, pre_key_model.key_id)
        except:
            return None

    async def remove_pre_key(self, key_id: int) -> None:
        """Remove a pre-key."""
        await PreKeyModel.filter(jid=self.jid, key_id=key_id).delete()

    async def mark_pre_keys_as_uploaded(self, up_to_id: int) -> None:
        """Mark pre-keys as uploaded up to the given ID."""
        await PreKeyModel.filter(
            jid=self.jid,
            key_id__lte=up_to_id
        ).update(uploaded=True)

    async def uploaded_prekey_count(self) -> int:
        """Get the count of uploaded pre-keys."""
        return await PreKeyModel.filter(jid=self.jid, uploaded=True).count()

    # Sender key methods
    async def put_sender_key(self, group: str, user: str, session: bytes) -> None:
        """Put a sender key in the store."""
        await SenderKeyModel.update_or_create(
            our_jid=self.jid,
            chat_id=group,
            sender_id=user,
            defaults={'sender_key': session}
        )

    async def get_sender_key(self, group: str, user: str) -> Optional[bytes]:
        """Get a sender key from the store."""
        try:
            sender_key = await SenderKeyModel.get(
                our_jid=self.jid,
                chat_id=group,
                sender_id=user
            )
            return sender_key.sender_key
        except:
            return None

    # App state sync key methods
    async def put_app_state_sync_key(self, key_id: bytes, key: AppStateSyncKey) -> None:
        """Put an app state sync key."""
        await AppStateSyncKeyModel.update_or_create(
            jid=self.jid,
            key_id=key_id,
            defaults={
                'key_data': key.data,
                'timestamp': key.timestamp,
                'fingerprint': key.fingerprint
            }
        )

    async def get_app_state_sync_key(self, key_id: bytes) -> Optional[AppStateSyncKeyModel]:
        """Get an app state sync key."""
        try:
            key_model = await AppStateSyncKeyModel.get(jid=self.jid, key_id=key_id)
            return AppStateSyncKeyModel(
                data=key_model.key_data,
                timestamp=key_model.timestamp,
                fingerprint=key_model.fingerprint
            )
        except:
            return None

    async def get_latest_app_state_sync_key_id(self) -> Optional[bytes]:
        """Get the latest app state sync key ID."""
        latest = await AppStateSyncKeyModel.filter(
            jid=self.jid
        ).order_by('-timestamp').first()
        return latest.key_id if latest else None

    # App state version methods
    async def put_app_state_version(self, name: str, version: int, hash_value: bytes) -> None:
        """Put an app state version."""
        await AppStateVersionModel.update_or_create(
            jid=self.jid,
            name=name,
            defaults={
                'version': version,
                'hash': hash_value
            }
        )

    async def get_app_state_version(self, name: str) -> Tuple[int, bytes]:
        """Get an app state version."""
        try:
            version_model = await AppStateVersionModel.get(jid=self.jid, name=name)
            return version_model.version, version_model.hash
        except:
            return 0, b'\x00' * 128

    async def delete_app_state_version(self, name: str) -> None:
        """Delete an app state version."""
        await AppStateVersionModel.filter(jid=self.jid, name=name).delete()

    # App state mutation MAC methods
    async def put_app_state_mutation_macs(
        self,
        name: str,
        version: int,
        mutations: List[AppStateMutationMAC]
    ) -> None:
        """Put app state mutation MACs."""
        if not mutations:
            return

        # Use transaction for batch insert
        async with in_transaction() as connection:
            for mutation in mutations:
                await AppStateMutationMACModel.create(
                    jid=self.jid,
                    name=name,
                    version=version,
                    index_mac=mutation.index_mac,
                    value_mac=mutation.value_mac,
                    using_db=connection
                )

    async def delete_app_state_mutation_macs(self, name: str, index_macs: List[bytes]) -> None:
        """Delete app state mutation MACs."""
        if not index_macs:
            return

        await AppStateMutationMACModel.filter(
            jid=self.jid,
            name=name,
            index_mac__in=index_macs
        ).delete()

    async def get_app_state_mutation_mac(self, name: str, index_mac: bytes) -> Optional[bytes]:
        """Get an app state mutation MAC."""
        mac_model = await AppStateMutationMACModel.filter(
            jid=self.jid,
            name=name,
            index_mac=index_mac
        ).order_by('-version').first()

        return mac_model.value_mac if mac_model else None

    # Contact methods
    async def _get_contact(self, jid: JID) -> ContactInfo:
        """Get contact from cache or database."""
        if jid in self.contact_cache:
            return self.contact_cache[jid]

        try:
            contact = await ContactModel.get(our_jid=self.jid, their_jid=str(jid))
            contact_info = ContactInfo(
                first_name=contact.first_name or "",
                full_name=contact.full_name or "",
                push_name=contact.push_name or "",
                business_name=contact.business_name or "",
                found=True
            )
        except:
            contact_info = ContactInfo(found=False)

        self.contact_cache[jid] = contact_info
        return contact_info

    async def put_contact_name(self, user: JID, first_name: str, full_name: str) -> None:
        """Put contact name."""
        async with self.contact_cache_lock:
            cached = await self._get_contact(user)
            if cached.first_name != first_name or cached.full_name != full_name:
                await ContactModel.update_or_create(
                    our_jid=self.jid,
                    their_jid=str(user),
                    defaults={
                        'first_name': first_name,
                        'full_name': full_name
                    }
                )
                cached.first_name = first_name
                cached.full_name = full_name
                cached.found = True

    async def put_many_contact_names(self, contacts: List[ContactEntry]) -> None:
        """Put many contact names in batch."""
        if not contacts:
            return

        # Remove duplicates and filter empty JIDs
        seen = set()
        unique_contacts = []
        for contact in contacts:
            if contact.jid and contact.jid not in seen:
                seen.add(contact.jid)
                unique_contacts.append(contact)

        async with in_transaction() as connection:
            for contact in unique_contacts:
                await ContactModel.update_or_create(
                    our_jid=self.jid,
                    their_jid=str(contact.jid),
                    defaults={
                        'first_name': contact.first_name,
                        'full_name': contact.full_name
                    },
                    using_db=connection
                )

    async def put_push_name(self, user: JID, push_name: str) -> Tuple[bool, str]:
        """Put push name, returns (changed, previous_name)."""
        async with self.contact_cache_lock:
            cached = await self._get_contact(user)
            if cached.push_name != push_name:
                await ContactModel.update_or_create(
                    our_jid=self.jid,
                    their_jid=str(user),
                    defaults={'push_name': push_name}
                )
                previous_name = cached.push_name
                cached.push_name = push_name
                cached.found = True
                return True, previous_name
            return False, ""

    async def put_business_name(self, user: JID, business_name: str) -> Tuple[bool, str]:
        """Put business name, returns (changed, previous_name)."""
        async with self.contact_cache_lock:
            cached = await self._get_contact(user)
            if cached.business_name != business_name:
                await ContactModel.update_or_create(
                    our_jid=self.jid,
                    their_jid=str(user),
                    defaults={'business_name': business_name}
                )
                previous_name = cached.business_name
                cached.business_name = business_name
                cached.found = True
                return True, previous_name
            return False, ""

    async def get_contact(self, jid: JID) -> ContactInfo:
        """Get contact info."""
        async with self.contact_cache_lock:
            return await self._get_contact(jid)

    async def get_all_contacts(self) -> Dict[JID, ContactInfo]:
        """Get all contacts."""
        contacts_result = {}
        contacts = await ContactModel.filter(our_jid=self.jid).all()
        for contact in contacts:
            jid = JID.from_string(contact.their_jid)
            contacts_result[jid] = ContactInfo(
                first_name=contact.first_name or "",
                full_name=contact.full_name or "",
                push_name=contact.push_name or "",
                business_name=contact.business_name or "",
                found=True
            )
        return contacts_result

    # Compatibility methods for the missing methods from the summary
    async def put_all_contact_names(self, contacts: List[ContactEntry]) -> None:
        """Alias for put_many_contact_names for compatibility."""
        await self.put_many_contact_names(contacts)
