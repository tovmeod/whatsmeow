"""
App state management for WhatsApp.

Port of whatsmeow/appstate.go
"""
import asyncio
import base64
import binascii
import contextlib
import logging
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Any, Tuple, Callable, Awaitable, Union

# Protocol buffer imports
from .generated.waE2E import WAE2E_pb2
from .generated.waServerSync import WAServerSync_pb2

# Internal imports
from .binary import node as binary_node
from .types import events, jid
from .types.jid import JID
from .store.store import Store
from .appstate.keys import WAPatchName, Processor, ExpandedAppStateKeys
from .appstate.hash import HashState
from .appstate.errors import ErrKeyNotFound

logger = logging.getLogger(__name__)

# Define ErrAppStateUpdate error class
class ErrAppStateUpdate(Exception):
    """Raised when the server returns an error updating app state."""
    def __init__(self, message="Server returned error updating app state"):
        self.message = message
        super().__init__(self.message)

class Client:
    """
    Client interface for app state operations.

    This is a minimal interface that the appstate module expects from the client.
    """
    async def download(self, ctx: Any, ref: Any) -> bytes:
        """Download external app state blob."""
        raise NotImplementedError()

    def get_own_id(self) -> JID:
        """Get the client's own JID."""
        raise NotImplementedError()

    async def send_message(self, ctx: Any, to: JID, message: Any, extra: Any) -> Any:
        """Send a message to the specified JID."""
        raise NotImplementedError()

    async def send_iq(self, query: Any) -> Any:
        """Send an IQ request."""
        raise NotImplementedError()

    def dispatch_event(self, event: Any) -> None:
        """Dispatch an event to event handlers."""
        raise NotImplementedError()

class AppState:
    """
    App state management for WhatsApp.

    This class handles fetching, decoding, and applying app state patches.
    """

    def __init__(self, client: Client, store: Store, processor: Processor, log: Optional[logging.Logger] = None):
        """
        Initialize a new app state manager.

        Args:
            client: The WhatsApp client
            store: The device store
            processor: The app state processor
            log: Logger for debug messages
        """
        self.client = client
        self.store = store
        self.processor = processor
        self.app_state_sync_lock = asyncio.Lock()
        self.app_state_key_requests_lock = asyncio.Lock()
        self.app_state_key_requests: Dict[str, float] = {}
        self.emit_app_state_events_on_full_sync = False

    async def fetch_app_state(self, ctx: Any, name: WAPatchName, full_sync: bool, only_if_not_synced: bool) -> None:
        """
        Fetch updates to the given type of app state.

        If full_sync is True, the current cached state will be removed and all app state
        patches will be re-fetched from the server.

        Args:
            ctx: Context for the operation
            name: The type of app state to fetch
            full_sync: Whether to do a full sync
            only_if_not_synced: Only sync if not already synced

        Raises:
            Exception: If there's an error fetching or decoding patches
        """
        async with self.app_state_sync_lock:
            if full_sync:
                err = await self.store.app_state.delete_app_state_version(str(name))
                if err:
                    raise Exception(f"Failed to reset app state {name} version: {err}")

            version, hash_val, err = await self.store.app_state.get_app_state_version(str(name))
            if err:
                raise Exception(f"Failed to get app state {name} version: {err}")

            if version == 0:
                full_sync = True
            elif only_if_not_synced:
                return

            state = HashState(version=version, hash=hash_val)

            has_more = True
            want_snapshot = full_sync
            while has_more:
                patches = await self.fetch_app_state_patches(ctx, name, state.version, want_snapshot)
                want_snapshot = False
                if not patches:
                    raise Exception(f"Failed to fetch app state {name} patches")

                has_more = patches.has_more_patches

                try:
                    mutations, new_state = await self.processor.decode_patches(ctx, patches, state, True)
                    if not mutations or not new_state:
                        raise Exception("Failed to decode patches")
                except ErrKeyNotFound:
                    asyncio.create_task(self.request_missing_app_state_keys(ctx, patches))
                    raise Exception(f"Failed to decode app state {name} patches: key not found")
                except Exception as e:
                    raise Exception(f"Failed to decode app state {name} patches: {e}")

                was_full_sync = state.version == 0 and patches.snapshot is not None
                state = new_state

                if name == WAPatchName.CRITICAL_UNBLOCK_LOW and was_full_sync and not self.emit_app_state_events_on_full_sync:
                    contacts = []
                    mutations, contacts = self.filter_contacts(mutations)
                    logger.debug(f"Mass inserting app state snapshot with {len(contacts)} contacts into the store")
                    err = await self.store.contacts.put_all_contact_names(ctx, contacts)
                    if err:
                        raise Exception(f"Failed to update contact store with data from snapshot: {err}")

                for mutation in mutations:
                    await self.dispatch_app_state(ctx, mutation, full_sync, self.emit_app_state_events_on_full_sync)

            if full_sync:
                logger.debug(f"Full sync of app state {name} completed. Current version: {state.version}")
                self.client.dispatch_event(events.AppStateSyncComplete(name=name))
            else:
                logger.debug(f"Synced app state {name} from version {version} to {state.version}")

    def filter_contacts(self, mutations: List[Any]) -> Tuple[List[Any], List[Any]]:
        """
        Filter contact mutations from a list of mutations.

        Args:
            mutations: The list of mutations to filter

        Returns:
            A tuple of (filtered_mutations, contacts)
        """
        filtered_mutations = []
        contacts = []

        for mutation in mutations:
            if mutation.index[0] == "contact" and len(mutation.index) > 1:
                contact_jid = jid.parse_jid(mutation.index[1])
                act = mutation.action.contact_action
                contacts.append({
                    "jid": contact_jid,
                    "first_name": act.first_name if act else "",
                    "full_name": act.full_name if act else ""
                })
            else:
                filtered_mutations.append(mutation)

        return filtered_mutations, contacts

    async def dispatch_app_state(self, ctx: Any, mutation: Any, full_sync: bool, emit_on_full_sync: bool) -> None:
        """
        Dispatch app state events based on mutations.

        Args:
            ctx: Context for the operation
            mutation: The mutation to dispatch
            full_sync: Whether this is part of a full sync
            emit_on_full_sync: Whether to emit events during a full sync
        """
        dispatch_evts = not full_sync or emit_on_full_sync

        if mutation.operation != WAServerSync_pb2.SyncdMutation.SET:
            return

        if dispatch_evts:
            self.client.dispatch_event(events.AppState(
                index=mutation.index,
                sync_action_value=mutation.action
            ))

        jid_obj = None
        if len(mutation.index) > 1:
            jid_obj = jid.parse_jid(mutation.index[1])

        ts = datetime.fromtimestamp(mutation.action.timestamp / 1000)

        store_update_error = None
        event_to_dispatch = None

        # Handle different types of mutations based on the index
        if mutation.index[0] == "mute":
            act = mutation.action.mute_action
            event_to_dispatch = events.Mute(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

            if act and act.muted and self.store.chat_settings:
                muted_until = datetime.fromtimestamp(act.mute_end_timestamp / 1000)
                store_update_error = await self.store.chat_settings.put_muted_until(ctx, jid_obj, muted_until)
            elif self.store.chat_settings:
                store_update_error = await self.store.chat_settings.put_muted_until(ctx, jid_obj, None)

        elif mutation.index[0] == "pin_v1":
            act = mutation.action.pin_action
            event_to_dispatch = events.Pin(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

            if act and self.store.chat_settings:
                store_update_error = await self.store.chat_settings.put_pinned(ctx, jid_obj, act.pinned)

        elif mutation.index[0] == "archive":
            act = mutation.action.archive_chat_action
            event_to_dispatch = events.Archive(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

            if act and self.store.chat_settings:
                store_update_error = await self.store.chat_settings.put_archived(ctx, jid_obj, act.archived)

        elif mutation.index[0] == "contact":
            act = mutation.action.contact_action
            event_to_dispatch = events.Contact(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

            if act and self.store.contacts:
                store_update_error = await self.store.contacts.put_contact_name(
                    jid_obj, act.first_name, act.full_name
                )

        elif mutation.index[0] == "clearChat":
            act = mutation.action.clear_chat_action
            event_to_dispatch = events.ClearChat(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "deleteChat":
            act = mutation.action.delete_chat_action
            event_to_dispatch = events.DeleteChat(
                jid=jid_obj,
                timestamp=ts,
                action=act,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "star" and len(mutation.index) >= 5:
            evt = events.Star(
                chat_jid=jid_obj,
                message_id=mutation.index[2],
                timestamp=ts,
                action=mutation.action.star_action,
                is_from_me=mutation.index[3] == "1",
                from_full_sync=full_sync
            )

            if mutation.index[4] != "0":
                evt.sender_jid = jid.parse_jid(mutation.index[4])

            event_to_dispatch = evt

        elif mutation.index[0] == "deleteMessageForMe" and len(mutation.index) >= 5:
            evt = events.DeleteForMe(
                chat_jid=jid_obj,
                message_id=mutation.index[2],
                timestamp=ts,
                action=mutation.action.delete_message_for_me_action,
                is_from_me=mutation.index[3] == "1",
                from_full_sync=full_sync
            )

            if mutation.index[4] != "0":
                evt.sender_jid = jid.parse_jid(mutation.index[4])

            event_to_dispatch = evt

        elif mutation.index[0] == "markChatAsRead":
            event_to_dispatch = events.MarkChatAsRead(
                jid=jid_obj,
                timestamp=ts,
                action=mutation.action.mark_chat_as_read_action,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "setting_pushName":
            event_to_dispatch = events.PushNameSetting(
                timestamp=ts,
                action=mutation.action.push_name_setting,
                from_full_sync=full_sync
            )

            self.store.push_name = mutation.action.push_name_setting.name
            err = await self.store.save(ctx)
            if err:
                logger.error(f"Failed to save device store after updating push name: {err}")

        elif mutation.index[0] == "setting_unarchiveChats":
            event_to_dispatch = events.UnarchiveChatsSetting(
                timestamp=ts,
                action=mutation.action.unarchive_chats_setting,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "userStatusMute":
            event_to_dispatch = events.UserStatusMute(
                jid=jid_obj,
                timestamp=ts,
                action=mutation.action.user_status_mute_action,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "label_edit":
            act = mutation.action.label_edit_action
            event_to_dispatch = events.LabelEdit(
                timestamp=ts,
                label_id=mutation.index[1],
                action=act,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "label_jid" and len(mutation.index) >= 3:
            jid_obj = jid.parse_jid(mutation.index[2])
            act = mutation.action.label_association_action
            event_to_dispatch = events.LabelAssociationChat(
                jid=jid_obj,
                timestamp=ts,
                label_id=mutation.index[1],
                action=act,
                from_full_sync=full_sync
            )

        elif mutation.index[0] == "label_message" and len(mutation.index) >= 6:
            jid_obj = jid.parse_jid(mutation.index[2])
            act = mutation.action.label_association_action
            event_to_dispatch = events.LabelAssociationMessage(
                jid=jid_obj,
                timestamp=ts,
                label_id=mutation.index[1],
                message_id=mutation.index[3],
                action=act,
                from_full_sync=full_sync
            )

        if store_update_error:
            logger.error(f"Failed to update device store after app state mutation: {store_update_error}")

        if dispatch_evts and event_to_dispatch:
            self.client.dispatch_event(event_to_dispatch)

    async def download_external_app_state_blob(self, ctx: Any, ref: Any) -> bytes:
        """
        Download an external app state blob.

        Args:
            ctx: Context for the operation
            ref: Reference to the blob

        Returns:
            The downloaded blob data
        """
        return await self.client.download(ctx, ref)

    async def fetch_app_state_patches(self, ctx: Any, name: WAPatchName, from_version: int, snapshot: bool) -> Any:
        """
        Fetch app state patches from the server.

        Args:
            ctx: Context for the operation
            name: The type of app state to fetch
            from_version: The version to fetch from
            snapshot: Whether to request a snapshot

        Returns:
            The fetched patches
        """
        attrs = {
            "name": str(name),
            "return_snapshot": snapshot
        }

        if not snapshot:
            attrs["version"] = from_version

        resp = await self.client.send_iq({
            "context": ctx,
            "namespace": "w:sync:app:state",
            "type": "set",
            "to": JID.create("s.whatsapp.net"),
            "content": [binary_node.Node(
                tag="sync",
                content=[binary_node.Node(
                    tag="collection",
                    attrs=attrs
                )]
            )]
        })

        if not resp:
            return None

        return await self.processor.parse_patch_list(ctx, resp, self.download_external_app_state_blob)

    async def request_missing_app_state_keys(self, ctx: Any, patches: Any) -> None:
        """
        Request missing app state keys.

        Args:
            ctx: Context for the operation
            patches: The patches with missing keys
        """
        async with self.app_state_key_requests_lock:
            raw_key_ids = await self.processor.get_missing_key_ids(patches)
            filtered_key_ids = []
            now = time.time()

            for key_id in raw_key_ids:
                string_key_id = binascii.hexlify(key_id).decode('ascii')
                last_request_time = self.app_state_key_requests.get(string_key_id, 0)
                if last_request_time == 0 or last_request_time + 24*60*60 < now:
                    self.app_state_key_requests[string_key_id] = now
                    filtered_key_ids.append(key_id)

        await self.request_app_state_keys(ctx, filtered_key_ids)

    async def request_app_state_keys(self, ctx: Any, raw_key_ids: List[bytes]) -> None:
        """
        Send requests for app state keys.

        Args:
            ctx: Context for the operation
            raw_key_ids: The key IDs to request
        """
        key_ids = []
        debug_key_ids = []

        for key_id in raw_key_ids:
            key_ids.append(WAE2E_pb2.AppStateSyncKeyId(key_id=key_id))
            debug_key_ids.append(binascii.hexlify(key_id).decode('ascii'))

        msg = WAE2E_pb2.Message(
            protocol_message=WAE2E_pb2.ProtocolMessage(
                type=WAE2E_pb2.ProtocolMessage.APP_STATE_SYNC_KEY_REQUEST,
                app_state_sync_key_request=WAE2E_pb2.AppStateSyncKeyRequest(
                    key_ids=key_ids
                )
            )
        )

        own_id = self.client.get_own_id().to_non_ad()
        if own_id.is_empty() or not debug_key_ids:
            return

        logger.info(f"Sending key request for app state keys {debug_key_ids}")

        try:
            await self.client.send_message(ctx, own_id, msg, {"peer": True})
        except Exception as e:
            logger.warning(f"Failed to send app state key request: {e}")

    async def send_app_state(self, ctx: Any, patch: Any) -> None:
        """
        Send an app state patch to the server.

        Args:
            ctx: Context for the operation
            patch: The patch to send

        Raises:
            Exception: If there's an error sending the patch
        """
        version, hash_val, err = await self.store.app_state.get_app_state_version(str(patch.type))
        if err:
            raise err

        latest_key_id, err = await self.store.app_state_keys.get_latest_app_state_sync_key_id(ctx)
        if err:
            raise Exception(f"Failed to get latest app state key ID: {err}")
        elif not latest_key_id:
            raise Exception("No app state keys found, creating app state keys is not yet supported")

        state = HashState(version=version, hash=hash_val)

        encoded_patch = await self.processor.encode_patch(ctx, latest_key_id, state, patch)
        if not encoded_patch:
            raise Exception("Failed to encode patch")

        resp = await self.client.send_iq({
            "context": ctx,
            "namespace": "w:sync:app:state",
            "type": "set",
            "to": JID.create("s.whatsapp.net"),
            "content": [binary_node.Node(
                tag="sync",
                content=[binary_node.Node(
                    tag="collection",
                    attrs={
                        "name": str(patch.type),
                        "version": version,
                        "return_snapshot": False
                    },
                    content=[binary_node.Node(
                        tag="patch",
                        content=encoded_patch
                    )]
                )]
            )]
        })

        if not resp:
            raise Exception("Failed to send app state patch")

        resp_collection = resp.get_child_by_tag("sync", "collection")
        if not resp_collection:
            raise Exception("Invalid response to app state patch")

        resp_collection_attr = resp_collection.attrs
        if resp_collection_attr.get("type") == "error":
            raise ErrAppStateUpdate(f"Error updating app state: {resp_collection}")

        await self.fetch_app_state(ctx, patch.type, False, False)

# Import datetime here to avoid circular imports
from datetime import datetime
