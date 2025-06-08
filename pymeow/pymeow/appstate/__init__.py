"""
App state management for WhatsApp.

Port of whatsmeow/appstate.go
"""
import logging
import time
from typing import Any, List, TYPE_CHECKING

from .. import download
from ..generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
from ..binary import node as binary_node
from ..exceptions import ErrAppStateUpdate
from ..request import InfoQuery, InfoQueryType
from ..store.store import ContactEntry
from ..types import events, JID

if TYPE_CHECKING:
    from pymeow.pymeow.client import Client

logger = logging.getLogger(__name__)


async def fetch_app_state(
    client: "Client",
    name: str,
    full_sync: bool,
    only_if_not_synced: bool
) -> None:
    """
    Fetch updates to the given type of app state. If full_sync is true, the current
    cached state will be removed and all app state patches will be re-fetched from the server.
    """
    if client is None:
        raise ValueError("Client is None")

    async with client.app_state_sync_lock:
        if full_sync:
            try:
                await client.store.app_state.delete_app_state_version(name)
            except Exception as err:
                raise Exception(f"failed to reset app state {name} version: {err}")

        try:
            version, hash_value = await client.store.app_state.get_app_state_version(name)
        except Exception as err:
            raise Exception(f"failed to get app state {name} version: {err}")

        if version == 0:
            full_sync = True
        elif only_if_not_synced:
            return

        from .__init__.hash import HashState
        state = HashState(version=version, hash=hash_value)

        has_more = True
        want_snapshot = full_sync

        while has_more:
            patches = await fetch_app_state_patches(client, name, state.version, want_snapshot)
            want_snapshot = False

            has_more = patches.has_more_patches

            try:
                mutations, new_state = await client.app_state_proc.decode_patches(patches, state, True)
            except Exception as err:
                if "key not found" in str(err).lower():
                    await request_missing_app_state_keys(client, patches)
                raise Exception(f"failed to decode app state {name} patches: {err}")

            was_full_sync = state.version == 0 and patches.snapshot is not None
            state = new_state

            if name == "critical_unblock_low" and was_full_sync and not client.emit_app_state_events_on_full_sync:
                mutations, contacts = filter_contacts(mutations)
                logger.debug(f"Mass inserting app state snapshot with {len(contacts)} contacts into the store")
                try:
                    await client.store.contacts.put_all_contact_names(contacts)
                except Exception as err:
                    raise Exception(f"failed to update contact store with data from snapshot: {err}")

            for mutation in mutations:
                await dispatch_app_state(client, mutation, full_sync, client.emit_app_state_events_on_full_sync)

        if full_sync:
            logger.debug(f"Full sync of app state {name} completed. Current version: {state.version}")
            await client.dispatch_event(events.AppStateSyncComplete(name=name))
        else:
            logger.debug(f"Synced app state {name} from version {version} to {state.version}")


def filter_contacts(mutations: List[Any]) -> tuple[List[Any], List[Any]]:
    """Filter contact mutations from the list and return them separately."""
    filtered_mutations = []
    contacts = []

    for mutation in mutations:
        if len(mutation.index) > 1 and mutation.index[0] == "contact":
            jid = JID.parse(mutation.index[1]) if len(mutation.index) > 1 else None
            if jid and mutation.action and hasattr(mutation.action, 'contact_action'):
                act = mutation.action.contact_action
                contacts.append(ContactEntry(
                    jid=jid,
                    first_name=getattr(act, 'first_name', '') if act else '',
                    full_name=getattr(act, 'full_name', '') if act else ''
                ))
        else:
            filtered_mutations.append(mutation)

    return filtered_mutations, contacts


async def dispatch_app_state(
    client: "Client",
    mutation: Any,
    full_sync: bool,
    emit_on_full_sync: bool
) -> None:
    """Dispatch app state mutation as events."""
    dispatch_evts = not full_sync or emit_on_full_sync

    # Only handle SET operations
    if not hasattr(mutation, 'operation') or mutation.operation != 'SET':
        return

    if dispatch_evts:
        await client.dispatch_event(events.AppState(
            index=mutation.index,
            sync_action_value=mutation.action
        ))

    jid = None
    if len(mutation.index) > 1:
        jid = JID.parse(mutation.index[1])

    timestamp = time.time()
    if hasattr(mutation.action, 'timestamp'):
        timestamp = mutation.action.timestamp / 1000  # Convert from milliseconds

    store_update_error = None
    event_to_dispatch = None

    index_type = mutation.index[0] if mutation.index else ""

    if index_type == "mute":
        if hasattr(mutation.action, 'mute_action'):
            act = mutation.action.mute_action
            event_to_dispatch = events.Mute(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

            muted_until = None
            if getattr(act, 'muted', False):
                muted_until = getattr(act, 'mute_end_timestamp', 0) / 1000

            if client.store.chat_settings:
                try:
                    await client.store.chat_settings.put_muted_until(jid, muted_until)
                except Exception as err:
                    store_update_error = err

    elif index_type == "pin":
        if hasattr(mutation.action, 'pin_action'):
            act = mutation.action.pin_action
            event_to_dispatch = events.Pin(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

            if client.store.chat_settings:
                try:
                    await client.store.chat_settings.put_pinned(jid, getattr(act, 'pinned', False))
                except Exception as err:
                    store_update_error = err

    elif index_type == "archive":
        if hasattr(mutation.action, 'archive_chat_action'):
            act = mutation.action.archive_chat_action
            event_to_dispatch = events.Archive(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

            if client.store.chat_settings:
                try:
                    await client.store.chat_settings.put_archived(jid, getattr(act, 'archived', False))
                except Exception as err:
                    store_update_error = err

    elif index_type == "contact":
        if hasattr(mutation.action, 'contact_action'):
            act = mutation.action.contact_action
            event_to_dispatch = events.Contact(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

            if client.store.contacts:
                try:
                    await client.store.contacts.put_contact_name(
                        jid,
                        getattr(act, 'first_name', ''),
                        getattr(act, 'full_name', '')
                    )
                except Exception as err:
                    store_update_error = err

    elif index_type == "clearChat":
        if hasattr(mutation.action, 'clear_chat_action'):
            act = mutation.action.clear_chat_action
            event_to_dispatch = events.ClearChat(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

    elif index_type == "deleteChat":
        if hasattr(mutation.action, 'delete_chat_action'):
            act = mutation.action.delete_chat_action
            event_to_dispatch = events.DeleteChat(
                jid=jid,
                timestamp=timestamp,
                action=act,
                from_full_sync=full_sync
            )

    elif index_type == "star":
        if len(mutation.index) >= 5:
            evt = events.Star(
                chat_jid=jid,
                message_id=mutation.index[2],
                timestamp=timestamp,
                action=getattr(mutation.action, 'star_action', None),
                is_from_me=mutation.index[3] == "1",
                from_full_sync=full_sync
            )
            if mutation.index[4] != "0":
                evt.sender_jid = JID.parse(mutation.index[4])
            event_to_dispatch = evt

    elif index_type == "deleteMessageForMe":
        if len(mutation.index) >= 5:
            evt = events.DeleteForMe(
                chat_jid=jid,
                message_id=mutation.index[2],
                timestamp=timestamp,
                action=getattr(mutation.action, 'delete_message_for_me_action', None),
                is_from_me=mutation.index[3] == "1",
                from_full_sync=full_sync
            )
            if mutation.index[4] != "0":
                evt.sender_jid = JID.parse_jid(mutation.index[4])
            event_to_dispatch = evt

    elif index_type == "markChatAsRead":
        event_to_dispatch = events.MarkChatAsRead(
            jid=jid,
            timestamp=timestamp,
            action=getattr(mutation.action, 'mark_chat_as_read_action', None),
            from_full_sync=full_sync
        )

    elif index_type == "setting_pushName":
        event_to_dispatch = events.PushNameSetting(
            timestamp=timestamp,
            action=getattr(mutation.action, 'push_name_setting', None),
            from_full_sync=full_sync
        )

        if hasattr(mutation.action, 'push_name_setting') and hasattr(mutation.action.push_name_setting, 'name'):
            client.store.push_name = mutation.action.push_name_setting.name
            try:
                await client.store.save()
            except Exception as err:
                logger.error(f"Failed to save device store after updating push name: {err}")

    elif index_type == "setting_unarchiveChats":
        event_to_dispatch = events.UnarchiveChatsSetting(
            timestamp=timestamp,
            action=getattr(mutation.action, 'unarchive_chats_setting', None),
            from_full_sync=full_sync
        )

    elif index_type == "userStatusMute":
        event_to_dispatch = events.UserStatusMute(
            jid=jid,
            timestamp=timestamp,
            action=getattr(mutation.action, 'user_status_mute_action', None),
            from_full_sync=full_sync
        )

    elif index_type == "labelEdit":
        event_to_dispatch = events.LabelEdit(
            timestamp=timestamp,
            label_id=mutation.index[1] if len(mutation.index) > 1 else "",
            action=getattr(mutation.action, 'label_edit_action', None),
            from_full_sync=full_sync
        )

    elif index_type == "labelAssociationChat":
        if len(mutation.index) >= 3:
            jid = JID.parse(mutation.index[2])
            event_to_dispatch = events.LabelAssociationChat(
                jid=jid,
                timestamp=timestamp,
                label_id=mutation.index[1],
                action=getattr(mutation.action, 'label_association_action', None),
                from_full_sync=full_sync
            )

    elif index_type == "labelAssociationMessage":
        if len(mutation.index) >= 6:
            jid = JID.parse(mutation.index[2])
            event_to_dispatch = events.LabelAssociationMessage(
                jid=jid,
                timestamp=timestamp,
                label_id=mutation.index[1],
                message_id=mutation.index[3],
                action=getattr(mutation.action, 'label_association_action', None),
                from_full_sync=full_sync
            )

    if store_update_error:
        logger.error(f"Failed to update device store after app state mutation: {store_update_error}")

    if dispatch_evts and event_to_dispatch:
        await client.dispatch_event(event_to_dispatch)


async def download_external_app_state_blob(client: "Client", ref: Any) -> bytes:
    """Download external app state blob."""
    return await download.download(client, ref)


async def fetch_app_state_patches(
    client: "Client",
    name: str,
    from_version: int,
    snapshot: bool
) -> Any:
    """Fetch app state patches from the server."""
    attrs = {
        "name": name,
        "return_snapshot": snapshot,
    }
    if not snapshot:
        attrs["version"] = from_version

    resp = await client.send_iq(InfoQuery(
        namespace="w:sync:app:state",
        type="set",
        to=client.store.server_jid,
        content=[binary_node.Node(
            tag="sync",
            content=[binary_node.Node(
                tag="collection",
                attrs=attrs
            )]
        )]
    ))

    from .decode import parse_patch_list
    return await parse_patch_list(resp, lambda ref: download_external_app_state_blob(client, ref))


async def request_missing_app_state_keys(client: "Client", patches: Any) -> None:
    """Request missing app state keys from the server."""
    async with client.app_state_key_requests_lock:
        raw_key_ids = await client.app_state_proc.get_missing_key_ids(patches)
        filtered_key_ids = []
        now = time.time()

        for key_id in raw_key_ids:
            string_key_id = key_id.hex()
            last_request_time = client.app_state_key_requests.get(string_key_id, 0)

            if last_request_time == 0 or (now - last_request_time) > 24 * 3600:  # 24 hours
                client.app_state_key_requests[string_key_id] = now
                filtered_key_ids.append(key_id)

    await request_app_state_keys(client, filtered_key_ids)


async def request_app_state_keys(client: "Client", raw_key_ids: List[bytes]) -> None:
    """Request app state keys from the server."""
    from ..send import SendRequestExtra
    if not raw_key_ids:
        return

    key_ids = []
    debug_key_ids = []

    for key_id in raw_key_ids:
        key_ids.append(waE2E_pb2.AppStateSyncKeyId(keyID=key_id))
        debug_key_ids.append(key_id.hex())

    msg = waE2E_pb2.Message(
        protocolMessage=waE2E_pb2.ProtocolMessage(
            type=waE2E_pb2.ProtocolMessage.APP_STATE_SYNC_KEY_REQUEST,
            appStateSyncKeyRequest=waE2E_pb2.AppStateSyncKeyRequest(
                keyIDs=key_ids
            )
        )
    )

    own_id = client.get_own_id().to_non_ad()
    if own_id.is_empty():
        return

    logger.info(f"Sending key request for app state keys {debug_key_ids}")
    try:
        await client.send_message(own_id, msg, SendRequestExtra(peer=True))
    except Exception as err:
        logger.warning(f"Failed to send app state key request: {err}")


async def send_app_state(client: "Client", ctx: Any, patch: Any) -> None:
    """
    Send the given app state patch, then resyncs that app state type from the server
    to update local caches and send events for the updates.
    """
    if client is None:
        raise ValueError("Client is None")

    try:
        version, hash_value = await client.store.app_state.get_app_state_version(ctx, patch.type)
    except Exception as err:
        raise err

    # TODO: create new key instead of reusing the primary client's keys
    try:
        latest_key_id = await client.store.app_state_keys.get_latest_app_state_sync_key_id(ctx)
    except Exception as err:
        raise Exception(f"failed to get latest app state key ID: {err}")

    if latest_key_id is None:
        raise Exception("no app state keys found, creating app state keys is not yet supported")

    from .__init__.hash import HashState
    state = HashState(version=version, hash=hash_value)

    encoded_patch = await client.app_state_proc.encode_patch(ctx, latest_key_id, state, patch)

    resp = await client.send_iq(InfoQuery(
        namespace="w:sync:app:state",
        type=InfoQueryType.SET,
        to=client.store.server_jid,
        content=[binary_node.Node(
            tag="sync",
            content=[binary_node.Node(
                tag="collection",
                attrs={
                    "name": patch.type,
                    "version": version,
                    "return_snapshot": False,
                },
                content=[binary_node.Node(
                    tag="patch",
                    content=encoded_patch
                )]
            )]
        )]
    ))

    resp_collection = resp.get_child_by_tag("sync").get_child_by_tag("collection")
    resp_collection_attr = resp_collection.attr_getter()

    if resp_collection_attr.optional_string("type") == "error":
        raise ErrAppStateUpdate(f"App state update failed: {resp_collection.xml_string()}")

    await fetch_app_state(client, ctx, patch.type, False, False)
