"""
App state encoding for WhatsApp.

Port of whatsmeow/appstate/encode.go
"""
import json
import logging
import time
import hashlib
from dataclasses import dataclass
from typing import List, Optional

from google.protobuf import proto_pb2

from ..generated.waCommon import WACommon_pb2
from ..generated.waServerSync import WAServerSync_pb2
from ..generated.waSyncAction import WASyncAction_pb2
from ..types import jid
from ..util.cbcutil import encrypt_cbc
from .hash import HashState, WAPatchName, concat_and_hmac, generate_content_mac, generate_patch_mac
from .keys import Processor, WAPatchName, INDEX_MUTE, INDEX_PIN, INDEX_ARCHIVE, INDEX_STAR, INDEX_LABEL_ASSOCIATION_CHAT, INDEX_LABEL_ASSOCIATION_MESSAGE, INDEX_LABEL_EDIT, INDEX_SETTING_PUSH_NAME

logger = logging.getLogger(__name__)

@dataclass
class MutationInfo:
    """
    Contains information about a single mutation to the app state.

    Attributes:
        index: Contains the thing being mutated (like `mute` or `pin_v1`), followed by parameters like the target JID.
        version: A static number that depends on the thing being mutated.
        value: Contains the data for the mutation.
    """
    index: List[str]
    version: int
    value: WASyncAction_pb2.SyncActionValue


@dataclass
class PatchInfo:
    """
    Contains information about a patch to the app state.
    A patch can contain multiple mutations, as long as all mutations are in the same app state type.

    Attributes:
        timestamp: The time when the patch was created. This will be filled automatically in encode_patch if it's zero.
        type: The app state type being mutated.
        mutations: Contains the individual mutations to apply to the app state in this patch.
    """
    type: WAPatchName
    mutations: List[MutationInfo]
    timestamp: Optional[float] = None


def build_mute(target: jid.JID, mute: bool, mute_duration: Optional[float] = None) -> PatchInfo:
    """
    Build an app state patch for muting or unmuting a chat.

    Args:
        target: The JID of the chat to mute/unmute
        mute: Whether to mute (True) or unmute (False) the chat
        mute_duration: The duration to mute the chat for in seconds. If None and mute is True, the chat is muted forever.

    Returns:
        A PatchInfo object containing the mutation
    """
    mute_end_timestamp = None
    if mute_duration is not None and mute_duration > 0:
        mute_end_timestamp = int((time.time() + mute_duration) * 1000)

    return PatchInfo(
        type=WAPatchName.REGULAR_HIGH,
        mutations=[
            MutationInfo(
                index=[INDEX_MUTE, str(target)],
                version=2,
                value=WASyncAction_pb2.SyncActionValue(
                    mute_action=WASyncAction_pb2.MuteAction(
                        muted=mute,
                        mute_end_timestamp=mute_end_timestamp
                    )
                )
            )
        ]
    )


def _new_pin_mutation_info(target: jid.JID, pin: bool) -> MutationInfo:
    """
    Create a new pin mutation info.

    Args:
        target: The JID of the chat to pin/unpin
        pin: Whether to pin (True) or unpin (False) the chat

    Returns:
        A MutationInfo object for the pin mutation
    """
    return MutationInfo(
        index=[INDEX_PIN, str(target)],
        version=5,
        value=WASyncAction_pb2.SyncActionValue(
            pin_action=WASyncAction_pb2.PinAction(
                pinned=pin
            )
        )
    )


def build_pin(target: jid.JID, pin: bool) -> PatchInfo:
    """
    Build an app state patch for pinning or unpinning a chat.

    Args:
        target: The JID of the chat to pin/unpin
        pin: Whether to pin (True) or unpin (False) the chat

    Returns:
        A PatchInfo object containing the mutation
    """
    return PatchInfo(
        type=WAPatchName.REGULAR_LOW,
        mutations=[
            _new_pin_mutation_info(target, pin)
        ]
    )


def build_archive(target: jid.JID, archive: bool, last_message_timestamp: Optional[float] = None,
                 last_message_key: Optional[WACommon_pb2.MessageKey] = None) -> PatchInfo:
    """
    Build an app state patch for archiving or unarchiving a chat.

    The last message timestamp and last message key are optional and can be set to None.
    Archiving a chat will also unpin it automatically.

    Args:
        target: The JID of the chat to archive/unarchive
        archive: Whether to archive (True) or unarchive (False) the chat
        last_message_timestamp: The timestamp of the last message in the chat
        last_message_key: The key of the last message in the chat

    Returns:
        A PatchInfo object containing the mutation(s)
    """
    if last_message_timestamp is None:
        last_message_timestamp = time.time()

    archive_mutation_info = MutationInfo(
        index=[INDEX_ARCHIVE, str(target)],
        version=3,
        value=WASyncAction_pb2.SyncActionValue(
            archive_chat_action=WASyncAction_pb2.ArchiveChatAction(
                archived=archive,
                message_range=WASyncAction_pb2.SyncActionMessageRange(
                    last_message_timestamp=int(last_message_timestamp)
                    # TODO: set LastSystemMessageTimestamp?
                )
            )
        )
    )

    if last_message_key is not None:
        archive_mutation_info.value.archive_chat_action.message_range.messages.append(
            WASyncAction_pb2.SyncActionMessage(
                key=last_message_key,
                timestamp=int(last_message_timestamp)
            )
        )

    mutations = [archive_mutation_info]
    if archive:
        mutations.append(_new_pin_mutation_info(target, False))

    return PatchInfo(
        type=WAPatchName.REGULAR_LOW,
        mutations=mutations
    )


def _new_label_chat_mutation(target: jid.JID, label_id: str, labeled: bool) -> MutationInfo:
    """
    Create a new label chat mutation info.

    Args:
        target: The JID of the chat to label/unlabel
        label_id: The ID of the label
        labeled: Whether to add (True) or remove (False) the label

    Returns:
        A MutationInfo object for the label chat mutation
    """
    return MutationInfo(
        index=[INDEX_LABEL_ASSOCIATION_CHAT, label_id, str(target)],
        version=3,
        value=WASyncAction_pb2.SyncActionValue(
            label_association_action=WASyncAction_pb2.LabelAssociationAction(
                labeled=labeled
            )
        )
    )


def build_label_chat(target: jid.JID, label_id: str, labeled: bool) -> PatchInfo:
    """
    Build an app state patch for labeling or unlabeling a chat.

    Args:
        target: The JID of the chat to label/unlabel
        label_id: The ID of the label
        labeled: Whether to add (True) or remove (False) the label

    Returns:
        A PatchInfo object containing the mutation
    """
    return PatchInfo(
        type=WAPatchName.REGULAR,
        mutations=[
            _new_label_chat_mutation(target, label_id, labeled)
        ]
    )


def _new_label_message_mutation(target: jid.JID, label_id: str, message_id: str, labeled: bool) -> MutationInfo:
    """
    Create a new label message mutation info.

    Args:
        target: The JID of the chat containing the message
        label_id: The ID of the label
        message_id: The ID of the message
        labeled: Whether to add (True) or remove (False) the label

    Returns:
        A MutationInfo object for the label message mutation
    """
    return MutationInfo(
        index=[INDEX_LABEL_ASSOCIATION_MESSAGE, label_id, str(target), message_id, "0", "0"],
        version=3,
        value=WASyncAction_pb2.SyncActionValue(
            label_association_action=WASyncAction_pb2.LabelAssociationAction(
                labeled=labeled
            )
        )
    )


def build_label_message(target: jid.JID, label_id: str, message_id: str, labeled: bool) -> PatchInfo:
    """
    Build an app state patch for labeling or unlabeling a message.

    Args:
        target: The JID of the chat containing the message
        label_id: The ID of the label
        message_id: The ID of the message
        labeled: Whether to add (True) or remove (False) the label

    Returns:
        A PatchInfo object containing the mutation
    """
    return PatchInfo(
        type=WAPatchName.REGULAR,
        mutations=[
            _new_label_message_mutation(target, label_id, message_id, labeled)
        ]
    )


def _new_label_edit_mutation(label_id: str, label_name: str, label_color: int, deleted: bool) -> MutationInfo:
    """
    Create a new label edit mutation info.

    Args:
        label_id: The ID of the label
        label_name: The name of the label
        label_color: The color of the label
        deleted: Whether the label is deleted

    Returns:
        A MutationInfo object for the label edit mutation
    """
    return MutationInfo(
        index=[INDEX_LABEL_EDIT, label_id],
        version=3,
        value=WASyncAction_pb2.SyncActionValue(
            label_edit_action=WASyncAction_pb2.LabelEditAction(
                name=label_name,
                color=label_color,
                deleted=deleted
            )
        )
    )


def build_label_edit(label_id: str, label_name: str, label_color: int, deleted: bool) -> PatchInfo:
    """
    Build an app state patch for editing a label.

    Args:
        label_id: The ID of the label
        label_name: The name of the label
        label_color: The color of the label
        deleted: Whether the label is deleted

    Returns:
        A PatchInfo object containing the mutation
    """
    return PatchInfo(
        type=WAPatchName.REGULAR,
        mutations=[
            _new_label_edit_mutation(label_id, label_name, label_color, deleted)
        ]
    )


def _new_setting_push_name_mutation(push_name: str) -> MutationInfo:
    """
    Create a new setting push name mutation info.

    Args:
        push_name: The push name to set

    Returns:
        A MutationInfo object for the setting push name mutation
    """
    return MutationInfo(
        index=[INDEX_SETTING_PUSH_NAME],
        version=1,
        value=WASyncAction_pb2.SyncActionValue(
            push_name_setting=WASyncAction_pb2.PushNameSetting(
                name=push_name
            )
        )
    )


def build_setting_push_name(push_name: str) -> PatchInfo:
    """
    Build an app state patch for setting the push name.

    Args:
        push_name: The push name to set

    Returns:
        A PatchInfo object containing the mutation
    """
    return PatchInfo(
        type=WAPatchName.CRITICAL_BLOCK,
        mutations=[
            _new_setting_push_name_mutation(push_name)
        ]
    )


def _new_star_mutation(target_jid: str, sender_jid: str, message_id: str, from_me: str, starred: bool) -> MutationInfo:
    """
    Create a new star mutation info.

    Args:
        target_jid: The JID of the chat containing the message
        sender_jid: The JID of the sender of the message
        message_id: The ID of the message
        from_me: "1" if the message is from the user, "0" otherwise
        starred: Whether to star (True) or unstar (False) the message

    Returns:
        A MutationInfo object for the star mutation
    """
    return MutationInfo(
        index=[INDEX_STAR, target_jid, message_id, from_me, sender_jid],
        version=2,
        value=WASyncAction_pb2.SyncActionValue(
            star_action=WASyncAction_pb2.StarAction(
                starred=starred
            )
        )
    )


def build_star(target: jid.JID, sender: jid.JID, message_id: str, from_me: bool, starred: bool) -> PatchInfo:
    """
    Build an app state patch for starring or unstarring a message.

    Args:
        target: The JID of the chat containing the message
        sender: The JID of the sender of the message
        message_id: The ID of the message
        from_me: Whether the message is from the user
        starred: Whether to star (True) or unstar (False) the message

    Returns:
        A PatchInfo object containing the mutation
    """
    is_from_me = "1" if from_me else "0"
    target_jid, sender_jid = str(target), str(sender)

    if target.user == sender.user:
        sender_jid = "0"

    return PatchInfo(
        type=WAPatchName.REGULAR_HIGH,
        mutations=[
            _new_star_mutation(target_jid, sender_jid, message_id, is_from_me, starred)
        ]
    )


async def encode_patch(processor: Processor, key_id: bytes, state: HashState, patch_info: PatchInfo) -> bytes:
    """
    Encode a patch for sending to the WhatsApp server.

    Args:
        processor:
        key_id: The key ID to use for encryption
        state: The current hash state
        patch_info: The patch information

    Returns:
        The encoded patch

    Raises:
        ValueError: If encoding fails
    """
    keys = await processor.get_app_state_key(key_id)

    if patch_info.timestamp is None:
        patch_info.timestamp = time.time()

    mutations = []
    for mutation_info in patch_info.mutations:
        mutation_info.value.timestamp = int(patch_info.timestamp * 1000)

        index_bytes = json.dumps(mutation_info.index).encode('utf-8')

        pb_obj = WASyncAction_pb2.SyncActionData(
            index=index_bytes,
            value=mutation_info.value,
            padding=b'',
            version=mutation_info.version
        )

        content = pb_obj.SerializeToString()

        # Generate a random IV (16 bytes)
        iv = bytes([x & 0xFF for x in range(16)])
        encrypted_content = encrypt_cbc(keys.value_encryption, iv, content)
        encrypted_content = iv + encrypted_content

        value_mac = generate_content_mac(
            WAServerSync_pb2.SyncdMutation.SyncdOperation.SET,
            encrypted_content,
            key_id,
            keys.value_mac
        )

        index_mac = concat_and_hmac(hashlib.sha256, keys.index, [index_bytes])

        mutations.append(WAServerSync_pb2.SyncdMutation(
            operation=WAServerSync_pb2.SyncdMutation.SyncdOperation.SET,
            record=WAServerSync_pb2.SyncdRecord(
                index=WAServerSync_pb2.SyncdIndex(blob=index_mac),
                value=WAServerSync_pb2.SyncdValue(blob=encrypted_content + value_mac),
                key_id=WAServerSync_pb2.KeyId(id=key_id)
            )
        ))

    async def get_prev_set_value_mac(index_mac: bytes, max_index: int) -> Optional[bytes]:
        return await processor.store.app_state.get_app_state_mutation_mac(str(patch_info.type), index_mac)


    warnings, err = state.update_hash(mutations, get_prev_set_value_mac)
    if warnings:
        logger.warning(f"Warnings while updating hash for {patch_info.type} (sending new app state): {warnings}")
    if err:
        raise ValueError(f"Failed to update state hash: {err}")

    state.version += 1

    syncd_patch = WAServerSync_pb2.SyncdPatch(
        snapshot_mac=state.generate_snapshot_mac(patch_info.type, keys.snapshot_mac),
        key_id=WAServerSync_pb2.KeyId(id=key_id),
        mutations=mutations
    )

    syncd_patch.patch_mac = generate_patch_mac(syncd_patch, patch_info.type, keys.patch_mac, state.version)

    result = syncd_patch.SerializeToString()

    return result
