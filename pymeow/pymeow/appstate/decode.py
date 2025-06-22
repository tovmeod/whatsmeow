"""
App state decoding for WhatsApp.

Port of whatsmeow/appstate/decode.go

This module implements the two main functions from the Go file:
1. ParsePatchList -> parse_patch_list
2. DecodePatches -> decode_patches (as a method on the Decoder class)

The Decoder class inherits from Processor (defined in keys.py) to maintain the same
functionality as the Go implementation where DecodePatches is a method on the Processor struct.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Awaitable, Callable, List, Optional, Tuple

from typing_extensions import Sequence

from ..generated.waServerSync import WAServerSync_pb2
from ..generated.waSyncAction import WASyncAction_pb2
from ..util.cbcutil import decrypt
from .errors import (
    ErrMismatchingContentMAC,
    ErrMismatchingIndexMAC,
    ErrMismatchingLTHash,
    ErrMismatchingPatchMAC,
)
from .hash import HashState, Mutation, concat_and_hmac, generate_content_mac, generate_patch_mac
from .keys import ExpandedAppStateKeys, Processor, WAPatchName

if TYPE_CHECKING:
    from ..binary.node import Node
    from ..store.store import AppStateMutationMAC

logger = logging.getLogger(__name__)


@dataclass
class PatchList:
    """Represents a decoded response to getting app state patches from the WhatsApp servers."""

    name: WAPatchName
    has_more_patches: bool
    patches: List[WAServerSync_pb2.SyncdPatch]
    snapshot: Optional[WAServerSync_pb2.SyncdSnapshot]


# Type alias for a function that can download a blob of external app state patches
DownloadExternalFunc = Callable[[WAServerSync_pb2.ExternalBlobReference], Awaitable[Optional[bytes]]]


async def parse_snapshot_internal(
    collection: "Node", download_external: DownloadExternalFunc
) -> Optional[WAServerSync_pb2.SyncdSnapshot]:
    """
    Parse a snapshot from a binary node.

    Args:
        collection: The collection node containing the snapshot
        download_external: Function to download external blobs

    Returns:
        The parsed snapshot, or None if no snapshot was found
    """
    snapshot_node = collection.get_child_by_tag("snapshot")
    if snapshot_node.tag != "snapshot" or not isinstance(snapshot_node.content, bytes):
        return None

    raw_snapshot = snapshot_node.content
    snapshot = WAServerSync_pb2.ExternalBlobReference()
    snapshot.ParseFromString(raw_snapshot)

    raw_data = await download_external(snapshot)
    if raw_data is None:
        raise ValueError("Failed to download external snapshot")

    downloaded = WAServerSync_pb2.SyncdSnapshot()
    downloaded.ParseFromString(raw_data)

    return downloaded


async def parse_patch_list_internal(
    collection: "Node", download_external: DownloadExternalFunc
) -> List[WAServerSync_pb2.SyncdPatch]:
    """
    Parse patches from a binary node.

    Args:
        collection: The collection node containing the patches
        download_external: Function to download external blobs

    Returns:
        List of parsed patches
    """
    patches_node = collection.get_child_by_tag("patches")
    patch_nodes = patches_node.get_children()
    patches = []

    for i, patch_node in enumerate(patch_nodes):
        if patch_node.tag != "patch" or not isinstance(patch_node.content, bytes):
            continue

        raw_patch = patch_node.content
        patch = WAServerSync_pb2.SyncdPatch()
        try:
            patch.ParseFromString(raw_patch)
        except Exception as err:
            raise ValueError(f"Failed to unmarshal patch #{i + 1}: {err}")

        if patch.HasField("externalMutations") and download_external is not None:
            raw_data = await download_external(patch.externalMutations)
            if raw_data is None:
                raise ValueError(f"Failed to download external mutations for patch #{i + 1}")

            downloaded = WAServerSync_pb2.SyncdMutations()
            downloaded.ParseFromString(raw_data)
            if len(downloaded.mutations) == 0:
                raise ValueError("Didn't get any mutations from download")

            patch.mutations.extend(downloaded.mutations)

        patches.append(patch)

    return patches


async def parse_patch_list(node: "Node", download_external: DownloadExternalFunc) -> PatchList:
    """
    Decode an XML node containing app state patches, including downloading any external blobs.

    Args:
        node: The node containing the patches
        download_external: Function to download external blobs

    Returns:
        A PatchList containing the decoded patches
    """
    collection = node.get_child_by_tag("sync", "collection")
    ag = collection.attr_getter()

    snapshot = await parse_snapshot_internal(collection, download_external)
    patches = await parse_patch_list_internal(collection, download_external)

    patch_list = PatchList(
        name=WAPatchName(ag.string("name")),
        has_more_patches=ag.optional_bool("has_more_patches"),
        patches=patches,
        snapshot=snapshot,
    )

    error = ag.error()
    if error is not None:
        raise error

    return patch_list


@dataclass
class PatchOutput:
    """Internal class for processing patch outputs."""

    removed_macs: List[bytes] = field(default_factory=list)
    added_macs: List["AppStateMutationMAC"] = field(default_factory=list)
    mutations: List[Mutation] = field(default_factory=list)


class Decoder(Processor):
    """Decoder for app state patches."""


async def decode_mutations(
    processor: Processor, mutations: Sequence[WAServerSync_pb2.SyncdMutation], out: PatchOutput, validate_macs: bool
) -> None:
    """
    Decode mutations from encrypted format.

    Args:
        processor
        mutations: The mutations to decode
        out: Output container for decoded mutations
        validate_macs: Whether to validate MACs

    Raises:
        ValueError: If decoding fails
    """
    from ..store.store import AppStateMutationMAC

    for i, mutation in enumerate(mutations):
        key_id = mutation.record.keyID.ID
        keys = await processor.get_app_state_key(key_id)

        content = mutation.record.value.blob
        content, value_mac = content[:-32], content[-32:]

        if validate_macs:
            expected_value_mac = generate_content_mac(mutation.operation, content, key_id, keys.value_mac)
            if expected_value_mac != value_mac:
                raise ErrMismatchingContentMAC(f"Failed to verify mutation #{i + 1}")

        iv, content = content[:16], content[16:]
        try:
            plaintext = decrypt(keys.value_encryption, iv, content)
        except Exception as err:
            raise ValueError(f"Failed to decrypt mutation #{i + 1}: {err}")

        sync_action = WASyncAction_pb2.SyncActionData()
        try:
            sync_action.ParseFromString(plaintext)
        except Exception as err:
            raise ValueError(f"Failed to unmarshal mutation #{i + 1}: {err}")

        index_mac = mutation.record.index.blob
        if validate_macs:
            expected_index_mac = concat_and_hmac(
                lambda: __import__("hashlib").sha256(), keys.index, [sync_action.index]
            )
            if expected_index_mac != index_mac:
                raise ErrMismatchingIndexMAC(f"Failed to verify mutation #{i + 1}")

        try:
            index = json.loads(sync_action.index)
        except Exception as err:
            raise ValueError(f"Failed to unmarshal index of mutation #{i + 1}: {err}")

        if mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.REMOVE:
            out.removed_macs.append(index_mac)
        elif mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.SET:
            out.added_macs.append(AppStateMutationMAC(index_mac=index_mac, value_mac=value_mac))

        out.mutations.append(
            Mutation(
                operation=mutation.operation,
                action=sync_action.value,
                index=index,
                index_mac=index_mac,
                value_mac=value_mac,
            )
        )


async def store_macs(processor: Processor, name: WAPatchName, current_state: HashState, out: PatchOutput) -> None:
    """
    Store MACs in the database.

    Args:
        processor
        name: The patch name
        current_state: The current hash state
        out: The patch output containing MACs to store
    """
    try:
        await processor.store.app_state.put_app_state_version(str(name), current_state.version, current_state.hash)
    except Exception as e:
        logger.exception(f"Failed to update app state version in the database: {e}")

    try:
        await processor.store.app_state.delete_app_state_mutation_macs(str(name), out.removed_macs)
    except Exception as e:
        logger.exception(f"Failed to remove deleted mutation MACs from the database: {e}")

    try:
        await processor.store.app_state.put_app_state_mutation_macs(str(name), current_state.version, out.added_macs)
    except Exception as e:
        logger.exception(f"Failed to insert added mutation MACs to the database: {e}")


async def validate_snapshot_mac(
    processor: Processor, name: WAPatchName, current_state: HashState, key_id: bytes, expected_snapshot_mac: bytes
) -> ExpandedAppStateKeys:
    """
    Validate a snapshot MAC.

    Args:
        processor
        name: The patch name
        current_state: The current hash state
        key_id: The key ID
        expected_snapshot_mac: The expected snapshot MAC

    Returns:
        expanded keys
    Raises:
        ValueError
        ErrMismatchingLTHash
    """
    keys = await processor.get_app_state_key(key_id)
    snapshot_mac = current_state.generate_snapshot_mac(name, keys.snapshot_mac)
    if snapshot_mac != expected_snapshot_mac:
        raise ErrMismatchingLTHash(f"Failed to verify patch v{current_state.version}")

    return keys


async def decode_snapshot(
    processor: Processor,
    name: WAPatchName,
    ss: WAServerSync_pb2.SyncdSnapshot,
    initial_state: HashState,
    validate_macs: bool,
    new_mutations_input: List[Mutation],
) -> Tuple[List[Mutation], HashState]:
    """
    Decode a snapshot.

    Args:
        processor
        name: The patch name
        ss: The snapshot to decode
        initial_state: The initial hash state
        validate_macs: Whether to validate MACs
        new_mutations_input: Input list of mutations

    Returns:
        A tuple of (new mutations, current state)
    Raises:
        ValueError
    """
    current_state = HashState(version=initial_state.version, hash=initial_state.hash)
    current_state.version = ss.version.version

    encrypted_mutations = []
    for record in ss.records:
        encrypted_mutations.append(
            WAServerSync_pb2.SyncdMutation(operation=WAServerSync_pb2.SyncdMutation.SyncdOperation.SET, record=record)
        )

    async def get_prev_set_value_mac(index_mac: bytes, max_index: int) -> Optional[bytes]:
        return None

    warnings = current_state.update_hash(encrypted_mutations, get_prev_set_value_mac)
    if warnings:
        logger.warning(f"Warnings while updating hash for {name}: {warnings}")

    if validate_macs:
        _ = await validate_snapshot_mac(processor, name, current_state, ss.keyID.ID, ss.mac)

    out = PatchOutput(mutations=new_mutations_input)
    await decode_mutations(processor, encrypted_mutations, out, validate_macs)
    await store_macs(processor, name, current_state, out)
    return out.mutations, current_state


async def decode_patches(
    processor: Processor, patch_list: PatchList, initial_state: HashState, validate_macs: bool
) -> Tuple[List[Mutation], HashState]:
    """
    Decode all the patches in a PatchList into a list of app state mutations.

    Args:
        processor:
        patch_list: The patch list to decode
        initial_state: The initial hash state
        validate_macs: Whether to validate MACs

    Returns:
        A tuple of (new mutations, current state)
    Raises:
        ErrMismatchingPatchMAC
    """
    current_state = HashState(version=initial_state.version, hash=initial_state.hash)
    expected_length = 0

    if patch_list.snapshot:
        expected_length += len(patch_list.snapshot.records)

    for patch in patch_list.patches:
        expected_length += len(patch.mutations)

    new_mutations: List[Mutation] = []

    if patch_list.snapshot:
        new_mutations, current_state = await decode_snapshot(
            processor, patch_list.name, patch_list.snapshot, current_state, validate_macs, new_mutations
        )

    for patch in patch_list.patches:
        version = patch.version.version
        current_state.version = version

        async def get_prev_set_value_mac(index_mac: bytes, max_index: int, current_patch=patch) -> Optional[bytes]:
            for i in range(max_index - 1, -1, -1):
                if current_patch.mutations[i].record.index.blob == index_mac:
                    value = current_patch.mutations[i].record.value.blob
                    return value[-32:]

            # Previous value not found in current patch, look in the database
            return await processor.store.app_state.get_app_state_mutation_mac(str(patch_list.name), index_mac)

        warnings = current_state.update_hash(patch.mutations, get_prev_set_value_mac)
        if warnings:
            logger.warning(f"Warnings while updating hash for {patch_list.name}: {warnings}")

        if validate_macs:
            keys = await validate_snapshot_mac(
                processor, patch_list.name, current_state, patch.keyID.ID, patch.snapshotMAC
            )

            patch_mac = generate_patch_mac(patch, patch_list.name, keys.patch_mac, patch.version.version)
            if patch_mac != patch.patchMAC:
                raise ErrMismatchingPatchMAC(f"Failed to verify patch v{version}")

        out = PatchOutput(mutations=new_mutations)
        await decode_mutations(processor, patch.mutations, out, validate_macs)
        await store_macs(processor, patch_list.name, current_state, out)
        new_mutations = out.mutations

    return new_mutations, current_state
