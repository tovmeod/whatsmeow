"""
App state decoding for WhatsApp.

Port of whatsmeow/appstate/decode.go

This module implements the two main functions from the Go file:
1. ParsePatchList -> parse_patch_list
2. DecodePatches -> decode_patches (as a method on the Decoder class)

The Decoder class inherits from Processor (defined in keys.py) to maintain the same
functionality as the Go implementation where DecodePatches is a method on the Processor struct.
"""
import asyncio
import base64
import json
import logging
from dataclasses import dataclass
from typing import List, Callable, Tuple, Optional, Dict, Any, Awaitable, Union

from ..binary import wabinary
from ..generated.waServerSync import WAServerSync_pb2
from ..generated.waSyncAction import WASyncAction_pb2
from ..generated.waCommon import WACommon_pb2
from ..store.store import Store
from ..util.cbcutil import decrypt_cbc
from .errors import (
    ErrMismatchingContentMAC,
    ErrMismatchingIndexMAC,
    ErrMismatchingLTHash,
    ErrMismatchingPatchMAC,
    KeyNotFoundError
)
from .hash import (
    HashState,
    Mutation,
    WAPatchName,
    concat_and_hmac,
    generate_content_mac,
    generate_patch_mac
)
from .keys import ExpandedAppStateKeys, Processor

logger = logging.getLogger(__name__)

@dataclass
class PatchList:
    """Represents a decoded response to getting app state patches from the WhatsApp servers."""
    name: WAPatchName
    has_more_patches: bool
    patches: List[WAServerSync_pb2.SyncdPatch]
    snapshot: Optional[WAServerSync_pb2.SyncdSnapshot]


# Type alias for a function that can download a blob of external app state patches
DownloadExternalFunc = Callable[[Any, WAServerSync_pb2.ExternalBlobReference], Awaitable[bytes]]


async def parse_snapshot_internal(ctx: Any, collection: wabinary.Node, download_external: DownloadExternalFunc) -> Optional[WAServerSync_pb2.SyncdSnapshot]:
    """
    Parse a snapshot from a binary node.

    Args:
        ctx: Context for the operation
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
    try:
        snapshot.ParseFromString(raw_snapshot)
    except Exception as err:
        raise ValueError(f"Failed to unmarshal snapshot: {err}")

    try:
        raw_data = await download_external(ctx, snapshot)
    except Exception as err:
        raise ValueError(f"Failed to download external mutations: {err}")

    downloaded = WAServerSync_pb2.SyncdSnapshot()
    try:
        downloaded.ParseFromString(raw_data)
    except Exception as err:
        raise ValueError(f"Failed to unmarshal mutation list: {err}")

    return downloaded


async def parse_patch_list_internal(ctx: Any, collection: wabinary.Node, download_external: DownloadExternalFunc) -> List[WAServerSync_pb2.SyncdPatch]:
    """
    Parse patches from a binary node.

    Args:
        ctx: Context for the operation
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
            raise ValueError(f"Failed to unmarshal patch #{i+1}: {err}")

        if patch.HasField("external_mutations") and download_external is not None:
            try:
                raw_data = await download_external(ctx, patch.external_mutations)
            except Exception as err:
                raise ValueError(f"Failed to download external mutations: {err}")

            downloaded = WAServerSync_pb2.SyncdMutations()
            try:
                downloaded.ParseFromString(raw_data)
            except Exception as err:
                raise ValueError(f"Failed to unmarshal mutation list: {err}")

            if len(downloaded.mutations) == 0:
                raise ValueError("Didn't get any mutations from download")

            patch.mutations.extend(downloaded.mutations)

        patches.append(patch)

    return patches


async def parse_patch_list(ctx: Any, node: wabinary.Node, download_external: DownloadExternalFunc) -> PatchList:
    """
    Decode an XML node containing app state patches, including downloading any external blobs.

    Args:
        ctx: Context for the operation
        node: The node containing the patches
        download_external: Function to download external blobs

    Returns:
        A PatchList containing the decoded patches
    """
    collection = node.get_child_by_tag("sync", "collection")
    ag = collection.attr_getter()

    snapshot = await parse_snapshot_internal(ctx, collection, download_external)
    patches = await parse_patch_list_internal(ctx, collection, download_external)

    patch_list = PatchList(
        name=WAPatchName(ag.string("name")),
        has_more_patches=ag.optional_bool("has_more_patches"),
        patches=patches,
        snapshot=snapshot
    )

    if ag.error():
        raise ag.error()

    return patch_list


@dataclass
class PatchOutput:
    """Internal class for processing patch outputs."""
    removed_macs: List[bytes] = None
    added_macs: List[Dict[str, bytes]] = None
    mutations: List[Mutation] = None

    def __post_init__(self):
        if self.removed_macs is None:
            self.removed_macs = []
        if self.added_macs is None:
            self.added_macs = []
        if self.mutations is None:
            self.mutations = []


class Decoder(Processor):
    """Decoder for app state patches."""

    async def decode_mutations(self, ctx: Any, mutations: List[WAServerSync_pb2.SyncdMutation],
                              out: PatchOutput, validate_macs: bool) -> None:
        """
        Decode mutations from encrypted format.

        Args:
            ctx: Context for the operation
            mutations: The mutations to decode
            out: Output container for decoded mutations
            validate_macs: Whether to validate MACs

        Raises:
            ValueError: If decoding fails
        """
        for i, mutation in enumerate(mutations):
            key_id = mutation.record.key_id.id
            keys, err = await self.get_app_state_key(key_id)
            if err:
                raise ValueError(f"Failed to get key {key_id.hex().upper()} to decode mutation: {err}")

            content = mutation.record.value.blob
            content, value_mac = content[:-32], content[-32:]

            if validate_macs:
                expected_value_mac = generate_content_mac(mutation.operation, content, key_id, keys.value_mac)
                if expected_value_mac != value_mac:
                    raise ErrMismatchingContentMAC(f"Failed to verify mutation #{i+1}")

            iv, content = content[:16], content[16:]
            try:
                plaintext = decrypt_cbc(keys.value_encryption, iv, content)
            except Exception as err:
                raise ValueError(f"Failed to decrypt mutation #{i+1}: {err}")

            sync_action = WASyncAction_pb2.SyncActionData()
            try:
                sync_action.ParseFromString(plaintext)
            except Exception as err:
                raise ValueError(f"Failed to unmarshal mutation #{i+1}: {err}")

            index_mac = mutation.record.index.blob
            if validate_macs:
                expected_index_mac = concat_and_hmac(lambda: __import__('hashlib').sha256(),
                                                   keys.index,
                                                   [sync_action.index])
                if expected_index_mac != index_mac:
                    raise ErrMismatchingIndexMAC(f"Failed to verify mutation #{i+1}")

            try:
                index = json.loads(sync_action.index)
            except Exception as err:
                raise ValueError(f"Failed to unmarshal index of mutation #{i+1}: {err}")

            if mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.REMOVE:
                out.removed_macs.append(index_mac)
            elif mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.SET:
                out.added_macs.append({
                    "index_mac": index_mac,
                    "value_mac": value_mac
                })

            out.mutations.append(Mutation(
                operation=mutation.operation,
                action=sync_action.value,
                index=index,
                index_mac=index_mac,
                value_mac=value_mac
            ))

    async def store_macs(self, ctx: Any, name: WAPatchName, current_state: HashState, out: PatchOutput) -> None:
        """
        Store MACs in the database.

        Args:
            ctx: Context for the operation
            name: The patch name
            current_state: The current hash state
            out: The patch output containing MACs to store
        """
        try:
            await self.store.app_state.put_app_state_version(ctx, str(name), current_state.version, current_state.hash)
        except Exception as err:
            logger.error(f"Failed to update app state version in the database: {err}")

        try:
            await self.store.app_state.delete_app_state_mutation_macs(str(name), out.removed_macs)
        except Exception as err:
            logger.error(f"Failed to remove deleted mutation MACs from the database: {err}")

        try:
            await self.store.app_state.put_app_state_mutation_macs(str(name), current_state.version, out.added_macs)
        except Exception as err:
            logger.error(f"Failed to insert added mutation MACs to the database: {err}")

    async def validate_snapshot_mac(self, ctx: Any, name: WAPatchName, current_state: HashState,
                                  key_id: bytes, expected_snapshot_mac: bytes) -> Tuple[ExpandedAppStateKeys, Optional[Exception]]:
        """
        Validate a snapshot MAC.

        Args:
            ctx: Context for the operation
            name: The patch name
            current_state: The current hash state
            key_id: The key ID
            expected_snapshot_mac: The expected snapshot MAC

        Returns:
            A tuple of (expanded keys, error)
        """
        keys, err = await self.get_app_state_key(key_id)
        if err:
            return None, ValueError(f"Failed to get key {key_id.hex().upper()} to verify patch v{current_state.version} MACs: {err}")

        snapshot_mac = current_state.generate_snapshot_mac(name, keys.snapshot_mac)
        if snapshot_mac != expected_snapshot_mac:
            return None, ErrMismatchingLTHash(f"Failed to verify patch v{current_state.version}")

        return keys, None

    async def decode_snapshot(self, ctx: Any, name: WAPatchName, ss: WAServerSync_pb2.SyncdSnapshot,
                            initial_state: HashState, validate_macs: bool,
                            new_mutations_input: List[Mutation]) -> Tuple[List[Mutation], HashState, Optional[Exception]]:
        """
        Decode a snapshot.

        Args:
            ctx: Context for the operation
            name: The patch name
            ss: The snapshot to decode
            initial_state: The initial hash state
            validate_macs: Whether to validate MACs
            new_mutations_input: Input list of mutations

        Returns:
            A tuple of (new mutations, current state, error)
        """
        current_state = HashState(version=initial_state.version, hash=initial_state.hash)
        current_state.version = ss.version.version

        encrypted_mutations = []
        for record in ss.records:
            encrypted_mutations.append(WAServerSync_pb2.SyncdMutation(
                operation=WAServerSync_pb2.SyncdMutation.SyncdOperation.SET,
                record=record
            ))

        def get_prev_set_value_mac(index_mac: bytes, max_index: int) -> Tuple[Optional[bytes], Optional[Exception]]:
            return None, None

        warnings, err = current_state.update_hash(encrypted_mutations, get_prev_set_value_mac)
        if warnings:
            logger.warning(f"Warnings while updating hash for {name}: {warnings}")
        if err:
            return None, None, ValueError(f"Failed to update state hash: {err}")

        if validate_macs:
            _, err = await self.validate_snapshot_mac(ctx, name, current_state, ss.key_id.id, ss.mac)
            if err:
                return None, None, err

        out = PatchOutput(mutations=new_mutations_input)
        try:
            await self.decode_mutations(ctx, encrypted_mutations, out, validate_macs)
        except Exception as err:
            return None, None, ValueError(f"Failed to decode snapshot of v{current_state.version}: {err}")

        await self.store_macs(ctx, name, current_state, out)
        return out.mutations, current_state, None

    async def decode_patches(self, ctx: Any, patch_list: PatchList, initial_state: HashState,
                           validate_macs: bool) -> Tuple[List[Mutation], HashState, Optional[Exception]]:
        """
        Decode all the patches in a PatchList into a list of app state mutations.

        Args:
            ctx: Context for the operation
            patch_list: The patch list to decode
            initial_state: The initial hash state
            validate_macs: Whether to validate MACs

        Returns:
            A tuple of (new mutations, current state, error)
        """
        current_state = HashState(version=initial_state.version, hash=initial_state.hash)
        expected_length = 0

        if patch_list.snapshot:
            expected_length += len(patch_list.snapshot.records)

        for patch in patch_list.patches:
            expected_length += len(patch.mutations)

        new_mutations = []

        if patch_list.snapshot:
            new_mutations, current_state, err = await self.decode_snapshot(
                ctx, patch_list.name, patch_list.snapshot, current_state, validate_macs, new_mutations
            )
            if err:
                return None, None, err

        for patch in patch_list.patches:
            version = patch.version.version
            current_state.version = version

            async def get_prev_set_value_mac(index_mac: bytes, max_index: int) -> Tuple[Optional[bytes], Optional[Exception]]:
                for i in range(max_index - 1, -1, -1):
                    if patch.mutations[i].record.index.blob == index_mac:
                        value = patch.mutations[i].record.value.blob
                        return value[-32:], None

                # Previous value not found in current patch, look in the database
                try:
                    return await self.store.app_state.get_app_state_mutation_mac(str(patch_list.name), index_mac), None
                except Exception as err:
                    return None, err

            warnings, err = current_state.update_hash(patch.mutations, get_prev_set_value_mac)
            if warnings:
                logger.warning(f"Warnings while updating hash for {patch_list.name}: {warnings}")
            if err:
                return None, None, ValueError(f"Failed to update state hash: {err}")

            if validate_macs:
                keys, err = await self.validate_snapshot_mac(
                    ctx, patch_list.name, current_state, patch.key_id.id, patch.snapshot_mac
                )
                if err:
                    return None, None, err

                patch_mac = generate_patch_mac(patch, patch_list.name, keys.patch_mac, patch.version.version)
                if patch_mac != patch.patch_mac:
                    return None, None, ErrMismatchingPatchMAC(f"Failed to verify patch v{version}")

            out = PatchOutput(mutations=new_mutations)
            try:
                await self.decode_mutations(ctx, patch.mutations, out, validate_macs)
            except Exception as err:
                return None, None, err

            await self.store_macs(ctx, patch_list.name, current_state, out)
            new_mutations = out.mutations

        return new_mutations, current_state, None
