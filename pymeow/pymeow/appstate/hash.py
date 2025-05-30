"""
Hash utilities for WhatsApp app state.

Port of whatsmeow/appstate/hash.go
"""
import hmac
import hashlib
import struct
from dataclasses import dataclass
from typing import List, Callable, Tuple, Optional

from ..appstate.lthash import LTHash, WAPatchIntegrity
from ..generated.waServerSync import WAServerSync_pb2
from ..generated.waSyncAction import WASyncAction_pb2
from .errors import ErrMissingPreviousSetValueOperation

# Type alias for WAPatchName
WAPatchName = str


@dataclass
class Mutation:
    """Represents a mutation in the app state."""
    operation: WAServerSync_pb2.SyncdMutation.SyncdOperation
    action: WASyncAction_pb2.SyncActionValue
    index: List[str]
    index_mac: bytes
    value_mac: bytes


@dataclass
class HashState:
    """Represents the hash state of the app state."""
    version: int
    hash: bytes  # 128 bytes

    def update_hash(self, mutations: List[WAServerSync_pb2.SyncdMutation],
                   get_prev_set_value_mac: Callable[[bytes, int], Tuple[Optional[bytes], Optional[Exception]]]) -> Tuple[List[Exception], Optional[Exception]]:
        """
        Update the hash state with the given mutations.

        Args:
            mutations: The mutations to apply
            get_prev_set_value_mac: A function that returns the value MAC of the previous SET operation

        Returns:
            A tuple containing (warnings, error)
        """
        added = []
        removed = []
        warnings = []

        for i, mutation in enumerate(mutations):
            if mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.SET:
                value = mutation.record.value.blob
                added.append(value[-32:])

            index_mac = mutation.record.index.blob
            removal, err = get_prev_set_value_mac(index_mac, i)

            if err:
                return warnings, Exception(f"failed to get value MAC of previous SET operation: {err}")
            elif removal:
                removed.append(removal)
            elif mutation.operation == WAServerSync_pb2.SyncdMutation.SyncdOperation.REMOVE:
                # TODO figure out if there are certain cases that are safe to ignore and others that aren't
                # At least removing contact access from WhatsApp seems to create a REMOVE op for your own JID
                # that points to a non-existent index and is safe to ignore here. Other keys might not be safe to ignore.
                warnings.append(ErrMissingPreviousSetValueOperation(f"for {index_mac.hex().upper()}"))
                # return ErrMissingPreviousSetValueOperation

        WAPatchIntegrity.subtract_then_add_in_place(self.hash, removed, added)
        return warnings, None

    def generate_snapshot_mac(self, name: WAPatchName, key: bytes) -> bytes:
        """
        Generate a snapshot MAC.

        Args:
            name: The patch name
            key: The key to use for HMAC

        Returns:
            The generated MAC
        """
        return concat_and_hmac(hashlib.sha256, key, [
            self.hash,
            uint64_to_bytes(self.version),
            name.encode()
        ])


def uint64_to_bytes(val: int) -> bytes:
    """
    Convert a uint64 to bytes in big-endian format.

    Args:
        val: The value to convert

    Returns:
        The bytes representation
    """
    return struct.pack(">Q", val)


def concat_and_hmac(alg: Callable[[], hashlib._hashlib.HASH], key: bytes, data: List[bytes]) -> bytes:
    """
    Concatenate the given data and compute an HMAC.

    Args:
        alg: The hash algorithm to use
        key: The key to use for HMAC
        data: The data to concatenate

    Returns:
        The computed HMAC
    """
    h = hmac.new(key, digestmod=alg)
    for item in data:
        h.update(item)
    return h.digest()


def generate_patch_mac(patch: WAServerSync_pb2.SyncdPatch, name: WAPatchName, key: bytes, version: int) -> bytes:
    """
    Generate a patch MAC.

    Args:
        patch: The patch
        name: The patch name
        key: The key to use for HMAC
        version: The version

    Returns:
        The generated MAC
    """
    data_to_hash = [patch.snapshot_mac]

    for mutation in patch.mutations:
        val = mutation.record.value.blob
        data_to_hash.append(val[-32:])

    data_to_hash.append(uint64_to_bytes(version))
    data_to_hash.append(name.encode())

    return concat_and_hmac(hashlib.sha256, key, data_to_hash)


def generate_content_mac(operation: WAServerSync_pb2.SyncdMutation.SyncdOperation, data: bytes, key_id: bytes, key: bytes) -> bytes:
    """
    Generate a content MAC.

    Args:
        operation: The operation
        data: The data
        key_id: The key ID
        key: The key to use for HMAC

    Returns:
        The generated MAC
    """
    operation_bytes = bytes([int(operation) + 1])
    key_data_length = uint64_to_bytes(len(key_id) + 1)

    return concat_and_hmac(hashlib.sha512, key, [
        operation_bytes,
        key_id,
        data,
        key_data_length
    ])[:32]
