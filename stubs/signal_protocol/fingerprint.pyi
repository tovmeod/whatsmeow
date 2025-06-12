from typing import Any, Union, Optional, List, Dict, Tuple
from signal_protocol.identity_key import IdentityKey

class Fingerprint:
	def __init__(
		self,
		version: int,
		iterations: int,
		local_id: bytes,
		local_key: IdentityKey,
		remote_id: bytes,
		remote_key: IdentityKey,
	) -> None: ...

	def display_string(self) -> str: ...
	def compare(self, combined: bytes) -> bool: ...
	def serialize(self) -> bytes: ...

	def __str__(self) -> str: ...
	def __repr__(self) -> str: ...
