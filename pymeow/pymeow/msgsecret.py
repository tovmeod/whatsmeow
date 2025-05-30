"""
WhatsApp message secret handling.

Port of whatsmeow/msgsecret.go
"""
import os
import asyncio
from enum import Enum
from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Tuple, List, Union, Callable, Awaitable, TypeVar

import google.protobuf.proto as proto

from .types.jid import JID
from .util.gcmutil import encrypt_gcm, decrypt_gcm
from .util.hkdfutil import expand_hmac
from .generated.waCommon import WACommon_pb2
from .generated.waE2E import WAE2E_pb2

# Type alias for MessageID
MessageID = str


class MsgSecretType(str, Enum):
    """Types of message secrets."""
    POLL_VOTE = "Poll Vote"
    REACTION = "Enc Reaction"
    COMMENT = "Enc Comment"
    REPORT_TOKEN = "Report Token"
    EVENT_RESPONSE = "Event Response"
    EVENT_EDIT = "Event Edit"
    BOT_MSG = "Bot Message"


def apply_bot_message_hkdf(message_secret: bytes) -> bytes:
    """Apply HKDF for bot messages."""
    return expand_hmac(message_secret, MsgSecretType.BOT_MSG.encode(), 32)


def generate_msg_secret_key(
    modification_type: MsgSecretType,
    modification_sender: JID,
    orig_msg_id: MessageID,
    orig_msg_sender: JID,
    orig_msg_secret: bytes
) -> Tuple[bytes, bytes]:
    """
    Generate a message secret key.

    Args:
        modification_type: The type of modification
        modification_sender: The JID of the sender making the modification
        orig_msg_id: The ID of the original message
        orig_msg_sender: The JID of the original message sender
        orig_msg_secret: The secret key of the original message

    Returns:
        A tuple containing (secret_key, additional_data)
    """
    orig_msg_sender_str = orig_msg_sender.to_non_ad().__str__()
    modification_sender_str = modification_sender.to_non_ad().__str__()

    # Create use case secret
    use_case_secret = (
        orig_msg_id.encode() +
        orig_msg_sender_str.encode() +
        modification_sender_str.encode() +
        modification_type.encode()
    )

    # Derive key using HKDF
    secret_key = expand_hmac(orig_msg_secret, use_case_secret, 32)

    # Generate additional data based on modification type
    additional_data = None
    if modification_type in [MsgSecretType.POLL_VOTE, MsgSecretType.EVENT_RESPONSE] or modification_type == "":
        additional_data = f"{orig_msg_id}\x00{modification_sender_str}".encode()

    return secret_key, additional_data or b""


class MessageEncryptedSecret:
    """Interface for encrypted message secrets."""

    def get_enc_iv(self) -> bytes:
        """Get the encryption IV."""
        raise NotImplementedError

    def get_enc_payload(self) -> bytes:
        """Get the encrypted payload."""
        raise NotImplementedError


@dataclass
class MessageSecret:
    """Message secret data."""
    secret: bytes
    expiration: int


class MessageSecretStore:
    """Handles message secret storage and encryption/decryption."""

    def __init__(self):
        """Initialize the message secret store."""
        self._secrets: Dict[str, Dict[str, Dict[str, MessageSecret]]] = {}

    async def get_message_secret(self, ctx: Any, chat: JID, sender: JID, msg_id: MessageID) -> Optional[bytes]:
        """
        Get a message secret from the store.

        Args:
            ctx: Context (unused in this implementation)
            chat: The chat JID
            sender: The sender JID
            msg_id: The message ID

        Returns:
            The message secret bytes or None if not found
        """
        chat_str = str(chat)
        sender_str = str(sender)

        if chat_str not in self._secrets:
            return None

        if sender_str not in self._secrets[chat_str]:
            return None

        if msg_id not in self._secrets[chat_str][sender_str]:
            return None

        return self._secrets[chat_str][sender_str][msg_id].secret

    async def store_message_secret(self, ctx: Any, chat: JID, sender: JID, msg_id: MessageID, secret: bytes, expiration: int) -> None:
        """
        Store a message secret.

        Args:
            ctx: Context (unused in this implementation)
            chat: The chat JID
            sender: The sender JID
            msg_id: The message ID
            secret: The secret bytes
            expiration: The expiration time
        """
        chat_str = str(chat)
        sender_str = str(sender)

        if chat_str not in self._secrets:
            self._secrets[chat_str] = {}

        if sender_str not in self._secrets[chat_str]:
            self._secrets[chat_str][sender_str] = {}

        self._secrets[chat_str][sender_str][msg_id] = MessageSecret(secret=secret, expiration=expiration)


class Client:
    """
    Client for WhatsApp message secret handling.

    This is a partial implementation that only includes the message secret functionality.
    """

    def __init__(self, store=None):
        """
        Initialize the client.

        Args:
            store: The store containing message secrets
        """
        self.store = store

    async def get_orig_sender_from_key(self, msg: 'Message', key: WACommon_pb2.MessageKey) -> JID:
        """
        Get the original sender JID from a message key.

        This function determines the original sender JID from a message key, handling:
        - fromMe messages (return msg.info.sender)
        - Direct messages (parse key.RemoteJid)
        - Group messages (parse key.Participant with validation)
        - Server validation for DEFAULT_USER_SERVER and HIDDEN_USER_SERVER

        Args:
            msg: The message event containing sender information
            key: The message key containing original message information

        Returns:
            JID of the original sender

        Raises:
            ValueError: If JID parsing fails or server validation fails

        Examples:
            >>> sender = await client.get_orig_sender_from_key(message, message_key)
            >>> print(f"Original sender: {sender}")
        """
        from .types.jid import DEFAULT_USER_SERVER, HIDDEN_USER_SERVER

        if key.FromMe:
            # fromMe always means the poll and vote were sent by the same user
            # TODO this is wrong if the message key used @s.whatsapp.net, but the new event is from @lid
            return msg.info.sender
        elif msg.info.chat.server == DEFAULT_USER_SERVER or msg.info.chat.server == HIDDEN_USER_SERVER:
            try:
                sender = JID.from_string(key.RemoteJid)
                if not sender:
                    raise ValueError(f"Failed to parse JID {key.RemoteJid} of original message sender")
                return sender
            except Exception as e:
                raise ValueError(f"Failed to parse JID {key.RemoteJid} of original message sender: {e}")
        else:
            try:
                sender = JID.from_string(key.Participant)
                if sender.server != DEFAULT_USER_SERVER and sender.server != HIDDEN_USER_SERVER:
                    raise ValueError(f"Unexpected server {sender.server} for participant JID")
                return sender
            except Exception as e:
                raise ValueError(f"Failed to parse JID {key.Participant} of original message sender: {e}")

    async def decrypt_msg_secret(self, ctx: Any, msg: 'Message', use_case: MsgSecretType,
                                encrypted: MessageEncryptedSecret, orig_msg_key: WACommon_pb2.MessageKey) -> bytes:
        """
        Decrypt a message secret using the original message key and sender information.

        This function handles the decryption of encrypted message content by:
        1. Determining the original sender using get_orig_sender_from_key()
        2. Retrieving the message secret from the store
        3. Handling LID/PN mapping for hidden user servers
        4. Generating the secret key using the appropriate use case
        5. Decrypting the message content

        Args:
            ctx: Context for store operations
            msg: The message event containing sender and chat information
            use_case: The message secret type (POLL_VOTE, REACTION, COMMENT, etc.)
            encrypted: The encrypted message content with IV and payload
            orig_msg_key: The original message key containing ID and sender information

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If client is nil, JID parsing fails, or decryption fails
            OriginalMessageSecretNotFound: If the original message secret is not found

        Examples:
            >>> plaintext = await client.decrypt_msg_secret(
            ...     ctx, message, MsgSecretType.REACTION,
            ...     encrypted_content, message.message.enc_reaction_message.target_message_key
            ... )
            >>> reaction_msg = WAE2E_pb2.ReactionMessage()
            >>> reaction_msg.ParseFromString(plaintext)
        """
        from .exceptions import OriginalMessageSecretNotFound
        from .types.jid import HIDDEN_USER_SERVER

        if not self.store:
            raise ValueError("Client is nil")

        # Get the original sender from the message key
        orig_sender = await self.get_orig_sender_from_key(msg, orig_msg_key)

        # Get message secret from store
        base_enc_key, err = await self.store.msg_secrets.get_message_secret(ctx, msg.info.chat, orig_sender, orig_msg_key.ID)
        if err:
            raise ValueError(f"Failed to get original message secret key: {err}")

        # Handle LID/PN mapping for hidden user servers
        if not base_enc_key and orig_msg_key.FromMe and orig_sender.server == HIDDEN_USER_SERVER:
            # Try to get PN for LID
            pn, err = await self.store.lids.get_pn_for_lid(ctx, orig_sender)
            if err:
                raise OriginalMessageSecretNotFound(f"Also failed to get PN for LID: {err}")
            if not pn or pn.is_empty():
                raise OriginalMessageSecretNotFound("PN for LID not found")

            orig_sender = pn
            base_enc_key, err = await self.store.msg_secrets.get_message_secret(ctx, msg.info.chat, orig_sender, orig_msg_key.ID)
            if err:
                raise ValueError(f"Failed to get original message secret key with PN: {err}")

        if not base_enc_key:
            raise OriginalMessageSecretNotFound("Original message secret not found")

        # Generate the secret key for this specific use case
        secret_key, additional_data = generate_msg_secret_key(
            use_case, msg.info.sender, orig_msg_key.ID, orig_sender, base_enc_key
        )

        # Decrypt the message content
        try:
            plaintext = decrypt_gcm(secret_key, encrypted.get_enc_iv(), encrypted.get_enc_payload(), additional_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Failed to decrypt secret message: {e}")

    async def encrypt_msg_secret(self, ctx: Any, own_id: JID, chat: JID, orig_sender: JID,
                                orig_msg_id: str, use_case: MsgSecretType,
                                plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt a message secret for reactions, comments, poll votes, etc.

        This function handles the encryption of message content by:
        1. Validating the client and user state
        2. Retrieving the original message secret from the store
        3. Generating the secret key using the appropriate use case
        4. Encrypting the message content with GCM

        Args:
            ctx: Context for store operations
            own_id: The JID of the current user sending the encrypted content
            chat: The chat JID where the message is being sent
            orig_sender: The original sender JID of the referenced message
            orig_msg_id: The original message ID being referenced
            use_case: The message secret type (POLL_VOTE, REACTION, COMMENT, etc.)
            plaintext: The plaintext content to encrypt

        Returns:
            A tuple containing (ciphertext, iv) where:
              - ciphertext: The encrypted message content
              - iv: The initialization vector used for encryption

        Raises:
            ValueError: If client is nil, user is not logged in, or encryption fails
            OriginalMessageSecretNotFound: If the original message secret is not found

        Examples:
            >>> ciphertext, iv = await client.encrypt_msg_secret(
            ...     ctx, client.get_own_id(), chat_jid, message_sender,
            ...     message_id, MsgSecretType.REACTION, reaction_proto.SerializeToString()
            ... )
            >>> # Use ciphertext and iv to create an encrypted reaction message
        """
        from .exceptions import OriginalMessageSecretNotFound

        # Validate client and user state
        if not self.store:
            raise ValueError("Client is nil")

        if not own_id or own_id.is_empty():
            raise ValueError("Not logged in")

        # Get message secret from store
        base_enc_key, err = await self.store.msg_secrets.get_message_secret(ctx, chat, orig_sender, orig_msg_id)
        if err:
            raise ValueError(f"Failed to get original message secret key: {err}")

        if not base_enc_key:
            raise OriginalMessageSecretNotFound("Original message secret not found")

        # Generate the secret key for this specific use case
        secret_key, additional_data = generate_msg_secret_key(
            use_case, own_id, orig_msg_id, orig_sender, base_enc_key
        )

        # Generate random IV and encrypt the content
        iv = os.urandom(12)  # 12 bytes (96 bits) for GCM mode

        try:
            ciphertext = encrypt_gcm(secret_key, iv, plaintext, additional_data)
            return ciphertext, iv
        except Exception as e:
            raise ValueError(f"Failed to encrypt secret message: {e}")

    async def decrypt_bot_message(self, ctx: Any, message_secret: bytes, ms_msg: Any,
                                 message_id: MessageID, target_sender_jid: JID,
                                 info: Any) -> bytes:
        """
        Decrypt a bot message.

        Args:
            ctx: Context
            message_secret: The message secret
            ms_msg: The encrypted message
            message_id: The message ID
            target_sender_jid: The target sender JID
            info: Message info

        Returns:
            Decrypted plaintext bytes

        Raises:
            ValueError: If decryption fails
        """
        new_key, additional_data = generate_msg_secret_key(
            "", info.sender, message_id, target_sender_jid, apply_bot_message_hkdf(message_secret)
        )

        try:
            plaintext = decrypt_gcm(new_key, ms_msg.get_enc_iv(), ms_msg.get_enc_payload(), additional_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Failed to decrypt secret message: {e}")

    async def decrypt_reaction(self, ctx: Any, reaction: Any) -> WAE2E_pb2.ReactionMessage:
        """
        Decrypt a reaction message.

        Args:
            ctx: Context
            reaction: The reaction message

        Returns:
            Decrypted reaction message

        Raises:
            NotEncryptedReactionMessage: If not an encrypted reaction message
            ValueError: If decryption or parsing fails
            OriginalMessageSecretNotFound: If the original message secret is not found
        """
        from .exceptions import NotEncryptedReactionMessage

        enc_reaction = reaction.message.enc_reaction_message
        if not enc_reaction:
            raise NotEncryptedReactionMessage("Not an encrypted reaction message")

        try:
            plaintext = await self.decrypt_msg_secret(
                ctx, reaction, MsgSecretType.REACTION, enc_reaction, enc_reaction.target_message_key
            )

            msg = WAE2E_pb2.ReactionMessage()
            msg.ParseFromString(plaintext)
            return msg
        except Exception as e:
            raise ValueError(f"Failed to decrypt or decode reaction: {e}")

    async def decrypt_comment(self, ctx: Any, comment: Any) -> WAE2E_pb2.Message:
        """
        Decrypt a comment message.

        Args:
            ctx: Context
            comment: The comment message

        Returns:
            Decrypted comment message

        Raises:
            NotEncryptedCommentMessage: If not an encrypted comment message
            ValueError: If decryption or parsing fails
            OriginalMessageSecretNotFound: If the original message secret is not found
        """
        from .exceptions import NotEncryptedCommentMessage

        enc_comment = comment.message.enc_comment_message
        if not enc_comment:
            raise NotEncryptedCommentMessage("Not an encrypted comment message")

        try:
            plaintext = await self.decrypt_msg_secret(
                ctx, comment, MsgSecretType.COMMENT, enc_comment, enc_comment.target_message_key
            )

            msg = WAE2E_pb2.Message()
            msg.ParseFromString(plaintext)
            return msg
        except Exception as e:
            raise ValueError(f"Failed to decrypt or decode comment: {e}")

    async def decrypt_poll_vote(self, ctx: Any, vote: Any) -> WAE2E_pb2.PollVoteMessage:
        """
        Decrypt a poll vote message.

        Args:
            ctx: Context
            vote: The poll vote message

        Returns:
            Decrypted poll vote message

        Raises:
            NotPollUpdateMessage: If not a poll update message
            ValueError: If decryption or parsing fails
            OriginalMessageSecretNotFound: If the original message secret is not found
        """
        from .exceptions import NotPollUpdateMessage

        poll_update = vote.message.poll_update_message
        if not poll_update:
            raise NotPollUpdateMessage("Not a poll update message")

        try:
            plaintext = await self.decrypt_msg_secret(
                ctx, vote, MsgSecretType.POLL_VOTE, poll_update.vote, poll_update.poll_creation_message_key
            )

            msg = WAE2E_pb2.PollVoteMessage()
            msg.ParseFromString(plaintext)
            return msg
        except Exception as e:
            raise ValueError(f"Failed to decrypt or decode poll vote: {e}")

    def get_key_from_info(self, msg_info: Any) -> WACommon_pb2.MessageKey:
        """
        Get a message key from message info.

        Args:
            msg_info: The message info

        Returns:
            A message key
        """
        creation_key = WACommon_pb2.MessageKey()
        creation_key.RemoteJid = str(msg_info.chat)
        creation_key.FromMe = msg_info.is_from_me
        creation_key.ID = msg_info.id

        if msg_info.is_group:
            creation_key.Participant = str(msg_info.sender)

        return creation_key

    @staticmethod
    def hash_poll_options(option_names: List[str]) -> List[bytes]:
        """
        Hash poll option names using SHA-256 for voting.

        Args:
            option_names: The option names

        Returns:
            A list of hashed options
        """
        import hashlib

        option_hashes = []
        for option in option_names:
            option_hash = hashlib.sha256(option.encode()).digest()
            option_hashes.append(option_hash)

        return option_hashes

    async def build_poll_vote(self, ctx: Any, poll_info: Any, option_names: List[str]) -> Tuple[WAE2E_pb2.Message, Optional[Exception]]:
        """
        Build a poll vote message.

        Args:
            ctx: Context
            poll_info: The poll message info
            option_names: The selected option names

        Returns:
            A tuple containing (message, error)
        """
        poll_update, err = await self.encrypt_poll_vote(
            ctx, poll_info, WAE2E_pb2.PollVoteMessage(
                selected_options=self.hash_poll_options(option_names)
            )
        )
        if err:
            return None, err

        return WAE2E_pb2.Message(poll_update_message=poll_update), None

    def build_poll_creation(self, name: str, option_names: List[str], selectable_option_count: int) -> WAE2E_pb2.Message:
        """
        Build a poll creation message.

        Args:
            name: The poll name
            option_names: The option names
            selectable_option_count: The number of options that can be selected

        Returns:
            A message
        """
        msg_secret = os.urandom(32)

        if selectable_option_count < 0 or selectable_option_count > len(option_names):
            selectable_option_count = 0

        options = []
        for option in option_names:
            options.append(WAE2E_pb2.PollCreationMessage.Option(option_name=option))

        return WAE2E_pb2.Message(
            poll_creation_message=WAE2E_pb2.PollCreationMessage(
                name=name,
                options=options,
                selectable_options_count=selectable_option_count
            ),
            message_context_info=WAE2E_pb2.MessageContextInfo(
                message_secret=msg_secret
            )
        )

    async def encrypt_poll_vote(self, ctx: Any, poll_info: Any, vote: WAE2E_pb2.PollVoteMessage) -> Tuple[WAE2E_pb2.PollUpdateMessage, Optional[Exception]]:
        """
        Encrypt a poll vote message.

        Args:
            ctx: Context
            poll_info: The poll message info
            vote: The poll vote message

        Returns:
            A tuple containing (poll_update_message, error)
        """
        try:
            plaintext = vote.SerializeToString()
        except Exception as e:
            return None, ValueError(f"failed to marshal poll vote protobuf: {e}")

        ciphertext, iv, err = await self.encrypt_msg_secret(
            ctx, self.get_own_id(), poll_info.chat, poll_info.sender,
            poll_info.id, MsgSecretType.POLL_VOTE, plaintext
        )
        if err:
            return None, ValueError(f"failed to encrypt poll vote: {err}")

        import time

        return WAE2E_pb2.PollUpdateMessage(
            poll_creation_message_key=self.get_key_from_info(poll_info),
            vote=WAE2E_pb2.PollEncValue(
                enc_payload=ciphertext,
                enc_iv=iv
            ),
            sender_timestamp_ms=int(time.time() * 1000)
        ), None

    async def encrypt_comment(self, ctx: Any, root_msg_info: Any, comment: WAE2E_pb2.Message) -> Tuple[WAE2E_pb2.Message, Optional[Exception]]:
        """
        Encrypt a comment message.

        Args:
            ctx: Context
            root_msg_info: The root message info
            comment: The comment message

        Returns:
            A tuple containing (message, error)
        """
        try:
            plaintext = comment.SerializeToString()
        except Exception as e:
            return None, ValueError(f"failed to marshal comment protobuf: {e}")

        # TODO: is hardcoding LID here correct? What about polls?
        ciphertext, iv, err = await self.encrypt_msg_secret(
            ctx, self.get_own_lid(), root_msg_info.chat, root_msg_info.sender,
            root_msg_info.id, MsgSecretType.COMMENT, plaintext
        )
        if err:
            return None, ValueError(f"failed to encrypt comment: {err}")

        return WAE2E_pb2.Message(
            enc_comment_message=WAE2E_pb2.EncCommentMessage(
                target_message_key=WACommon_pb2.MessageKey(
                    remote_jid=str(root_msg_info.chat),
                    participant=str(root_msg_info.sender.to_non_ad()),
                    from_me=root_msg_info.is_from_me,
                    id=root_msg_info.id
                ),
                enc_payload=ciphertext,
                enc_iv=iv
            )
        ), None

    async def encrypt_reaction(self, ctx: Any, root_msg_info: Any, reaction: WAE2E_pb2.ReactionMessage) -> Tuple[WAE2E_pb2.EncReactionMessage, Optional[Exception]]:
        """
        Encrypt a reaction message.

        Args:
            ctx: Context
            root_msg_info: The root message info
            reaction: The reaction message

        Returns:
            A tuple containing (enc_reaction_message, error)
        """
        reaction_key = reaction.key
        reaction.key = None

        try:
            plaintext = reaction.SerializeToString()
        except Exception as e:
            return None, ValueError(f"failed to marshal reaction protobuf: {e}")

        ciphertext, iv, err = await self.encrypt_msg_secret(
            ctx, self.get_own_lid(), root_msg_info.chat, root_msg_info.sender,
            root_msg_info.id, MsgSecretType.REACTION, plaintext
        )
        if err:
            return None, ValueError(f"failed to encrypt reaction: {err}")

        return WAE2E_pb2.EncReactionMessage(
            target_message_key=reaction_key,
            enc_payload=ciphertext,
            enc_iv=iv
        ), None

    def get_own_id(self) -> JID:
        """Get the JID of the current user."""
        # This would be implemented in the actual client
        raise NotImplementedError

    def get_own_lid(self) -> JID:
        """Get the LID of the current user."""
        # This would be implemented in the actual client
        raise NotImplementedError
