
# Copyright (c) 2022 Tulir Asokan
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

"""
Message secret handling for PyMeow.

Port of whatsmeow/msgsecret.go - handles encryption/decryption of secret messages
like poll votes, reactions, and comments.
"""

import hashlib
import time
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple

from Crypto.Random import get_random_bytes

from .datatypes.message import MessageID
from .exceptions import (
    ErrClientIsNil,
    ErrNotLoggedIn,
    ErrOriginalMessageSecretNotFound,
)
from .generated.waCommon import WACommon_pb2
from .generated.waE2E import WAWebProtobufsE2E_pb2
from .util.gcmutil import gcm
from .util.hkdfutil import hkdf

if TYPE_CHECKING:
    from .client import Client
    from .datatypes import JID, MessageInfo
    from .datatypes.events import Message as MessageEvent

# Message secret type constants - matching Go exactly
ENC_SECRET_POLL_VOTE = "Poll Vote"
ENC_SECRET_REACTION = "Enc Reaction"
ENC_SECRET_COMMENT = "Enc Comment"
ENC_SECRET_REPORT_TOKEN = "Report Token"
ENC_SECRET_EVENT_RESPONSE = "Event Response"
ENC_SECRET_EVENT_EDIT = "Event Edit"
ENC_SECRET_BOT_MSG = "Bot Message"


class MessageEncryptedSecret(ABC):
    """Interface for encrypted secret messages."""

    @abstractmethod
    def get_enc_iv(self) -> bytes:
        """Get the encryption IV."""
        pass

    @abstractmethod
    def get_enc_payload(self) -> bytes:
        """Get the encrypted payload."""
        pass


def apply_bot_message_hkdf(message_secret: bytes) -> bytes:
    """Apply HKDF for bot message encryption."""
    return hkdf.sha256(message_secret, b'', ENC_SECRET_BOT_MSG.encode('utf-8'), 32)


def generate_msg_secret_key(
    modification_type: str,
    modification_sender: 'JID',
    orig_msg_id: MessageID,
    orig_msg_sender: 'JID',
    orig_msg_secret: bytes
) -> Tuple[bytes, Optional[bytes]]:
    """Generate message secret key for encryption/decryption."""
    orig_msg_sender_str = str(orig_msg_sender.to_non_ad())
    modification_sender_str = str(modification_sender.to_non_ad())

    use_case_secret = bytearray()
    use_case_secret.extend(orig_msg_id.encode('utf-8'))
    use_case_secret.extend(orig_msg_sender_str.encode('utf-8'))
    use_case_secret.extend(modification_sender_str.encode('utf-8'))
    use_case_secret.extend(modification_type.encode('utf-8'))

    secret_key = hkdf.sha256(orig_msg_secret, b'', bytes(use_case_secret), 32)

    additional_data = None
    if modification_type in [ENC_SECRET_POLL_VOTE, ENC_SECRET_EVENT_RESPONSE, ""]:
        additional_data = f"{orig_msg_id}\x00{modification_sender_str}".encode('utf-8')

    return secret_key, additional_data


def get_orig_sender_from_key(msg: 'MessageEvent', key: WACommon_pb2.MessageKey) -> 'JID':
    """Get original sender from message key."""
    from .datatypes import JID
    if key.fromMe:
        # fromMe always means the poll and vote were sent by the same user
        # TODO this is wrong if the message key used @s.whatsapp.net, but the new event is from @lid
        return msg.info.sender
    elif msg.info.chat.server in ["s.whatsapp.net", "lid"]:
        sender = JID.from_string(key.remoteJID)
        if sender is None:
            raise ValueError(f"failed to parse JID {key.remoteJID} of original message sender")
        return sender
    else:
        sender = JID.from_string(key.participant)
        if sender is None:
            raise ValueError(f"failed to parse JID {key.participant} of original message sender")
        if sender.server not in ["s.whatsapp.net", "lid"]:
            raise ValueError("unexpected server")
        return sender


def get_key_from_info(msg_info: 'MessageInfo') -> Dict[str, Any]:
    """Create message key from message info."""
    creation_key = {
        'remote_jid': str(msg_info.chat),
        'from_me': msg_info.is_from_me,
        'id': msg_info.id
    }
    if msg_info.message_source.is_group:
        creation_key['participant'] = str(msg_info.sender)
    return creation_key


def hash_poll_options(option_names: List[str]) -> List[bytes]:
    """Hash poll option names using SHA-256 for voting."""
    option_hashes = []
    for option in option_names:
        option_hash = hashlib.sha256(option.encode('utf-8')).digest()
        option_hashes.append(option_hash)
    return option_hashes


# The following methods would be added to the main Client class in client.py:

async def decrypt_msg_secret(
    client: 'Client',
    msg: 'MessageEvent',
    use_case: str,
    encrypted: MessageEncryptedSecret,
    orig_msg_key: WACommon_pb2.MessageKey
) -> bytes:
    """Decrypt a message secret."""
    if client is None:
        raise ErrClientIsNil()

    orig_sender = get_orig_sender_from_key(msg, orig_msg_key)

    base_enc_key = await client.store.msg_secrets.get_message_secret(
        msg.info.chat, orig_sender, orig_msg_key.ID
    )

    if base_enc_key is None:
        raise ErrOriginalMessageSecretNotFound

    if (base_enc_key is None and orig_msg_key.fromMe and
        orig_sender.server == "lid"):
        orig_sender = await client.store.lids.get_pn_for_lid(orig_sender)
        if orig_sender.is_empty():
            raise ErrOriginalMessageSecretNotFound("PN for LID not found")

        base_enc_key = await client.store.msg_secrets.get_message_secret(
            msg.info.chat, orig_sender, orig_msg_key.ID
        )

        if base_enc_key is None:
            raise ErrOriginalMessageSecretNotFound

    secret_key, additional_data = generate_msg_secret_key(
        use_case, msg.info.sender, MessageID(orig_msg_key.ID), orig_sender, base_enc_key
    )

    plaintext = gcm.decrypt(
        secret_key,
        encrypted.get_enc_iv(),
        encrypted.get_enc_payload(),
        additional_data
    )

    return plaintext


async def encrypt_msg_secret(
    client: 'Client',
    own_id: 'JID',
    chat: 'JID',
    orig_sender: 'JID',
    orig_msg_id: MessageID,
    use_case: str,
    plaintext: bytes
) -> Tuple[bytes, bytes]:
    """Encrypt a message secret."""
    if client is None:
        raise ErrClientIsNil()

    if own_id.is_empty():
        raise ErrNotLoggedIn()

    base_enc_key = await client.store.msg_secrets.get_message_secret(
        chat, orig_sender, orig_msg_id
    )

    if base_enc_key is None:
        raise ErrOriginalMessageSecretNotFound

    secret_key, additional_data = generate_msg_secret_key(
        use_case, own_id, orig_msg_id, orig_sender, base_enc_key
    )

    iv = get_random_bytes(12)
    ciphertext = gcm.encrypt(secret_key, iv, plaintext, additional_data)

    return ciphertext, iv


async def decrypt_bot_message(
    message_secret: bytes,
    ms_msg: WAWebProtobufsE2E_pb2.MessageSecretMessage,
    message_id: MessageID,
    target_sender_jid: 'JID',
    info: 'MessageInfo'
) -> bytes:
    """Decrypt a bot message."""
    new_key, additional_data = generate_msg_secret_key(
        "", info.sender, message_id, target_sender_jid,
        apply_bot_message_hkdf(message_secret)
    )

    plaintext = gcm.decrypt(
        new_key,
        ms_msg.encIV,
        ms_msg.encPayload,
        additional_data
    )

    return plaintext


# async def decrypt_reaction(client: 'Client', reaction: MessageEvent) -> WAWebProtobufsE2E_pb2.ReactionMessage:
#     """Decrypt a reaction message in a community announcement group."""
#     enc_reaction = reaction.message.encReactionMessage
#     if enc_reaction is None:
#         raise ErrNotEncryptedReactionMessage()
#
#     plaintext = await decrypt_msg_secret(
#         client, reaction, ENC_SECRET_REACTION, enc_reaction,
#         enc_reaction.targetMessageKey
#     )
#
#     # Parse protobuf
#     from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
#     msg = waE2E_pb2.ReactionMessage()
#     msg.ParseFromString(plaintext)
#
#     return msg


# async def decrypt_comment(client: 'Client', comment: MessageEvent) -> WAWebProtobufsE2E_pb2.Message:
#     """Decrypt a reply/comment message in a community announcement group."""
#     enc_comment = comment.message.encCommentMessage
#     if enc_comment is None:
#         raise ErrNotEncryptedCommentMessage()
#
#     plaintext = await decrypt_msg_secret(
#         client, comment, ENC_SECRET_COMMENT, enc_comment,
#         enc_comment.targetMessageKey
#     )
#
#     # Parse protobuf
#     from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
#     msg = waE2E_pb2.Message()
#     msg.ParseFromString(plaintext)
#
#     return msg


# async def decrypt_poll_vote(client: 'Client', vote: MessageEvent) -> WAWebProtobufsE2E_pb2.PollVoteMessage:
#     """Decrypt a poll update message."""
#     assert vote.message is not None
#     poll_update = vote.message.pollUpdateMessage
#     if poll_update is None:
#         raise ErrNotPollUpdateMessage()
#
#     plaintext = await decrypt_msg_secret(
#         client, vote, ENC_SECRET_POLL_VOTE, poll_update.vote,
#         poll_update.pollCreationMessageKey
#     )
#
#     # Parse protobuf
#     from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2
#     msg = waE2E_pb2.PollVoteMessage()
#     msg.ParseFromString(plaintext)
#
#     return msg


async def build_poll_vote(client: 'Client', poll_info: Any, option_names: List[str]) -> WAWebProtobufsE2E_pb2.Message:
    """Build a poll vote message using the given poll message info and option names."""
    from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2

    poll_vote_msg = waE2E_pb2.PollVoteMessage()
    poll_vote_msg.selectedOptions.extend(hash_poll_options(option_names))

    poll_update = await encrypt_poll_vote(client, poll_info, poll_vote_msg)

    msg = waE2E_pb2.Message()
    msg.pollUpdateMessage.CopyFrom(poll_update)

    return msg


def build_poll_creation(name: str, option_names: List[str], selectable_option_count: int) -> WAWebProtobufsE2E_pb2.Message:
    """Build a poll creation message with the given poll name, options and maximum number of selections."""
    msg_secret = get_random_bytes(32)
    if selectable_option_count < 0 or selectable_option_count > len(option_names):
        selectable_option_count = 0

    options = []
    for option in option_names:
        opt = WAWebProtobufsE2E_pb2.PollCreationMessage.Option()
        opt.optionName = option
        options.append(opt)

    poll_creation = WAWebProtobufsE2E_pb2.PollCreationMessage()
    poll_creation.name = name
    poll_creation.options.extend(options)
    poll_creation.selectableOptionsCount = selectable_option_count

    msg_context = WAWebProtobufsE2E_pb2.MessageContextInfo()
    msg_context.messageSecret = msg_secret

    msg = WAWebProtobufsE2E_pb2.Message()
    msg.pollCreationMessage.CopyFrom(poll_creation)
    msg.messageContextInfo.CopyFrom(msg_context)

    return msg


async def encrypt_poll_vote(client: 'Client', poll_info: Any, vote: WAWebProtobufsE2E_pb2.PollVoteMessage) -> WAWebProtobufsE2E_pb2.PollUpdateMessage:
    """Encrypt a poll vote message."""
    from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2

    plaintext = vote.SerializeToString()

    ciphertext, iv = await encrypt_msg_secret(
        client, client.get_own_id(), poll_info.chat, poll_info.sender,
        poll_info.id, ENC_SECRET_POLL_VOTE, plaintext
    )

    poll_enc_value = waE2E_pb2.PollEncValue()
    poll_enc_value.encPayload = ciphertext
    poll_enc_value.encIV = iv

    poll_update = waE2E_pb2.PollUpdateMessage()
    poll_update.pollCreationMessageKey.CopyFrom(get_key_from_info(poll_info))
    poll_update.vote.CopyFrom(poll_enc_value)
    poll_update.senderTimestampMS = int(time.time() * 1000)

    return poll_update


async def encrypt_comment(client: 'Client', root_msg_info: Any, comment: WAWebProtobufsE2E_pb2.Message) -> WAWebProtobufsE2E_pb2.Message:
    """Encrypt a comment message."""
    from .generated.waCommon import WACommon_pb2 as waCommon_pb2
    from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2

    plaintext = comment.SerializeToString()

    # TODO is hardcoding LID here correct? What about polls?
    ciphertext, iv = await encrypt_msg_secret(
        client, client.get_own_lid(), root_msg_info.chat, root_msg_info.sender,
        root_msg_info.id, ENC_SECRET_COMMENT, plaintext
    )

    target_key = waCommon_pb2.MessageKey()
    target_key.remoteJID = str(root_msg_info.chat)
    target_key.participant = str(root_msg_info.sender.to_non_ad())
    target_key.fromMe = root_msg_info.is_from_me
    target_key.ID = root_msg_info.id

    enc_comment = waE2E_pb2.EncCommentMessage()
    enc_comment.targetMessageKey.CopyFrom(target_key)
    enc_comment.encPayload = ciphertext
    enc_comment.encIV = iv

    msg = waE2E_pb2.Message()
    msg.encCommentMessage.CopyFrom(enc_comment)

    return msg


async def encrypt_reaction(client: 'Client', root_msg_info: Any, reaction: WAWebProtobufsE2E_pb2.ReactionMessage) -> WAWebProtobufsE2E_pb2.EncReactionMessage:
    """Encrypt a reaction message."""
    from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E_pb2

    reaction_key = reaction.key
    reaction.key = None

    plaintext = reaction.SerializeToString()

    ciphertext, iv = await encrypt_msg_secret(
        client, client.get_own_lid(), root_msg_info.chat, root_msg_info.sender,
        root_msg_info.id, ENC_SECRET_REACTION, plaintext
    )

    enc_reaction = waE2E_pb2.EncReactionMessage()
    enc_reaction.targetMessageKey.CopyFrom(reaction_key)
    enc_reaction.encPayload = ciphertext
    enc_reaction.encIV = iv

    return enc_reaction
