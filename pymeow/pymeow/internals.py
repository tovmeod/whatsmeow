"""
Dangerous internal client implementation for WhatsApp.

Port of whatsmeow/internals.go
"""
import asyncio
import io
import json
from typing import Any, Dict, List, Optional, Tuple, Union, Callable, Set, TypeVar, cast, Awaitable
from datetime import datetime
import time
import contextlib

from .binary.node import Node, Attrs
# Protocol buffer imports
from .generated.waE2E import WAWebProtobufsE2E_pb2 as waE2E
from .generated.waCommon import WAWebProtobufsCommon_pb2 as waCommon
from .generated.waMsgTransport import WAMsgTransport_pb2 as waMsgTransport
from .generated.waServerSync import WAServerSync_pb2 as waServerSync
from .generated.waHistorySync import WAHistorySync_pb2 as waHistorySync
from .generated.waMsgApplication import WAMsgApplication_pb2 as waMsgApplication

# TODO: Verify import when appstate is ported
from .appstate import appstate
# TODO: Verify import when socket.noisesocket is ported
from .socket import noisesocket
# TODO: Verify import when store.store is ported
from .store import store
# TODO: Verify import when types.events is ported
from .types import events
# TODO: Verify import when util.keys.keypair is ported
from .util.keys import keypair

class DangerousInternalClient:
    """
    Provides access to unexported methods in the Client class.

    This class is dangerous and should only be used for advanced use cases.
    """

    def __init__(self, client):
        """
        Initialize with a client instance.

        Args:
            client: The WhatsApp client instance
        """
        self.c = client

    async def filter_contacts(self, mutations: List[appstate.Mutation]) -> Tuple[List[appstate.Mutation], List[store.ContactEntry]]:
        """
        Filter contact mutations.

        Args:
            mutations: List of app state mutations

        Returns:
            Tuple containing filtered mutations and contact entries
        """
        return await self.c._filter_contacts(mutations)

    async def dispatch_app_state(self, ctx, mutation: appstate.Mutation, full_sync: bool, emit_on_full_sync: bool) -> None:
        """
        Dispatch app state mutation.

        Args:
            ctx: Context
            mutation: App state mutation
            full_sync: Whether this is a full sync
            emit_on_full_sync: Whether to emit events on full sync
        """
        await self.c._dispatch_app_state(ctx, mutation, full_sync, emit_on_full_sync)

    async def download_external_app_state_blob(self, ctx, ref: waServerSync.ExternalBlobReference) -> bytes:
        """
        Download external app state blob.

        Args:
            ctx: Context
            ref: External blob reference

        Returns:
            Blob data
        """
        return await self.c._download_external_app_state_blob(ctx, ref)

    async def fetch_app_state_patches(self, ctx, name: appstate.WAPatchName, from_version: int, snapshot: bool) -> appstate.PatchList:
        """
        Fetch app state patches.

        Args:
            ctx: Context
            name: Patch name
            from_version: Version to fetch from
            snapshot: Whether to fetch a snapshot

        Returns:
            Patch list
        """
        return await self.c._fetch_app_state_patches(ctx, name, from_version, snapshot)

    async def request_missing_app_state_keys(self, ctx, patches: appstate.PatchList) -> None:
        """
        Request missing app state keys.

        Args:
            ctx: Context
            patches: Patch list
        """
        await self.c._request_missing_app_state_keys(ctx, patches)

    async def request_app_state_keys(self, ctx, raw_key_ids: List[bytes]) -> None:
        """
        Request app state keys.

        Args:
            ctx: Context
            raw_key_ids: Raw key IDs
        """
        await self.c._request_app_state_keys(ctx, raw_key_ids)

    async def handle_decrypted_armadillo(self, ctx, info, decrypted: bytes, retry_count: int) -> bool:
        """
        Handle decrypted armadillo message.

        Args:
            ctx: Context
            info: Message info
            decrypted: Decrypted data
            retry_count: Retry count

        Returns:
            Whether the message was handled successfully
        """
        return await self.c._handle_decrypted_armadillo(ctx, info, decrypted, retry_count)

    async def get_broadcast_list_participants(self, ctx, jid) -> List:
        """
        Get broadcast list participants.

        Args:
            ctx: Context
            jid: Broadcast list JID

        Returns:
            List of participant JIDs
        """
        return await self.c._get_broadcast_list_participants(ctx, jid)

    async def get_status_broadcast_recipients(self, ctx) -> List:
        """
        Get status broadcast recipients.

        Args:
            ctx: Context

        Returns:
            List of recipient JIDs
        """
        return await self.c._get_status_broadcast_recipients(ctx)

    async def handle_call_event(self, node: Node) -> None:
        """
        Handle call event.

        Args:
            node: Binary node
        """
        await self.c._handle_call_event(node)

    def get_socket_wait_chan(self) -> asyncio.Event:
        """
        Get socket wait channel.

        Returns:
            Socket wait event
        """
        return self.c._get_socket_wait_chan()

    def close_socket_wait_chan(self) -> None:
        """Close socket wait channel."""
        self.c._close_socket_wait_chan()

    def get_own_id(self):
        """
        Get own JID.

        Returns:
            Own JID
        """
        return self.c._get_own_id()

    def get_own_lid(self):
        """
        Get own LID.

        Returns:
            Own LID
        """
        return self.c._get_own_lid()

    async def on_disconnect(self, ns: noisesocket.NoiseSocket, remote: bool) -> None:
        """
        Handle disconnection.

        Args:
            ns: Noise socket
            remote: Whether disconnection was initiated remotely
        """
        await self.c._on_disconnect(ns, remote)

    def expect_disconnect(self) -> None:
        """Set expected disconnect flag."""
        self.c._expect_disconnect()

    def reset_expected_disconnect(self) -> None:
        """Reset expected disconnect flag."""
        self.c._reset_expected_disconnect()

    def is_expected_disconnect(self) -> bool:
        """
        Check if disconnect is expected.

        Returns:
            Whether disconnect is expected
        """
        return self.c._is_expected_disconnect()

    async def auto_reconnect(self) -> None:
        """Automatically reconnect."""
        await self.c._auto_reconnect()

    def unlocked_disconnect(self) -> None:
        """Disconnect without locking."""
        self.c._unlocked_disconnect()

    async def handle_frame(self, data: bytes) -> None:
        """
        Handle frame data.

        Args:
            data: Frame data
        """
        await self.c._handle_frame(data)

    async def handler_queue_loop(self, ctx) -> None:
        """
        Handler queue loop.

        Args:
            ctx: Context
        """
        await self.c._handler_queue_loop(ctx)

    async def send_node_and_get_data(self, node: Node) -> bytes:
        """
        Send node and get data.

        Args:
            node: Binary node

        Returns:
            Response data
        """
        return await self.c._send_node_and_get_data(node)

    async def send_node(self, node: Node) -> None:
        """
        Send node.

        Args:
            node: Binary node
        """
        await self.c._send_node(node)

    def dispatch_event(self, evt: Any) -> None:
        """
        Dispatch event.

        Args:
            evt: Event to dispatch
        """
        self.c._dispatch_event(evt)

    async def handle_stream_error(self, node: Node) -> None:
        """
        Handle stream error.

        Args:
            node: Binary node
        """
        await self.c._handle_stream_error(node)

    async def handle_ib(self, node: Node) -> None:
        """
        Handle IB node.

        Args:
            node: Binary node
        """
        await self.c._handle_ib(node)

    async def handle_connect_failure(self, node: Node) -> None:
        """
        Handle connection failure.

        Args:
            node: Binary node
        """
        await self.c._handle_connect_failure(node)

    async def handle_connect_success(self, node: Node) -> None:
        """
        Handle connection success.

        Args:
            node: Binary node
        """
        await self.c._handle_connect_success(node)

    async def download_and_decrypt(self, ctx, url: str, media_key: bytes, app_info, file_length: int,
                                  file_enc_sha256: bytes, file_sha256: bytes) -> bytes:
        """
        Download and decrypt media.

        Args:
            ctx: Context
            url: Media URL
            media_key: Media encryption key
            app_info: Media type info
            file_length: File length
            file_enc_sha256: Encrypted file SHA256
            file_sha256: File SHA256

        Returns:
            Decrypted media data
        """
        return await self.c._download_and_decrypt(ctx, url, media_key, app_info, file_length,
                                                file_enc_sha256, file_sha256)

    async def download_possibly_encrypted_media_with_retries(self, ctx, url: str, checksum: bytes) -> Tuple[bytes, bytes]:
        """
        Download possibly encrypted media with retries.

        Args:
            ctx: Context
            url: Media URL
            checksum: Media checksum

        Returns:
            Tuple of file data and MAC
        """
        return await self.c._download_possibly_encrypted_media_with_retries(ctx, url, checksum)

    async def do_media_download_request(self, ctx, url: str):
        """
        Do media download request.

        Args:
            ctx: Context
            url: Media URL

        Returns:
            HTTP response
        """
        return await self.c._do_media_download_request(ctx, url)

    async def download_media(self, ctx, url: str) -> bytes:
        """
        Download media.

        Args:
            ctx: Context
            url: Media URL

        Returns:
            Media data
        """
        return await self.c._download_media(ctx, url)

    async def download_encrypted_media(self, ctx, url: str, checksum: bytes) -> Tuple[bytes, bytes]:
        """
        Download encrypted media.

        Args:
            ctx: Context
            url: Media URL
            checksum: Media checksum

        Returns:
            Tuple of file data and MAC
        """
        return await self.c._download_encrypted_media(ctx, url, checksum)

    async def download_and_decrypt_to_file(self, ctx, url: str, media_key: bytes, app_info, file_length: int,
                                         file_enc_sha256: bytes, file_sha256: bytes, file) -> None:
        """
        Download and decrypt media to file.

        Args:
            ctx: Context
            url: Media URL
            media_key: Media encryption key
            app_info: Media type info
            file_length: File length
            file_enc_sha256: Encrypted file SHA256
            file_sha256: File SHA256
            file: File object to write to
        """
        await self.c._download_and_decrypt_to_file(ctx, url, media_key, app_info, file_length,
                                                file_enc_sha256, file_sha256, file)

    async def download_possibly_encrypted_media_with_retries_to_file(self, ctx, url: str, checksum: bytes, file) -> bytes:
        """
        Download possibly encrypted media with retries to file.

        Args:
            ctx: Context
            url: Media URL
            checksum: Media checksum
            file: File object to write to

        Returns:
            MAC
        """
        return await self.c._download_possibly_encrypted_media_with_retries_to_file(ctx, url, checksum, file)

    async def download_media_to_file(self, ctx, url: str, file) -> Tuple[int, bytes]:
        """
        Download media to file.

        Args:
            ctx: Context
            url: Media URL
            file: File object to write to

        Returns:
            Tuple of bytes written and checksum
        """
        return await self.c._download_media_to_file(ctx, url, file)

    async def download_encrypted_media_to_file(self, ctx, url: str, checksum: bytes, file) -> bytes:
        """
        Download encrypted media to file.

        Args:
            ctx: Context
            url: Media URL
            checksum: Media checksum
            file: File object to write to

        Returns:
            MAC
        """
        return await self.c._download_encrypted_media_to_file(ctx, url, checksum, file)

    async def send_group_iq(self, ctx, iq_type, jid, content: Node) -> Node:
        """
        Send group IQ.

        Args:
            ctx: Context
            iq_type: IQ type
            jid: Group JID
            content: IQ content

        Returns:
            Response node
        """
        return await self.c._send_group_iq(ctx, iq_type, jid, content)

    async def get_group_info(self, ctx, jid, lock_participant_cache: bool = True):
        """
        Get group info.

        Args:
            ctx: Context
            jid: Group JID
            lock_participant_cache: Whether to lock participant cache

        Returns:
            Group info
        """
        return await self.c._get_group_info(ctx, jid, lock_participant_cache)

    async def get_cached_group_data(self, ctx, jid):
        """
        Get cached group data.

        Args:
            ctx: Context
            jid: Group JID

        Returns:
            Cached group data
        """
        return await self.c._get_cached_group_data(ctx, jid)

    def parse_group_node(self, group_node: Node):
        """
        Parse group node.

        Args:
            group_node: Group node

        Returns:
            Group info
        """
        return self.c._parse_group_node(group_node)

    def parse_group_create(self, parent_node: Node, node: Node):
        """
        Parse group create.

        Args:
            parent_node: Parent node
            node: Group create node

        Returns:
            Joined group event
        """
        return self.c._parse_group_create(parent_node, node)

    def parse_group_change(self, node: Node):
        """
        Parse group change.

        Args:
            node: Group change node

        Returns:
            Group info event
        """
        return self.c._parse_group_change(node)

    def update_group_participant_cache(self, evt):
        """
        Update group participant cache.

        Args:
            evt: Group info event
        """
        self.c._update_group_participant_cache(evt)

    def parse_group_notification(self, node: Node):
        """
        Parse group notification.

        Args:
            node: Group notification node

        Returns:
            Group notification event
        """
        return self.c._parse_group_notification(node)

    async def do_handshake(self, fs, ephemeral_kp: keypair.KeyPair) -> None:
        """
        Do handshake.

        Args:
            fs: Frame socket
            ephemeral_kp: Ephemeral key pair
        """
        await self.c._do_handshake(fs, ephemeral_kp)

    async def keep_alive_loop(self, ctx) -> None:
        """
        Keep alive loop.

        Args:
            ctx: Context
        """
        await self.c._keep_alive_loop(ctx)

    async def send_keep_alive(self, ctx) -> Tuple[bool, bool]:
        """
        Send keep alive.

        Args:
            ctx: Context

        Returns:
            Tuple of is_success and should_continue
        """
        return await self.c._send_keep_alive(ctx)

    async def refresh_media_conn(self, ctx, force: bool = False):
        """
        Refresh media connection.

        Args:
            ctx: Context
            force: Whether to force refresh

        Returns:
            Media connection
        """
        return await self.c._refresh_media_conn(ctx, force)

    async def query_media_conn(self, ctx):
        """
        Query media connection.

        Args:
            ctx: Context

        Returns:
            Media connection
        """
        return await self.c._query_media_conn(ctx)

    async def handle_media_retry_notification(self, ctx, node: Node) -> None:
        """
        Handle media retry notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_media_retry_notification(ctx, node)

    async def handle_encrypted_message(self, node: Node) -> None:
        """
        Handle encrypted message.

        Args:
            node: Message node
        """
        await self.c._handle_encrypted_message(node)

    def parse_message_source(self, node: Node, require_participant: bool = False):
        """
        Parse message source.

        Args:
            node: Message node
            require_participant: Whether participant is required

        Returns:
            Message source
        """
        return self.c._parse_message_source(node, require_participant)

    def parse_msg_bot_info(self, node: Node):
        """
        Parse message bot info.

        Args:
            node: Message node

        Returns:
            Message bot info
        """
        return self.c._parse_msg_bot_info(node)

    def parse_msg_meta_info(self, node: Node):
        """
        Parse message meta info.

        Args:
            node: Message node

        Returns:
            Message meta info
        """
        return self.c._parse_msg_meta_info(node)

    def parse_message_info(self, node: Node):
        """
        Parse message info.

        Args:
            node: Message node

        Returns:
            Message info
        """
        return self.c._parse_message_info(node)

    async def handle_plaintext_message(self, ctx, info, node: Node) -> None:
        """
        Handle plaintext message.

        Args:
            ctx: Context
            info: Message info
            node: Message node
        """
        await self.c._handle_plaintext_message(ctx, info, node)

    async def migrate_session_store(self, ctx, pn, lid) -> None:
        """
        Migrate session store.

        Args:
            ctx: Context
            pn: Phone number JID
            lid: LID
        """
        await self.c._migrate_session_store(ctx, pn, lid)

    async def decrypt_messages(self, ctx, info, node: Node) -> None:
        """
        Decrypt messages.

        Args:
            ctx: Context
            info: Message info
            node: Message node
        """
        await self.c._decrypt_messages(ctx, info, node)

    async def clear_untrusted_identity(self, ctx, target) -> None:
        """
        Clear untrusted identity.

        Args:
            ctx: Context
            target: Target JID
        """
        await self.c._clear_untrusted_identity(ctx, target)

    async def buffered_decrypt(self, ctx, ciphertext: bytes, server_timestamp: datetime,
                             decrypt_func: Callable[[Any], Awaitable[bytes]]) -> Tuple[bytes, bytes]:
        """
        Buffered decrypt.

        Args:
            ctx: Context
            ciphertext: Ciphertext
            server_timestamp: Server timestamp
            decrypt_func: Decrypt function

        Returns:
            Tuple of plaintext and ciphertext hash
        """
        return await self.c._buffered_decrypt(ctx, ciphertext, server_timestamp, decrypt_func)

    async def decrypt_dm(self, ctx, child: Node, from_jid, is_pre_key: bool, server_ts: datetime) -> Tuple[bytes, bytes]:
        """
        Decrypt direct message.

        Args:
            ctx: Context
            child: Message node
            from_jid: Sender JID
            is_pre_key: Whether it's a pre-key message
            server_ts: Server timestamp

        Returns:
            Tuple of plaintext and ciphertext hash
        """
        return await self.c._decrypt_dm(ctx, child, from_jid, is_pre_key, server_ts)

    async def decrypt_group_msg(self, ctx, child: Node, from_jid, chat_jid, server_ts: datetime) -> Tuple[bytes, bytes]:
        """
        Decrypt group message.

        Args:
            ctx: Context
            child: Message node
            from_jid: Sender JID
            chat_jid: Chat JID
            server_ts: Server timestamp

        Returns:
            Tuple of plaintext and ciphertext hash
        """
        return await self.c._decrypt_group_msg(ctx, child, from_jid, chat_jid, server_ts)

    async def handle_sender_key_distribution_message(self, ctx, chat, from_jid, axolotl_skdm: bytes) -> None:
        """
        Handle sender key distribution message.

        Args:
            ctx: Context
            chat: Chat JID
            from_jid: Sender JID
            axolotl_skdm: Axolotl SKDM
        """
        await self.c._handle_sender_key_distribution_message(ctx, chat, from_jid, axolotl_skdm)

    async def handle_history_sync_notification_loop(self) -> None:
        """Handle history sync notification loop."""
        await self.c._handle_history_sync_notification_loop()

    async def handle_history_sync_notification(self, ctx, notif: waE2E.HistorySyncNotification) -> None:
        """
        Handle history sync notification.

        Args:
            ctx: Context
            notif: History sync notification
        """
        await self.c._handle_history_sync_notification(ctx, notif)

    async def handle_app_state_sync_key_share(self, ctx, keys: waE2E.AppStateSyncKeyShare) -> None:
        """
        Handle app state sync key share.

        Args:
            ctx: Context
            keys: App state sync key share
        """
        await self.c._handle_app_state_sync_key_share(ctx, keys)

    def handle_placeholder_resend_response(self, msg: waE2E.PeerDataOperationRequestResponseMessage) -> None:
        """
        Handle placeholder resend response.

        Args:
            msg: Peer data operation request response message
        """
        self.c._handle_placeholder_resend_response(msg)

    async def handle_protocol_message(self, ctx, info, msg: waE2E.Message) -> None:
        """
        Handle protocol message.

        Args:
            ctx: Context
            info: Message info
            msg: Protocol message
        """
        await self.c._handle_protocol_message(ctx, info, msg)

    async def process_protocol_parts(self, ctx, info, msg: waE2E.Message) -> None:
        """
        Process protocol parts.

        Args:
            ctx: Context
            info: Message info
            msg: Protocol message
        """
        await self.c._process_protocol_parts(ctx, info, msg)

    async def store_message_secret(self, ctx, info, msg: waE2E.Message) -> None:
        """
        Store message secret.

        Args:
            ctx: Context
            info: Message info
            msg: Message
        """
        await self.c._store_message_secret(ctx, info, msg)

    async def store_historical_message_secrets(self, ctx, conversations: List[waHistorySync.Conversation]) -> None:
        """
        Store historical message secrets.

        Args:
            ctx: Context
            conversations: Conversations
        """
        await self.c._store_historical_message_secrets(ctx, conversations)

    async def handle_decrypted_message(self, ctx, info, msg: waE2E.Message, retry_count: int) -> None:
        """
        Handle decrypted message.

        Args:
            ctx: Context
            info: Message info
            msg: Decrypted message
            retry_count: Retry count
        """
        await self.c._handle_decrypted_message(ctx, info, msg, retry_count)

    def send_protocol_message_receipt(self, id, msg_type) -> None:
        """
        Send protocol message receipt.

        Args:
            id: Message ID
            msg_type: Receipt type
        """
        self.c._send_protocol_message_receipt(id, msg_type)

    async def decrypt_msg_secret(self, ctx, msg, use_case, encrypted, orig_msg_key) -> bytes:
        """
        Decrypt message secret.

        Args:
            ctx: Context
            msg: Message
            use_case: Use case
            encrypted: Encrypted secret
            orig_msg_key: Original message key

        Returns:
            Decrypted secret
        """
        return await self.c._decrypt_msg_secret(ctx, msg, use_case, encrypted, orig_msg_key)

    async def encrypt_msg_secret(self, ctx, own_id, chat, orig_sender, orig_msg_id, use_case, plaintext: bytes) -> Tuple[bytes, bytes]:
        """
        Encrypt message secret.

        Args:
            ctx: Context
            own_id: Own JID
            chat: Chat JID
            orig_sender: Original sender JID
            orig_msg_id: Original message ID
            use_case: Use case
            plaintext: Plaintext

        Returns:
            Tuple of ciphertext and IV
        """
        return await self.c._encrypt_msg_secret(ctx, own_id, chat, orig_sender, orig_msg_id, use_case, plaintext)

    async def decrypt_bot_message(self, ctx, message_secret: bytes, ms_msg, message_id, target_sender_jid, info) -> bytes:
        """
        Decrypt bot message.

        Args:
            ctx: Context
            message_secret: Message secret
            ms_msg: Message secret message
            message_id: Message ID
            target_sender_jid: Target sender JID
            info: Message info

        Returns:
            Decrypted message
        """
        return await self.c._decrypt_bot_message(ctx, message_secret, ms_msg, message_id, target_sender_jid, info)

    async def send_mex_iq(self, ctx, query_id: str, variables: Any) -> json.RawMessage:
        """
        Send MEX IQ.

        Args:
            ctx: Context
            query_id: Query ID
            variables: Variables

        Returns:
            Raw JSON response
        """
        return await self.c._send_mex_iq(ctx, query_id, variables)

    def get_newsletter_info(self, input_data: Dict[str, Any], fetch_viewer_meta: bool = False):
        """
        Get newsletter info.

        Args:
            input_data: Input data
            fetch_viewer_meta: Whether to fetch viewer metadata

        Returns:
            Newsletter metadata
        """
        return self.c._get_newsletter_info(input_data, fetch_viewer_meta)

    async def handle_encrypt_notification(self, ctx, node: Node) -> None:
        """
        Handle encrypt notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_encrypt_notification(ctx, node)

    async def handle_app_state_notification(self, ctx, node: Node) -> None:
        """
        Handle app state notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_app_state_notification(ctx, node)

    async def handle_picture_notification(self, ctx, node: Node) -> None:
        """
        Handle picture notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_picture_notification(ctx, node)

    async def handle_device_notification(self, ctx, node: Node) -> None:
        """
        Handle device notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_device_notification(ctx, node)

    async def handle_fb_device_notification(self, ctx, node: Node) -> None:
        """
        Handle FB device notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_fb_device_notification(ctx, node)

    async def handle_own_devices_notification(self, ctx, node: Node) -> None:
        """
        Handle own devices notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_own_devices_notification(ctx, node)

    async def handle_blocklist(self, ctx, node: Node) -> None:
        """
        Handle blocklist.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_blocklist(ctx, node)

    async def handle_account_sync_notification(self, ctx, node: Node) -> None:
        """
        Handle account sync notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_account_sync_notification(ctx, node)

    async def handle_privacy_token_notification(self, ctx, node: Node) -> None:
        """
        Handle privacy token notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_privacy_token_notification(ctx, node)

    def parse_newsletter_messages(self, node: Node) -> List:
        """
        Parse newsletter messages.

        Args:
            node: Newsletter node

        Returns:
            List of newsletter messages
        """
        return self.c._parse_newsletter_messages(node)

    async def handle_newsletter_notification(self, ctx, node: Node) -> None:
        """
        Handle newsletter notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_newsletter_notification(ctx, node)

    async def handle_mex_notification(self, ctx, node: Node) -> None:
        """
        Handle MEX notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_mex_notification(ctx, node)

    async def handle_status_notification(self, ctx, node: Node) -> None:
        """
        Handle status notification.

        Args:
            ctx: Context
            node: Notification node
        """
        await self.c._handle_status_notification(ctx, node)

    async def handle_notification(self, node: Node) -> None:
        """
        Handle notification.

        Args:
            node: Notification node
        """
        await self.c._handle_notification(node)

    async def try_handle_code_pair_notification(self, ctx, parent_node: Node) -> None:
        """
        Try handle code pair notification.

        Args:
            ctx: Context
            parent_node: Parent node
        """
        await self.c._try_handle_code_pair_notification(ctx, parent_node)

    async def handle_code_pair_notification(self, ctx, parent_node: Node) -> None:
        """
        Handle code pair notification.

        Args:
            ctx: Context
            parent_node: Parent node
        """
        await self.c._handle_code_pair_notification(ctx, parent_node)

    async def handle_iq(self, node: Node) -> None:
        """
        Handle IQ.

        Args:
            node: IQ node
        """
        await self.c._handle_iq(node)

    async def handle_pair_device(self, node: Node) -> None:
        """
        Handle pair device.

        Args:
            node: Pair device node
        """
        await self.c._handle_pair_device(node)

    def make_qr_data(self, ref: str) -> str:
        """
        Make QR data.

        Args:
            ref: Reference

        Returns:
            QR data
        """
        return self.c._make_qr_data(ref)

    async def handle_pair_success(self, node: Node) -> None:
        """
        Handle pair success.

        Args:
            node: Pair success node
        """
        await self.c._handle_pair_success(node)

    async def handle_pair(self, ctx, device_identity_bytes: bytes, req_id: str, business_name: str,
                        platform: str, jid, lid) -> None:
        """
        Handle pair.

        Args:
            ctx: Context
            device_identity_bytes: Device identity bytes
            req_id: Request ID
            business_name: Business name
            platform: Platform
            jid: JID
            lid: LID
        """
        await self.c._handle_pair(ctx, device_identity_bytes, req_id, business_name, platform, jid, lid)

    def send_pair_error(self, id: str, code: int, text: str) -> None:
        """
        Send pair error.

        Args:
            id: Request ID
            code: Error code
            text: Error text
        """
        self.c._send_pair_error(id, code, text)

    async def get_server_pre_key_count(self, ctx) -> int:
        """
        Get server pre-key count.

        Args:
            ctx: Context

        Returns:
            Pre-key count
        """
        return await self.c._get_server_pre_key_count(ctx)

    async def upload_pre_keys(self, ctx) -> None:
        """
        Upload pre-keys.

        Args:
            ctx: Context
        """
        await self.c._upload_pre_keys(ctx)

    async def fetch_pre_keys(self, ctx, users: List) -> Dict:
        """
        Fetch pre-keys.

        Args:
            ctx: Context
            users: List of users

        Returns:
            Dictionary of pre-key responses
        """
        return await self.c._fetch_pre_keys(ctx, users)

    async def handle_chat_state(self, node: Node) -> None:
        """
        Handle chat state.

        Args:
            node: Chat state node
        """
        await self.c._handle_chat_state(node)

    async def handle_presence(self, node: Node) -> None:
        """
        Handle presence.

        Args:
            node: Presence node
        """
        await self.c._handle_presence(node)

    def parse_privacy_settings(self, privacy_node: Node, settings) -> events.PrivacySettings:
        """
        Parse privacy settings.

        Args:
            privacy_node: Privacy node
            settings: Settings

        Returns:
            Privacy settings event
        """
        return self.c._parse_privacy_settings(privacy_node, settings)

    async def handle_privacy_settings_notification(self, ctx, privacy_node: Node) -> None:
        """
        Handle privacy settings notification.

        Args:
            ctx: Context
            privacy_node: Privacy node
        """
        await self.c._handle_privacy_settings_notification(ctx, privacy_node)

    async def handle_receipt(self, node: Node) -> None:
        """
        Handle receipt.

        Args:
            node: Receipt node
        """
        await self.c._handle_receipt(node)

    def handle_grouped_receipt(self, partial_receipt: events.Receipt, participants: Node) -> None:
        """
        Handle grouped receipt.

        Args:
            partial_receipt: Partial receipt
            participants: Participants node
        """
        self.c._handle_grouped_receipt(partial_receipt, participants)

    def parse_receipt(self, node: Node) -> events.Receipt:
        """
        Parse receipt.

        Args:
            node: Receipt node

        Returns:
            Receipt event
        """
        return self.c._parse_receipt(node)

    def maybe_deferred_ack(self, node: Node) -> Callable[[], None]:
        """
        Maybe deferred ack.

        Args:
            node: Node

        Returns:
            Ack function
        """
        return self.c._maybe_deferred_ack(node)

    def send_ack(self, node: Node) -> None:
        """
        Send ack.

        Args:
            node: Node to acknowledge
        """
        self.c._send_ack(node)

    def send_message_receipt(self, info) -> None:
        """
        Send message receipt.

        Args:
            info: Message info
        """
        self.c._send_message_receipt(info)

    def generate_request_id(self) -> str:
        """
        Generate request ID.

        Returns:
            Request ID
        """
        return self.c._generate_request_id()

    def clear_response_waiters(self, node: Node) -> None:
        """
        Clear response waiters.

        Args:
            node: Node
        """
        self.c._clear_response_waiters(node)

    def wait_response(self, req_id: str) -> asyncio.Queue:
        """
        Wait for response.

        Args:
            req_id: Request ID

        Returns:
            Response queue
        """
        return self.c._wait_response(req_id)

    def cancel_response(self, req_id: str, ch: asyncio.Queue) -> None:
        """
        Cancel response.

        Args:
            req_id: Request ID
            ch: Response queue
        """
        self.c._cancel_response(req_id, ch)

    def receive_response(self, data: Node) -> bool:
        """
        Receive response.

        Args:
            data: Response data

        Returns:
            Whether response was handled
        """
        return self.c._receive_response(data)

    async def send_iq_async_and_get_data(self, query) -> Tuple[asyncio.Queue, bytes]:
        """
        Send IQ async and get data.

        Args:
            query: Query

        Returns:
            Tuple of response queue and data
        """
        return await self.c._send_iq_async_and_get_data(query)

    async def send_iq_async(self, query) -> asyncio.Queue:
        """
        Send IQ async.

        Args:
            query: Query

        Returns:
            Response queue
        """
        return await self.c._send_iq_async(query)

    async def send_iq(self, query) -> Node:
        """
        Send IQ.

        Args:
            query: Query

        Returns:
            Response node
        """
        return await self.c._send_iq(query)

    async def retry_frame(self, req_type: str, id: str, data: bytes, orig_resp: Node, ctx, timeout: float) -> Node:
        """
        Retry frame.

        Args:
            req_type: Request type
            id: Request ID
            data: Request data
            orig_resp: Original response
            ctx: Context
            timeout: Timeout

        Returns:
            Response node
        """
        return await self.c._retry_frame(req_type, id, data, orig_resp, ctx, timeout)

    def add_recent_message(self, to, id, wa: waE2E.Message, fb: waMsgApplication.MessageApplication) -> None:
        """
        Add recent message.

        Args:
            to: Recipient JID
            id: Message ID
            wa: WhatsApp message
            fb: Facebook message
        """
        self.c._add_recent_message(to, id, wa, fb)

    def get_recent_message(self, to, id):
        """
        Get recent message.

        Args:
            to: Recipient JID
            id: Message ID

        Returns:
            Recent message
        """
        return self.c._get_recent_message(to, id)

    async def get_message_for_retry(self, ctx, receipt, message_id):
        """
        Get message for retry.

        Args:
            ctx: Context
            receipt: Receipt
            message_id: Message ID

        Returns:
            Recent message
        """
        return await self.c._get_message_for_retry(ctx, receipt, message_id)

    async def should_recreate_session(self, ctx, retry_count: int, jid) -> Tuple[str, bool]:
        """
        Should recreate session.

        Args:
            ctx: Context
            retry_count: Retry count
            jid: JID

        Returns:
            Tuple of reason and whether to recreate
        """
        return await self.c._should_recreate_session(ctx, retry_count, jid)

    async def handle_retry_receipt(self, ctx, receipt, node: Node) -> None:
        """
        Handle retry receipt.

        Args:
            ctx: Context
            receipt: Receipt
            node: Receipt node
        """
        await self.c._handle_retry_receipt(ctx, receipt, node)

    def cancel_delayed_request_from_phone(self, msg_id) -> None:
        """
        Cancel delayed request from phone.

        Args:
            msg_id: Message ID
        """
        self.c._cancel_delayed_request_from_phone(msg_id)

    def delayed_request_message_from_phone(self, info) -> None:
        """
        Delayed request message from phone.

        Args:
            info: Message info
        """
        self.c._delayed_request_message_from_phone(info)

    def clear_delayed_message_requests(self) -> None:
        """Clear delayed message requests."""
        self.c._clear_delayed_message_requests()

    async def send_retry_receipt(self, ctx, node: Node, info, force_include_identity: bool = False) -> None:
        """
        Send retry receipt.

        Args:
            ctx: Context
            node: Node
            info: Message info
            force_include_identity: Whether to force include identity
        """
        await self.c._send_retry_receipt(ctx, node, info, force_include_identity)

    async def send_group_v3(self, ctx, to, own_id, id, message_app: bytes, msg_attrs, franking_tag: bytes, timings) -> Tuple[str, bytes]:
        """
        Send group message (v3).

        Args:
            ctx: Context
            to: Group JID
            own_id: Own JID
            id: Message ID
            message_app: Message application
            msg_attrs: Message attributes
            franking_tag: Franking tag
            timings: Message debug timings

        Returns:
            Tuple of sender key ID and ciphertext
        """
        return await self.c._send_group_v3(ctx, to, own_id, id, message_app, msg_attrs, franking_tag, timings)

    async def send_dm_v3(self, ctx, to, own_id, id, message_app: bytes, msg_attrs, franking_tag: bytes, timings) -> Tuple[bytes, str]:
        """
        Send direct message (v3).

        Args:
            ctx: Context
            to: Recipient JID
            own_id: Own JID
            id: Message ID
            message_app: Message application
            msg_attrs: Message attributes
            franking_tag: Franking tag
            timings: Message debug timings

        Returns:
            Tuple of ciphertext and sender key ID
        """
        return await self.c._send_dm_v3(ctx, to, own_id, id, message_app, msg_attrs, franking_tag, timings)

    async def prepare_message_node_v3(self, ctx, to, own_id, id, payload, skdm, msg_attrs, franking_tag: bytes, participants: List, timings) -> Tuple[Node, List]:
        """
        Prepare message node (v3).

        Args:
            ctx: Context
            to: Recipient JID
            own_id: Own JID
            id: Message ID
            payload: Message payload
            skdm: Sender key distribution message
            msg_attrs: Message attributes
            franking_tag: Franking tag
            participants: Participants
            timings: Message debug timings

        Returns:
            Tuple of message node and participants
        """
        return await self.c._prepare_message_node_v3(ctx, to, own_id, id, payload, skdm, msg_attrs, franking_tag, participants, timings)

    async def encrypt_message_for_devices_v3(self, ctx, all_devices: List, own_id, id: str, payload, skdm, dsm, enc_attrs) -> List[Node]:
        """
        Encrypt message for devices (v3).

        Args:
            ctx: Context
            all_devices: All devices
            own_id: Own JID
            id: Message ID
            payload: Message payload
            skdm: Sender key distribution message
            dsm: Device sent message
            enc_attrs: Encryption attributes

        Returns:
            List of encrypted message nodes
        """
        return await self.c._encrypt_message_for_devices_v3(ctx, all_devices, own_id, id, payload, skdm, dsm, enc_attrs)

    async def encrypt_message_for_device_and_wrap_v3(self, ctx, payload, skdm, dsm, to, bundle, enc_attrs) -> Node:
        """
        Encrypt message for device and wrap (v3).

        Args:
            ctx: Context
            payload: Message payload
            skdm: Sender key distribution message
            dsm: Device sent message
            to: Recipient JID
            bundle: Pre-key bundle
            enc_attrs: Encryption attributes

        Returns:
            Encrypted message node
        """
        return await self.c._encrypt_message_for_device_and_wrap_v3(ctx, payload, skdm, dsm, to, bundle, enc_attrs)

    async def encrypt_message_for_device_v3(self, ctx, payload, skdm, dsm, to, bundle, extra_attrs) -> Node:
        """
        Encrypt message for device (v3).

        Args:
            ctx: Context
            payload: Message payload
            skdm: Sender key distribution message
            dsm: Device sent message
            to: Recipient JID
            bundle: Pre-key bundle
            extra_attrs: Extra attributes

        Returns:
            Encrypted message node
        """
        return await self.c._encrypt_message_for_device_v3(ctx, payload, skdm, dsm, to, bundle, extra_attrs)

    async def send_newsletter(self, to, id, message: waE2E.Message, media_id: str, timings) -> bytes:
        """
        Send newsletter.

        Args:
            to: Newsletter JID
            id: Message ID
            message: Message
            media_id: Media ID
            timings: Message debug timings

        Returns:
            Ciphertext
        """
        return await self.c._send_newsletter(to, id, message, media_id, timings)

    async def send_group(self, ctx, to, participants: List, id, message: waE2E.Message, timings, extra_params) -> Tuple[str, bytes]:
        """
        Send group message.

        Args:
            ctx: Context
            to: Group JID
            participants: Participants
            id: Message ID
            message: Message
            timings: Message debug timings
            extra_params: Extra parameters

        Returns:
            Tuple of sender key ID and ciphertext
        """
        return await self.c._send_group(ctx, to, participants, id, message, timings, extra_params)

    async def send_peer_message(self, ctx, to, id, message: waE2E.Message, timings) -> bytes:
        """
        Send peer message.

        Args:
            ctx: Context
            to: Recipient JID
            id: Message ID
            message: Message
            timings: Message debug timings

        Returns:
            Ciphertext
        """
        return await self.c._send_peer_message(ctx, to, id, message, timings)

    async def send_dm(self, ctx, own_id, to, id, message: waE2E.Message, timings, extra_params) -> bytes:
        """
        Send direct message.

        Args:
            ctx: Context
            own_id: Own JID
            to: Recipient JID
            id: Message ID
            message: Message
            timings: Message debug timings
            extra_params: Extra parameters

        Returns:
            Ciphertext
        """
        return await self.c._send_dm(ctx, own_id, to, id, message, timings, extra_params)

    async def prepare_peer_message_node(self, ctx, to, id, message: waE2E.Message, timings) -> Node:
        """
        Prepare peer message node.

        Args:
            ctx: Context
            to: Recipient JID
            id: Message ID
            message: Message
            timings: Message debug timings

        Returns:
            Message node
        """
        return await self.c._prepare_peer_message_node(ctx, to, id, message, timings)

    def get_message_content(self, base_node: Node, message: waE2E.Message, msg_attrs: Attrs, include_identity: bool, extra_params) -> List[Node]:
        """
        Get message content.

        Args:
            base_node: Base node
            message: Message
            msg_attrs: Message attributes
            include_identity: Whether to include identity
            extra_params: Extra parameters

        Returns:
            List of content nodes
        """
        return self.c._get_message_content(base_node, message, msg_attrs, include_identity, extra_params)

    async def prepare_message_node(self, ctx, to, id, message: waE2E.Message, participants: List, plaintext: bytes, dsm_plaintext: bytes, timings, extra_params) -> Tuple[Node, List]:
        """
        Prepare message node.

        Args:
            ctx: Context
            to: Recipient JID
            id: Message ID
            message: Message
            participants: Participants
            plaintext: Plaintext
            dsm_plaintext: DSM plaintext
            timings: Message debug timings
            extra_params: Extra parameters

        Returns:
            Tuple of message node and participants
        """
        return await self.c._prepare_message_node(ctx, to, id, message, participants, plaintext, dsm_plaintext, timings, extra_params)

    def make_device_identity_node(self) -> Node:
        """
        Make device identity node.

        Returns:
            Device identity node
        """
        return self.c._make_device_identity_node()

    async def encrypt_message_for_devices(self, ctx, all_devices: List, id: str, msg_plaintext: bytes, dsm_plaintext: bytes, enc_attrs) -> Tuple[List[Node], bool]:
        """
        Encrypt message for devices.

        Args:
            ctx: Context
            all_devices: All devices
            id: Message ID
            msg_plaintext: Message plaintext
            dsm_plaintext: DSM plaintext
            enc_attrs: Encryption attributes

        Returns:
            Tuple of encrypted message nodes and whether identity was included
        """
        return await self.c._encrypt_message_for_devices(ctx, all_devices, id, msg_plaintext, dsm_plaintext, enc_attrs)

    async def encrypt_message_for_device_and_wrap(self, ctx, plaintext: bytes, wire_identity, encryption_identity, bundle, enc_attrs) -> Tuple[Node, bool]:
        """
        Encrypt message for device and wrap.

        Args:
            ctx: Context
            plaintext: Plaintext
            wire_identity: Wire identity
            encryption_identity: Encryption identity
            bundle: Pre-key bundle
            enc_attrs: Encryption attributes

        Returns:
            Tuple of encrypted message node and whether identity was included
        """
        return await self.c._encrypt_message_for_device_and_wrap(ctx, plaintext, wire_identity, encryption_identity, bundle, enc_attrs)

    async def encrypt_message_for_device(self, ctx, plaintext: bytes, to, bundle, extra_attrs) -> Tuple[Node, bool]:
        """
        Encrypt message for device.

        Args:
            ctx: Context
            plaintext: Plaintext
            to: Recipient JID
            bundle: Pre-key bundle
            extra_attrs: Extra attributes

        Returns:
            Tuple of encrypted message node and whether identity was included
        """
        return await self.c._encrypt_message_for_device(ctx, plaintext, to, bundle, extra_attrs)

    async def raw_upload(self, ctx, data_to_upload, upload_size: int, file_hash: bytes, app_info, newsletter: bool, resp) -> None:
        """
        Raw upload.

        Args:
            ctx: Context
            data_to_upload: Data to upload
            upload_size: Upload size
            file_hash: File hash
            app_info: App info
            newsletter: Whether it's a newsletter
            resp: Upload response
        """
        await self.c._raw_upload(ctx, data_to_upload, upload_size, file_hash, app_info, newsletter, resp)

    def parse_business_profile(self, node: Node):
        """
        Parse business profile.

        Args:
            node: Business profile node

        Returns:
            Business profile
        """
        return self.c._parse_business_profile(node)

    async def handle_historical_push_names(self, ctx, names: List[waHistorySync.Pushname]) -> None:
        """
        Handle historical push names.

        Args:
            ctx: Context
            names: Push names
        """
        await self.c._handle_historical_push_names(ctx, names)

    async def update_push_name(self, ctx, user, message_info, name: str) -> None:
        """
        Update push name.

        Args:
            ctx: Context
            user: User JID
            message_info: Message info
            name: Push name
        """
        await self.c._update_push_name(ctx, user, message_info, name)

    async def update_business_name(self, ctx, user, message_info, name: str) -> None:
        """
        Update business name.

        Args:
            ctx: Context
            user: User JID
            message_info: Message info
            name: Business name
        """
        await self.c._update_business_name(ctx, user, message_info, name)

    async def get_fbid_devices_internal(self, ctx, jids: List) -> Node:
        """
        Get FBID devices internal.

        Args:
            ctx: Context
            jids: JIDs

        Returns:
            Response node
        """
        return await self.c._get_fbid_devices_internal(ctx, jids)

    async def get_fbid_devices(self, ctx, jids: List) -> List:
        """
        Get FBID devices.

        Args:
            ctx: Context
            jids: JIDs

        Returns:
            List of device JIDs
        """
        return await self.c._get_fbid_devices(ctx, jids)

    async def usync(self, ctx, jids: List, mode: str, context_str: str, query: List[Node], *extra) -> Node:
        """
        User sync.

        Args:
            ctx: Context
            jids: JIDs
            mode: Mode
            context_str: Context string
            query: Query
            extra: Extra parameters

        Returns:
            Response node
        """
        return await self.c._usync(ctx, jids, mode, context_str, query, *extra)

    def parse_blocklist(self, node: Node):
        """
        Parse blocklist.

        Args:
            node: Blocklist node

        Returns:
            Blocklist
        """
        return self.c._parse_blocklist(node)

class DangerousInfoQuery:
    """Type alias for info query."""
    pass

class DangerousInfoQueryType:
    """Type alias for info query type."""
    pass

def dangerous_internals(client):
    """
    Get access to dangerous internal client methods.

    This is dangerous and should only be used for advanced use cases.

    Args:
        client: The WhatsApp client instance

    Returns:
        DangerousInternalClient instance
    """
    return DangerousInternalClient(client)
