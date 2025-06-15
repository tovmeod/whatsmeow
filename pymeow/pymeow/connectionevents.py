"""
Connection events handling for WhatsApp client.

Port of whatsmeow/connectionevents.go
"""
import asyncio
import logging
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Optional

from . import request
from .binary.node import Node
from .prekeys import get_server_pre_key_count, upload_prekeys
from .request import InfoQuery, InfoQueryType
from .store import store
from .store.clientpayload import get_wa_version
from .types import events, jid

if TYPE_CHECKING:
    from .client import Client

# Constants
MIN_PREKEY_COUNT = 5  # Threshold for when to upload new prekeys

logger = logging.getLogger(__name__)

async def handle_stream_error(client: "Client", node: Node) -> None:
    """
    Handle a stream error from the WhatsApp server.

    Args:
        client: The WhatsApp client
        node: The stream error node from the server
    """
    client._is_logged_in = False
    await request.clear_response_waiters(client, node)

    code = node.attrs.get("code", "")
    conflict, _ = node.get_optional_child_by_tag("conflict")
    conflict_type = conflict.attrs.get("type") if conflict else None

    if code == "515":
        if client.disable_login_auto_reconnect:
            logger.info("Got 515 code, but login autoreconnect is disabled, not reconnecting")
            await client.dispatch_event(events.ManualLoginReconnect())
            return

        logger.info("Got 515 code, reconnecting...")
        await _reconnect_after_515(client)
    elif code == "401" and conflict_type == "device_removed":
        client._expect_disconnect()
        logger.info("Got device removed stream error, sending LoggedOut event and deleting session")
        await client.dispatch_event(events.LoggedOut(on_connect=False, reason=events.ConnectFailureReason.LOGGED_OUT))
        try:
            await client.store.delete()
        except Exception as e:
            logger.warning(f"Failed to delete store after device_removed error: {e}")
    elif conflict_type == "replaced":
        client._expect_disconnect()
        logger.info("Got replaced stream error, sending StreamReplaced event")
        await client.dispatch_event(events.StreamReplaced())
    elif code == "503":
        # This seems to happen when the server wants to restart or something.
        # The disconnection will be emitted as an events.Disconnected and then the auto-reconnect will do its thing.
        logger.warning("Got 503 stream error, assuming automatic reconnect will handle it")
    else:
        logger.error(f"Unknown stream error: {node.xml_string()}")
        await client.dispatch_event(events.StreamError(code=code, raw=node))


async def handle_ib(cli: "Client", node: Node) -> None:
    """
    Handle an IB node from the WhatsApp server.

    Args:
        cli: The WhatsApp client
        node: The IB node from the server
    """
    children = node.get_children()
    for child in children:
        if child.tag == "downgrade_webclient":
            await cli.dispatch_event(events.QRScannedWithoutMultidevice())
        elif child.tag == "offline_preview":
            await cli.dispatch_event(events.OfflineSyncPreview(
                total=int(child.attrs.get("count", 0)),
                app_data_changes=int(child.attrs.get("appdata", 0)),
                messages=int(child.attrs.get("message", 0)),
                notifications=int(child.attrs.get("notification", 0)),
                receipts=int(child.attrs.get("receipt", 0))
            ))
        elif child.tag == "offline":
            await cli.dispatch_event(events.OfflineSyncCompleted(
                count=int(child.attrs.get("count", 0))
            ))


async def handle_connect_failure(client: "Client", node: Node) -> None:
    """
    Handle a connection failure from the WhatsApp server.

    Args:
        client: The WhatsApp client
        node: The connection failure node from the server
    """
    reason = events.ConnectFailureReason(int(node.attrs.get("reason", 0)))
    message = node.attrs.get("message", "")
    will_auto_reconnect = True

    # Handle different failure reasons - use switch-like logic from Go
    if reason == events.ConnectFailureReason.SERVICE_UNAVAILABLE or reason == events.ConnectFailureReason.INTERNAL_SERVER_ERROR:
        # Auto-reconnect for 503s
        pass
    elif reason == events.ConnectFailureReason.CAT_INVALID or reason == events.ConnectFailureReason.CAT_EXPIRED:
        # Auto-reconnect when rotating CAT, lock socket to ensure refresh goes through before reconnect
        async with client.socket_lock:
            pass
    else:
        # By default, expect a disconnect (i.e. prevent auto-reconnect)
        client._expect_disconnect()
        will_auto_reconnect = False

    # Check for 403 by comparing the enum value directly
    if reason.value == 403:
        logger.debug(
            f"Message for 403 connect failure: {node.attrs.get('logout_message_header', '')} / "
            f"{node.attrs.get('logout_message_subtext', '')}"
        )

    if reason.is_logged_out():
        logger.info(f"Got {reason} connect failure, sending LoggedOut event and deleting session")
        await client.dispatch_event(events.LoggedOut(on_connect=True, reason=reason))
        try:
            await client.store.delete()
        except Exception as e:
            logger.warning(f"Failed to delete store after {reason.value} failure: {e}")
    elif reason == events.ConnectFailureReason.TEMP_BANNED:
        logger.warning(f"Temporary ban connect failure: {node.xml_string()}")
        await client.dispatch_event(events.TemporaryBan(
            code=events.TempBanReason(int(node.attrs.get("code", 0))),
            expire=timedelta(seconds=int(node.attrs.get("expire", 0)))
        ))
    elif reason == events.ConnectFailureReason.CLIENT_OUTDATED:
        logger.error(f"Client outdated (405) connect failure (client version: {get_wa_version()})")
        await client.dispatch_event(events.ClientOutdated())
    elif reason == events.ConnectFailureReason.CAT_INVALID or reason == events.ConnectFailureReason.CAT_EXPIRED:
        logger.info(f"Got {reason.value}/{message} connect failure, refreshing CAT before reconnecting...")
        # try:
        #     await client.refresh_cat()
        # except Exception as e:
        #     logger.error(f"Failed to refresh CAT: {e}")
        #     client._expect_disconnect()
        #     await client.dispatch_event(events.CATRefreshError(error=e))
    elif will_auto_reconnect:
        logger.warning(f"Got {reason.value}/{message} connect failure, assuming automatic reconnect will handle it")
    else:
        logger.warning(f"Unknown connect failure: {node.xml_string()}")
        await client.dispatch_event(events.ConnectFailure(reason=reason, message=message, raw=node))


async def handle_connect_success(cli: "Client", node: Node) -> None:
    """
    Handle a successful connection to the WhatsApp server.

    Args:
        cli: The WhatsApp client
        node: The connection success node from the server
    """
    logger.info("Successfully authenticated")
    cli.last_successful_connect = datetime.now()
    cli.auto_reconnect_errors = 0
    cli._is_logged_in = True

    node_lid_str = node.attrs.get("lid", "")
    node_lid = jid.JID.parse_jid(node_lid_str) if node_lid_str else jid.JID()

    if cli.store.lid.is_empty() and not node_lid.is_empty():
        cli.store.lid = node_lid
        try:
            await cli.store.save()
        except Exception as e:
            logger.warning(f"Failed to save device after updating LID: {e}")
        else:
            logger.info(f"Updated LID to {cli.store.lid}")

        await cli.store_lid_pn_mapping(cli.store.get_lid(), cli.store.get_jid())

    # Start a task to handle post-connection setup
    await _post_connect_setup(cli)


async def _post_connect_setup(cli: "Client") -> None:
    """
    Handle post-connection setup tasks.

    Args:
        cli: The WhatsApp client
    """

    # Check and upload prekeys if needed
    db_count = None
    server_count = None

    try:
        db_count = await cli.store.pre_keys.uploaded_prekey_count()
    except Exception as e:
        logger.error(f"Failed to get number of prekeys in database: {e}")

    if db_count is not None:
        try:
            server_count = await get_server_pre_key_count(cli)
        except Exception as e:
            logger.warning(f"Failed to get number of prekeys on server: {e}")
        else:
            logger.debug(f"Database has {db_count} prekeys, server says we have {server_count}")
            if server_count < MIN_PREKEY_COUNT or db_count < MIN_PREKEY_COUNT:
                await upload_prekeys(cli)
                try:
                    sc = await get_server_pre_key_count(cli)
                    logger.debug(f"Prekey count after upload: {sc}")
                except Exception:
                    pass

    # Set passive mode to false
    try:
        await set_passive(cli,False)
    except Exception as e:
        logger.warning(f"Failed to send post-connect passive IQ: {e}")

    # Dispatch connected event
    await cli.dispatch_event(events.Connected())
    await cli.close_socket_wait_chan()


async def _reconnect_after_515(cli: "Client") -> None:
    """
    Reconnect after receiving a 515 error code.

    Args:
        cli: The WhatsApp client
    """
    await cli.disconnect()
    try:
        await cli.connect()
    except Exception as e:
        logger.error(f"Failed to reconnect after 515 code: {e}")


async def set_passive(client: "Client", passive: bool) -> None:
    """
    Tell the WhatsApp server whether this device is passive or not.

    This seems to mostly affect whether the device receives certain events.
    By default, whatsmeow will automatically do set_passive(False) after connecting.

    Args:
        client: The WhatsApp client
        passive: Whether to set the device as passive

    Returns:
        None

    Raises:
        Exception: If there's an error sending the IQ
    """
    tag = "passive" if passive else "active"

    _ = await request.send_iq(client, InfoQuery(
        namespace="passive",
        type=InfoQueryType.SET,  # Fixed: Use enum value instead of string
        to=jid.SERVER_JID,
        content=[Node(tag=tag)]
    ))
