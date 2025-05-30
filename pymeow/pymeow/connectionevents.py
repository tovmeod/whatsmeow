"""
Connection events handling for WhatsApp client.

Port of whatsmeow/connectionevents.go
"""
import asyncio
import logging
from datetime import datetime
from typing import Optional, Dict, Any, Callable, List, TYPE_CHECKING

from .binary.node import Node
from .types import types
from .types.events import events
from .types.jid import JID

if TYPE_CHECKING:
    from .client import Client

# Constants
MIN_PREKEY_COUNT = 5  # Threshold for when to upload new prekeys


async def handle_stream_error(cli: "Client", node: Node) -> None:
    """
    Handle a stream error from the WhatsApp server.

    Args:
        cli: The WhatsApp client
        node: The stream error node from the server
    """
    ctx = asyncio.get_event_loop()
    cli.is_logged_in.store(False)
    cli.clear_response_waiters(node)

    code = node.attrs.get("code", "")
    conflict = node.get_optional_child_by_tag("conflict")
    conflict_type = conflict.attr_getter().optional_string("type") if conflict else None

    if code == "515":
        if cli.disable_login_auto_reconnect:
            cli.log.info("Got 515 code, but login autoreconnect is disabled, not reconnecting")
            asyncio.create_task(cli.dispatch_event(events.ManualLoginReconnect()))
            return

        cli.log.info("Got 515 code, reconnecting...")
        asyncio.create_task(_reconnect_after_515(cli))
    elif code == "401" and conflict_type == "device_removed":
        cli.expect_disconnect()
        cli.log.info("Got device removed stream error, sending LoggedOut event and deleting session")
        asyncio.create_task(cli.dispatch_event(events.LoggedOut(on_connect=False, reason=events.ConnectFailureReason.LOGGED_OUT)))
        try:
            await cli.store.delete(ctx)
        except Exception as e:
            cli.log.warning(f"Failed to delete store after device_removed error: {e}")
    elif conflict_type == "replaced":
        cli.expect_disconnect()
        cli.log.info("Got replaced stream error, sending StreamReplaced event")
        asyncio.create_task(cli.dispatch_event(events.StreamReplaced()))
    elif code == "503":
        # This seems to happen when the server wants to restart or something.
        # The disconnection will be emitted as an events.Disconnected and then the auto-reconnect will do its thing.
        cli.log.warning("Got 503 stream error, assuming automatic reconnect will handle it")
    elif cli.refresh_cat is not None and (code == events.ConnectFailureReason.CAT_INVALID.number_string() or
                                         code == events.ConnectFailureReason.CAT_EXPIRED.number_string()):
        cli.log.info(f"Got {code} stream error, refreshing CAT before reconnecting...")
        async with cli.socket_lock.reader_lock:
            try:
                await cli.refresh_cat()
            except Exception as e:
                cli.log.error(f"Failed to refresh CAT: {e}")
                cli.expect_disconnect()
                asyncio.create_task(cli.dispatch_event(events.CATRefreshError(error=e)))
    else:
        cli.expect_disconnect()
        cli.log.warning(f"Unknown stream error: {node.xml_string()}")
        asyncio.create_task(cli.dispatch_event(events.StreamError(code=code, raw=node)))


async def handle_connect_failure(cli: "Client", node: Node) -> None:
    """
    Handle a connection failure from the WhatsApp server.

    Args:
        cli: The WhatsApp client
        node: The connection failure node from the server
    """
    ctx = asyncio.get_event_loop()
    ag = node.attr_getter()
    reason = events.ConnectFailureReason(ag.int("reason"))
    message = ag.optional_string("message")
    will_auto_reconnect = True

    # Handle different failure reasons
    if reason == events.ConnectFailureReason.SERVICE_UNAVAILABLE or reason == events.ConnectFailureReason.INTERNAL_SERVER_ERROR:
        # Auto-reconnect for 503s
        pass
    elif reason == events.ConnectFailureReason.CAT_INVALID or reason == events.ConnectFailureReason.CAT_EXPIRED:
        # Auto-reconnect when rotating CAT, lock socket to ensure refresh goes through before reconnect
        async with cli.socket_lock.reader_lock:
            pass
    else:
        # By default, expect a disconnect (i.e. prevent auto-reconnect)
        cli.expect_disconnect()
        will_auto_reconnect = False

    if reason == 403:
        cli.log.debug(
            f"Message for 403 connect failure: {ag.optional_string('logout_message_header')} / "
            f"{ag.optional_string('logout_message_subtext')}"
        )

    if reason.is_logged_out():
        cli.log.info(f"Got {reason} connect failure, sending LoggedOut event and deleting session")
        asyncio.create_task(cli.dispatch_event(events.LoggedOut(on_connect=True, reason=reason)))
        try:
            await cli.store.delete(ctx)
        except Exception as e:
            cli.log.warning(f"Failed to delete store after {int(reason)} failure: {e}")
    elif reason == events.ConnectFailureReason.TEMP_BANNED:
        cli.log.warning(f"Temporary ban connect failure: {node.xml_string()}")
        asyncio.create_task(cli.dispatch_event(events.TemporaryBan(
            code=events.TempBanReason(ag.int("code")),
            expire=datetime.fromtimestamp(ag.int("expire"))
        )))
    elif reason == events.ConnectFailureReason.CLIENT_OUTDATED:
        cli.log.error(f"Client outdated (405) connect failure (client version: {cli.store.get_wa_version()})")
        asyncio.create_task(cli.dispatch_event(events.ClientOutdated()))
    elif reason == events.ConnectFailureReason.CAT_INVALID or reason == events.ConnectFailureReason.CAT_EXPIRED:
        cli.log.info(f"Got {int(reason)}/{message} connect failure, refreshing CAT before reconnecting...")
        try:
            await cli.refresh_cat()
        except Exception as e:
            cli.log.error(f"Failed to refresh CAT: {e}")
            cli.expect_disconnect()
            asyncio.create_task(cli.dispatch_event(events.CATRefreshError(error=e)))
    elif will_auto_reconnect:
        cli.log.warning(f"Got {int(reason)}/{message} connect failure, assuming automatic reconnect will handle it")
    else:
        cli.log.warning(f"Unknown connect failure: {node.xml_string()}")
        asyncio.create_task(cli.dispatch_event(events.ConnectFailure(reason=reason, message=message, raw=node)))


async def handle_connect_success(cli: "Client", node: Node) -> None:
    """
    Handle a successful connection to the WhatsApp server.

    Args:
        cli: The WhatsApp client
        node: The connection success node from the server
    """
    ctx = asyncio.get_event_loop()
    cli.log.info("Successfully authenticated")
    cli.last_successful_connect = datetime.now()
    cli.auto_reconnect_errors = 0
    cli.is_logged_in.store(True)

    node_lid = node.attr_getter().jid("lid")
    if cli.store.lid.is_empty() and not node_lid.is_empty():
        cli.store.lid = node_lid
        try:
            await cli.store.save(ctx)
        except Exception as e:
            cli.log.warning(f"Failed to save device after updating LID: {e}")
        else:
            cli.log.info(f"Updated LID to {cli.store.lid}")

        await cli.store_lid_pn_mapping(ctx, cli.store.get_lid(), cli.store.get_jid())

    # Start a task to handle post-connection setup
    asyncio.create_task(_post_connect_setup(cli))


async def _post_connect_setup(cli: "Client") -> None:
    """
    Handle post-connection setup tasks.

    Args:
        cli: The WhatsApp client
    """
    ctx = asyncio.get_event_loop()

    # Check and upload prekeys if needed
    try:
        db_count = await cli.store.pre_keys.uploaded_prekey_count(ctx)
    except Exception as e:
        cli.log.error(f"Failed to get number of prekeys in database: {e}")
    else:
        try:
            server_count = await cli.get_server_prekey_count(ctx)
        except Exception as e:
            cli.log.warning(f"Failed to get number of prekeys on server: {e}")
        else:
            cli.log.debug(f"Database has {db_count} prekeys, server says we have {server_count}")
            if server_count < MIN_PREKEY_COUNT or db_count < MIN_PREKEY_COUNT:
                await cli.upload_prekeys(ctx)
                sc, _ = await cli.get_server_prekey_count(ctx)
                cli.log.debug(f"Prekey count after upload: {sc}")

    # Set passive mode to false
    try:
        await cli.set_passive(ctx, False)
    except Exception as e:
        cli.log.warning(f"Failed to send post-connect passive IQ: {e}")

    # Dispatch connected event
    await cli.dispatch_event(events.Connected())
    cli.close_socket_wait_chan()


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
        cli.log.error(f"Failed to reconnect after 515 code: {e}")


async def set_passive(cli: "Client", ctx: asyncio.AbstractEventLoop, passive: bool) -> None:
    """
    Tell the WhatsApp server whether this device is passive or not.

    This seems to mostly affect whether the device receives certain events.
    By default, whatsmeow will automatically do set_passive(False) after connecting.

    Args:
        cli: The WhatsApp client
        ctx: The async context
        passive: Whether to set the device as passive

    Returns:
        None

    Raises:
        Exception: If there's an error sending the IQ
    """
    tag = "passive" if passive else "active"

    _, err = await cli.send_iq({
        "namespace": "passive",
        "type": "set",
        "to": types.SERVER_JID,
        "context": ctx,
        "content": [Node(tag=tag)]
    })

    if err:
        raise err
