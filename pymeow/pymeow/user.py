"""
WhatsApp user management functions.

Port of whatsmeow/user.go
"""

import dataclasses
import logging
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from google.protobuf.internal.containers import RepeatedCompositeFieldContainer

from .datatypes.jid import (
    DEFAULT_USER_SERVER,
    HIDDEN_USER_SERVER,
    JID,
    LEGACY_USER_SERVER,
    MESSENGER_SERVER,
    SERVER_JID,
)
from .datatypes.user import (
    BotListInfo,
    BotProfileCommand,
    BotProfileInfo,
    BusinessHoursConfig,
    BusinessMessageLinkTarget,
    BusinessProfile,
    Category,
    ContactQRLinkTarget,
    IsOnWhatsAppResponse,
    ProfilePictureInfo,
    UserInfo,
    VerifiedName,
)
from .exceptions import (
    ElementMissingError,
    ErrBusinessMessageLinkNotFound,
    ErrClientIsNil,
    ErrContactQRLinkNotFound,
    ErrIQNotAuthorized,
    ErrIQNotFound,
    ErrProfilePictureNotSet,
    ErrProfilePictureUnauthorized,
)
from .generated.waHistorySync import WAWebProtobufsHistorySync_pb2

if TYPE_CHECKING:
    from .binary.node import Node
    from .client import Client
    from .datatypes import MessageInfo

# Link prefixes
BUSINESS_MESSAGE_LINK_PREFIX = "https://wa.me/message/"
CONTACT_QR_LINK_PREFIX = "https://wa.me/qr/"
BUSINESS_MESSAGE_LINK_DIRECT_PREFIX = "https://api.whatsapp.com/message/"
CONTACT_QR_LINK_DIRECT_PREFIX = "https://api.whatsapp.com/qr/"
NEWSLETTER_LINK_PREFIX = "https://whatsapp.com/channel/"

logger = logging.getLogger(__name__)


class GetProfilePictureParams:
    """Parameters for getting profile pictures."""

    def __init__(self, preview: bool = False, existing_id: str = "", is_community: bool = False):
        self.preview = preview
        self.existing_id = existing_id
        self.is_community = is_community


class UsyncQueryExtras:
    """Extra parameters for usync queries."""

    def __init__(self, bot_list_info: Optional[List[BotListInfo]] = None):
        self.bot_list_info = bot_list_info or []


async def resolve_business_message_link(client: "Client", code: str) -> Optional[BusinessMessageLinkTarget]:
    """
    Resolves a business message short link and returns the target JID, business name and
    text to prefill in the input field (if any).

    The links look like https://wa.me/message/<code> or https://api.whatsapp.com/message/<code>.
    You can either provide the full link, or just the <code> part.
    """
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    code = code.removeprefix(BUSINESS_MESSAGE_LINK_PREFIX)
    code = code.removeprefix(BUSINESS_MESSAGE_LINK_DIRECT_PREFIX)

    try:
        resp = await send_iq(
            client,
            InfoQuery(namespace="w:qr", type=InfoQueryType.GET, content=[Node(tag="qr", attrs=Attrs({"code": code}))]),
        )
    except ErrIQNotFound as e:
        raise ErrBusinessMessageLinkNotFound() from e

    qr_child, found = resp.get_optional_child_by_tag("qr")
    if not found:
        raise ElementMissingError(tag="qr", in_location="response to business message link query")

    target = BusinessMessageLinkTarget()
    ag = qr_child.attr_getter()
    target.jid = ag.jid("jid")
    target.push_name = ag.string("notify")

    message_child, found = qr_child.get_optional_child_by_tag("message")
    if found and isinstance(message_child.content, bytes):
        target.message = message_child.content.decode("utf-8")

    business_child, found = qr_child.get_optional_child_by_tag("business")
    if found:
        bag = business_child.attr_getter()
        target.is_signed = bag.optional_bool("is_signed")
        target.verified_name = bag.optional_string("verified_name")
        target.verified_level = bag.optional_string("verified_level")

    err = ag.error()
    if err:
        raise err

    return target


async def resolve_contact_qr_link(client: "Client", code: str) -> Optional[ContactQRLinkTarget]:
    """
    Resolves a link from a contact share QR code and returns the target JID and push name.

    The links look like https://wa.me/qr/<code> or https://api.whatsapp.com/qr/<code>.
    You can either provide the full link, or just the <code> part.
    """
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    code = code.removeprefix(CONTACT_QR_LINK_PREFIX)
    code = code.removeprefix(CONTACT_QR_LINK_DIRECT_PREFIX)

    try:
        resp = await send_iq(
            client,
            InfoQuery(namespace="w:qr", type=InfoQueryType.GET, content=[Node(tag="qr", attrs=Attrs({"code": code}))]),
        )
    except ErrIQNotFound as e:
        raise ErrContactQRLinkNotFound() from e

    qr_child, found = resp.get_optional_child_by_tag("qr")
    if not found:
        raise ElementMissingError(tag="qr", in_location="response to contact link query")

    target = ContactQRLinkTarget()
    ag = qr_child.attr_getter()
    target.jid = ag.jid("jid")
    target.push_name = ag.optional_string("notify")
    target.type = ag.string("type")

    err = ag.error()
    if err:
        raise err

    return target


async def get_contact_qr_link(client: "Client", revoke: bool = False) -> str:
    """
    Get your own contact share QR link that can be resolved using resolve_contact_qr_link
    (or scanned with the official apps when encoded as a QR code).

    If the revoke parameter is set to True, it will ask the server to revoke the previous
    link and generate a new one.
    """
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    action = "revoke" if revoke else "get"

    resp = await send_iq(
        client,
        InfoQuery(
            namespace="w:qr",
            type=InfoQueryType.SET,
            content=[Node(tag="qr", attrs=Attrs({"type": "contact", "action": action}))],
        ),
    )

    qr_child, found = resp.get_optional_child_by_tag("qr")
    if not found:
        raise ElementMissingError(tag="qr", in_location="response to own contact link fetch")

    ag = qr_child.attr_getter()
    code = ag.string("code")

    err = ag.error()
    if err:
        raise err

    return code


async def set_status_message(client: "Client", msg: str) -> None:
    """
    Update the current user's status text, which is shown in the "About" section in the user profile.

    This is different from the ephemeral status broadcast messages. Use send_message to
    STATUS_BROADCAST_JID to send such messages.
    """
    from .binary.node import Node
    from .request import InfoQuery, InfoQueryType, send_iq

    await send_iq(
        client,
        InfoQuery(
            namespace="status",
            type=InfoQueryType.SET,
            to=SERVER_JID,
            content=[Node(tag="status", content=msg.encode("utf-8"))],
        ),
    )


async def is_on_whatsapp(client: "Client", phones: List[str]) -> List[IsOnWhatsAppResponse]:
    """
    Check if the given phone numbers are registered on WhatsApp.
    The phone numbers should be in international format, including the `+` prefix.
    """
    from .binary.node import Node

    jids = [JID(user=phone, server=LEGACY_USER_SERVER) for phone in phones]

    list_node = await usync(
        client,
        jids,
        "query",
        "interactive",
        [
            Node(tag="business", content=[Node(tag="verified_name")]),
            Node(tag="contact"),
        ],
    )

    output = []
    query_suffix = f"@{LEGACY_USER_SERVER}"

    for child in list_node.get_children():
        if child.tag != "user":
            continue

        jid_attr = child.attrs.get("jid")
        if not isinstance(jid_attr, JID):
            continue

        info = IsOnWhatsAppResponse()
        info.jid = jid_attr

        try:
            info.verified_name = parse_verified_name(child.get_child_by_tag("business"))
        except Exception as e:
            logger.warning(f"Failed to parse {jid_attr}'s verified name details: {e}")

        contact_node = child.get_child_by_tag("contact")
        info.is_in = contact_node.attr_getter().string("type") == "in"

        if isinstance(contact_node.content, bytes):
            contact_query = contact_node.content.decode("utf-8")
            info.query = contact_query.removesuffix(query_suffix)

        output.append(info)

    return output


async def get_user_info(client: "Client", jids: List[JID]) -> Dict[JID, UserInfo]:
    """Get basic user info (avatar, status, verified business name, device list)."""
    from .binary.node import Attrs, Node

    list_node = await usync(
        client,
        jids,
        "full",
        "background",
        [
            Node(tag="business", content=[Node(tag="verified_name")]),
            Node(tag="status"),
            Node(tag="picture"),
            Node(tag="devices", attrs=Attrs({"version": "2"})),
        ],
    )

    resp_data = {}

    for child in list_node.get_children():
        if child.tag != "user":
            continue

        jid_attr = child.attrs.get("jid")
        if not isinstance(jid_attr, JID):
            continue

        info = UserInfo()

        try:
            verified_name = parse_verified_name(child.get_child_by_tag("business"))
        except Exception as e:
            logger.warning(f"Failed to parse {jid_attr}'s verified name details: {e}")
            verified_name = None

        status_node = child.get_child_by_tag("status")
        if isinstance(status_node.content, bytes):
            info.status = status_node.content.decode("utf-8")

        picture_node = child.get_child_by_tag("picture")
        info.picture_id = picture_node.attrs.get("id", "")

        info.devices = parse_device_list(jid_attr, child.get_child_by_tag("devices"))

        if verified_name:
            # Note: updateBusinessName would be called here in the Go version
            # but that requires access to client context and contacts store
            pass

        resp_data[jid_attr] = info

    return resp_data


async def get_bot_list_v2(client: "Client") -> List[BotListInfo]:
    """Get the list of available bots."""
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    resp = await send_iq(
        client,
        InfoQuery(
            to=SERVER_JID, namespace="bot", type=InfoQueryType.GET, content=[Node(tag="bot", attrs=Attrs({"v": "2"}))]
        ),
    )

    bot_node, found = resp.get_optional_child_by_tag("bot")
    if not found:
        raise ElementMissingError(tag="bot", in_location="response to bot list query")

    bot_list = []

    for section in bot_node.get_children_by_tag("section"):
        if section.attr_getter().string("type") == "all":
            for bot in section.get_children_by_tag("bot"):
                ag = bot.attr_getter()
                bot_list.append(BotListInfo(persona_id=ag.string("persona_id"), bot_jid=ag.jid("jid")))

    return bot_list


async def get_bot_profiles(client: "Client", bot_info: List[BotListInfo]) -> List[BotProfileInfo]:
    """Get detailed profile information for bots."""
    from .binary.node import Attrs, Node

    jids = [bot.bot_jid for bot in bot_info]

    list_node = await usync(
        client,
        jids,
        "query",
        "interactive",
        [Node(tag="bot", content=[Node(tag="profile", attrs=Attrs({"v": "1"}))])],
        UsyncQueryExtras(bot_list_info=bot_info),
    )

    profiles = []
    for user in list_node.get_children():
        jid = user.attr_getter().jid("jid")
        bot = user.get_child_by_tag("bot")
        profile = bot.get_child_by_tag("profile")

        # Extract name
        name_content = profile.get_child_by_tag("name").content
        if isinstance(name_content, bytes):
            name = name_content.decode("utf-8")
        else:
            name = ""

        # Extract attributes
        attributes_content = profile.get_child_by_tag("attributes").content
        if isinstance(attributes_content, bytes):
            attributes = attributes_content.decode("utf-8")
        else:
            attributes = ""

        # Extract description
        description_content = profile.get_child_by_tag("description").content
        if isinstance(description_content, bytes):
            description = description_content.decode("utf-8")
        else:
            description = ""

        # Extract category
        category_content = profile.get_child_by_tag("category").content
        if isinstance(category_content, bytes):
            category = category_content.decode("utf-8")
        else:
            category = ""

        _, is_default = profile.get_optional_child_by_tag("default")
        persona_id = profile.attr_getter().string("persona_id")

        commands_node = profile.get_child_by_tag("commands")

        # Extract command description
        commands_desc_content = commands_node.get_child_by_tag("description").content
        if isinstance(commands_desc_content, bytes):
            command_description = commands_desc_content.decode("utf-8")
        else:
            command_description = ""

        commands = []
        for command_node in commands_node.get_children_by_tag("command"):
            # Extract command name
            cmd_name_content = command_node.get_child_by_tag("name").content
            if isinstance(cmd_name_content, bytes):
                cmd_name = cmd_name_content.decode("utf-8")
            else:
                cmd_name = ""

            # Extract command description
            cmd_desc_content = command_node.get_child_by_tag("description").content
            if isinstance(cmd_desc_content, bytes):
                cmd_desc = cmd_desc_content.decode("utf-8")
            else:
                cmd_desc = ""

            commands.append(BotProfileCommand(name=cmd_name, description=cmd_desc))

        prompts_node = profile.get_child_by_tag("prompts")
        prompts = []
        for prompt_node in prompts_node.get_children_by_tag("prompt"):
            # Extract emoji
            emoji_content = prompt_node.get_child_by_tag("emoji").content
            if isinstance(emoji_content, bytes):
                emoji = emoji_content.decode("utf-8")
            else:
                emoji = ""

            # Extract text
            text_content = prompt_node.get_child_by_tag("text").content
            if isinstance(text_content, bytes):
                text = text_content.decode("utf-8")
            else:
                text = ""
            prompts.append(f"{emoji} {text}")

        profiles.append(
            BotProfileInfo(
                jid=jid,
                name=name,
                attributes=attributes,
                description=description,
                category=category,
                is_default=is_default,
                prompts=prompts,
                persona_id=persona_id,
                commands=commands,
                commands_description=command_description,
            )
        )

    return profiles


def parse_business_profile(node: "Node") -> BusinessProfile:
    """Parse a business profile from a node."""
    profile_node = node.get_child_by_tag("profile")

    jid = profile_node.attr_getter().jid("jid")
    if not jid:
        raise ValueError("missing jid in business profile")

    # Extract address
    address_content = profile_node.get_child_by_tag("address").content
    if isinstance(address_content, bytes):
        address = address_content.decode("utf-8")
    else:
        address = ""

    # Extract email
    email_content = profile_node.get_child_by_tag("email").content
    if isinstance(email_content, bytes):
        email = email_content.decode("utf-8")
    else:
        email = ""

    business_hour = profile_node.get_child_by_tag("business_hours")
    business_hour_timezone = business_hour.attr_getter().string("timezone")

    business_hours = []
    for config in business_hour.get_children():
        if config.tag != "business_hours_config":
            continue

        ag = config.attr_getter()
        business_hours.append(
            BusinessHoursConfig(
                day_of_week=ag.string("dow"),
                mode=ag.string("mode"),
                open_time=ag.string("open_time"),
                close_time=ag.string("close_time"),
            )
        )

    categories_node = profile_node.get_child_by_tag("categories")
    categories = []
    for category in categories_node.get_children():
        if category.tag != "category":
            continue

        category_id = category.attr_getter().string("id")

        # Extract category name
        category_name_content = category.content
        if isinstance(category_name_content, bytes):
            name = category_name_content.decode("utf-8")
        else:
            name = ""

        categories.append(Category(id=category_id, name=name))

    profile_options_node = profile_node.get_child_by_tag("profile_options")
    profile_options = {}
    for option in profile_options_node.get_children():
        # Extract option content
        option_content = option.content
        if isinstance(option_content, bytes):
            content = option_content.decode("utf-8")
        else:
            content = ""

        profile_options[option.tag] = content

    return BusinessProfile(
        jid=jid,
        email=email,
        address=address,
        categories=categories,
        profile_options=profile_options,
        business_hours_time_zone=business_hour_timezone,
        business_hours=business_hours,
    )


async def get_business_profile(client: "Client", jid: JID) -> BusinessProfile:
    """Get the profile info of a WhatsApp business account."""
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    resp = await send_iq(
        client,
        InfoQuery(
            type=InfoQueryType.GET,
            to=SERVER_JID,
            namespace="w:biz",
            content=[
                Node(
                    tag="business_profile",
                    attrs=Attrs({"v": "244"}),
                    content=[Node(tag="profile", attrs=Attrs({"jid": jid}))],
                )
            ],
        ),
    )

    node, found = resp.get_optional_child_by_tag("business_profile")
    if not found:
        raise ElementMissingError(tag="business_profile", in_location="response to business profile query")

    return parse_business_profile(node)


async def get_user_devices(client: "Client", jids: List[JID]) -> List[JID]:
    """
    Get the list of devices that the given user has. The input should be a list of
    regular JIDs, and the output will be a list of AD JIDs. The local device will not be included in
    the output even if the user's JID is included in the input. All other devices will be included.

    Deprecated: use get_user_devices_context instead.
    """
    return await get_user_devices_context(client, jids)


async def get_user_devices_context(client: "Client", jids: List[JID]) -> List[JID]:
    """Get user devices with context support."""
    from .binary.node import Attrs, Node

    if client is None:
        raise ErrClientIsNil()

    # This would need access to client's device cache and lock
    # For now, implementing a simplified version
    devices = []
    jids_to_sync = []
    fb_jids_to_sync = []

    for jid in jids:
        if jid.server == MESSENGER_SERVER:
            fb_jids_to_sync.append(jid)
        elif jid.is_bot():
            # Bot JIDs do not have devices, the usync query is empty
            devices.append(jid)
        else:
            jids_to_sync.append(jid)

    if jids_to_sync:
        list_node = await usync(
            client, jids_to_sync, "query", "message", [Node(tag="devices", attrs=Attrs({"version": "2"}))]
        )

        for user in list_node.get_children():
            if user.tag != "user":
                continue

            jid_attr = user.attrs.get("jid")
            if not isinstance(jid_attr, JID):
                continue

            user_devices = parse_device_list(jid_attr, user.get_child_by_tag("devices"))
            devices.extend(user_devices)

    if fb_jids_to_sync:
        user_devices = await get_fbid_devices(client, fb_jids_to_sync)
        devices.extend(user_devices)

    return devices


async def get_profile_picture_info(
    client: "Client", jid: JID, params: Optional[GetProfilePictureParams] = None
) -> Optional[ProfilePictureInfo]:
    """
    Get the URL where you can download a WhatsApp user's profile picture or group's photo.

    Optionally, you can pass the last known profile picture ID.
    If the profile picture hasn't changed, this will return None with no error.

    To get a community photo, you should pass `is_community=True`, as otherwise you may get a 401 error.
    """
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    attrs = Attrs({"query": "url"})

    if params is None:
        params = GetProfilePictureParams()

    if params.preview:
        attrs["type"] = "preview"
    else:
        attrs["type"] = "image"

    if params.existing_id:
        attrs["id"] = params.existing_id

    expect_wrapped = False
    namespace = "w:profile:picture"

    if params.is_community:
        target = None
        namespace = "w:g2"
        to = jid
        attrs["parent_group_jid"] = jid
        expect_wrapped = True
        content = [Node(tag="pictures", content=[Node(tag="picture", attrs=attrs)])]
    else:
        to = SERVER_JID
        target = jid
        content = [Node(tag="picture", attrs=attrs)]

    try:
        resp = await send_iq(
            client, InfoQuery(namespace=namespace, type=InfoQueryType.GET, to=to, target=target, content=content)
        )
    except ErrIQNotAuthorized as e:
        raise ErrProfilePictureUnauthorized() from e
    except ErrIQNotFound as e:
        raise ErrProfilePictureNotSet() from e

    if expect_wrapped:
        pics, found = resp.get_optional_child_by_tag("pictures")
        if not found:
            raise ElementMissingError(tag="pictures", in_location="response to profile picture query")
        resp = pics

    picture, found = resp.get_optional_child_by_tag("picture")
    if not found:
        if params.existing_id:
            return None
        raise ElementMissingError(tag="picture", in_location="response to profile picture query")

    ag = picture.attr_getter()
    if ag.optional_int("status") == 304:
        return None

    info = ProfilePictureInfo()
    info.id = ag.string("id")
    info.url = ag.string("url")
    info.type = ag.string("type")
    info.direct_path = ag.string("direct_path")

    err = ag.error()
    if err is not None:
        raise err
    return info


async def handle_historical_push_names(
    client: "Client", names: RepeatedCompositeFieldContainer[WAWebProtobufsHistorySync_pb2.Pushname]
) -> None:
    """
    Handle historical push names from history sync.

    Args:
        client: The WhatsApp client instance
        names: List of push name objects from history sync (waHistorySync.Pushname protobuf objects)
    """
    logger.info(f"Updating contact store with {len(names)} push names from history sync")

    for user_pushname in names:
        # Skip entries with "-" as push name (indicates deleted/empty)
        if user_pushname.pushname == "-":
            continue

        try:
            # Parse the JID from the user ID
            jid = JID.parse_jid(user_pushname.ID)
        except Exception as e:
            logger.warning(f"Failed to parse user ID '{user_pushname.ID}' in push name history sync: {e}")
            continue
        try:
            # Store the push name and check if it changed
            changed, previous_name = await client.store.contacts.put_push_name(jid, user_pushname.pushname)

            if changed:
                logger.debug(f"Got push name {user_pushname.pushname} for {jid} in history sync")
        except Exception as e:
            logger.warning(f"Failed to store push name of {jid} from history sync: {e}")
            continue


async def update_push_name(client: "Client", user: JID, message_info: "MessageInfo", name: str) -> None:
    """
    Update push name for a user and dispatch event if changed.

    Args:
        client: The WhatsApp client instance
        user: JID of the user whose push name is being updated
        message_info: MessageInfo object associated with this update (can be None)
        name: The new push name
    """
    from .datatypes.events import PushName

    # Convert to non-AD JID for storage
    user = user.to_non_ad()

    try:
        # Store the push name and check if it changed
        changed, previous_name = await client.store.contacts.put_push_name(user, name)

        if changed:
            logger.debug(f"Push name of {user} changed from {previous_name} to {name}, dispatching event")

            # Dispatch PushName event
            event = PushName(jid=user, message=message_info, old_push_name=previous_name, new_push_name=name)

            # Dispatch the event through the client's event system
            await client.dispatch_event(event)

    except Exception as e:
        logger.error(f"Failed to save push name of {user} in device store: {e}")


async def update_business_name(client: "Client", user: JID, message_info: "MessageInfo", name: str) -> None:
    """
    Update business name for a user and dispatch event if changed.

    Args:
        client: The WhatsApp client instance
        user: JID of the user whose business name is being updated
        message_info: MessageInfo object associated with this update (can be None)
        name: The new business name
    """
    from .datatypes.events import BusinessName

    try:
        # Store the business name and check if it changed
        changed, previous_name = await client.store.contacts.put_business_name(user, name)

        if changed:
            logger.debug(f"Business name of {user} changed from {previous_name} to {name}, dispatching event")

            # Dispatch BusinessName event
            event = BusinessName(
                jid=user, message=message_info, old_business_name=previous_name, new_business_name=name
            )
            # Dispatch the event through the client's event system
            await client.dispatch_event(event)

    except Exception as e:
        logger.error(f"Failed to save business name of {user} in device store: {e}")


def parse_verified_name(business_node: "Node") -> Optional[VerifiedName]:
    """Parse verified name from business node."""
    if business_node.tag != "business":
        return None

    verified_name_node, found = business_node.get_optional_child_by_tag("verified_name")
    if not found:
        return None

    return parse_verified_name_content(verified_name_node)


def parse_verified_name_content(verified_name_node: "Node") -> Optional[VerifiedName]:
    """Parse verified name content."""
    if not isinstance(verified_name_node.content, bytes):
        return None

    # This would require protobuf unmarshaling
    # Implementation depends on waVnameCert protobuf definitions
    # For now, return a placeholder
    return VerifiedName()


def parse_device_list(user: JID, device_node: "Node") -> List[JID]:
    """Parse device list from node."""
    device_list = device_node.get_child_by_tag("device-list")
    if device_node.tag != "devices" or device_list.tag != "device-list":
        return []

    devices: List[JID] = []
    for device in device_list.get_children():
        if device.tag != "device":
            continue

        device_id = device.attr_getter().int64("id")
        if device_id is not None:
            device_jid = dataclasses.replace(user, device=device_id)
            devices.append(device_jid)

    return devices


def parse_fb_device_list(user: JID, device_list: "Node") -> Dict[str, Any]:
    """Parse Facebook device list."""
    devices: List[JID] = []
    for device in device_list.get_children():
        if device.tag != "device":
            continue

        device_id = device.attr_getter().int64("id")
        if device_id is not None:
            device_jid = dataclasses.replace(user, device=device_id)
            devices.append(device_jid)

    return {"devices": devices, "dhash": device_list.attr_getter().string("dhash")}


async def get_fbid_devices_internal(client: "Client", jids: List[JID]) -> "Node":
    """Get Facebook ID devices internal."""
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq

    users = []
    for jid in jids:
        users.append(Node(tag="user", attrs=Attrs({"jid": jid})))

    resp = await send_iq(
        client,
        InfoQuery(
            namespace="fbid:devices", type=InfoQueryType.GET, to=SERVER_JID, content=[Node(tag="users", content=users)]
        ),
    )

    list_node, found = resp.get_optional_child_by_tag("users")
    if not found:
        raise ElementMissingError(tag="users", in_location="response to fbid devices query")

    return list_node


async def get_fbid_devices(client: "Client", jids: List[JID]) -> List[JID]:
    """Get Facebook ID devices."""
    devices = []

    # Process in chunks of 15
    for i in range(0, len(jids), 15):
        chunk = jids[i : i + 15]
        list_node = await get_fbid_devices_internal(client, chunk)

        for user in list_node.get_children():
            if user.tag != "user":
                continue

            jid_attr = user.attrs.get("jid")
            if not isinstance(jid_attr, JID):
                continue

            user_devices_data = parse_fb_device_list(jid_attr, user.get_child_by_tag("devices"))
            devices.extend(user_devices_data["devices"])

    return devices


async def usync(
    client: "Client",
    jids: List[JID],
    mode: str,
    context: str,
    query: List["Node"],
    extras: Optional[UsyncQueryExtras] = None,
) -> "Node":
    """
    Perform a usync operation.
    """
    from .binary.node import Attrs, Node
    from .request import InfoQuery, InfoQueryType, send_iq, generate_request_id

    if client is None:
        raise ErrClientIsNil()

    if extras is None:
        extras = UsyncQueryExtras()

    user_list = []
    for jid in jids:
        user_node = Node(tag="user")
        jid = jid.to_non_ad()

        if jid.server == LEGACY_USER_SERVER:
            user_node.content = [Node(tag="contact", content=str(jid).encode("utf-8"))]
        elif jid.server in [DEFAULT_USER_SERVER, HIDDEN_USER_SERVER]:
            user_node.attrs = Attrs({"jid": jid})
            if jid.is_bot():
                persona_id = ""
                for bot in extras.bot_list_info:
                    if bot.bot_jid.user == jid.user:
                        persona_id = bot.persona_id
                        break

                user_node.content = [
                    Node(tag="bot", content=[Node(tag="profile", attrs=Attrs({"persona_id": persona_id}))])
                ]
        else:
            raise ValueError(f"unknown user server '{jid.server}'")

        user_list.append(user_node)

    resp = await send_iq(
        client,
        InfoQuery(
            namespace="usync",
            type=InfoQueryType.GET,
            to=SERVER_JID,
            content=[
                Node(
                    tag="usync",
                    attrs=Attrs(
                        {
                            "sid": generate_request_id(client),
                            "mode": mode,
                            "last": "true",
                            "index": "0",
                            "context": context,
                        }
                    ),
                    content=[
                        Node(tag="query", content=query),
                        Node(tag="list", content=user_list),
                    ],
                )
            ],
        ),
    )

    list_node, found = resp.get_optional_child_by_tag("usync", "list")
    if not found:
        raise ElementMissingError(tag="list", in_location="response to usync query")

    return list_node
