"""
WhatsApp user-related functionality.

Port of whatsmeow/user.go - uses composition pattern instead of mixins.
Each function receives the client as the first argument.
"""

import logging
from typing import List, Optional, Dict, Any

from .types.jid import JID
from .types.user import (
    BusinessMessageLinkTarget, ContactQRLinkTarget, IsOnWhatsAppResponse,
    UserInfo, BotListInfo, BotProfileInfo, BotProfileCommand, VerifiedName,
    BusinessProfile, BusinessHoursConfig, Category, ProfilePictureInfo
)
from .binary.node import Node, Attrs
from .exceptions import ElementMissingError

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


async def resolve_business_message_link(client, code: str) -> Optional[BusinessMessageLinkTarget]:
    """
    Resolves a business message short link and returns the target JID, business name and
    text to prefill in the input field (if any).

    The links look like https://wa.me/message/<code> or https://api.whatsapp.com/message/<code>.
    You can either provide the full link, or just the <code> part.
    """
    code = code.replace(BUSINESS_MESSAGE_LINK_PREFIX, "")
    code = code.replace(BUSINESS_MESSAGE_LINK_DIRECT_PREFIX, "")

    try:
        resp = await client.send_iq({
            "namespace": "w:qr",
            "type": "get",
            "content": [Node(
                tag="qr",
                attributes=Attrs({
                    "code": code
                })
            )]
        })
    except Exception as err:
        # Handle specific error cases like ErrIQNotFound -> ErrBusinessMessageLinkNotFound
        raise err

    qr_child = resp.get_optional_child_by_tag("qr")
    if not qr_child:
        raise ElementMissingError(tag="qr", in_location="response to business message link query")

    target = BusinessMessageLinkTarget()
    ag = qr_child.attr_getter()
    target.jid = ag.jid("jid")
    target.push_name = ag.string("notify")

    message_child = qr_child.get_optional_child_by_tag("message")
    if message_child:
        message_bytes = message_child.content
        if isinstance(message_bytes, bytes):
            target.message = message_bytes.decode('utf-8')

    business_child = qr_child.get_optional_child_by_tag("business")
    if business_child:
        bag = business_child.attr_getter()
        target.is_signed = bag.optional_bool("is_signed")
        target.verified_name = bag.optional_string("verified_name")
        target.verified_level = bag.optional_string("verified_level")

    if not ag.ok():
        raise ag.error()

    return target


async def resolve_contact_qr_link(client, code: str) -> Optional[ContactQRLinkTarget]:
    """
    Resolves a link from a contact share QR code and returns the target JID and push name.

    The links look like https://wa.me/qr/<code> or https://api.whatsapp.com/qr/<code>.
    You can either provide the full link, or just the <code> part.
    """
    code = code.replace(CONTACT_QR_LINK_PREFIX, "")
    code = code.replace(CONTACT_QR_LINK_DIRECT_PREFIX, "")

    try:
        resp = await client.send_iq({
            "namespace": "w:qr",
            "type": "get",
            "content": [Node(
                tag="qr",
                attributes=Attrs({
                    "code": code
                })
            )]
        })
    except Exception as err:
        # Handle specific error cases like ErrIQNotFound -> ErrContactQRLinkNotFound
        raise err

    qr_child = resp.get_optional_child_by_tag("qr")
    if not qr_child:
        raise ElementMissingError(tag="qr", in_location="response to contact link query")

    target = ContactQRLinkTarget()
    ag = qr_child.attr_getter()
    target.jid = ag.jid("jid")
    target.push_name = ag.optional_string("notify")
    target.type = ag.string("type")

    if not ag.ok():
        raise ag.error()

    return target


async def get_contact_qr_link(client, revoke: bool = False) -> str:
    """
    Gets your own contact share QR link that can be resolved using resolve_contact_qr_link
    (or scanned with the official apps when encoded as a QR code).

    If the revoke parameter is set to true, it will ask the server to revoke the previous link and generate a new one.
    """
    action = "revoke" if revoke else "get"

    resp = await client.send_iq({
        "namespace": "w:qr",
        "type": "set",
        "content": [Node(
            tag="qr",
            attributes=Attrs({
                "type": "contact",
                "action": action
            })
        )]
    })

    qr_child = resp.get_optional_child_by_tag("qr")
    if not qr_child:
        raise ElementMissingError(tag="qr", in_location="response to own contact link fetch")

    ag = qr_child.attr_getter()
    code = ag.string("code")

    if not ag.ok():
        raise ag.error()

    return code


async def set_status_message(client, msg: str) -> None:
    """
    Updates the current user's status text, which is shown in the "About" section in the user profile.

    This is different from the ephemeral status broadcast messages. Use send_message to types.StatusBroadcastJID to send
    such messages.
    """
    await client.send_iq({
        "namespace": "status",
        "type": "set",
        "to": client.get_server_jid(),  # types.ServerJID equivalent
        "content": [Node(
            tag="status",
            content=msg
        )]
    })


async def is_on_whatsapp(client, phones: List[str]) -> List[IsOnWhatsAppResponse]:
    """
    Checks if the given phone numbers are registered on WhatsApp.
    The phone numbers should be in international format, including the `+` prefix.
    """
    jids = []
    for phone in phones:
        jids.append(JID.new_jid(phone, client.get_legacy_user_server()))  # types.LegacyUserServer

    list_node = await usync(
        client,
        jids=jids,
        mode="query",
        context="interactive",
        query=[
            Node(tag="business", content=[Node(tag="verified_name")]),
            Node(tag="contact")
        ]
    )

    output = []
    query_suffix = "@" + client.get_legacy_user_server()

    for child in list_node.get_children():
        jid = child.attrs.get("jid")
        if child.tag != "user" or not isinstance(jid, JID):
            continue

        info = IsOnWhatsAppResponse()
        info.jid = jid

        try:
            info.verified_name = parse_verified_name(child.get_child_by_tag("business"))
        except Exception as e:
            logger.warning(f"Failed to parse {jid}'s verified name details: {e}")

        contact_node = child.get_child_by_tag("contact")
        info.is_in = contact_node.attr_getter().string("type") == "in"

        contact_query = contact_node.content
        if isinstance(contact_query, bytes):
            info.query = contact_query.decode('utf-8').replace(query_suffix, "")

        output.append(info)

    return output


async def get_user_info(client, jids: List[JID]) -> Dict[JID, UserInfo]:
    """
    Gets basic user info (avatar, status, verified business name, device list).
    """
    list_node = await usync(
        client,
        jids=jids,
        mode="full",
        context="background",
        query=[
            Node(tag="business", content=[Node(tag="verified_name")]),
            Node(tag="status"),
            Node(tag="picture"),
            Node(tag="devices", attributes=Attrs({"version": "2"}))
        ]
    )

    resp_data = {}

    for child in list_node.get_children():
        jid = child.attrs.get("jid")
        if child.tag != "user" or not isinstance(jid, JID):
            continue

        info = UserInfo()

        try:
            verified_name = parse_verified_name(child.get_child_by_tag("business"))
            if verified_name:
                await update_business_name(client, jid, None, verified_name.details.get_verified_name())
        except Exception as e:
            logger.warning(f"Failed to parse {jid}'s verified name details: {e}")

        status_bytes = child.get_child_by_tag("status").content
        if isinstance(status_bytes, bytes):
            info.status = status_bytes.decode('utf-8')

        picture_attrs = child.get_child_by_tag("picture").attrs
        info.picture_id = picture_attrs.get("id", "")

        info.devices = parse_device_list(jid, child.get_child_by_tag("devices"))

        resp_data[jid] = info

    return resp_data


async def get_bot_list_v2(client) -> List[BotListInfo]:
    """
    Gets the list of available bots.
    """
    resp = await client.send_iq({
        "to": client.get_server_jid(),  # types.ServerJID
        "namespace": "bot",
        "type": "get",
        "content": [Node(
            tag="bot",
            attributes=Attrs({"v": "2"})
        )]
    })

    bot_node = resp.get_optional_child_by_tag("bot")
    if not bot_node:
        raise ElementMissingError(tag="bot", in_location="response to bot list query")

    bot_list = []

    for section in bot_node.get_children_by_tag("section"):
        if section.attr_getter().string("type") == "all":
            for bot in section.get_children_by_tag("bot"):
                ag = bot.attr_getter()
                bot_list.append(BotListInfo(
                    persona_id=ag.string("persona_id"),
                    bot_jid=ag.jid("jid")
                ))

    return bot_list


async def get_bot_profiles(client, bot_info: List[BotListInfo]) -> List[BotProfileInfo]:
    """
    Gets detailed profile information for bots.
    """
    jids = [bot.bot_jid for bot in bot_info]

    list_node = await usync(
        client,
        jids=jids,
        mode="query",
        context="interactive",
        query=[
            Node(tag="bot", content=[Node(tag="profile", attributes=Attrs({"v": "1"}))])
        ],
        extras=UsyncQueryExtras(bot_list_info=bot_info)
    )

    profiles = []
    for user in list_node.get_children():
        jid = user.attr_getter().jid("jid")
        bot = user.get_child_by_tag("bot")
        profile = bot.get_child_by_tag("profile")

        name = profile.get_child_by_tag("name").content
        if isinstance(name, bytes):
            name = name.decode('utf-8')

        attributes = profile.get_child_by_tag("attributes").content
        if isinstance(attributes, bytes):
            attributes = attributes.decode('utf-8')

        description = profile.get_child_by_tag("description").content
        if isinstance(description, bytes):
            description = description.decode('utf-8')

        category = profile.get_child_by_tag("category").content
        if isinstance(category, bytes):
            category = category.decode('utf-8')

        _, is_default = profile.get_optional_child_by_tag("default")
        persona_id = profile.attr_getter().string("persona_id")

        commands_node = profile.get_child_by_tag("commands")
        command_description = commands_node.get_child_by_tag("description").content
        if isinstance(command_description, bytes):
            command_description = command_description.decode('utf-8')

        commands = []
        for command_node in commands_node.get_children_by_tag("command"):
            cmd_name = command_node.get_child_by_tag("name").content
            cmd_desc = command_node.get_child_by_tag("description").content
            if isinstance(cmd_name, bytes):
                cmd_name = cmd_name.decode('utf-8')
            if isinstance(cmd_desc, bytes):
                cmd_desc = cmd_desc.decode('utf-8')

            commands.append(BotProfileCommand(
                name=cmd_name,
                description=cmd_desc
            ))

        prompts_node = profile.get_child_by_tag("prompts")
        prompts = []
        for prompt_node in prompts_node.get_children_by_tag("prompt"):
            emoji = prompt_node.get_child_by_tag("emoji").content
            text = prompt_node.get_child_by_tag("text").content
            if isinstance(emoji, bytes):
                emoji = emoji.decode('utf-8')
            if isinstance(text, bytes):
                text = text.decode('utf-8')

            prompts.append(f"{emoji} {text}")

        profiles.append(BotProfileInfo(
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
        ))

    return profiles


def parse_business_profile(client, node: Node) -> BusinessProfile:
    """
    Parse business profile from a node.
    """
    profile_node = node.get_child_by_tag("profile")
    ag = profile_node.attr_getter()
    jid, err = ag.get_jid("jid", required=True)
    if not jid or not err:
        raise Exception("missing jid in business profile")

    address_content = profile_node.get_child_by_tag("address").content
    address = address_content.decode('utf-8') if isinstance(address_content, bytes) else str(address_content)

    email_content = profile_node.get_child_by_tag("email").content
    email = email_content.decode('utf-8') if isinstance(email_content, bytes) else str(email_content)

    business_hour = profile_node.get_child_by_tag("business_hours")
    business_hour_timezone = business_hour.attr_getter().string("timezone")
    business_hours_configs = business_hour.get_children()
    business_hours = []

    for config in business_hours_configs:
        if config.tag != "business_hours_config":
            continue
        cag = config.attr_getter()
        business_hours.append(BusinessHoursConfig(
            day_of_week=cag.string("dow"),
            mode=cag.string("mode"),
            open_time=cag.string("open_time"),
            close_time=cag.string("close_time")
        ))

    categories_node = profile_node.get_child_by_tag("categories")
    categories = []
    for category in categories_node.get_children():
        if category.tag != "category":
            continue
        cat_id = category.attr_getter().string("id")
        cat_content = category.content
        cat_name = cat_content.decode('utf-8') if isinstance(cat_content, bytes) else str(cat_content)
        categories.append(Category(id=cat_id, name=cat_name))

    profile_options_node = profile_node.get_child_by_tag("profile_options")
    profile_options = {}
    for option in profile_options_node.get_children():
        opt_content = option.content
        opt_value = opt_content.decode('utf-8') if isinstance(opt_content, bytes) else str(opt_content)
        profile_options[option.tag] = opt_value

    return BusinessProfile(
        jid=jid,
        email=email,
        address=address,
        categories=categories,
        profile_options=profile_options,
        business_hours_time_zone=business_hour_timezone,
        business_hours=business_hours
    )


async def get_business_profile(client, jid: JID) -> BusinessProfile:
    """
    Gets the profile info of a WhatsApp business account.
    """
    resp = await client.send_iq({
        "type": "get",
        "to": client.get_server_jid(),  # types.ServerJID
        "namespace": "w:biz",
        "content": [Node(
            tag="business_profile",
            attributes=Attrs({"v": "244"}),
            content=[Node(
                tag="profile",
                attributes=Attrs({"jid": jid})
            )]
        )]
    })

    node = resp.get_optional_child_by_tag("business_profile")
    if not node:
        raise ElementMissingError(tag="business_profile", in_location="response to business profile query")

    return parse_business_profile(client, node)


async def get_user_devices(client, jids: List[JID]) -> List[JID]:
    """
    Gets the list of devices that the given user has.

    Deprecated: use get_user_devices_context instead.
    """
    return await get_user_devices_context(client, jids)


async def get_user_devices_context(client, jids: List[JID]) -> List[JID]:
    """
    Gets the list of devices that the given user has. The input should be a list of
    regular JIDs, and the output will be a list of AD JIDs. The local device will not be included in
    the output even if the user's JID is included in the input. All other devices will be included.
    """
    if client is None:
        from .exceptions import ErrClientIsNil
        raise ErrClientIsNil()

    # Use client's device cache with locking
    async with client.get_user_devices_cache_lock():
        devices = []
        jids_to_sync = []
        fb_jids_to_sync = []

        for jid in jids:
            cached = client.get_user_devices_cache().get(jid)
            if cached and len(cached.get('devices', [])) > 0:
                devices.extend(cached['devices'])
            elif jid.server == client.get_messenger_server():  # types.MessengerServer
                fb_jids_to_sync.append(jid)
            elif jid.is_bot():
                # Bot JIDs do not have devices, the usync query is empty
                devices.append(jid)
            else:
                jids_to_sync.append(jid)

        if jids_to_sync:
            list_node = await usync(
                client,
                jids=jids_to_sync,
                mode="query",
                context="message",
                query=[
                    Node(tag="devices", attrs=Attrs({"version": "2"}))
                ]
            )

            for user in list_node.get_children():
                jid = user.attrs.get("jid")
                if user.tag != "user" or not isinstance(jid, JID):
                    continue

                user_devices = parse_device_list(jid, user.get_child_by_tag("devices"))
                # Update cache
                client.set_user_devices_cache(jid, {
                    'devices': user_devices,
                    'dhash': client.participant_list_hash_v2(user_devices)
                })
                devices.extend(user_devices)

        if fb_jids_to_sync:
            user_devices = await get_fbid_devices(client, fb_jids_to_sync)
            devices.extend(user_devices)

    return devices


async def get_profile_picture_info(client, jid: JID, params: Optional[GetProfilePictureParams] = None) -> Optional[ProfilePictureInfo]:
    """
    Gets the URL where you can download a WhatsApp user's profile picture or group's photo.

    Optionally, you can pass the last known profile picture ID.
    If the profile picture hasn't changed, this will return None with no error.

    To get a community photo, you should pass `IsCommunity: True`, as otherwise you may get a 401 error.
    """
    if params is None:
        params = GetProfilePictureParams()

    attrs = Attrs({"query": "url"})

    if params.preview:
        attrs["type"] = "preview"
    else:
        attrs["type"] = "image"

    if params.existing_id:
        attrs["id"] = params.existing_id

    target = None
    to = client.get_server_jid()  # types.ServerJID
    namespace = "w:profile:picture"
    expect_wrapped = False
    content = [Node(tag="picture", attributes=attrs)]

    if params.is_community:
        target = client.get_empty_jid()  # types.EmptyJID
        namespace = "w:g2"
        to = jid
        attrs["parent_group_jid"] = jid
        expect_wrapped = True
        content = [Node(
            tag="pictures",
            content=[Node(tag="picture", attributes=attrs)]
        )]
    else:
        target = jid

    try:
        resp = await client.send_iq({
            "namespace": namespace,
            "type": "get",
            "to": to,
            "target": target,
            "content": content
        })
    except Exception as err:
        # Handle specific errors like ErrIQNotAuthorized -> ErrProfilePictureUnauthorized
        # and ErrIQNotFound -> ErrProfilePictureNotSet
        raise err

    if expect_wrapped:
        pics = resp.get_optional_child_by_tag("pictures")
        if not pics:
            raise ElementMissingError(tag="pictures", in_location="response to profile picture query")
        resp = pics

    picture = resp.get_optional_child_by_tag("picture")
    if not picture:
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

    if not ag.ok():
        return info, ag.error()  # Return partial info with error

    return info


async def handle_historical_push_names(client, names: List[Any]) -> None:
    """
    Handle historical push names from history sync.
    """
    if not client.has_contact_store():
        return

    logger.info(f"Updating contact store with {len(names)} push names from history sync")

    for user in names:
        if user.get_pushname() == "-":
            continue

        try:
            jid = JID.parse_jid(user.get_id())
            changed, _, err = await client.put_push_name(jid, user.get_pushname())
            if err:
                logger.warning(f"Failed to store push name of {jid} from history sync: {err}")
            elif changed:
                logger.debug(f"Got push name {user.get_pushname()} for {jid} in history sync")
        except Exception as e:
            logger.warning(f"Failed to parse user ID '{user.get_id()}' in push name history sync: {e}")


async def update_push_name(client, user: JID, message_info: Optional[Any], name: str) -> None:
    """
    Update push name for a user.
    """
    if not client.has_contact_store():
        return

    user = user.to_non_ad()
    try:
        changed, previous_name, err = await client.put_push_name(user, name)
        if err:
            logger.error(f"Failed to save push name of {user} in device store: {err}")
        elif changed:
            logger.debug(f"Push name of {user} changed from {previous_name} to {name}, dispatching event")
            await client.dispatch_event({
                'type': 'push_name',
                'jid': user,
                'message': message_info,
                'old_push_name': previous_name,
                'new_push_name': name
            })
    except Exception as e:
        logger.error(f"Failed to update push name for {user}: {e}")


async def update_business_name(client, user: JID, message_info: Optional[Any], name: str) -> None:
    """
    Update business name for a user.
    """
    if not client.has_contact_store():
        return

    try:
        changed, previous_name, err = await client.put_business_name(user, name)
        if err:
            logger.error(f"Failed to save business name of {user} in device store: {err}")
        elif changed:
            logger.debug(f"Business name of {user} changed from {previous_name} to {name}, dispatching event")
            await client.dispatch_event({
                'type': 'business_name',
                'jid': user,
                'message': message_info,
                'old_business_name': previous_name,
                'new_business_name': name
            })
    except Exception as e:
        logger.error(f"Failed to update business name for {user}: {e}")


def parse_verified_name(business_node: Node) -> Optional[VerifiedName]:
    """
    Parse verified name from business node.
    """
    if business_node.tag != "business":
        return None

    verified_name_node = business_node.get_optional_child_by_tag("verified_name")
    if not verified_name_node:
        return None

    return parse_verified_name_content(verified_name_node)


def parse_verified_name_content(verified_name_node: Node) -> Optional[VerifiedName]:
    """
    Parse verified name content from node.
    """
    raw_cert = verified_name_node.content
    if not isinstance(raw_cert, bytes):
        return None

    # This would require protobuf parsing similar to the Go version
    # For now, return a placeholder implementation
    # TODO: Implement proper protobuf parsing when waVnameCert equivalent is available
    return None


def parse_device_list(user: JID, device_node: Node) -> List[JID]:
    """
    Parse device list from node.
    """
    device_list = device_node.get_child_by_tag("device-list")
    if device_node.tag != "devices" or device_list.tag != "device-list":
        return []

    children = device_list.get_children()
    devices = []

    for device in children:
        ag = device.attr_getter()
        device_id = ag.get_int64("id", required=True)
        if device.tag != "device" or device_id is None:
            continue

        # Create new JID with device ID
        user_copy = JID(user=user.user, server=user.server, device=int(device_id))
        devices.append(user_copy)

    return devices


def parse_fb_device_list(user: JID, device_list: Node) -> Dict[str, Any]:
    """
    Parse Facebook device list from node.
    """
    children = device_list.get_children()
    devices = []

    for device in children:
        ag = device.attr_getter()
        device_id = ag.get_int64("id", required=True)
        if device.tag != "device" or device_id is None:
            continue

        user_copy = JID(user=user.user, server=user.server, device=int(device_id))
        devices.append(user_copy)
        # TODO: take identities here too?

    # TODO: do something with the icdc blob?
    return {
        "devices": devices,
        "dhash": device_list.attr_getter().string("dhash")
    }


async def get_fbid_devices_internal(client, jids: List[JID]) -> Node:
    """
    Internal function to get Facebook ID devices.
    """
    users = []
    for jid in jids:
        users.append(Node(tag="user", attributes=Attrs({"jid": jid})))
        # TODO: include dhash for users

    resp = await client.send_iq({
        "namespace": "fbid:devices",
        "type": "get",
        "to": client.get_server_jid(),  # types.ServerJID
        "content": [Node(tag="users", content=users)]
    })

    list_node = resp.get_optional_child_by_tag("users")
    if not list_node:
        raise ElementMissingError(tag="users", in_location="response to fbid devices query")

    return list_node


async def get_fbid_devices(client, jids: List[JID]) -> List[JID]:
    """
    Get Facebook ID devices.
    """
    devices = []

    # Process in chunks of 15 (matching the Go implementation using slices.Chunk)
    for i in range(0, len(jids), 15):
        chunk = jids[i:i+15]
        list_node = await get_fbid_devices_internal(client, chunk)

        for user in list_node.get_children():
            jid = user.attrs.get("jid")
            if user.tag != "user" or not isinstance(jid, JID):
                continue

            user_devices_cache = parse_fb_device_list(jid, user.get_child_by_tag("devices"))
            client.set_user_devices_cache(jid, user_devices_cache)
            devices.extend(user_devices_cache["devices"])

    return devices


async def usync(client, jids: List[JID], mode: str, context: str, query: List[Node], extras: Optional[UsyncQueryExtras] = None) -> Node:
    """
    Perform a usync operation.
    """
    if client is None:
        from .exceptions import ErrClientIsNil
        raise ErrClientIsNil()

    if extras is None:
        extras = UsyncQueryExtras()

    for jid in jids:
        user_node = Node(tag="user")
        jid = jid.to_non_ad()

        if jid.server == client.get_legacy_user_server():  # types.LegacyUserServer
            user_node.content = [Node(
                tag="contact",
                content=str(jid)
            )]
        elif jid.server in [client.get_default_user_server(), client.get_hidden_user_server()]:  # types.DefaultUserServer, types.HiddenUserServer
            user_node.attributes = Attrs({"jid": jid})
            if jid.is_bot():
                persona_id = ""
                for bot in extras.bot_list_info:
                    if bot.bot_jid.user == jid.user:
                        persona_id = bot.persona_id
                        break

                user_node.content = [Node(
                    tag="bot",
                    content=[Node(
                        tag="profile",
                        attrs=Attrs({"persona_id": persona_id})
                    )]
                )]
