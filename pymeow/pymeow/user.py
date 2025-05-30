"""
User-related functionality for PyMeow.

Port of whatsmeow/user.go
"""
import asyncio
import logging
from typing import List, Dict, Optional, Any, Tuple, Union
import contextlib
import string

from .binary.node import Node, Attrs
from .types.jid import JID
from .types.user import (
    BusinessMessageLinkTarget, ContactQRLinkTarget, UserInfo, ProfilePictureInfo,
    Blocklist, BusinessProfile, VerifiedName, BotListInfo, BotProfileInfo,
    BotProfileCommand, IsOnWhatsAppResponse, BusinessHoursConfig, Category
)
from .types.events import BlocklistChangeAction
from .exceptions import ElementMissingError

# Constants
BUSINESS_MESSAGE_LINK_PREFIX = "https://wa.me/message/"
CONTACT_QR_LINK_PREFIX = "https://wa.me/qr/"
BUSINESS_MESSAGE_LINK_DIRECT_PREFIX = "https://api.whatsapp.com/message/"
CONTACT_QR_LINK_DIRECT_PREFIX = "https://api.whatsapp.com/qr/"
NEWSLETTER_LINK_PREFIX = "https://whatsapp.com/channel/"


class Client:
    """
    This is a partial implementation of the Client class that only includes
    the user-related methods ported from user.go.

    The actual implementation will be merged with the main Client class.
    """

    async def resolve_business_message_link(self, code: str) -> Optional[BusinessMessageLinkTarget]:
        """
        Resolves a business message short link and returns the target JID, business name and
        text to prefill in the input field (if any).

        The links look like https://wa.me/message/<code> or https://api.whatsapp.com/message/<code>.
        You can either provide the full link, or just the <code> part.

        Args:
            code: The code or full link to resolve

        Returns:
            BusinessMessageLinkTarget object containing the resolved information, or None if not found

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        code = code.replace(BUSINESS_MESSAGE_LINK_PREFIX, "")
        code = code.replace(BUSINESS_MESSAGE_LINK_DIRECT_PREFIX, "")

        resp = await self.send_iq_async({
            "namespace": "w:qr",
            "type": "get",
            "content": [Node(
                tag="qr",
                attrs=Attrs({
                    "code": code
                })
            )]
        })

        qr_child = resp.get_optional_child_by_tag("qr")
        if not qr_child:
            raise ElementMissingError(tag="qr", in_="response to business message link query")

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

        return target

    async def resolve_contact_qr_link(self, code: str) -> Optional[ContactQRLinkTarget]:
        """
        Resolves a link from a contact share QR code and returns the target JID and push name.

        The links look like https://wa.me/qr/<code> or https://api.whatsapp.com/qr/<code>.
        You can either provide the full link, or just the <code> part.

        Args:
            code: The code or full link to resolve

        Returns:
            ContactQRLinkTarget object containing the resolved information, or None if not found

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        code = code.replace(CONTACT_QR_LINK_PREFIX, "")
        code = code.replace(CONTACT_QR_LINK_DIRECT_PREFIX, "")

        resp = await self.send_iq_async({
            "namespace": "w:qr",
            "type": "get",
            "content": [Node(
                tag="qr",
                attrs=Attrs({
                    "code": code
                })
            )]
        })

        qr_child = resp.get_optional_child_by_tag("qr")
        if not qr_child:
            raise ElementMissingError(tag="qr", in_="response to contact link query")

        target = ContactQRLinkTarget()
        ag = qr_child.attr_getter()
        target.jid = ag.jid("jid")
        target.push_name = ag.optional_string("notify")
        target.type = ag.string("type")

        return target

    async def get_contact_qr_link(self, revoke: bool = False) -> str:
        """
        Gets your own contact share QR link that can be resolved using resolve_contact_qr_link
        (or scanned with the official apps when encoded as a QR code).

        Args:
            revoke: If True, it will ask the server to revoke the previous link and generate a new one

        Returns:
            The contact QR link code

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        action = "revoke" if revoke else "get"

        resp = await self.send_iq_async({
            "namespace": "w:qr",
            "type": "set",
            "content": [Node(
                tag="qr",
                attrs=Attrs({
                    "type": "contact",
                    "action": action
                })
            )]
        })

        qr_child = resp.get_optional_child_by_tag("qr")
        if not qr_child:
            raise ElementMissingError(tag="qr", in_="response to own contact link fetch")

        ag = qr_child.attr_getter()
        return ag.string("code")

    async def set_status_message(self, msg: str) -> None:
        """
        Updates the current user's status text, which is shown in the "About" section in the user profile.

        This is different from the ephemeral status broadcast messages. Use send_message to types.StatusBroadcastJID to send
        such messages.

        Args:
            msg: The status message to set

        Raises:
            Exception: For errors during the request
        """
        await self.send_iq_async({
            "namespace": "status",
            "type": "set",
            "to": JID(server="s.whatsapp.net"),
            "content": [Node(
                tag="status",
                content=msg
            )]
        })

    async def is_on_whatsapp(self, phones: List[str]) -> List[IsOnWhatsAppResponse]:
        """
        Checks if the given phone numbers are registered on WhatsApp.
        The phone numbers should be in international format, including the `+` prefix.

        Args:
            phones: List of phone numbers to check

        Returns:
            List of IsOnWhatsAppResponse objects with information about each phone number

        Raises:
            Exception: For errors during the request
        """
        jids = [JID(user=phone, server="s.whatsapp.net") for phone in phones]

        list_node = await self.usync(
            jids=jids,
            mode="query",
            context="interactive",
            query=[
                Node(tag="business", content=[Node(tag="verified_name")]),
                Node(tag="contact")
            ]
        )

        output = []
        query_suffix = "@s.whatsapp.net"

        for child in list_node.get_children():
            jid = child.attrs.get("jid")
            if child.tag != "user" or not isinstance(jid, JID):
                continue

            info = IsOnWhatsAppResponse()
            info.jid = jid

            try:
                info.verified_name = self._parse_verified_name(child.get_child_by_tag("business"))
            except Exception as e:
                self.log.warning(f"Failed to parse {jid}'s verified name details: {e}")

            contact_node = child.get_child_by_tag("contact")
            info.is_in = contact_node.attr_getter().string("type") == "in"

            contact_query = contact_node.content
            if isinstance(contact_query, bytes):
                info.query = contact_query.decode('utf-8').replace(query_suffix, "")

            output.append(info)

        return output

    async def get_user_info(self, jids: List[JID]) -> Dict[JID, UserInfo]:
        """
        Gets basic user info (avatar, status, verified business name, device list).

        Args:
            jids: List of JIDs to get info for

        Returns:
            Dictionary mapping JIDs to UserInfo objects

        Raises:
            Exception: For errors during the request
        """
        list_node = await self.usync(
            jids=jids,
            mode="full",
            context="background",
            query=[
                Node(tag="business", content=[Node(tag="verified_name")]),
                Node(tag="status"),
                Node(tag="picture"),
                Node(tag="devices", attrs=Attrs({"version": "2"}))
            ]
        )

        resp_data = {}

        for child in list_node.get_children():
            jid = child.attrs.get("jid")
            if child.tag != "user" or not isinstance(jid, JID):
                continue

            info = UserInfo()

            try:
                verified_name = self._parse_verified_name(child.get_child_by_tag("business"))
                if verified_name:
                    await self._update_business_name(jid, None, verified_name.details.verified_name)
            except Exception as e:
                self.log.warning(f"Failed to parse {jid}'s verified name details: {e}")

            status_bytes = child.get_child_by_tag("status").content
            if isinstance(status_bytes, bytes):
                info.status = status_bytes.decode('utf-8')

            info.picture_id = child.get_child_by_tag("picture").attrs.get("id", "")
            info.devices = self._parse_device_list(jid, child.get_child_by_tag("devices"))

            resp_data[jid] = info

        return resp_data

    async def get_bot_list_v2(self) -> List[BotListInfo]:
        """
        Gets the list of available bots.

        Returns:
            List of BotListInfo objects

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        resp = await self.send_iq_async({
            "to": JID(server="s.whatsapp.net"),
            "namespace": "bot",
            "type": "get",
            "content": [Node(
                tag="bot",
                attrs=Attrs({"v": "2"})
            )]
        })

        bot_node = resp.get_optional_child_by_tag("bot")
        if not bot_node:
            raise ElementMissingError(tag="bot", in_="response to bot list query")

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

    async def get_bot_profiles(self, bot_info: List[BotListInfo]) -> List[BotProfileInfo]:
        """
        Gets detailed profile information for bots.

        Args:
            bot_info: List of BotListInfo objects to get profiles for

        Returns:
            List of BotProfileInfo objects with detailed information

        Raises:
            Exception: For errors during the request
        """
        jids = [bot.bot_jid for bot in bot_info]

        list_node = await self.usync(
            jids=jids,
            mode="query",
            context="interactive",
            query=[
                Node(tag="bot", content=[Node(tag="profile", attrs=Attrs({"v": "1"}))])
            ],
            extras={"bot_list_info": bot_info}
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

            is_default = profile.get_optional_child_by_tag("default") is not None
            persona_id = profile.attr_getter().string("persona_id")

            commands_node = profile.get_child_by_tag("commands")
            command_description = commands_node.get_child_by_tag("description").content
            if isinstance(command_description, bytes):
                command_description = command_description.decode('utf-8')

            commands = []
            for command_node in commands_node.get_children_by_tag("command"):
                cmd_name = command_node.get_child_by_tag("name").content
                if isinstance(cmd_name, bytes):
                    cmd_name = cmd_name.decode('utf-8')

                cmd_desc = command_node.get_child_by_tag("description").content
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
                if isinstance(emoji, bytes):
                    emoji = emoji.decode('utf-8')

                text = prompt_node.get_child_by_tag("text").content
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
                commands_description=command_description
            ))

        return profiles

    def _parse_business_profile(self, node: Node) -> BusinessProfile:
        """
        Parse a business profile node into a BusinessProfile object.

        Args:
            node: The Node containing business profile data

        Returns:
            BusinessProfile object

        Raises:
            Exception: If parsing fails
        """
        profile_node = node.get_child_by_tag("profile")
        jid = profile_node.attr_getter().get_jid("jid")
        if not jid:
            raise ValueError("missing jid in business profile")

        address_bytes = profile_node.get_child_by_tag("address").content
        address = address_bytes.decode('utf-8') if isinstance(address_bytes, bytes) else ""

        email_bytes = profile_node.get_child_by_tag("email").content
        email = email_bytes.decode('utf-8') if isinstance(email_bytes, bytes) else ""

        business_hour = profile_node.get_child_by_tag("business_hours")
        business_hour_timezone = business_hour.attr_getter().string("timezone")
        business_hours_configs = business_hour.get_children()
        business_hours = []

        for config in business_hours_configs:
            if config.tag != "business_hours_config":
                continue

            ag = config.attr_getter()
            business_hours.append(BusinessHoursConfig(
                day_of_week=ag.string("dow"),
                mode=ag.string("mode"),
                open_time=ag.string("open_time"),
                close_time=ag.string("close_time")
            ))

        categories_node = profile_node.get_child_by_tag("categories")
        categories = []

        for category in categories_node.get_children():
            if category.tag != "category":
                continue

            category_id = category.attr_getter().string("id")
            name_bytes = category.content
            name = name_bytes.decode('utf-8') if isinstance(name_bytes, bytes) else ""

            categories.append(Category(
                id=category_id,
                name=name
            ))

        profile_options_node = profile_node.get_child_by_tag("profile_options")
        profile_options = {}

        for option in profile_options_node.get_children():
            option_content = option.content
            if isinstance(option_content, bytes):
                profile_options[option.tag] = option_content.decode('utf-8')

        return BusinessProfile(
            jid=jid,
            email=email,
            address=address,
            categories=categories,
            profile_options=profile_options,
            business_hours_time_zone=business_hour_timezone,
            business_hours=business_hours
        )

    async def get_business_profile(self, jid: JID) -> BusinessProfile:
        """
        Gets the profile info of a WhatsApp business account.

        Args:
            jid: The JID of the business account

        Returns:
            BusinessProfile object with the business information

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        resp = await self.send_iq_async({
            "type": "get",
            "to": JID(server="s.whatsapp.net"),
            "namespace": "w:biz",
            "content": [Node(
                tag="business_profile",
                attrs=Attrs({"v": "244"}),
                content=[Node(
                    tag="profile",
                    attrs=Attrs({"jid": jid})
                )]
            )]
        })

        node = resp.get_optional_child_by_tag("business_profile")
        if not node:
            raise ElementMissingError(tag="business_profile", in_="response to business profile query")

        return self._parse_business_profile(node)

    async def get_user_devices(self, jids: List[JID]) -> List[JID]:
        """
        Gets the list of devices that the given users have. The input should be a list of
        regular JIDs, and the output will be a list of AD JIDs. The local device will not be included in
        the output even if the user's JID is included in the input. All other devices will be included.

        Args:
            jids: List of JIDs to get devices for

        Returns:
            List of device JIDs

        Raises:
            Exception: For errors during the request
        """
        return await self.get_user_devices_context(jids)

    async def get_user_devices_context(self, jids: List[JID]) -> List[JID]:
        """
        Gets the list of devices that the given users have with context support.

        Args:
            jids: List of JIDs to get devices for

        Returns:
            List of device JIDs

        Raises:
            Exception: For errors during the request
        """
        # This would normally use a lock, but we'll simplify for the port
        devices = []
        jids_to_sync = []
        fb_jids_to_sync = []

        for jid in jids:
            cached = self.user_devices_cache.get(jid)
            if cached and len(cached.devices) > 0:
                devices.extend(cached.devices)
            elif jid.server == "fb.com":
                fb_jids_to_sync.append(jid)
            elif jid.is_bot():
                # Bot JIDs do not have devices, the usync query is empty
                devices.append(jid)
            else:
                jids_to_sync.append(jid)

        if jids_to_sync:
            list_node = await self.usync(
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

                user_devices = self._parse_device_list(jid, user.get_child_by_tag("devices"))
                self.user_devices_cache[jid] = {
                    "devices": user_devices,
                    "dhash": self._participant_list_hash_v2(user_devices)
                }
                devices.extend(user_devices)

        if fb_jids_to_sync:
            user_devices = await self._get_fbid_devices(fb_jids_to_sync)
            devices.extend(user_devices)

        return devices

    @dataclass
    class GetProfilePictureParams:
        """Parameters for getting a profile picture."""
        preview: bool = False
        existing_id: str = ""
        is_community: bool = False

    async def get_profile_picture_info(self, jid: JID, params: Optional[GetProfilePictureParams] = None) -> Optional[ProfilePictureInfo]:
        """
        Gets the URL where you can download a WhatsApp user's profile picture or group's photo.

        Optionally, you can pass the last known profile picture ID.
        If the profile picture hasn't changed, this will return None with no error.

        To get a community photo, you should pass `is_community: True`, as otherwise you may get a 401 error.

        Args:
            jid: The JID to get the profile picture for
            params: Optional parameters for the request

        Returns:
            ProfilePictureInfo object with the picture information, or None if unchanged

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        attrs = {"query": "url"}

        if params is None:
            params = self.GetProfilePictureParams()

        if params.preview:
            attrs["type"] = "preview"
        else:
            attrs["type"] = "image"

        if params.existing_id:
            attrs["id"] = params.existing_id

        expect_wrapped = False
        content = []
        namespace = "w:profile:picture"
        target = None
        to = None

        if params.is_community:
            target = JID()  # Empty JID
            namespace = "w:g2"
            to = jid
            attrs["parent_group_jid"] = jid
            expect_wrapped = True
            content = [Node(
                tag="pictures",
                content=[Node(
                    tag="picture",
                    attrs=Attrs(attrs)
                )]
            )]
        else:
            to = JID(server="s.whatsapp.net")
            target = jid
            content = [Node(
                tag="picture",
                attrs=Attrs(attrs)
            )]

        resp = await self.send_iq_async({
            "namespace": namespace,
            "type": "get",
            "to": to,
            "target": target,
            "content": content
        })

        if expect_wrapped:
            pics = resp.get_optional_child_by_tag("pictures")
            if not pics:
                raise ElementMissingError(tag="pictures", in_="response to profile picture query")
            resp = pics

        picture = resp.get_optional_child_by_tag("picture")
        if not picture:
            if params.existing_id:
                return None
            raise ElementMissingError(tag="picture", in_="response to profile picture query")

        info = ProfilePictureInfo()
        ag = picture.attr_getter()

        if ag.optional_int("status") == 304:
            return None

        info.id = ag.string("id")
        info.url = ag.string("url")
        info.type = ag.string("type")
        info.direct_path = ag.string("direct_path")

        return info

    async def _update_push_name(self, user: JID, message_info: Any, name: str) -> None:
        """
        Updates the push name of a user in the store and dispatches an event.

        Args:
            user: The JID of the user
            message_info: Information about the message that triggered the update
            name: The new push name
        """
        if not hasattr(self, "store") or not self.store.contacts:
            return

        user = user.to_non_ad()
        changed, previous_name = await self.store.contacts.put_push_name(user, name)

        if changed:
            self.log.debug(f"Push name of {user} changed from {previous_name} to {name}, dispatching event")
            self.dispatch_event({
                "type": "push_name",
                "jid": user,
                "message": message_info,
                "old_push_name": previous_name,
                "new_push_name": name
            })

    async def _update_business_name(self, user: JID, message_info: Any, name: str) -> None:
        """
        Updates the business name of a user in the store and dispatches an event.

        Args:
            user: The JID of the user
            message_info: Information about the message that triggered the update
            name: The new business name
        """
        if not hasattr(self, "store") or not self.store.contacts:
            return

        changed, previous_name = await self.store.contacts.put_business_name(user, name)

        if changed:
            self.log.debug(f"Business name of {user} changed from {previous_name} to {name}, dispatching event")
            self.dispatch_event({
                "type": "business_name",
                "jid": user,
                "message": message_info,
                "old_business_name": previous_name,
                "new_business_name": name
            })

    def _parse_verified_name(self, business_node: Node) -> Optional[VerifiedName]:
        """
        Parse a verified name from a business node.

        Args:
            business_node: The Node containing business data

        Returns:
            VerifiedName object or None if not found

        Raises:
            Exception: If parsing fails
        """
        if business_node.tag != "business":
            return None

        verified_name_node = business_node.get_optional_child_by_tag("verified_name")
        if not verified_name_node:
            return None

        return self._parse_verified_name_content(verified_name_node)

    def _parse_verified_name_content(self, verified_name_node: Node) -> Optional[VerifiedName]:
        """
        Parse verified name content from a node.

        Args:
            verified_name_node: The Node containing verified name data

        Returns:
            VerifiedName object or None if not found

        Raises:
            Exception: If parsing fails
        """
        from ..generated.waVnameCert import WAWebProtobufsVnameCert_pb2
        import google.protobuf.proto as proto

        raw_cert = verified_name_node.content
        if not isinstance(raw_cert, bytes):
            return None

        cert = WAWebProtobufsVnameCert_pb2.VerifiedNameCertificate()
        cert.ParseFromString(raw_cert)

        cert_details = WAWebProtobufsVnameCert_pb2.VerifiedNameCertificate.Details()
        cert_details.ParseFromString(cert.details)

        return VerifiedName(
            certificate=cert,
            details=cert_details
        )

    def _parse_device_list(self, user: JID, device_node: Node) -> List[JID]:
        """
        Parse a device list from a node.

        Args:
            user: The base JID
            device_node: The Node containing device list data

        Returns:
            List of device JIDs
        """
        device_list = device_node.get_child_by_tag("device-list")
        if device_node.tag != "devices" or device_list.tag != "device-list":
            return []

        children = device_list.get_children()
        devices = []

        for device in children:
            device_id = device.attr_getter().get_int("id")
            if device.tag != "device" or device_id is None:
                continue

            device_jid = user.copy()
            device_jid.device = device_id
            devices.append(device_jid)

        return devices

    def _parse_fb_device_list(self, user: JID, device_list: Node) -> Dict:
        """
        Parse a Facebook device list from a node.

        Args:
            user: The base JID
            device_list: The Node containing device list data

        Returns:
            Dictionary with devices and dhash
        """
        children = device_list.get_children()
        devices = []

        for device in children:
            device_id = device.attr_getter().get_int("id")
            if device.tag != "device" or device_id is None:
                continue

            device_jid = user.copy()
            device_jid.device = device_id
            devices.append(device_jid)

        return {
            "devices": devices,
            "dhash": device_list.attr_getter().string("dhash")
        }

    async def _get_fbid_devices_internal(self, jids: List[JID]) -> Node:
        """
        Internal method to get Facebook device information.

        Args:
            jids: List of JIDs to get devices for

        Returns:
            Node containing the device information

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        users = []
        for jid in jids:
            users.append(Node(
                tag="user",
                attrs=Attrs({"jid": jid})
            ))

        resp = await self.send_iq_async({
            "namespace": "fbid:devices",
            "type": "get",
            "to": JID(server="s.whatsapp.net"),
            "content": [Node(
                tag="users",
                content=users
            )]
        })

        list_node = resp.get_optional_child_by_tag("users")
        if not list_node:
            raise ElementMissingError(tag="users", in_="response to fbid devices query")

        return list_node

    async def _get_fbid_devices(self, jids: List[JID]) -> List[JID]:
        """
        Get Facebook device JIDs.

        Args:
            jids: List of JIDs to get devices for

        Returns:
            List of device JIDs

        Raises:
            Exception: For errors during the request
        """
        devices = []

        # Process in chunks of 15
        for i in range(0, len(jids), 15):
            chunk = jids[i:i+15]
            list_node = await self._get_fbid_devices_internal(chunk)

            for user in list_node.get_children():
                jid = user.attrs.get("jid")
                if user.tag != "user" or not isinstance(jid, JID):
                    continue

                user_devices = self._parse_fb_device_list(jid, user.get_child_by_tag("devices"))
                self.user_devices_cache[jid] = user_devices
                devices.extend(user_devices["devices"])

        return devices

    @dataclass
    class UsyncQueryExtras:
        """Extra parameters for usync queries."""
        bot_list_info: List[BotListInfo] = None

    async def usync(self, jids: List[JID], mode: str, context: str, query: List[Node], extras: Optional[UsyncQueryExtras] = None) -> Node:
        """
        Perform a usync query to get information about users.

        Args:
            jids: List of JIDs to query
            mode: Query mode (e.g., "query", "full")
            context: Query context (e.g., "interactive", "message")
            query: List of query nodes
            extras: Optional extra parameters

        Returns:
            Node containing the response data

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        user_list = []

        for jid in jids:
            user_node = Node(tag="user")
            jid = jid.to_non_ad()

            if jid.server == "s.whatsapp.net":
                user_node.content = [Node(
                    tag="contact",
                    content=str(jid)
                )]
            elif jid.server in ["whatsapp.net", "lid.whatsapp.net"]:
                user_node.attrs = Attrs({"jid": jid})
                if jid.is_bot():
                    persona_id = ""
                    if extras and extras.bot_list_info:
                        for bot in extras.bot_list_info:
                            if bot.bot_jid.user == jid.user:
                                persona_id = bot.persona_id

                    user_node.content = [Node(
                        tag="bot",
                        content=[Node(
                            tag="profile",
                            attrs=Attrs({"persona_id": persona_id})
                        )]
                    )]
            else:
                raise ValueError(f"unknown user server '{jid.server}'")

            user_list.append(user_node)

        resp = await self.send_iq_async({
            "namespace": "usync",
            "type": "get",
            "to": JID(server="s.whatsapp.net"),
            "content": [Node(
                tag="usync",
                attrs=Attrs({
                    "sid": self.generate_request_id(),
                    "mode": mode,
                    "last": "true",
                    "index": "0",
                    "context": context
                }),
                content=[
                    Node(tag="query", content=query),
                    Node(tag="list", content=user_list)
                ]
            )]
        })

        list_node = resp.get_optional_child_by_tag("usync", "list")
        if not list_node:
            raise ElementMissingError(tag="list", in_="response to usync query")

        return list_node

    def _parse_blocklist(self, node: Node) -> Blocklist:
        """
        Parse a blocklist from a node.

        Args:
            node: The Node containing blocklist data

        Returns:
            Blocklist object
        """
        output = Blocklist(d_hash=node.attr_getter().string("dhash"))

        for child in node.get_children():
            ag = child.attr_getter()
            blocked_jid = ag.jid("jid")
            if not ag.ok():
                self.log.debug(f"Ignoring contact blocked data with unexpected attributes: {ag.error()}")
                continue

            output.jids.append(blocked_jid)

        return output

    async def get_blocklist(self) -> Blocklist:
        """
        Gets the list of users that this user has blocked.

        Returns:
            Blocklist object with the list of blocked JIDs

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        resp = await self.send_iq_async({
            "namespace": "blocklist",
            "type": "get",
            "to": JID(server="s.whatsapp.net")
        })

        list_node = resp.get_optional_child_by_tag("list")
        if not list_node:
            raise ElementMissingError(tag="list", in_="response to blocklist query")

        return self._parse_blocklist(list_node)

    async def update_blocklist(self, jid: JID, action: BlocklistChangeAction) -> Blocklist:
        """
        Updates the user's block list and returns the updated list.

        Args:
            jid: The JID to block or unblock
            action: The action to perform (block or unblock)

        Returns:
            Updated Blocklist object

        Raises:
            ElementMissingError: If the response is missing expected elements
            Exception: For other errors during the request
        """
        resp = await self.send_iq_async({
            "namespace": "blocklist",
            "type": "set",
            "to": JID(server="s.whatsapp.net"),
            "content": [Node(
                tag="item",
                attrs=Attrs({
                    "jid": jid,
                    "action": action
                })
            )]
        })

        list_node = resp.get_optional_child_by_tag("list")
        if not list_node:
            raise ElementMissingError(tag="list", in_="response to blocklist update")

        return self._parse_blocklist(list_node)
