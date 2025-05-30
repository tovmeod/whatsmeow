"""
WhatsApp group management functionality.

Port of whatsmeow/group.go
"""
import asyncio
import contextlib
from dataclasses import dataclass
from datetime import datetime
from typing import List, Optional, Dict, Any, Tuple, Union

from .binary.node import Node, Attrs
from .types.jid import JID, GROUP_SERVER
from .types.group import (
    GroupInfo, GroupParticipant, GroupName, GroupTopic, GroupLocked,
    GroupAnnounce, GroupEphemeral, GroupParent, GroupLinkedParent,
    GroupIsDefaultSub, GroupMembershipApprovalMode, GroupMemberAddMode,
    GroupLinkTarget, GroupParticipantRequest, GroupLinkChangeType,
    GroupUnlinkReason, AddressingMode
)
from .types.events import events
from .exceptions import ElementMissingError, ErrIQNotAcceptable, ErrIQNotFound, ErrIQForbidden, ErrIQGone, ErrInvalidImageFormat, ErrGroupNotFound, ErrNotInGroup, ErrGroupInviteLinkUnauthorized, ErrInviteLinkRevoked, ErrInviteLinkInvalid

# Constants
INVITE_LINK_PREFIX = "https://chat.whatsapp.com/"

@dataclass
class ReqCreateGroup:
    """Request data for creating a group."""
    # Group names are limited to 25 characters. A longer group name will cause a 406 not acceptable error.
    name: str
    # You don't need to include your own JID in the participants array, the WhatsApp servers will add it implicitly.
    participants: List[JID]
    # A create key can be provided to deduplicate the group create notification that will be triggered
    # when the group is created. If provided, the JoinedGroup event will contain the same key.
    create_key: str = ""
    # Set is_parent to true to create a community instead of a normal group.
    # When creating a community, the linked announcement group will be created automatically by the server.
    is_parent: bool = False
    default_membership_approval_mode: str = ""
    # Set linked_parent_jid to create a group inside a community.
    linked_parent_jid: JID = None

class Client:
    """
    WhatsApp group management functionality.

    This class is not meant to be instantiated directly. It's a mixin that's used by the main Client class.
    """

    async def send_group_iq(self, ctx: asyncio.AbstractEventLoop, iq_type: str, jid: JID, content: Node) -> Tuple[Optional[Node], Optional[Exception]]:
        """
        Send an IQ (info query) to the WhatsApp group server.

        Args:
            ctx: The async context
            iq_type: The type of IQ (get, set)
            jid: The JID to send the IQ to
            content: The content of the IQ

        Returns:
            A tuple containing the response node and any error
        """
        return await self.send_iq({
            "context": ctx,
            "namespace": "w:g2",
            "type": iq_type,
            "to": jid,
            "content": [content]
        })

    async def create_group(self, req: ReqCreateGroup) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Creates a group on WhatsApp with the given name and participants.

        Args:
            req: The request data for creating the group

        Returns:
            A tuple containing the group info and any error

        Raises:
            Exception: If there's an error creating the group
        """
        participant_nodes = []
        for participant in req.participants:
            participant_nodes.append(Node(
                tag="participant",
                attributes={"jid": participant}
            ))

        if not req.create_key:
            req.create_key = self.generate_message_id()

        if req.is_parent:
            if not req.default_membership_approval_mode:
                req.default_membership_approval_mode = "request_required"
            participant_nodes.append(Node(
                tag="parent",
                attributes={"default_membership_approval_mode": req.default_membership_approval_mode}
            ))
        elif req.linked_parent_jid and not req.linked_parent_jid.is_empty():
            participant_nodes.append(Node(
                tag="linked_parent",
                attributes={"jid": req.linked_parent_jid}
            ))

        # WhatsApp web doesn't seem to include the static prefix for these
        key = req.create_key.replace("3EB0", "", 1)

        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            types.GROUP_SERVER_JID,
            Node(
                tag="create",
                attributes={"subject": req.name, "key": key},
                content=participant_nodes
            )
        )

        if err:
            return None, err

        group_node, ok = resp.get_optional_child_by_tag("group")
        if not ok:
            return None, ElementMissingError(tag="group", in_="response to create group query")

        return await self.parse_group_node(group_node)

    async def unlink_group(self, parent: JID, child: JID) -> Optional[Exception]:
        """
        Removes a child group from a parent community.

        Args:
            parent: The parent community JID
            child: The child group JID

        Returns:
            An exception if there was an error, None otherwise
        """
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            parent,
            Node(
                tag="unlink",
                attributes={"unlink_type": str(GroupLinkChangeType.SUB)},
                content=[Node(
                    tag="group",
                    attributes={"jid": child}
                )]
            )
        )
        return err

    async def link_group(self, parent: JID, child: JID) -> Optional[Exception]:
        """
        Adds an existing group as a child group in a community.

        To create a new group within a community, set linked_parent_jid in the CreateGroup request.

        Args:
            parent: The parent community JID
            child: The child group JID

        Returns:
            An exception if there was an error, None otherwise
        """
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            parent,
            Node(
                tag="links",
                content=[Node(
                    tag="link",
                    attributes={"link_type": str(GroupLinkChangeType.SUB)},
                    content=[Node(
                        tag="group",
                        attributes={"jid": child}
                    )]
                )]
            )
        )
        return err

    async def leave_group(self, jid: JID) -> Optional[Exception]:
        """
        Leaves the specified group on WhatsApp.

        Args:
            jid: The group JID

        Returns:
            An exception if there was an error, None otherwise
        """
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            types.GROUP_SERVER_JID,
            Node(
                tag="leave",
                content=[Node(
                    tag="group",
                    attributes={"id": jid}
                )]
            )
        )
        return err

    async def update_group_participants(self, jid: JID, participant_changes: List[JID], action: str) -> Tuple[List[GroupParticipant], Optional[Exception]]:
        """
        Can be used to add, remove, promote and demote members in a WhatsApp group.

        Args:
            jid: The group JID
            participant_changes: The list of participants to change
            action: The action to perform (add, remove, promote, demote)

        Returns:
            A tuple containing the list of participants and any error
        """
        content = []
        for participant_jid in participant_changes:
            content.append(Node(
                tag="participant",
                attributes={"jid": participant_jid}
            ))

        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(
                tag=action,
                content=content
            )
        )

        if err:
            return [], err

        request_action, ok = resp.get_optional_child_by_tag(action)
        if not ok:
            return [], ElementMissingError(tag=action, in_="response to group participants update")

        request_participants = request_action.get_children_by_tag("participant")
        participants = []

        for child in request_participants:
            participants.append(self.parse_participant(child.attr_getter(), child))

        return participants, None

    async def get_group_request_participants(self, jid: JID) -> Tuple[List[GroupParticipantRequest], Optional[Exception]]:
        """
        Gets the list of participants that have requested to join the group.

        Args:
            jid: The group JID

        Returns:
            A tuple containing the list of participant requests and any error
        """
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            jid,
            Node(tag="membership_approval_requests")
        )

        if err:
            return [], err

        request, ok = resp.get_optional_child_by_tag("membership_approval_requests")
        if not ok:
            return [], ElementMissingError(tag="membership_approval_requests", in_="response to group request participants query")

        request_participants = request.get_children_by_tag("membership_approval_request")
        participants = []

        for req in request_participants:
            ag = req.attr_getter()
            participants.append(GroupParticipantRequest(
                jid=ag.jid("jid"),
                requested_at=ag.unix_time("request_time")
            ))

        return participants, None

    async def update_group_request_participants(self, jid: JID, participant_changes: List[JID], action: str) -> Tuple[List[GroupParticipant], Optional[Exception]]:
        """
        Can be used to approve or reject requests to join the group.

        Args:
            jid: The group JID
            participant_changes: The list of participants to change
            action: The action to perform (approve, reject)

        Returns:
            A tuple containing the list of participants and any error
        """
        content = []
        for participant_jid in participant_changes:
            content.append(Node(
                tag="participant",
                attributes={"jid": participant_jid}
            ))

        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(
                tag="membership_requests_action",
                content=[Node(
                    tag=action,
                    content=content
                )]
            )
        )

        if err:
            return [], err

        request, ok = resp.get_optional_child_by_tag("membership_requests_action")
        if not ok:
            return [], ElementMissingError(tag="membership_requests_action", in_="response to group request participants update")

        request_action, ok = request.get_optional_child_by_tag(action)
        if not ok:
            return [], ElementMissingError(tag=action, in_="response to group request participants update")

        request_participants = request_action.get_children_by_tag("participant")
        participants = []

        for child in request_participants:
            participants.append(self.parse_participant(child.attr_getter(), child))

        return participants, None

    async def set_group_photo(self, jid: JID, avatar: Optional[bytes]) -> Tuple[str, Optional[Exception]]:
        """
        Updates the group picture/icon of the given group on WhatsApp.

        The avatar should be a JPEG photo, other formats may be rejected with ErrInvalidImageFormat.
        The bytes can be None to remove the photo. Returns the new picture ID.

        Args:
            jid: The group JID
            avatar: The avatar bytes or None to remove

        Returns:
            A tuple containing the picture ID and any error
        """
        content = None
        if avatar:
            content = [Node(
                tag="picture",
                attributes={"type": "image"},
                content=avatar
            )]

        resp, err = await self.send_iq({
            "namespace": "w:profile:picture",
            "type": "set",
            "to": types.SERVER_JID,
            "target": jid,
            "content": content,
            "context": asyncio.get_event_loop()
        })

        if isinstance(err, ErrIQNotAcceptable):
            return "", ErrInvalidImageFormat(f"Invalid image format: {err}")
        elif err:
            return "", err

        if not avatar:
            return "remove", None

        picture_id = resp.get_child_by_tag("picture").attributes.get("id")
        if not picture_id:
            return "", Exception("didn't find picture ID in response")

        return picture_id, None

    async def set_group_name(self, jid: JID, name: str) -> Optional[Exception]:
        """
        Updates the name (subject) of the given group on WhatsApp.

        Args:
            jid: The group JID
            name: The new group name

        Returns:
            An exception if there was an error, None otherwise
        """
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(
                tag="subject",
                content=name.encode('utf-8')
            )
        )
        return err

    async def set_group_topic(self, jid: JID, previous_id: str, new_id: str, topic: str) -> Optional[Exception]:
        """
        Updates the topic (description) of the given group on WhatsApp.

        The previous_id and new_id fields are optional. If the previous ID is not specified, this will
        automatically fetch the current group info to find the previous topic ID. If the new ID is not
        specified, one will be generated with Client.generate_message_id().

        Args:
            jid: The group JID
            previous_id: The previous topic ID
            new_id: The new topic ID
            topic: The new topic

        Returns:
            An exception if there was an error, None otherwise
        """
        if not previous_id:
            old_info, err = await self.get_group_info(jid)
            if err:
                return Exception(f"failed to get old group info to update topic: {err}")
            previous_id = old_info.topic_id

        if not new_id:
            new_id = self.generate_message_id()

        attrs = {"id": new_id}
        if previous_id:
            attrs["prev"] = previous_id

        content = None
        if topic:
            content = [Node(
                tag="body",
                content=topic.encode('utf-8')
            )]
        else:
            attrs["delete"] = "true"

        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(
                tag="description",
                attributes=attrs,
                content=content
            )
        )
        return err

    async def set_group_locked(self, jid: JID, locked: bool) -> Optional[Exception]:
        """
        Changes whether the group is locked (i.e. whether only admins can modify group info).

        Args:
            jid: The group JID
            locked: Whether the group should be locked

        Returns:
            An exception if there was an error, None otherwise
        """
        tag = "locked" if locked else "unlocked"
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(tag=tag)
        )
        return err

    async def set_group_announce(self, jid: JID, announce: bool) -> Optional[Exception]:
        """
        Changes whether the group is in announce mode (i.e. whether only admins can send messages).

        Args:
            jid: The group JID
            announce: Whether the group should be in announce mode

        Returns:
            An exception if there was an error, None otherwise
        """
        tag = "announcement" if announce else "not_announcement"
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(tag=tag)
        )
        return err

    async def get_group_invite_link(self, jid: JID, reset: bool) -> Tuple[str, Optional[Exception]]:
        """
        Requests the invite link to the group from the WhatsApp servers.

        If reset is true, then the old invite link will be revoked and a new one generated.

        Args:
            jid: The group JID
            reset: Whether to reset the invite link

        Returns:
            A tuple containing the invite link and any error
        """
        iq_type = "set" if reset else "get"
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            iq_type,
            jid,
            Node(tag="invite")
        )

        if isinstance(err, ErrIQNotAuthorized):
            return "", ErrGroupInviteLinkUnauthorized(f"Not authorized to get invite link: {err}")
        elif isinstance(err, ErrIQNotFound):
            return "", ErrGroupNotFound(f"Group not found: {err}")
        elif isinstance(err, ErrIQForbidden):
            return "", ErrNotInGroup(f"Not in group: {err}")
        elif err:
            return "", err

        code = resp.get_child_by_tag("invite").attributes.get("code")
        if not code:
            return "", Exception("didn't find invite code in response")

        return INVITE_LINK_PREFIX + code, None

    async def get_group_info_from_invite(self, jid: JID, inviter: JID, code: str, expiration: int) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Gets the group info from an invite message.

        Note that this is specifically for invite messages, not invite links. Use get_group_info_from_link for resolving chat.whatsapp.com links.

        Args:
            jid: The group JID
            inviter: The JID of the user who sent the invite
            code: The invite code
            expiration: The expiration timestamp

        Returns:
            A tuple containing the group info and any error
        """
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            jid,
            Node(
                tag="query",
                content=[Node(
                    tag="add_request",
                    attributes={
                        "code": code,
                        "expiration": expiration,
                        "admin": inviter
                    }
                )]
            )
        )

        if err:
            return None, err

        group_node, ok = resp.get_optional_child_by_tag("group")
        if not ok:
            return None, ElementMissingError(tag="group", in_="response to invite group info query")

        return await self.parse_group_node(group_node)

    async def join_group_with_invite(self, jid: JID, inviter: JID, code: str, expiration: int) -> Optional[Exception]:
        """
        Joins a group using an invite message.

        Note that this is specifically for invite messages, not invite links. Use join_group_with_link for joining with chat.whatsapp.com links.

        Args:
            jid: The group JID
            inviter: The JID of the user who sent the invite
            code: The invite code
            expiration: The expiration timestamp

        Returns:
            An exception if there was an error, None otherwise
        """
        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            Node(
                tag="accept",
                attributes={
                    "code": code,
                    "expiration": expiration,
                    "admin": inviter
                }
            )
        )
        return err

    async def get_group_info_from_link(self, code: str) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Resolves the given invite link and asks the WhatsApp servers for info about the group.

        This will not cause the user to join the group.

        Args:
            code: The invite code or full invite link

        Returns:
            A tuple containing the group info and any error
        """
        code = code.replace(INVITE_LINK_PREFIX, "", 1)
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            types.GROUP_SERVER_JID,
            Node(
                tag="invite",
                attributes={"code": code}
            )
        )

        if isinstance(err, ErrIQGone):
            return None, ErrInviteLinkRevoked(f"Invite link revoked: {err}")
        elif isinstance(err, ErrIQNotAcceptable):
            return None, ErrInviteLinkInvalid(f"Invalid invite link: {err}")
        elif err:
            return None, err

        group_node, ok = resp.get_optional_child_by_tag("group")
        if not ok:
            return None, ElementMissingError(tag="group", in_="response to group link info query")

        return await self.parse_group_node(group_node)

    async def join_group_with_link(self, code: str) -> Tuple[JID, Optional[Exception]]:
        """
        Joins the group using the given invite link.

        Args:
            code: The invite code or full invite link

        Returns:
            A tuple containing the group JID and any error
        """
        code = code.replace(INVITE_LINK_PREFIX, "", 1)
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            types.GROUP_SERVER_JID,
            Node(
                tag="invite",
                attributes={"code": code}
            )
        )

        if isinstance(err, ErrIQGone):
            return JID(user="", server=""), ErrInviteLinkRevoked(f"Invite link revoked: {err}")
        elif isinstance(err, ErrIQNotAcceptable):
            return JID(user="", server=""), ErrInviteLinkInvalid(f"Invalid invite link: {err}")
        elif err:
            return JID(user="", server=""), err

        membership_approval_mode_node, ok = resp.get_optional_child_by_tag("membership_approval_request")
        if ok:
            return membership_approval_mode_node.attr_getter().jid("jid"), None

        group_node, ok = resp.get_optional_child_by_tag("group")
        if not ok:
            return JID(user="", server=""), ElementMissingError(tag="group", in_="response to group link join query")

        return group_node.attr_getter().jid("jid"), None

    async def get_joined_groups(self) -> Tuple[List[GroupInfo], Optional[Exception]]:
        """
        Returns the list of groups the user is participating in.

        Returns:
            A tuple containing the list of group info and any error
        """
        resp, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            types.GROUP_SERVER_JID,
            Node(
                tag="participating",
                content=[
                    Node(tag="participants"),
                    Node(tag="description")
                ]
            )
        )

        if err:
            return [], err

        groups, ok = resp.get_optional_child_by_tag("groups")
        if not ok:
            return [], ElementMissingError(tag="groups", in_="response to group list query")

        children = groups.get_children()
        infos = []

        for child in children:
            if child.tag != "group":
                self.log.debug(f"Unexpected child in group list response: {child.xml_string()}")
                continue

            parsed, parse_err = await self.parse_group_node(child)
            if parse_err:
                self.log.warning(f"Error parsing group {parsed.jid}: {parse_err}")

            infos.append(parsed)

        return infos, None

    async def get_sub_groups(self, community: JID) -> Tuple[List[GroupLinkTarget], Optional[Exception]]:
        """
        Gets the subgroups of the given community.

        Args:
            community: The community JID

        Returns:
            A tuple containing the list of subgroups and any error
        """
        res, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            community,
            Node(tag="sub_groups")
        )

        if err:
            return [], err

        groups, ok = res.get_optional_child_by_tag("sub_groups")
        if not ok:
            return [], ElementMissingError(tag="sub_groups", in_="response to subgroups query")

        parsed_groups = []

        for child in groups.get_children():
            if child.tag == "group":
                parsed_group, err = self.parse_group_link_target_node(child)
                if err:
                    return parsed_groups, Exception(f"failed to parse group in subgroups list: {err}")

                parsed_groups.append(parsed_group)

        return parsed_groups, None

    async def get_linked_groups_participants(self, community: JID) -> Tuple[List[JID], Optional[Exception]]:
        """
        Gets all the participants in the groups of the given community.

        Args:
            community: The community JID

        Returns:
            A tuple containing the list of participant JIDs and any error
        """
        res, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "get",
            community,
            Node(tag="linked_groups_participants")
        )

        if err:
            return [], err

        participants, ok = res.get_optional_child_by_tag("linked_groups_participants")
        if not ok:
            return [], ElementMissingError(tag="linked_groups_participants", in_="response to community participants query")

        return self.parse_participant_list(participants), None

    async def get_group_info(self, jid: JID) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Requests basic info about a group chat from the WhatsApp servers.

        Args:
            jid: The group JID

        Returns:
            A tuple containing the group info and any error
        """
        return await self.get_group_info_internal(asyncio.get_event_loop(), jid, True)

    async def get_group_info_internal(self, ctx: asyncio.AbstractEventLoop, jid: JID, lock_participant_cache: bool) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Internal method to get group info.

        Args:
            ctx: The async context
            jid: The group JID
            lock_participant_cache: Whether to lock the participant cache

        Returns:
            A tuple containing the group info and any error
        """
        res, err = await self.send_group_iq(
            ctx,
            "get",
            jid,
            Node(
                tag="query",
                attributes={"request": "interactive"}
            )
        )

        if isinstance(err, ErrIQNotFound):
            return None, ErrGroupNotFound(f"Group not found: {err}")
        elif isinstance(err, ErrIQForbidden):
            return None, ErrNotInGroup(f"Not in group: {err}")
        elif err:
            return None, err

        group_node, ok = res.get_optional_child_by_tag("group")
        if not ok:
            return None, ElementMissingError(tag="groups", in_="response to group info query")

        group_info, err = await self.parse_group_node(group_node)
        if err:
            return group_info, err

        if lock_participant_cache:
            async with self.group_cache_lock:
                participants = []
                lid_pairs = []

                for part in group_info.participants:
                    participants.append(part.jid)
                    if not part.phone_number.is_empty() and not part.lid.is_empty():
                        lid_pairs.append({
                            "lid": part.lid,
                            "pn": part.phone_number
                        })

                self.group_cache[jid] = {
                    "addressing_mode": group_info.addressing_mode,
                    "community_announcement_group": group_info.is_announce and group_info.is_default_sub_group,
                    "members": participants
                }

                try:
                    await self.store.lids.put_many_lid_mappings(ctx, lid_pairs)
                except Exception as e:
                    self.log.warning(f"Failed to store LID mappings for members of {jid}: {e}")

        return group_info, None

    async def get_cached_group_data(self, ctx: asyncio.AbstractEventLoop, jid: JID) -> Tuple[Dict[str, Any], Optional[Exception]]:
        """
        Get cached group data.

        Args:
            ctx: The async context
            jid: The group JID

        Returns:
            A tuple containing the cached group data and any error
        """
        async with self.group_cache_lock:
            if jid in self.group_cache:
                return self.group_cache[jid], None

        _, err = await self.get_group_info_internal(ctx, jid, False)
        if err:
            return None, err

        async with self.group_cache_lock:
            return self.group_cache[jid], None

    def parse_participant(self, child_ag, child: Node) -> GroupParticipant:
        """
        Parse a participant node.

        Args:
            child_ag: The attribute getter for the node
            child: The node

        Returns:
            The parsed participant
        """
        pcp_type = child_ag.optional_string("type")
        participant = GroupParticipant(
            is_admin=pcp_type == "admin" or pcp_type == "superadmin",
            is_super_admin=pcp_type == "superadmin",
            jid=child_ag.jid("jid"),
            display_name=child_ag.optional_string("display_name"),
            phone_number=JID(user="", server=""),
            lid=JID(user="", server="")
        )

        if participant.jid.server == "lid":
            participant.lid = participant.jid
            participant.phone_number = child_ag.optional_jid_or_empty("phone_number")
        elif participant.jid.server == "s.whatsapp.net":
            participant.phone_number = participant.jid
            participant.lid = child_ag.optional_jid_or_empty("lid")

        error_code = child_ag.optional_int("error")
        if error_code != 0:
            participant.error = error_code
            add_request, ok = child.get_optional_child_by_tag("add_request")
            if ok:
                add_ag = add_request.attr_getter()
                participant.add_request = GroupParticipantAddRequest(
                    code=add_ag.string("code"),
                    expiration=add_ag.unix_time("expiration")
                )

        return participant

    async def parse_group_node(self, group_node: Node) -> Tuple[Optional[GroupInfo], Optional[Exception]]:
        """
        Parse a group node.

        Args:
            group_node: The group node

        Returns:
            A tuple containing the parsed group info and any error
        """
        ag = group_node.attr_getter()

        group = GroupInfo(
            jid=JID.new_jid(ag.string("id"), GROUP_SERVER),
            owner_jid=ag.optional_jid_or_empty("creator"),
            owner_pn=ag.optional_jid_or_empty("creator_pn"),

            name=ag.string("subject"),
            name_set_at=ag.unix_time("s_t"),
            name_set_by=ag.optional_jid_or_empty("s_o"),
            name_set_by_pn=ag.optional_jid_or_empty("s_o_pn"),

            group_created=ag.unix_time("creation"),
            creator_country_code=ag.optional_string("creator_country_code"),

            announce_version_id=ag.optional_string("a_v_id"),
            participant_version_id=ag.optional_string("p_v_id"),
            addressing_mode=AddressingMode(ag.optional_string("addressing_mode") or "unknown"),

            participants=[]
        )

        for child in group_node.get_children():
            child_ag = child.attr_getter()

            if child.tag == "participant":
                group.participants.append(self.parse_participant(child_ag, child))
            elif child.tag == "description":
                body, body_ok = child.get_optional_child_by_tag("body")
                if body_ok:
                    topic_bytes = body.content
                    if isinstance(topic_bytes, bytes):
                        group.topic = topic_bytes.decode('utf-8')
                    group.topic_id = child_ag.string("id")
                    group.topic_set_by = child_ag.optional_jid_or_empty("participant")
                    group.topic_set_by_pn = child_ag.optional_jid_or_empty("participant_pn")  # TODO confirm field name
                    group.topic_set_at = child_ag.unix_time("t")
            elif child.tag == "announcement":
                group.is_announce = True
            elif child.tag == "locked":
                group.is_locked = True
            elif child.tag == "ephemeral":
                group.is_ephemeral = True
                group.disappearing_timer = child_ag.uint64("expiration")
            elif child.tag == "member_add_mode":
                mode_bytes = child.content
                if isinstance(mode_bytes, bytes):
                    group.member_add_mode = GroupMemberAddMode(mode_bytes.decode('utf-8'))
            elif child.tag == "linked_parent":
                group.linked_parent_jid = child_ag.jid("jid")
            elif child.tag == "default_sub_group":
                group.is_default_sub_group = True
            elif child.tag == "parent":
                group.is_parent = True
                group.default_membership_approval_mode = child_ag.optional_string("default_membership_approval_mode")
            elif child.tag == "incognito":
                group.is_incognito = True
            elif child.tag == "membership_approval_mode":
                group.is_join_approval_required = True
            else:
                self.log.debug(f"Unknown element in group node {group.jid}: {child.xml_string()}")

            if not child_ag.ok():
                self.log.warning(f"Possibly failed to parse {child.tag} element in group node: {child_ag.errors}")

        return group, ag.error()

    def parse_group_link_target_node(self, group_node: Node) -> Tuple[GroupLinkTarget, Optional[Exception]]:
        """
        Parse a group link target node.

        Args:
            group_node: The group node

        Returns:
            A tuple containing the parsed group link target and any error
        """
        ag = group_node.attr_getter()
        jid_key = ag.optional_jid_or_empty("jid")
        if jid_key.is_empty():
            jid_key = JID.new_jid(ag.string("id"), GROUP_SERVER)

        return GroupLinkTarget(
            jid=jid_key,
            group_name=GroupName(
                name=ag.string("subject"),
                name_set_at=ag.unix_time("s_t"),
                name_set_by=None,
                name_set_by_pn=None
            ),
            group_is_default_sub=GroupIsDefaultSub(
                is_default_sub_group=group_node.get_child_by_tag("default_sub_group").tag == "default_sub_group"
            )
        ), ag.error()

    def parse_participant_list(self, node: Node) -> List[JID]:
        """
        Parse a participant list node.

        Args:
            node: The node

        Returns:
            The list of participant JIDs
        """
        children = node.get_children()
        participants = []

        for child in children:
            jid = child.attributes.get("jid")
            if child.tag != "participant" or not jid:
                continue

            participants.append(jid)

        return participants

    async def parse_group_create(self, parent_node: Node, node: Node) -> Tuple[Optional[events.JoinedGroup], Optional[Exception]]:
        """
        Parse a group create notification.

        Args:
            parent_node: The parent node
            node: The node

        Returns:
            A tuple containing the parsed joined group event and any error
        """
        group_node, ok = node.get_optional_child_by_tag("group")
        if not ok:
            return None, Exception("group create notification didn't contain group info")

        pag = parent_node.attr_getter()
        ag = node.attr_getter()

        evt = events.JoinedGroup(
            reason=ag.optional_string("reason"),
            create_key=ag.optional_string("key"),
            type=ag.optional_string("type"),
            sender=pag.optional_jid("participant"),
            sender_pn=pag.optional_jid("participant_pn"),
            notify=pag.optional_string("notify")
        )

        info, err = await self.parse_group_node(group_node)
        if err:
            return None, Exception(f"failed to parse group info in create notification: {err}")

        evt.jid = info.jid
        evt.name = info.name
        evt.topic = info.topic
        evt.creation_time = info.group_created
        evt.participants = [{"jid": p.jid, "is_admin": p.is_admin} for p in info.participants]

        return evt, None

    async def parse_group_change(self, node: Node) -> Tuple[Optional[events.GroupInfo], Optional[Exception]]:
        """
        Parse a group change notification.

        Args:
            node: The node

        Returns:
            A tuple containing the parsed group info event and any error
        """
        ag = node.attr_getter()

        evt = events.GroupInfo(
            jid=ag.jid("from"),
            notify=ag.optional_string("notify"),
            sender=ag.optional_jid("participant"),
            sender_pn=ag.optional_jid("participant_pn"),
            timestamp=ag.unix_time("t")
        )

        if not ag.ok():
            return None, Exception(f"group change doesn't contain required attributes: {ag.error()}")

        for child in node.get_children():
            cag = child.attr_getter()

            if child.tag == "add" or child.tag == "remove" or child.tag == "promote" or child.tag == "demote":
                evt.prev_participant_version_id = cag.string("prev_v_id")
                evt.participant_version_id = cag.string("v_id")

            if child.tag == "add":
                evt.join_reason = cag.optional_string("reason")
                evt.join = self.parse_participant_list(child)
            elif child.tag == "remove":
                evt.leave = self.parse_participant_list(child)
            elif child.tag == "promote":
                evt.promote = self.parse_participant_list(child)
            elif child.tag == "demote":
                evt.demote = self.parse_participant_list(child)
            elif child.tag == "locked":
                evt.locked = True
            elif child.tag == "unlocked":
                evt.locked = False
            elif child.tag == "delete":
                evt.delete = True
            elif child.tag == "subject":
                evt.name = cag.string("subject")
            elif child.tag == "description":
                _, is_delete = child.get_optional_child_by_tag("delete")
                if not is_delete:
                    topic_child = child.get_child_by_tag("body")
                    topic_bytes = topic_child.content
                    if not isinstance(topic_bytes, bytes):
                        return None, Exception(f"group change description has unexpected body: {topic_child.xml_string()}")
                    evt.topic = topic_bytes.decode('utf-8')
            elif child.tag == "announcement":
                evt.announce = True
            elif child.tag == "not_announcement":
                evt.announce = False
            elif child.tag == "invite":
                link = INVITE_LINK_PREFIX + cag.string("code")
                evt.new_invite_link = link
            elif child.tag == "ephemeral":
                evt.ephemeral = int(cag.uint64("expiration"))
            elif child.tag == "not_ephemeral":
                evt.ephemeral = 0
            elif child.tag == "link":
                evt.link = {
                    "type": cag.string("link_type")
                }
                group_node, ok = child.get_optional_child_by_tag("group")
                if not ok:
                    return None, ElementMissingError(tag="group", in_="group link")

                group_link, err = self.parse_group_link_target_node(group_node)
                if err:
                    return None, Exception(f"failed to parse group link node in group change: {err}")

                evt.link["group"] = {
                    "jid": group_link.jid,
                    "name": group_link.group_name.name,
                    "is_default_sub_group": group_link.group_is_default_sub.is_default_sub_group
                }
            elif child.tag == "unlink":
                evt.unlink = {
                    "type": cag.string("unlink_type"),
                    "reason": cag.string("unlink_reason")
                }
                group_node, ok = child.get_optional_child_by_tag("group")
                if not ok:
                    return None, ElementMissingError(tag="group", in_="group unlink")

                group_link, err = self.parse_group_link_target_node(group_node)
                if err:
                    return None, Exception(f"failed to parse group unlink node in group change: {err}")

                evt.unlink["group"] = {
                    "jid": group_link.jid,
                    "name": group_link.group_name.name,
                    "is_default_sub_group": group_link.group_is_default_sub.is_default_sub_group
                }
            elif child.tag == "membership_approval_mode":
                evt.membership_approval_mode = "on"
            else:
                if not evt.unknown_changes:
                    evt.unknown_changes = []
                evt.unknown_changes.append(child)

            if not cag.ok():
                return None, Exception(f"group change {child.tag} element doesn't contain required attributes: {cag.error()}")

        return evt, None

    async def update_group_participant_cache(self, evt: events.GroupInfo) -> None:
        """
        Update the group participant cache.

        Args:
            evt: The group info event
        """
        if not evt.join and not evt.leave:
            return

        async with self.group_cache_lock:
            cached = self.group_cache.get(evt.jid)
            if not cached:
                return

            # Add new participants
            for jid in evt.join:
                if jid not in cached["members"]:
                    cached["members"].append(jid)

            # Remove participants who left
            for jid in evt.leave:
                if jid in cached["members"]:
                    cached["members"].remove(jid)

    async def parse_group_notification(self, node: Node) -> Tuple[Any, Optional[Exception]]:
        """
        Parse a group notification.

        Args:
            node: The node

        Returns:
            A tuple containing the parsed event and any error
        """
        children = node.get_children()
        if len(children) == 1 and children[0].tag == "create":
            return await self.parse_group_create(node, children[0])
        else:
            group_change, err = await self.parse_group_change(node)
            if err:
                return None, err

            await self.update_group_participant_cache(group_change)
            return group_change, None

    async def set_group_join_approval_mode(self, jid: JID, mode: bool) -> Optional[Exception]:
        """
        Sets the group join approval mode to 'on' or 'off'.

        Args:
            jid: The group JID
            mode: Whether join approval is required

        Returns:
            An exception if there was an error, None otherwise
        """
        mode_str = "on" if mode else "off"

        content = Node(
            tag="membership_approval_mode",
            content=[Node(
                tag="group_join",
                attributes={"state": mode_str}
            )]
        )

        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            content
        )
        return err

    async def set_group_member_add_mode(self, jid: JID, mode: GroupMemberAddMode) -> Optional[Exception]:
        """
        Sets the group member add mode to 'admin_add' or 'all_member_add'.

        Args:
            jid: The group JID
            mode: The member add mode

        Returns:
            An exception if there was an error, None otherwise
        """
        if mode != GroupMemberAddMode.ADMIN and mode != GroupMemberAddMode.ALL_MEMBER:
            return Exception("invalid mode, must be 'admin_add' or 'all_member_add'")

        content = Node(
            tag="member_add_mode",
            content=str(mode).encode('utf-8')
        )

        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            content
        )
        return err

    async def set_group_description(self, jid: JID, description: str) -> Optional[Exception]:
        """
        Updates the group description.

        Args:
            jid: The group JID
            description: The new description

        Returns:
            An exception if there was an error, None otherwise
        """
        content = Node(
            tag="description",
            content=[Node(
                tag="body",
                content=description.encode('utf-8')
            )]
        )

        _, err = await self.send_group_iq(
            asyncio.get_event_loop(),
            "set",
            jid,
            content
        )
        return err
