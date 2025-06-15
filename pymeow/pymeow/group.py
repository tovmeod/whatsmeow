"""
WhatsApp group management functionality.

Port of whatsmeow/group.go
"""
import logging
from typing import TYPE_CHECKING, List, Optional

from . import request, types
from .binary.attrs import AttrUtility
from .binary.node import Node
from .exceptions import (
    ElementMissingError,
    ErrGroupInviteLinkUnauthorized,
    ErrGroupNotFound,
    ErrInvalidImageFormat,
    ErrNotInGroup,
    IQError,
)
from .request import InfoQuery, InfoQueryType
from .types.group import (
    GroupLinkTarget,
    GroupMemberAddMode,
    GroupName,
    GroupParticipantAddRequest,
    GroupParticipantRequest,
)
from .types.jid import DEFAULT_USER_SERVER, GROUP_SERVER, GROUP_SERVER_JID, HIDDEN_USER_SERVER, SERVER_JID, JID
from .types.message import AddressingMode

if TYPE_CHECKING:
    from .client import Client, GroupMetaCache

logger = logging.getLogger(__name__)

INVITE_LINK_PREFIX = "https://chat.whatsapp.com/"


class ReqCreateGroup:
    """Request data for CreateGroup.

    Attributes:
        name: Group names are limited to 25 characters. A longer group name will cause a 406 not acceptable error.
        participants: You don't need to include your own JID in the participants array, the WhatsApp servers will add it implicitly.
        create_key: A create key can be provided to deduplicate the group create notification that will be triggered
                   when the group is created. If provided, the JoinedGroup event will contain the same key.
        is_parent: Set to True to create a community instead of a normal group.
                  When creating a community, the linked announcement group will be created automatically by the server.
        default_membership_approval_mode: Default membership approval mode for communities.
        linked_parent_jid: Set to create a group inside a community.
    """

    def __init__(
        self,
        name: str,
        participants: List[types.JID],
        create_key: Optional[str] = None,
        is_parent: bool = False,
        default_membership_approval_mode: str = "",
        linked_parent_jid: Optional[types.JID] = None
    ):
        self.name = name
        self.participants = participants
        self.create_key = create_key
        self.is_parent = is_parent
        self.default_membership_approval_mode = default_membership_approval_mode
        self.linked_parent_jid = linked_parent_jid


class ParticipantChange:
    ADD = "add"
    REMOVE = "remove"
    PROMOTE = "promote"
    DEMOTE = "demote"


class ParticipantRequestChange:
    APPROVE = "approve"
    REJECT = "reject"


async def send_group_iq(
    client: "Client",
    iq_type: InfoQueryType,
    jid: types.JID,
    content: Node
) -> Node:
    """Send a group IQ request."""
    res = await request.send_iq(client, InfoQuery(
        namespace="w:g2",
        type=iq_type,
        to=jid,
        content=[content]
    ))
    return res


async def create_group(client: "Client", req: ReqCreateGroup) -> types.GroupInfo:
    """Creates a group on WhatsApp with the given name and participants.

    Args:
        client: Client instance
        req: The request data for creating the group

    Returns:
        The group info for the created group

    Raises:
        Exception: If there's an error creating the group
    """
    from .send import generate_message_id
    participant_nodes = []
    for participant in req.participants:
        participant_nodes.append(Node(
            tag="participant",
            attrs={"jid": participant}
        ))

    if not req.create_key:
        req.create_key = generate_message_id(client)

    if req.is_parent:
        if not req.default_membership_approval_mode:
            req.default_membership_approval_mode = "request_required"
        participant_nodes.append(Node(
            tag="parent",
            attrs={"default_membership_approval_mode": req.default_membership_approval_mode}
        ))
    elif req.linked_parent_jid and not req.linked_parent_jid.is_empty():
        participant_nodes.append(Node(
            tag="linked_parent",
            attrs={"jid": req.linked_parent_jid}
        ))

    # WhatsApp web doesn't seem to include the static prefix for these
    key = req.create_key
    if key.startswith("3EB0"):
        key = key[4:]

    resp = await send_group_iq(
        client,
        InfoQueryType.SET,
        GROUP_SERVER_JID,
        Node(
            tag="create",
            attrs={"subject": req.name, "key": key},
            content=participant_nodes
        )
    )

    group_node, found = resp.get_optional_child_by_tag("group")
    if not group_node:
        raise ElementMissingError(tag="group", in_location="response to create group query")

    return await parse_group_node(client, group_node)


async def unlink_group(client: "Client", parent: types.JID, child: types.JID) -> None:
    """Removes a child group from a parent community."""
    await send_group_iq(
        client,
        InfoQueryType.SET,
        parent,
        Node(
            tag="unlink",
            attrs={"unlink_type": str(types.GroupLinkChangeType.SUB)},
            content=[Node(
                tag="group",
                attrs={"jid": child}
            )]
        )
    )


async def link_group(client: "Client", parent: types.JID, child: types.JID) -> None:
    """Adds an existing group as a child group in a community.

    To create a new group within a community, set linked_parent_jid in the CreateGroup request.
    """
    await send_group_iq(
        client,
        InfoQueryType.SET,
        parent,
        Node(
            tag="links",
            content=[Node(
                tag="link",
                attrs={"link_type": str(types.GroupLinkChangeType.SUB)},
                content=[Node(
                    tag="group",
                    attrs={"jid": child}
                )]
            )]
        )
    )


async def leave_group(client: "Client", jid: types.JID) -> None:
    """Leaves the specified group on WhatsApp."""
    await send_group_iq(
        client,
        InfoQueryType.SET,
        GROUP_SERVER_JID,
        Node(
            tag="leave",
            content=[Node(
                tag="group",
                attrs={"id": jid}
            )]
        )
    )


async def update_group_participants(
    client: "Client",
    jid: types.JID,
    participant_changes: List[types.JID],
    action: str
) -> List[types.GroupParticipant]:
    """Can be used to add, remove, promote and demote members in a WhatsApp group."""
    content = []
    for participant_jid in participant_changes:
        content.append(Node(
            tag="participant",
            attrs={"jid": participant_jid}
        ))

    resp = await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(
            tag=action,
            content=content
        )
    )

    request_action, found = resp.get_optional_child_by_tag(action)
    if not request_action:
        raise ElementMissingError(tag=action, in_location="response to group participants update")

    request_participants = request_action.get_children_by_tag("participant")
    participants = []
    for child in request_participants:
        participants.append(parse_participant(child.attr_getter(), child))

    return participants


async def get_group_request_participants(client: "Client", jid: types.JID) -> List[GroupParticipantRequest]:
    """Gets the list of participants that have requested to join the group."""
    resp = await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(tag="membership_approval_requests")
    )

    request, found = resp.get_optional_child_by_tag("membership_approval_requests")
    if not request:
        raise ElementMissingError(tag="membership_approval_requests", in_location="response to group request participants query")

    request_participants = request.get_children_by_tag("membership_approval_request")
    participants = []
    for req in request_participants:
        participants.append(GroupParticipantRequest(
            jid=req.attr_getter().jid("jid"),
            requested_at=req.attr_getter().unix_time("request_time")
        ))

    return participants


async def update_group_request_participants(
    client: "Client",
    jid: types.JID,
    participant_changes: List[types.JID],
    action: str
) -> List[types.GroupParticipant]:
    """Can be used to approve or reject requests to join the group."""
    content = []
    for participant_jid in participant_changes:
        content.append(Node(
            tag="participant",
            attrs={"jid": participant_jid}
        ))

    resp = await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(
            tag="membership_requests_action",
            content=[Node(
                tag=action,
                content=content
            )]
        )
    )

    request, found = resp.get_optional_child_by_tag("membership_requests_action")
    if not request:
        raise ElementMissingError(tag="membership_requests_action", in_location="response to group request participants update")

    request_action, found = request.get_optional_child_by_tag(action)
    if not request_action:
        raise ElementMissingError(tag=action, in_location="response to group request participants update")

    request_participants = request_action.get_children_by_tag("participant")
    participants = []
    for child in request_participants:
        participants.append(parse_participant(child.attr_getter(), child))

    return participants


async def set_group_photo(client: "Client", jid: types.JID, avatar: Optional[bytes]) -> str:
    """Updates the group picture/icon of the given group on WhatsApp.

    The avatar should be a JPEG photo, other formats may be rejected with ErrInvalidImageFormat.
    The bytes can be None to remove the photo. Returns the new picture ID.
    """
    from .client import InfoQuery

    content = None
    if avatar is not None:
        content = [Node(
            tag="picture",
            attrs={"type": "image"},
            content=avatar
        )]

    try:
        resp = await request.send_iq(client, InfoQuery(
            namespace="w:profile:picture",
            type=InfoQueryType.SET,
            to=SERVER_JID,
            target=jid,
            content=content
        ))
    except IQError as e:
        if e.code == 406:  # Not acceptable
            raise ErrInvalidImageFormat() from e
        raise

    if avatar is None:
        return "remove"

    picture_id = resp.get_child_by_tag("picture").attrs.get("id")
    if not picture_id:
        raise Exception("didn't find picture ID in response")

    return str(picture_id)


async def set_group_name(client: "Client", jid: types.JID, name: str) -> None:
    """Updates the name (subject) of the given group on WhatsApp."""
    await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(
            tag="subject",
            content=name.encode()
        )
    )


async def set_group_topic(
    client: "Client",
    jid: types.JID,
    previous_id: str = "",
    new_id: str = "",
    topic: str = ""
) -> None:
    """Updates the topic (description) of the given group on WhatsApp.

    The previous_id and new_id fields are optional. If the previous ID is not specified, this will
    automatically fetch the current group info to find the previous topic ID. If the new ID is not
    specified, one will be generated with Client.generate_message_id().
    """
    from .send import generate_message_id
    if not previous_id:
        old_info = await get_group_info(client, jid)
        previous_id = old_info.group_topic.topic_id

    if not new_id:
        new_id = generate_message_id(client)

    attrs = {"id": new_id}
    if previous_id:
        attrs["prev"] = previous_id

    content = None
    if topic:
        content = [Node(
            tag="body",
            content=topic.encode()
        )]
    else:
        attrs["delete"] = "true"

    await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(
            tag="description",
            attrs=attrs,
            content=content
        )
    )


async def set_group_locked(client: "Client", jid: types.JID, locked: bool) -> None:
    """Changes whether the group is locked (i.e. whether only admins can modify group info)."""
    tag = "locked" if locked else "unlocked"
    await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(tag=tag)
    )


async def set_group_announce(client: "Client", jid: types.JID, announce: bool) -> None:
    """Changes whether the group is in announce mode (i.e. whether only admins can send messages)."""
    tag = "announcement" if announce else "not_announcement"
    await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(tag=tag)
    )


async def get_group_invite_link(client: "Client", jid: types.JID, reset: bool = False) -> str:
    """Requests the invite link to the group from the WhatsApp servers.

    If reset is True, then the old invite link will be revoked and a new one generated.
    """
    iq_type = InfoQueryType.SET if reset else InfoQueryType.GET

    try:
        resp = await send_group_iq(client, iq_type, jid, Node(tag="invite"))
    except IQError as e:
        if e.code == 401:  # Unauthorized
            raise ErrGroupInviteLinkUnauthorized() from e
        elif e.code == 404:  # Not found
            raise ErrGroupNotFound() from e
        elif e.code == 403:  # Forbidden
            raise ErrNotInGroup() from e
        raise

    code = resp.get_child_by_tag("invite").attrs.get("code")
    if not code:
        raise Exception("didn't find invite code in response")

    return INVITE_LINK_PREFIX + str(code)


async def get_group_info_from_invite(
    client: "Client",
    jid: types.JID,
    inviter: types.JID,
    code: str,
    expiration: int
) -> types.GroupInfo:
    """Gets the group info from an invite message.

    Note that this is specifically for invite messages, not invite links.
    Use get_group_info_from_link for resolving chat.whatsapp.com links.
    """
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        jid,
        Node(
            tag="query",
            content=[Node(
                tag="add_request",
                attrs={
                    "code": code,
                    "expiration": str(expiration),
                    "admin": inviter
                }
            )]
        )
    )

    group_node, found = resp.get_optional_child_by_tag("group")
    if not group_node:
        raise ElementMissingError(tag="group", in_location="response to invite group info query")

    return await parse_group_node(client, group_node)


async def join_group_with_invite(
    client: "Client",
    jid: types.JID,
    inviter: types.JID,
    code: str,
    expiration: int
) -> None:
    """Joins a group using an invite message.

    Note that this is specifically for invite messages, not invite links.
    Use join_group_with_link for joining with chat.whatsapp.com links.
    """
    await send_group_iq(
        client,
        InfoQueryType.SET,
        jid,
        Node(
            tag="add",
            content=[Node(
                tag="participant",
                attrs={
                    "code": code,
                    "expiration": str(expiration),
                    "admin": inviter
                }
            )]
        )
    )


async def get_group_info_from_link(client: "Client", code: str) -> types.GroupInfo:
    """Gets the group info from an invite link.

    Note that this is specifically for invite links. Use get_group_info_from_invite for invite messages.
    """
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        GROUP_SERVER_JID,
        Node(
            tag="invite",
            attrs={"code": code}
        )
    )

    group_node, found = resp.get_optional_child_by_tag("group")
    if not group_node:
        raise ElementMissingError(tag="group", in_location="response to group info from link query")

    return await parse_group_node(client, group_node)


async def join_group_with_link(client: "Client", code: str) -> Optional[JID]:
    """Joins a group using an invite link.

    Returns the JID of the joined group.
    """
    resp = await send_group_iq(
        client,
        InfoQueryType.SET,
        GROUP_SERVER_JID,
        Node(
            tag="accept",
            attrs={"code": code}
        )
    )

    group_node, found = resp.get_optional_child_by_tag("group")
    if not group_node:
        raise ElementMissingError(tag="group", in_location="response to join group with link")

    group_jid = group_node.attrs.get("jid")
    if not group_jid:
        raise Exception("didn't find group JID in response")

    return JID.from_string(group_jid)


async def get_joined_groups(client: "Client") -> List[types.GroupInfo]:
    """Gets the list of groups the user has joined."""
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        GROUP_SERVER_JID,
        Node(tag="participating")
    )

    participating, found = resp.get_optional_child_by_tag("participating")
    if not participating:
        return []

    groups = []
    for group_node in participating.get_children_by_tag("group"):
        group_info = await parse_group_node(client, group_node)
        groups.append(group_info)

    return groups


async def get_sub_groups(client: "Client", jid: types.JID) -> List[GroupLinkTarget]:
    """Gets the subgroups of a community."""
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        jid,
        Node(tag="linked_groups")
    )

    linked_groups, found = resp.get_optional_child_by_tag("linked_groups")
    if not linked_groups:
        return []

    subgroups = []
    for group_node in linked_groups.get_children_by_tag("group"):
        subgroup = parse_group_link_target_node(client, group_node)
        subgroups.append(subgroup)

    return subgroups


async def get_linked_groups_participants(client: "Client", jid: types.JID) -> List[types.GroupParticipant]:
    """Gets participants from linked groups."""
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        jid,
        Node(tag="linked_groups_participants")
    )

    participants_node, found = resp.get_optional_child_by_tag("linked_groups_participants")
    if not participants_node:
        return []

    participants = []
    for participant_node in participants_node.get_children_by_tag("participant"):
        participant = parse_participant(participant_node.attr_getter(), participant_node)
        participants.append(participant)

    return participants


async def get_group_info(client: "Client", jid: types.JID) -> types.GroupInfo:
    """Gets group information for the specified group."""
    return await get_group_info_internal(client, jid, True)


async def get_group_info_internal(client: "Client", jid: types.JID, lock_participant_cache: bool = True) -> types.GroupInfo:
    """Internal method to get group information and populate cache."""
    from .client import GroupMetaCache
    resp = await send_group_iq(
        client,
        InfoQueryType.GET,
        jid,
        Node(
            tag="query",
            attrs={"request": "interactive"}
        )
    )

    group_node, found = resp.get_optional_child_by_tag("group")
    if not found:
        raise ElementMissingError(tag="group", in_location="response to group info query")

    group_info = await parse_group_node(client, group_node)
    if not group_info:
        return group_info

    # Cache population logic (inline like Go code)
    if lock_participant_cache:
        async with client.group_cache_lock:
            participants = [participant.jid for participant in group_info.participants]
            lid_pairs = []
            for participant in group_info.participants:
                if (participant.phone_number and not participant.phone_number.is_empty() and
                    participant.lid and not participant.lid.is_empty()):
                    lid_pairs.append({
                        'lid': participant.lid,
                        'phone_number': participant.phone_number
                    })

            client.group_cache[jid] = GroupMetaCache(
                addressing_mode=group_info.addressing_mode,
                community_announcement_group=group_info.group_announce.is_announce and group_info.group_is_default_sub.is_default_sub_group,
                members=participants
            )

            # Store LID mappings if available
            if lid_pairs:
                # await client.store.lids.put_many_lid_mappings(lid_pairs)
                pass
    else:
        # Same logic without lock
        participants = [participant.jid for participant in group_info.participants]
        lid_pairs = []
        for participant in group_info.participants:
            if (participant.phone_number and not participant.phone_number.is_empty() and
                participant.lid and not participant.lid.is_empty()):
                lid_pairs.append({
                    'lid': participant.lid,
                    'phone_number': participant.phone_number
                })

        client.group_cache[jid] = GroupMetaCache(
            addressing_mode=group_info.addressing_mode,
            community_announcement_group=group_info.group_announce.is_announce and group_info.group_is_default_sub.is_default_sub_group,
            members=participants
        )

        if lid_pairs:
            # await client.store.lids.put_many_lid_mappings(lid_pairs)
            pass

    return group_info


async def get_cached_group_data(client: "Client", jid: types.JID) -> GroupMetaCache:
    """Gets cached group data if available, fetches it if not."""
    async with client.group_cache_lock:
        if jid in client.group_cache:
            return client.group_cache[jid]

    # If not cached, fetch group info and populate cache
    await get_group_info_internal(client, jid, lock_participant_cache=False)
    group_meta_cache = client.group_cache.get(jid)
    assert group_meta_cache is not None
    return group_meta_cache


def parse_participant(child_ag: AttrUtility, child: Node) -> types.GroupParticipant:
    """
    Parse a participant node into a GroupParticipant object.

    Args:
        child_ag: AttrUtility for the participant node
        child: The participant node itself

    Returns:
        GroupParticipant object
    """
    pcp_type = child_ag.optional_string("type")
    participant = types.GroupParticipant(
        is_admin=(pcp_type == "admin" or pcp_type == "superadmin"),
        is_super_admin=(pcp_type == "superadmin"),
        jid=child_ag.jid("jid"),
        display_name=child_ag.optional_string("display_name")
    )

    if participant.jid.server == HIDDEN_USER_SERVER:
        participant.lid = participant.jid
        participant.phone_number = child_ag.optional_jid_or_empty("phone_number")
    elif participant.jid.server == DEFAULT_USER_SERVER:
        participant.phone_number = participant.jid
        participant.lid = child_ag.optional_jid_or_empty("lid")

    error_code = child_ag.optional_int("error")
    if error_code and error_code != 0:
        participant.error = error_code
        add_request_node, found = child.get_optional_child_by_tag("add_request")
        if found:
            add_ag = add_request_node.attr_getter()
            participant.add_request = GroupParticipantAddRequest(
                code=add_ag.string("code"),
                expiration=add_ag.unix_time("expiration")
            )

    return participant


async def parse_group_node(client: "Client", group_node: Node) -> types.GroupInfo:
    """Parse a group node into GroupInfo.

    Args:
        client: Client instance
        group_node: The group node to parse

    Returns:
        The parsed GroupInfo

    Raises:
        Exception: If there's an error parsing the group node
    """
    ag = group_node.attr_getter()
    group = types.GroupInfo(
        # Basic group information
        jid=types.JID.new_jid(ag.string("id"), GROUP_SERVER)
    )


    group.owner_jid = ag.optional_jid_or_empty("creator")
    group.owner_pn = ag.optional_jid_or_empty("creator_pn")

    group.group_name.name = ag.string("subject")
    group.group_name.name_set_at = ag.unix_time("s_t")
    group.group_name.name_set_by = ag.optional_jid_or_empty("s_o")
    group.group_name.name_set_by_pn = ag.optional_jid_or_empty("s_o_pn")

    group.group_created = ag.unix_time("creation")
    group.creator_country_code = ag.optional_string("creator_country_code")

    group.group_announce.announce_version_id = ag.optional_string("a_v_id")
    group.participant_version_id = ag.optional_string("p_v_id")
    group.addressing_mode = AddressingMode(ag.optional_string("addressing_mode") or "")

    # Parse child elements
    for child in group_node.get_children():
        child_ag = child.attr_getter()

        if child.tag == "participant":
            group.participants.append(parse_participant(child_ag, child))
        elif child.tag == "description":
            body, found = child.get_optional_child_by_tag("body")
            if body:
                if isinstance(body.content, bytes):
                    group.group_topic.topic = body.content.decode('utf-8')
                else:
                    group.group_topic.topic = str(body.content) if body.content else ""
                group.group_topic.topic_id = child_ag.string("id")
                group.group_topic.topic_set_by = child_ag.optional_jid_or_empty("participant")
                group.group_topic.topic_set_by_pn = child_ag.optional_jid_or_empty("participant_pn")
                group.group_topic.topic_set_at = child_ag.unix_time("t")
        elif child.tag == "announcement":
            group.group_announce.is_announce = True
        elif child.tag == "locked":
            group.group_locked.is_locked = True
        elif child.tag == "ephemeral":
            group.group_ephemeral.is_ephemeral = True
            group.group_ephemeral.disappearing_timer = int(child_ag.uint64("expiration"))  # Cast to int (Python equivalent of uint32)
        elif child.tag == "member_add_mode":
            if isinstance(child.content, bytes):
                group.member_add_mode = GroupMemberAddMode(child.content)
            else:
                group.member_add_mode = GroupMemberAddMode(child.content)
        elif child.tag == "linked_parent":
            group.group_linked_parent.linked_parent_jid = child_ag.jid("jid")
        elif child.tag == "default_sub_group":
            group.group_is_default_sub.is_default_sub_group = True
        elif child.tag == "parent":
            group.group_parent.is_parent = True
            group.group_parent.default_membership_approval_mode = child_ag.optional_string("default_membership_approval_mode")
        elif child.tag == "incognito":
            group.group_incognito.is_incognito = True
        elif child.tag == "membership_approval_mode":
            group.group_membership_approval_mode.is_join_approval_required = True
        else:
            logger.debug(f"Unknown element in group node {group.jid}: {child.xml_string()}")

        # Check for parsing errors (equivalent to Go's childAG.OK())
        if not child_ag.ok():
            logger.warning(f"Possibly failed to parse {child.tag} element in group node: {child_ag.errors}")

    # Check for main attribute parsing errors (equivalent to Go's ag.Error())
    if ag.error():
        raise Exception(f"Error parsing group node attributes: {ag.error()}")

    return group


def parse_group_link_target_node(client: "Client", node: Node) -> GroupLinkTarget:
    """Parses a group link target node."""
    ag = node.attr_getter()
    return GroupLinkTarget(
        jid=ag.jid("jid"),
        group_name=GroupName(name=ag.optional_string("subject"))
    )


def parse_participant_list(node: Node) -> List[types.GroupParticipant]:
    """Parses a list of participants from a group node."""
    participants = []
    for participant_node in node.get_children_by_tag("participant"):
        participant = parse_participant(participant_node.attr_getter(), participant_node)
        participants.append(participant)
    return participants
