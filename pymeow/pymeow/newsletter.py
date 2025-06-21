"""
WhatsApp newsletter handling.

Port of whatsmeow/newsletter.go - uses composition pattern instead of mixins.
Each function receives the client as the first argument.
"""
import base64
import json
from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from . import request, send
from .binary.node import Node
from .datatypes.jid import JID, SERVER_JID
from .datatypes.message import MessageID, MessageServerID
from .datatypes.newsletter import GraphQLErrors, GraphQLResponse, NewsletterMessage, NewsletterMetadata
from .exceptions import ElementMissingError, ErrClientIsNil
from .request import InfoQuery, InfoQueryType

if TYPE_CHECKING:
    from .client import Client

# GraphQL query/mutation constants - matching Go exactly
QUERY_FETCH_NEWSLETTER = "6563316087068696"
QUERY_FETCH_NEWSLETTER_DEHYDRATED = "7272540469429201"
QUERY_RECOMMENDED_NEWSLETTERS = "7263823273662354"
QUERY_NEWSLETTERS_DIRECTORY = "6190824427689257"
QUERY_SUBSCRIBED_NEWSLETTERS = "6388546374527196"
QUERY_NEWSLETTER_SUBSCRIBERS = "9800646650009898"
MUTATION_MUTE_NEWSLETTER = "6274038279359549"
MUTATION_UNMUTE_NEWSLETTER = "6068417879924485"
MUTATION_UPDATE_NEWSLETTER = "7150902998257522"
MUTATION_CREATE_NEWSLETTER = "6234210096708695"
MUTATION_UNFOLLOW_NEWSLETTER = "6392786840836363"
MUTATION_FOLLOW_NEWSLETTER = "9926858900719341"

# Newsletter link prefix
NEWSLETTER_LINK_PREFIX = "https://whatsapp.com/channel/"


@dataclass
class CreateNewsletterParams:
    """Parameters for creating a newsletter."""
    name: str
    description: str = ""
    picture: Optional[bytes] = None


@dataclass
class GetNewsletterMessagesParams:
    """Parameters for getting newsletter messages."""
    count: int = 0
    before: Optional[MessageServerID] = None


@dataclass
class GetNewsletterUpdatesParams:
    """Parameters for getting newsletter updates."""
    count: int = 0
    since: Optional[datetime] = None
    after: Optional[MessageServerID] = None


async def newsletter_subscribe_live_updates(client: 'Client', jid: JID) -> int:
    """Subscribe to receive live updates from a WhatsApp channel temporarily (for the duration returned).

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter to subscribe to

    Returns:
        The duration of the subscription in seconds

    Raises:
        Exception: If the request fails
        ValueError
        TypeError
    """
    resp = await request.send_iq(client, InfoQuery(
        namespace= "newsletter",
        type=InfoQueryType.SET,
        to=jid,
        content=[Node(tag="live_updates")]
    ))

    child = resp.get_child_by_tag("live_updates")
    duration_str = child.attrs.get("duration")
    if duration_str is None:
        raise ValueError("Duration attribute missing from live_updates response")
    try:
        dur = int(duration_str)
    except (ValueError, TypeError) as e:
        raise ValueError(f"Invalid duration value: {duration_str}") from e
    return dur

async def newsletter_mark_viewed(client: 'Client', jid: JID, server_ids: List[MessageServerID]) -> None:
    """Mark a channel message as viewed, incrementing the view counter.

    This is not the same as marking the channel as read on your other devices,
    use the usual MarkRead function for that.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
        server_ids: The server IDs of the messages to mark as viewed

    Raises:
        ErrClientIsNil: If the client is nil
    """
    if client is None:
        raise ErrClientIsNil()

    items = [Node(
        tag="item",
        attrs={"server_id": server_id}
    ) for server_id in server_ids]

    req_id = request.generate_request_id(client)
    resp = await request.wait_response(client, req_id)

    try:
        await client.send_node(Node(
            tag="receipt",
            attrs={
                "to": jid,
                "type": "view",
                "id": req_id
            },
            content=[Node(
                tag="list",
                content=items
            )]
        ))
    except Exception as e:
        await request.cancel_response(client, req_id, resp)
        raise e

    await resp.get()


async def newsletter_send_reaction(
    client: 'Client',
    jid: JID,
    server_id: MessageServerID,
    reaction: str,
    message_id: MessageID = MessageID("")
) -> None:
    """Send a reaction to a channel message.

    To remove a reaction sent earlier, set reaction to an empty string.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
        server_id: The server ID of the message to react to
        reaction: The reaction to send (emoji) or empty string to remove
        message_id: The message ID of the reaction itself (optional, will be generated if empty)
    """
    if not message_id:
        message_id = send.generate_message_id(client)

    reaction_attrs = {}
    message_attrs = {
        "to": jid,
        "id": message_id,
        "server_id": server_id,
        "type": "reaction"
    }

    if reaction:
        reaction_attrs["code"] = reaction
    else:
        # EditAttributeSenderRevoke
        message_attrs["edit"] = "7"

    await client.send_node(Node(
        tag="message",
        attrs=message_attrs,
        content=[Node(
            tag="reaction",
            attrs=reaction_attrs
        )]
    ))


class BytesEncoder(json.JSONEncoder):
    """Custom JSON encoder that handles bytes objects by encoding them as base64."""

    def default(self, obj: Any) -> Any:
        if isinstance(obj, bytes):
            return base64.b64encode(obj).decode('utf-8')
        return super().default(obj)

async def send_mex_iq(client: 'Client', query_id: str, variables: Any) -> Dict[str, Any]:
    """Send a MEX IQ request (GraphQL).

    Args:
        client: The WhatsApp client
        query_id: The GraphQL query ID
        variables: The variables for the query

    Returns:
        The parsed JSON response data
    Raises:
        Exception: If the request fails
        GraphQLErrors: If the GraphQL response contains errors
    """
    payload = json.dumps({"variables": variables}, cls=BytesEncoder).encode('utf-8')

    resp = await request.send_iq(client, InfoQuery(
        namespace="w:mex",
        type=InfoQueryType.GET,
        to=SERVER_JID,
        content=[Node(
            tag="query",
            attrs={"query_id": query_id},
            content=payload
        )]
    ))

    result, found = resp.get_optional_child_by_tag("result")
    if not found or not result:
        raise ElementMissingError(tag="result", in_location="mex response")

    result_content = result.content
    if not isinstance(result_content, bytes):
        raise ValueError(f"unexpected content type {type(result_content)} in mex response")

    gql_resp_dict = json.loads(result_content)
    gql_resp = GraphQLResponse(**gql_resp_dict)

    if len(gql_resp.errors) > 0:
        raise GraphQLErrors(gql_resp.errors.errors)

    # Parse the data field if it's JSON bytes, otherwise return as dict
    if isinstance(gql_resp.data, bytes):
        parsed_data = json.loads(gql_resp.data.decode('utf-8'))
        if isinstance(parsed_data, dict):
            return parsed_data
        else:
            raise ValueError(f"Expected dict from parsed JSON, got {type(parsed_data)}")
    elif isinstance(gql_resp.data, dict):
        return gql_resp.data
    else:
        raise ValueError(f"Expected dict or bytes from GraphQL response data, got {type(gql_resp.data)}")

async def get_newsletter_info_internal(
    client: 'Client',
    input_data: Dict[str, Any],
    fetch_viewer_meta: bool
) -> Optional[NewsletterMetadata]:
    """Get newsletter info (internal implementation).

    Args:
        client: The WhatsApp client
        input_data: The input data for the query
        fetch_viewer_meta: Whether to fetch viewer metadata

    Returns:
        The newsletter metadata or None
    """
    data = await send_mex_iq(client, QUERY_FETCH_NEWSLETTER, {
        "fetch_creation_time": True,
        "fetch_full_image": True,
        "fetch_viewer_metadata": fetch_viewer_meta,
        "input": input_data
    })

    if not data or "xwa2_newsletter" not in data:
        return None

    return NewsletterMetadata(**data["xwa2_newsletter"])


async def get_newsletter_info(client: 'Client', jid: JID) -> Optional[NewsletterMetadata]:
    """Get the info of a newsletter that you're joined to.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter

    Returns:
        The newsletter metadata or None
    """
    from .datatypes.newsletter import NewsletterKeyType

    return await get_newsletter_info_internal(client, {
        "key": str(jid),
        "type": NewsletterKeyType.JID
    }, True)


async def get_newsletter_info_with_invite(client: 'Client', key: str) -> Optional[NewsletterMetadata]:
    """Get the info of a newsletter with an invite link.

    You can either pass the full link (https://whatsapp.com/channel/...) or just the `...` part.

    Note that the ViewerMeta field of the returned NewsletterMetadata will be nil.

    Args:
        client: The WhatsApp client
        key: The invite key or full link

    Returns:
        The newsletter metadata or None
    """
    from .datatypes.newsletter import NewsletterKeyType

    clean_key = key
    if key.startswith(NEWSLETTER_LINK_PREFIX):
        clean_key = key[len(NEWSLETTER_LINK_PREFIX):]

    return await get_newsletter_info_internal(client, {
        "key": clean_key,
        "type": NewsletterKeyType.INVITE
    }, False)


async def get_subscribed_newsletters(client: 'Client') -> List[NewsletterMetadata]:
    """Get the info of all newsletters that you're joined to.

    Args:
        client: The WhatsApp client

    Returns:
        A list of newsletter metadata
    """
    data = await send_mex_iq(client, QUERY_SUBSCRIBED_NEWSLETTERS, {})

    if not data or "xwa2_newsletter_subscribed" not in data:
        return []

    newsletters_data = data["xwa2_newsletter_subscribed"]
    return [NewsletterMetadata(**n) for n in newsletters_data]


async def create_newsletter(client: 'Client', params: CreateNewsletterParams) -> Optional[NewsletterMetadata]:
    """Create a new WhatsApp channel.

    Args:
        client: The WhatsApp client
        params: The parameters for creating the newsletter

    Returns:
        The created newsletter metadata or None
    """
    # Convert dataclass to dictionary, filtering out None values
    params_dict: Dict[str, str | bytes] = {}
    if params.name:
        params_dict["name"] = params.name
    if params.description:
        params_dict["description"] = params.description
    if params.picture is not None:
        params_dict["picture"] = params.picture

    resp = await send_mex_iq(client, MUTATION_CREATE_NEWSLETTER, {
        "newsletter_input": params_dict
    })

    if not resp or "xwa2_newsletter_create" not in resp:
        return None

    return NewsletterMetadata(**resp["xwa2_newsletter_create"])


async def accept_tos_notice(client: 'Client', notice_id: str, stage: str) -> None:
    """Accept a ToS notice.

    To accept the terms for creating newsletters, use:
        await accept_tos_notice(client, "20601218", "5")

    Args:
        client: The WhatsApp client
        notice_id: The notice ID
        stage: The stage
    """
    await request.send_iq(client, InfoQuery(
        namespace="tos",
        type=InfoQueryType.SET,
        to=SERVER_JID,
        content=[Node(
            tag="notice",
            attrs={
                "id": notice_id,
                "stage": stage
            }
        )]
    ))


async def newsletter_toggle_mute(client: 'Client', jid: JID, mute: bool) -> None:
    """Change the mute status of a newsletter.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
        mute: Whether to mute the newsletter
    """
    query = MUTATION_MUTE_NEWSLETTER if mute else MUTATION_UNMUTE_NEWSLETTER
    await send_mex_iq(client, query, {
        "newsletter_id": str(jid)
    })


async def follow_newsletter(client: 'Client', jid: JID) -> None:
    """Make the user follow (join) a WhatsApp channel.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
    """
    await send_mex_iq(client, MUTATION_FOLLOW_NEWSLETTER, {
        "newsletter_id": str(jid)
    })


async def unfollow_newsletter(client: 'Client', jid: JID) -> None:
    """Make the user unfollow (leave) a WhatsApp channel.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
    """
    await send_mex_iq(client, MUTATION_UNFOLLOW_NEWSLETTER, {
        "newsletter_id": str(jid)
    })


async def get_newsletter_messages(
    client: 'Client',
    jid: JID,
    params: Optional[GetNewsletterMessagesParams] = None
) -> List[NewsletterMessage]:
    """Get messages in a WhatsApp channel.

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
        params: Parameters for getting messages

    Returns:
        A list of newsletter messages
    """
    attrs = {
        "type": "jid",
        "jid": jid
    }

    if params:
        if params.count != 0:
            attrs["count"] = params.count
        if params.before is not None and params.before != 0:
            attrs["before"] = params.before

    resp = await request.send_iq(client, InfoQuery(
        namespace="newsletter",
        type=InfoQueryType.GET,
        to=SERVER_JID,
        content=[Node(
            tag="messages",
            attrs=attrs
        )]
    ))

    messages, found = resp.get_optional_child_by_tag("messages")
    if not found or not messages:
        raise ElementMissingError(tag="messages", in_location="newsletter messages response")

    return parse_newsletter_messages(messages)


async def get_newsletter_message_updates(
    client: 'Client',
    jid: JID,
    params: Optional[GetNewsletterUpdatesParams] = None
) -> List[NewsletterMessage]:
    """Get updates in a WhatsApp channel.

    These are the same kind of updates that newsletter_subscribe_live_updates triggers
    (reaction and view counts).

    Args:
        client: The WhatsApp client
        jid: The JID of the newsletter
        params: Parameters for getting updates

    Returns:
        A list of newsletter messages
    """
    attrs = {}

    if params:
        if params.count != 0:
            attrs["count"] = params.count
        if params.since is not None and not params.since == datetime.min:
            attrs["since"] = int(params.since.timestamp())
        if params.after is not None and params.after != 0:
            attrs["after"] = params.after

    resp = await request.send_iq(client, InfoQuery(
        namespace="newsletter",
        type=InfoQueryType.GET,
        to=jid,
        content=[Node(
            tag="message_updates",
            attrs=attrs
        )]
    ))

    messages, found = resp.get_optional_child_by_tag("message_updates", "messages")
    if not found and not messages:
        raise ElementMissingError(tag="messages", in_location="newsletter messages response")

    return parse_newsletter_messages(messages)


def parse_newsletter_messages(messages: Node) -> List[NewsletterMessage]:
    """Parse newsletter messages from a node.

    Args:
        messages: The messages node

    Returns:
        A list of newsletter messages
    """
    # This method matches the Go version's parseNewsletterMessages method
    # The actual implementation would depend on the NewsletterMessage structure
    # and the parsing logic from the Go version

    result = []
    for msg_node in messages.get_children():
        if msg_node.tag != "message":
            continue

        # Parse message attributes
        attrs = msg_node.attrs
        server_id = MessageServerID(int(attrs.get("server_id", 0)))
        message_id = MessageID(attrs.get("id", ""))
        msg_type = attrs.get("type", "")
        timestamp = datetime.fromtimestamp(int(attrs.get("t", 0)))
        views_count = int(attrs.get("views_count", 0))

        # Parse reaction counts if present
        reaction_counts = {}
        reactions_node, found = msg_node.get_optional_child_by_tag("reactions")
        if reactions_node:
            for reaction_node in reactions_node.get_children():
                if reaction_node.tag == "reaction":
                    code = reaction_node.attrs.get("code", "")
                    count = int(reaction_node.attrs.get("count", 0))
                    if code:
                        reaction_counts[code] = count

        # Create NewsletterMessage object
        # This structure should match the Go types.NewsletterMessage
        newsletter_msg = NewsletterMessage(
            message_server_id=server_id,
            message_id=message_id,
            type=msg_type,
            timestamp=timestamp,
            views_count=views_count,
            reaction_counts=reaction_counts
            # Additional fields would be parsed here based on the Go implementation
        )

        result.append(newsletter_msg)

    return result
