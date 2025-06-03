"""
WhatsApp newsletter handling.

Port of whatsmeow/newsletter.go
"""
import asyncio
import json
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
import time

from .binary.node import Node, Attrs
from .types.jid import JID, SERVER_JID
from .types.message import MessageServerID, MessageID
from .types.newsletter import (
    NewsletterMetadata, NewsletterMessage, GraphQLResponse, GraphQLErrors,
    NewsletterKeyType
)
from .request import InfoQuery, InfoQueryType


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


@dataclass
class RespGetNewsletterInfo:
    """Response for getting newsletter info."""
    newsletter: Optional[NewsletterMetadata] = None

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'RespGetNewsletterInfo':
        """Create from JSON data."""
        if not data:
            return cls()

        newsletter_data = data.get("xwa2_newsletter")
        if not newsletter_data:
            return cls()

        return cls(newsletter=NewsletterMetadata(**newsletter_data))


@dataclass
class RespGetSubscribedNewsletters:
    """Response for getting subscribed newsletters."""
    newsletters: List[NewsletterMetadata] = field(default_factory=list)

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'RespGetSubscribedNewsletters':
        """Create from JSON data."""
        if not data:
            return cls(newsletters=[])

        newsletters_data = data.get("xwa2_newsletter_subscribed", [])
        newsletters = [NewsletterMetadata(**n) for n in newsletters_data]
        return cls(newsletters=newsletters)


@dataclass
class RespCreateNewsletter:
    """Response for creating a newsletter."""
    newsletter: Optional[NewsletterMetadata] = None

    @classmethod
    def from_json(cls, data: Dict[str, Any]) -> 'RespCreateNewsletter':
        """Create from JSON data."""
        if not data:
            return cls()

        newsletter_data = data.get("xwa2_newsletter_create")
        if not newsletter_data:
            return cls()

        return cls(newsletter=NewsletterMetadata(**newsletter_data))


class NewsletterMixin:
    """Mixin class for newsletter functionality."""
    # GraphQL query/mutation constants
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

    async def newsletter_subscribe_live_updates(self, jid: JID) -> float:
        """Subscribe to receive live updates from a WhatsApp channel temporarily (for the duration returned).

        Args:
            jid: The JID of the newsletter to subscribe to

        Returns:
            The duration of the subscription in seconds

        Raises:
            ValueError: If the request fails
        """
        resp, err = await self.send_iq(InfoQuery(
            namespace="newsletter",
            type=InfoQueryType.SET,
            to=jid,
            content=[Node(
                tag="live_updates",
            )]
        ))

        if err:
            raise ValueError(f"Failed to subscribe to live updates: {err}")

        child = resp.get_child_by_tag("live_updates")
        dur = child.attrs.get_int("duration")
        return dur

    async def newsletter_mark_viewed(self, jid: JID, server_ids: List[MessageServerID]) -> None:
        """Mark a channel message as viewed, incrementing the view counter.

        This is not the same as marking the channel as read on your other devices, use the usual MarkRead function for that.

        Args:
            jid: The JID of the newsletter
            server_ids: The server IDs of the messages to mark as viewed

        Raises:
            ValueError: If the client is nil or the request fails
        """
        if self is None:
            raise ValueError("Client is nil")

        items = [Node(
            tag="item",
            attrs={"server_id": id}
        ) for id in server_ids]

        req_id = self.generate_request_id()
        resp = self.wait_response(req_id)

        try:
            await self.send_node(Node(
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
            self.cancel_response(req_id, resp)
            raise e

        # Wait for response
        await resp.get()
        return None

    async def newsletter_send_reaction(self, jid: JID, server_id: MessageServerID, reaction: str, message_id: Optional[MessageID] = None) -> None:
        """Send a reaction to a channel message.

        To remove a reaction sent earlier, set reaction to an empty string.

        Args:
            jid: The JID of the newsletter
            server_id: The server ID of the message to react to
            reaction: The reaction to send (emoji) or empty string to remove
            message_id: The message ID of the reaction itself (optional, will be generated if not provided)

        Raises:
            ValueError: If the request fails
        """
        if not message_id:
            message_id = self.generate_message_id()

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
            message_attrs["edit"] = "7"  # EditAttributeSenderRevoke

        await self.send_node(Node(
            tag="message",
            attrs=message_attrs,
            content=[Node(
                tag="reaction",
                attrs=reaction_attrs
            )]
        ))
        return None

    async def send_mex_iq(self, ctx: Any, query_id: str, variables: Any) -> Dict[str, Any]:
        """Send a MEX IQ request (GraphQL).

        Args:
            ctx: The context
            query_id: The GraphQL query ID
            variables: The variables for the query

        Returns:
            The response data

        Raises:
            ValueError: If the request fails
            GraphQLErrors: If the GraphQL response contains errors
        """
        payload = json.dumps({"variables": variables})

        resp, err = await self.send_iq(InfoQuery(
            namespace="w:mex",
            type=InfoQueryType.GET,
            to=SERVER_JID,
            content=[Node(
                tag="query",
                attributes={"query_id": query_id},
                content=payload
            )],
            context=ctx
        ))

        if err:
            raise ValueError(f"Failed to send MEX IQ request: {err}")

        result = resp.get_optional_child_by_tag("result")
        if not result:
            raise ValueError("Missing result in mex response")

        result_content = result.content
        if not isinstance(result_content, bytes):
            raise ValueError(f"Unexpected content type {type(result_content)} in mex response")

        gql_resp_dict = json.loads(result_content)

        # Create a GraphQLResponse object
        gql_resp = GraphQLResponse(
            data=gql_resp_dict.get("data", {}),
            errors=GraphQLErrors([
                GraphQLError(
                    extensions=GraphQLErrorExtensions(
                        error_code=err.get("extensions", {}).get("error_code", 0),
                        is_retryable=err.get("extensions", {}).get("is_retryable", False),
                        severity=err.get("extensions", {}).get("severity", "")
                    ),
                    message=err.get("message", ""),
                    path=err.get("path", [])
                ) for err in gql_resp_dict.get("errors", [])
            ])
        )

        # If there are errors, raise them
        if len(gql_resp.errors) > 0:
            raise gql_resp.errors

        return gql_resp.data

    async def get_newsletter_info_internal(self, input_data: Dict[str, Any], fetch_viewer_meta: bool = False) -> Optional[NewsletterMetadata]:
        """Get newsletter info.

        Args:
            input_data: The input data for the query
            fetch_viewer_meta: Whether to fetch viewer metadata

        Returns:
            The newsletter metadata

        Raises:
            ValueError: If the request fails
        """
        data = await self.send_mex_iq(None, self.QUERY_FETCH_NEWSLETTER, {
            "fetch_creation_time": True,
            "fetch_full_image": True,
            "fetch_viewer_metadata": fetch_viewer_meta,
            "input": input_data
        })

        resp_data = RespGetNewsletterInfo.from_json(data)
        return resp_data.newsletter

    async def get_newsletter_info_with_invite(self, key: str) -> Optional[NewsletterMetadata]:
        """Get the info of a newsletter with an invite link.

        You can either pass the full link (https://whatsapp.com/channel/...) or just the `...` part.

        Note that the ViewerMeta field of the returned NewsletterMetadata will be nil.

        Args:
            key: The invite key or full link

        Returns:
            The newsletter metadata

        Raises:
            ValueError: If the request fails
        """
        return await self.get_newsletter_info_internal({
            "key": key.replace(self.NEWSLETTER_LINK_PREFIX, ""),
            "type": NewsletterKeyType.INVITE
        }, False)

    async def get_newsletter_info(self, jid: JID) -> Optional[NewsletterMetadata]:
        """Get the info of a newsletter that you're joined to.

        Args:
            jid: The JID of the newsletter

        Returns:
            The newsletter metadata

        Raises:
            ValueError: If the request fails
        """
        return await self.get_newsletter_info_internal({
            "key": str(jid),
            "type": NewsletterKeyType.JID
        }, True)

    async def get_subscribed_newsletters(self) -> List[NewsletterMetadata]:
        """Get the info of all newsletters that you're joined to.

        Returns:
            A list of newsletter metadata

        Raises:
            ValueError: If the request fails
        """
        data = await self.send_mex_iq(None, self.QUERY_SUBSCRIBED_NEWSLETTERS, {})
        resp_data = RespGetSubscribedNewsletters.from_json(data)
        return resp_data.newsletters

    async def create_newsletter(self, params: CreateNewsletterParams) -> Optional[NewsletterMetadata]:
        """Create a new WhatsApp channel.

        Args:
            params: The parameters for creating the newsletter

        Returns:
            The created newsletter metadata

        Raises:
            ValueError: If the request fails
        """
        # Convert dataclass to dictionary for proper serialization
        params_dict = {k: v for k, v in vars(params).items() if v is not None}
        resp = await self.send_mex_iq(None, self.MUTATION_CREATE_NEWSLETTER, {
            "newsletter_input": params_dict
        })

        resp_data = RespCreateNewsletter.from_json(resp)
        return resp_data.newsletter

    async def accept_tos_notice(self, notice_id: str, stage: str) -> None:
        """Accept a ToS notice.

        To accept the terms for creating newsletters, use:
            await client.accept_tos_notice("20601218", "5")

        Args:
            notice_id: The notice ID
            stage: The stage

        Raises:
            ValueError: If the request fails
        """
        await self.send_iq({
            "namespace": "tos",
            "type": "set",
            "to": SERVER_JID,
            "content": [Node(
                tag="notice",
                attrs={
                    "id": notice_id,
                    "stage": stage
                }
            )]
        })
        return None

    async def newsletter_toggle_mute(self, jid: JID, mute: bool) -> None:
        """Change the mute status of a newsletter.

        Args:
            jid: The JID of the newsletter
            mute: Whether to mute the newsletter

        Raises:
            ValueError: If the request fails
        """
        query = self.MUTATION_MUTE_NEWSLETTER if mute else self.MUTATION_UNMUTE_NEWSLETTER
        await self.send_mex_iq(None, query, {
            "newsletter_id": str(jid)
        })
        return None

    async def follow_newsletter(self, jid: JID) -> None:
        """Make the user follow (join) a WhatsApp channel.

        Args:
            jid: The JID of the newsletter

        Raises:
            ValueError: If the request fails
        """
        await self.send_mex_iq(None, self.MUTATION_FOLLOW_NEWSLETTER, {
            "newsletter_id": str(jid)
        })
        return None

    async def unfollow_newsletter(self, jid: JID) -> None:
        """Make the user unfollow (leave) a WhatsApp channel.

        Args:
            jid: The JID of the newsletter

        Raises:
            ValueError: If the request fails
        """
        await self.send_mex_iq(None, self.MUTATION_UNFOLLOW_NEWSLETTER, {
            "newsletter_id": str(jid)
        })
        return None

    async def get_newsletter_messages(self, jid: JID, params: Optional[GetNewsletterMessagesParams] = None) -> List[NewsletterMessage]:
        """Get messages in a WhatsApp channel.

        Args:
            jid: The JID of the newsletter
            params: Parameters for getting messages

        Returns:
            A list of newsletter messages

        Raises:
            ValueError: If the request fails
        """
        attrs = {
            "type": "jid",
            "jid": jid
        }

        if params:
            if params.count:
                attrs["count"] = params.count
            if params.before:
                attrs["before"] = params.before

        resp = await self.send_iq({
            "namespace": "newsletter",
            "type": "get",
            "to": SERVER_JID,
            "content": [Node(
                tag="messages",
                attrs=attrs
            )],
            "context": None
        })

        messages = resp.get_optional_child_by_tag("messages")
        if not messages:
            raise ValueError("Missing messages in newsletter messages response")

        return self.parse_newsletter_messages(messages)

    async def get_newsletter_message_updates(self, jid: JID, params: Optional[GetNewsletterUpdatesParams] = None) -> List[NewsletterMessage]:
        """Get updates in a WhatsApp channel.

        These are the same kind of updates that NewsletterSubscribeLiveUpdates triggers (reaction and view counts).

        Args:
            jid: The JID of the newsletter
            params: Parameters for getting updates

        Returns:
            A list of newsletter messages

        Raises:
            ValueError: If the request fails
        """
        attrs = {}

        if params:
            if params.count:
                attrs["count"] = params.count
            if params.since:
                attrs["since"] = int(params.since.timestamp())
            if params.after:
                attrs["after"] = params.after

        resp = await self.send_iq({
            "namespace": "newsletter",
            "type": "get",
            "to": jid,
            "content": [Node(
                tag="message_updates",
                attrs=attrs
            )],
            "context": None
        })

        messages = resp.get_optional_child_by_tag("message_updates", "messages")
        if not messages:
            raise ValueError("Missing messages in newsletter messages response")

        return self.parse_newsletter_messages(messages)

    def parse_newsletter_messages(self, messages: Node) -> List[NewsletterMessage]:
        """Parse newsletter messages from a node.

        Args:
            messages: The messages node

        Returns:
            A list of newsletter messages
        """
        result = []
        for msg in messages.get_children_by_tag("message"):
            server_id = MessageServerID(int(msg.attrs.get("server_id", 0)))
            message_id = MessageID(msg.attrs.get("id", ""))
            msg_type = msg.attrs.get("type", "")
            timestamp = datetime.fromtimestamp(int(msg.attrs.get("t", 0)))
            views_count = int(msg.attrs.get("views_count", 0))

            reaction_counts = {}
            reactions = msg.get_optional_child_by_tag("reactions")
            if reactions:
                for reaction in reactions.get_children_by_tag("reaction"):
                    code = reaction.attrs.get("code", "")
                    count = int(reaction.attrs.get("count", 0))
                    reaction_counts[code] = count

            # TODO: Parse message content if needed

            result.append(NewsletterMessage(
                message_server_id=server_id,
                message_id=message_id,
                type=msg_type,
                timestamp=timestamp,
                views_count=views_count,
                reaction_counts=reaction_counts
            ))

        return result
