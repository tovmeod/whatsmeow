"""
WhatsApp broadcast list handling.

Port of whatsmeow/broadcast.go
"""
import asyncio
from typing import List, Optional, Dict, Any

from .binary import node as binary_node
from .request import InfoQuery, InfoQueryType
from .types.jid import JID, STATUS_BROADCAST_JID, SERVER_JID
from .types.user import StatusPrivacy, StatusPrivacyType
from .exceptions import PymeowError, NotFoundError


# Error constants
class BroadcastError(PymeowError):
    """Broadcast-specific error."""
    pass


class BroadcastListUnsupportedError(BroadcastError):
    """Raised when trying to send to non-status broadcast lists."""
    def __init__(self, message="Sending to non-status broadcast lists is not yet supported"):
        self.message = message
        super().__init__(self.message)


class NotLoggedInError(BroadcastError):
    """Raised when the store doesn't contain a device JID."""
    def __init__(self, message="The store doesn't contain a device JID"):
        self.message = message
        super().__init__(self.message)


# For compatibility with code expecting error constants
ErrBroadcastListUnsupported = BroadcastListUnsupportedError()
ErrNotLoggedIn = NotLoggedInError()


# Default status privacy settings
DEFAULT_STATUS_PRIVACY = [
    StatusPrivacy(
        type=StatusPrivacyType.CONTACTS,
        is_default=True
    )
]


class BroadcastClient:
    """Client for handling WhatsApp broadcast lists."""

    def __init__(self, client):
        """Initialize the broadcast client.

        Args:
            client: The WhatsApp client instance
        """
        self.client = client

    async def get_broadcast_list_participants(self, jid: JID) -> List[JID]:
        """Get the participants of a broadcast list.

        Args:
            jid: The JID of the broadcast list

        Returns:
            A list of JIDs of the participants

        Raises:
            BroadcastListUnsupportedError: If the broadcast list is not supported
            NotLoggedInError: If the client is not logged in
            Exception: For any other errors
        """
        participants_list: List[JID] = []

        if jid == STATUS_BROADCAST_JID:
            participants_list = await self.get_status_broadcast_recipients()
        else:
            raise ErrBroadcastListUnsupported

        own_id = self.client.get_own_id().to_non_ad()
        if own_id.is_empty():
            raise ErrNotLoggedIn

        # Check if own ID is in the list, add it if not
        self_index = -1
        for i, participant in enumerate(participants_list):
            if participant.user == own_id.user:
                self_index = i
                break

        if self_index < 0:
            participants_list.append(own_id)

        return participants_list

    async def get_status_broadcast_recipients(self) -> List[JID]:
        """Get the recipients for status broadcasts.

        Returns:
            A list of JIDs of the recipients

        Raises:
            Exception: If there's an error getting the status privacy settings or contacts
        """
        status_privacy_options = await self.get_status_privacy()
        status_privacy = status_privacy_options[0]

        if status_privacy.type == StatusPrivacyType.WHITELIST:
            # Whitelist mode, just return the list
            return status_privacy.list

        # Blacklist or all contacts mode. Find all contacts from database, then filter them appropriately.
        contacts = await self.client.store.contacts.get_all_contacts()

        blacklist: Dict[JID, Any] = {}
        if status_privacy.type == StatusPrivacyType.BLACKLIST:
            for jid in status_privacy.list:
                blacklist[jid] = {}

        contacts_array: List[JID] = []
        for jid, contact in contacts.items():
            is_blacklisted = jid in blacklist
            if is_blacklisted:
                continue

            # TODO should there be a better way to separate contacts and found push names in the db?
            if contact.full_name:
                contacts_array.append(jid)

        return contacts_array

    async def get_status_privacy(self) -> List[StatusPrivacy]:
        """Get the user's status privacy settings (who to send status broadcasts to).

        There can be multiple different stored settings, the first one is always the default.

        Returns:
            A list of StatusPrivacy objects

        Raises:
            Exception: If there's an error getting the status privacy settings
        """
        query = InfoQuery(
            namespace="status",
            type=InfoQueryType.GET,
            to=SERVER_JID,
            content=[binary_node.Node(tag="privacy")]
        )

        response, err = await self.client.send_iq(query)
        if err is not None:
            if isinstance(err, NotFoundError):
                return DEFAULT_STATUS_PRIVACY
            raise err

        privacy_lists = response.get_child_by_tag("privacy")
        outputs: List[StatusPrivacy] = []

        for list_node in privacy_lists.get_children():
            if list_node.tag != "list":
                continue

            attr_getter = list_node.attr_getter()
            output = StatusPrivacy()
            output.is_default = attr_getter.optional_bool("default")
            output.type = StatusPrivacyType(attr_getter.string("type"))

            children = list_node.get_children()
            if children:
                output.list = []
                for child in children:
                    jid = child.attrs.get("jid")
                    if child.tag == "user" and jid is not None:
                        output.list.append(jid)

            outputs.append(output)
            if output.is_default:
                # Move default to always be first in the list
                outputs[len(outputs) - 1] = outputs[0]
                outputs[0] = output

            if attr_getter.errors:
                raise Exception(attr_getter.error())

        if not outputs:
            return DEFAULT_STATUS_PRIVACY

        return outputs
