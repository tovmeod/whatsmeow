"""
WhatsApp broadcast list handling.

Port of whatsmeow/broadcast.go
"""

from typing import TYPE_CHECKING, Dict, List

from . import request
from .binary import node as binary_node
from .datatypes.jid import JID, SERVER_JID, STATUS_BROADCAST_JID
from .datatypes.user import StatusPrivacy, StatusPrivacyType
from .exceptions import PymeowError

if TYPE_CHECKING:
    from .client import Client


# Error constants - these match the Go implementation
class BroadcastListUnsupportedError(PymeowError):
    """Raised when trying to send to non-status broadcast lists."""

    pass


class NotLoggedInError(PymeowError):
    """Raised when the store doesn't contain a device JID."""

    pass


# Error instances for compatibility
ErrBroadcastListUnsupported = BroadcastListUnsupportedError(
    "sending to non-status broadcast lists is not yet supported"
)
ErrNotLoggedIn = NotLoggedInError("the store doesn't contain a device JID")


# Default status privacy settings
DEFAULT_STATUS_PRIVACY: List[StatusPrivacy] = [StatusPrivacy(type=StatusPrivacyType.CONTACTS, is_default=True)]


async def get_broadcast_list_participants(client: "Client", jid: JID) -> List[JID]:
    """Get the participants of a broadcast list.

    Args:
        client: The WhatsApp client instance
        jid: The JID of the broadcast list

    Returns:
        A list of JIDs of the participants

    Raises:
        BroadcastListUnsupportedError: If the broadcast list is not supported
        NotLoggedInError: If the client is not logged in
        Exception: For any other errors
    """
    if jid == STATUS_BROADCAST_JID:
        participant_list = await get_status_broadcast_recipients(client)
    else:
        raise ErrBroadcastListUnsupported

    own_id = client.get_own_id().to_non_ad()
    if own_id.is_empty():
        raise ErrNotLoggedIn

    # Check if own ID is in the list, add it if not
    self_index = -1
    for i, participant in enumerate(participant_list):
        if participant.user == own_id.user:
            self_index = i
            break

    if self_index < 0:
        participant_list.append(own_id)

    return participant_list


async def get_status_broadcast_recipients(client: "Client") -> List[JID]:
    """Get the recipients for status broadcasts.

    Args:
        client: The WhatsApp client instance

    Returns:
        A list of JIDs of the recipients

    Raises:
        Exception: If there's an error getting the status privacy settings or contacts
    """
    try:
        status_privacy_options = await get_status_privacy(client)
    except Exception as e:
        raise Exception(f"failed to get status privacy: {e}")

    status_privacy = status_privacy_options[0]

    if status_privacy.type == StatusPrivacyType.WHITELIST:
        # Whitelist mode, just return the list
        return status_privacy.list

    # Blacklist or all contacts mode. Find all contacts from database, then filter them appropriately.
    try:
        contacts = await client.store.contacts.get_all_contacts()
    except Exception as e:
        raise Exception(f"failed to get contact list from db: {e}")

    blacklist: Dict[JID, None] = {}
    if status_privacy.type == StatusPrivacyType.BLACKLIST:
        for jid in status_privacy.list:
            blacklist[jid] = None

    contacts_array: List[JID] = []
    for jid, contact in contacts.items():
        if jid in blacklist:
            continue

        # TODO should there be a better way to separate contacts and found push names in the db?
        if contact.full_name:
            contacts_array.append(jid)

    return contacts_array


async def get_status_privacy(client: "Client") -> List[StatusPrivacy]:
    """Get the user's status privacy settings (who to send status broadcasts to).

    There can be multiple different stored settings, the first one is always the default.

    Args:
        client: The WhatsApp client instance

    Returns:
        A list of StatusPrivacy objects

    Raises:
        Exception: If there's an error getting the status privacy settings
    """
    from .request import InfoQuery, InfoQueryType

    query = InfoQuery(
        namespace="status", type=InfoQueryType.GET, to=SERVER_JID, content=[binary_node.Node(tag="privacy")]
    )

    response = await request.send_iq(client, query)
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
