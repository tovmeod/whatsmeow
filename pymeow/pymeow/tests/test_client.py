"""
Tests for the pymeow client.
"""

from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from pymeow.client import Client  # Corrected import
from pymeow.datatypes.jid import JID
from pymeow.exceptions import PymeowError


@pytest.mark.asyncio
async def test_client_initialization():
    """Test that the client can be initialized."""
    client = Client()
    assert client is not None


@pytest.mark.asyncio
async def test_connect_disconnect():
    """Test connecting and disconnecting the client."""
    client = Client()

    # Test successful connection
    with patch("pymeow.client.Client._connect_ws") as mock_connect:
        await client.connect()
        mock_connect.assert_called_once()

    # Test disconnection
    with patch("pymeow.client.Client._disconnect_ws") as mock_disconnect:
        await client.disconnect()
        mock_disconnect.assert_called_once()


@pytest.mark.asyncio
async def test_event_handlers():
    """Test that event handlers are called correctly."""
    client = Client()

    # Mock event handler
    mock_handler = AsyncMock()
    client.on("message")(mock_handler)

    # Test event dispatching
    test_message = {"id": "123", "content": "test"}
    await client._dispatch_event("message", test_message)

    # Check that the handler was called with the correct arguments
    mock_handler.assert_awaited_once_with(test_message)


@pytest.mark.asyncio
async def test_send_message():
    """Test sending a message."""
    client = Client()

    # Mock the WebSocket send method
    with patch("pymeow.client.Client._send_ws") as mock_send:
        mock_send.return_value = {"id": "msg_123"}

        # Send a test message
        message_id = await client.send_message("1234567890@s.whatsapp.net", "Hello!")

        # Check that the message was sent with the correct parameters
        mock_send.assert_awaited_once()
        assert message_id == "msg_123"


@pytest.mark.asyncio
async def test_context_manager():
    """Test using the client as a context manager."""
    with (
        patch("pymeow.client.Client.connect") as mock_connect,
        patch("pymeow.client.Client.disconnect") as mock_disconnect,
    ):
        async with Client() as client:
            assert client is not None
            mock_connect.assert_awaited_once()

        # Check that disconnect was called when exiting the context
        mock_disconnect.assert_awaited_once()


@pytest.mark.asyncio
async def test_error_handling():
    """Test error handling in the client."""
    client = Client()

    # Mock a connection error
    with patch("pymeow.client.Client._connect_ws", side_effect=Exception("Connection failed")):
        with pytest.raises(PymeowError, match="Connection failed"):
            await client.connect()

    # Test that the error event is dispatched
    mock_handler = AsyncMock()
    client.on("error")(mock_handler)

    # Trigger an error
    await client._dispatch_event("error", "Test error")
    mock_handler.assert_awaited_once_with("Test error")


@pytest.mark.asyncio
async def test_send_reaction_success():
    """Test sending a reaction successfully."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    # Simulate a logged-in state by setting auth_state.me
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    with patch("pymeow.pymeow.client.Client._send_reaction_node", new_callable=AsyncMock) as mock_send_reaction_node:
        mock_send_reaction_node.return_value = {"status": "ok", "ts": "1234567890"}

        chat_jid_str = "recipient@s.whatsapp.net"
        message_id = "test_message_id_123"
        emoji = "👍"

        # sender_jid is optional, _send_reaction_node should handle if it's None
        # by using client.auth_state.me.jid
        result = await client.send_reaction(message_id=message_id, chat_jid=chat_jid_str, emoji=emoji)

        mock_send_reaction_node.assert_awaited_once_with(
            JID.from_string(chat_jid_str),
            message_id,
            emoji,
            None,  # sender_jid was not provided, so it's passed as None
        )
        assert result == {"status": "ok", "ts": "1234567890"}


@pytest.mark.asyncio
async def test_send_reaction_success_with_sender_jid():
    """Test sending a reaction successfully when sender_jid is provided."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    # No need to mock client.auth_state.me if sender_jid is provided directly to send_reaction
    # and then passed to _send_reaction_node.

    with patch("pymeow.pymeow.client.Client._send_reaction_node", new_callable=AsyncMock) as mock_send_reaction_node:
        mock_send_reaction_node.return_value = {"status": "ok", "ts": "1234567891"}

        chat_jid_str = "recipient@s.whatsapp.net"
        message_id = "test_message_id_456"
        emoji = "😊"
        sender_jid_str = "sender@s.whatsapp.net"  # Explicitly providing sender_jid

        result = await client.send_reaction(
            message_id=message_id, chat_jid=chat_jid_str, emoji=emoji, sender_jid=sender_jid_str
        )

        mock_send_reaction_node.assert_awaited_once_with(
            JID.from_string(chat_jid_str),
            message_id,
            emoji,
            JID.from_string(sender_jid_str),  # sender_jid is provided
        )
        assert result == {"status": "ok", "ts": "1234567891"}


@pytest.mark.asyncio
async def test_send_reaction_remove_reaction_success():
    """Test removing a reaction by sending an empty emoji string."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    with patch("pymeow.pymeow.client.Client._send_reaction_node", new_callable=AsyncMock) as mock_send_reaction_node:
        mock_send_reaction_node.return_value = {"status": "ok", "ts": "1234567892"}

        chat_jid_str = "recipient@s.whatsapp.net"
        message_id = "test_message_id_789"
        empty_emoji = ""  # To remove reaction

        result = await client.send_reaction(message_id=message_id, chat_jid=chat_jid_str, emoji=empty_emoji)

        mock_send_reaction_node.assert_awaited_once_with(JID.from_string(chat_jid_str), message_id, empty_emoji, None)
        assert result == {"status": "ok", "ts": "1234567892"}


@pytest.mark.asyncio
async def test_send_reaction_underlying_send_fails():
    """Test that send_reaction propagates exceptions from _send_reaction_node."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    with patch("pymeow.pymeow.client.Client._send_reaction_node", new_callable=AsyncMock) as mock_send_reaction_node:
        mock_send_reaction_node.side_effect = PymeowError("Failed to send reaction node")

        chat_jid_str = "recipient@s.whatsapp.net"
        message_id = "test_message_id_000"
        emoji = "👍"

        with pytest.raises(PymeowError, match="Failed to send reaction node"):
            await client.send_reaction(message_id=message_id, chat_jid=chat_jid_str, emoji=emoji)

        mock_send_reaction_node.assert_awaited_once_with(JID.from_string(chat_jid_str), message_id, emoji, None)


@pytest.mark.asyncio
async def test_send_reply_success_text_message():
    """Test sending a text reply successfully."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    # Mocked return values for _get_quoted_ui_elements
    mock_stanza_id = "quoted_message_stanza_id"
    mock_participant_jid = JID.from_string("participant@s.whatsapp.net")
    # WAWebMessage is the actual message content protobuf.
    # For simplicity, using a MagicMock. In a real scenario, this would be a WAWebMessage instance.
    mock_quoted_message_proto = MagicMock(spec_set=["SerializeToString"])  # Simulate a protobuf message

    # Mock _get_quoted_ui_elements
    mock_get_quoted_elements = AsyncMock(return_value=(mock_stanza_id, mock_participant_jid, mock_quoted_message_proto))
    client._get_quoted_ui_elements = mock_get_quoted_elements

    # Mock send_message
    mock_send_message_method = AsyncMock(return_value={"id": "reply_msg_id_123"})
    client.send_message = mock_send_message_method

    chat_jid_str = "group_chat@g.us"
    to_message_id = "message_to_reply_to_id"
    reply_content = "This is a reply."

    result = await client.send_reply(to_message_id=to_message_id, chat_jid=chat_jid_str, content=reply_content)

    # Assert _get_quoted_ui_elements was called correctly
    mock_get_quoted_elements.assert_awaited_once_with(JID.from_string(chat_jid_str), to_message_id)

    # Assert send_message was called correctly
    mock_send_message_method.assert_awaited_once()


@pytest.mark.asyncio
async def test_send_contacts_success_single_contact():
    """Test sending a single contact in a contacts array successfully."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    mock_send_message_method = AsyncMock(return_value={"id": "contacts_array_msg_id_001"})
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contacts_list = [{"contact_jid": "user1@s.whatsapp.net", "name": "User One", "phone_number": "+111222333"}]

    result = await client.send_contacts(JID.from_string(to_jid_str), contacts_list)

    mock_send_message_method.assert_awaited_once()
    call_args = mock_send_message_method.call_args
    sent_to_jid, sent_message_proto = call_args.args

    assert sent_to_jid == JID.from_string(to_jid_str)
    assert hasattr(sent_message_proto, "contactsArrayMessage")
    array_msg = sent_message_proto.contactsArrayMessage
    assert len(array_msg.contacts) == 1

    contact1_proto = array_msg.contacts[0]
    assert contact1_proto.displayName == contacts_list[0]["name"]

    contact1_jid_obj = JID.from_string(contacts_list[0]["contact_jid"])
    contact1_waid_phone = "".join(filter(str.isdigit, contacts_list[0]["phone_number"]))
    expected_vcard1 = (
        f"BEGIN:VCARD\nVERSION:3.0\nFN:{contacts_list[0]['name']}\n"
        f"TEL;type=CELL;type=VOICE;waid={contact1_jid_obj.user}:{contact1_waid_phone}\nEND:VCARD"
    )
    assert contact1_proto.vcard == expected_vcard1
    assert result == {"id": "contacts_array_msg_id_001"}


@pytest.mark.asyncio
async def test_send_contacts_success_multiple_contacts():
    """Test sending multiple contacts in a contacts array successfully."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    mock_send_message_method = AsyncMock(return_value={"id": "contacts_array_msg_id_002"})
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contacts_list = [
        {"contact_jid": "user1@s.whatsapp.net", "name": "User One", "phone_number": "+111222333"},
        {"contact_jid": "user2@other.domain", "name": "User Two", "phone_number": "444555666"},
        # Non-WA JID, number only
    ]

    result = await client.send_contacts(JID.from_string(to_jid_str), contacts_list)

    mock_send_message_method.assert_awaited_once()
    call_args = mock_send_message_method.call_args
    sent_to_jid, sent_message_proto = call_args.args

    assert sent_to_jid == JID.from_string(to_jid_str)
    assert hasattr(sent_message_proto, "contactsArrayMessage")
    array_msg = sent_message_proto.contactsArrayMessage
    assert len(array_msg.contacts) == 2

    # Contact 1
    contact1_proto = array_msg.contacts[0]
    assert contact1_proto.displayName == contacts_list[0]["name"]
    contact1_jid_obj = JID.from_string(contacts_list[0]["contact_jid"])
    contact1_waid_phone = "".join(filter(str.isdigit, contacts_list[0]["phone_number"]))
    expected_vcard1 = (
        f"BEGIN:VCARD\nVERSION:3.0\nFN:{contacts_list[0]['name']}\n"
        f"TEL;type=CELL;type=VOICE;waid={contact1_jid_obj.user}:{contact1_waid_phone}\nEND:VCARD"
    )
    assert contact1_proto.vcard == expected_vcard1

    # Contact 2
    contact2_proto = array_msg.contacts[1]
    assert contact2_proto.displayName == contacts_list[1]["name"]
    contact2_jid_obj = JID.from_string(contacts_list[1]["contact_jid"])
    contact2_waid_phone = "".join(filter(str.isdigit, contacts_list[1]["phone_number"]))
    expected_vcard2 = (
        f"BEGIN:VCARD\nVERSION:3.0\nFN:{contacts_list[1]['name']}\n"
        f"TEL;type=CELL;type=VOICE;waid={contact2_jid_obj.user}:{contact2_waid_phone}\nEND:VCARD"
    )
    assert contact2_proto.vcard == expected_vcard2

    assert result == {"id": "contacts_array_msg_id_002"}


@pytest.mark.asyncio
async def test_send_contacts_empty_list():
    """Test sending an empty list of contacts."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    mock_send_message_method = AsyncMock(return_value={"id": "contacts_array_msg_id_003"})
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contacts_list = []

    result = await client.send_contacts(JID.from_string(to_jid_str), contacts_list)

    mock_send_message_method.assert_awaited_once()
    call_args = mock_send_message_method.call_args
    sent_to_jid, sent_message_proto = call_args.args

    assert sent_to_jid == JID.from_string(to_jid_str)
    assert hasattr(sent_message_proto, "contactsArrayMessage")
    array_msg = sent_message_proto.contactsArrayMessage
    assert len(array_msg.contacts) == 0
    assert result == {"id": "contacts_array_msg_id_003"}


@pytest.mark.asyncio
async def test_send_contacts_send_message_fails():
    """Test that send_contacts propagates errors from send_message."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    mock_send_message_method = AsyncMock(side_effect=PymeowError("Send contacts array failed"))
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contacts_list = [{"contact_jid": "user1@s.whatsapp.net", "name": "User One", "phone_number": "+111222333"}]

    with pytest.raises(PymeowError, match="Send contacts array failed"):
        await client.send_contacts(JID.from_string(to_jid_str), contacts_list)

    mock_send_message_method.assert_awaited_once()

    # Inspect the arguments passed to send_message
    # send_message(self, to: JID, message: WAWebMessage, **kwargs)
    call_args = mock_send_message_method.call_args
    assert call_args is not None

    sent_to_jid, sent_message_proto = call_args.args

    assert sent_to_jid == JID.from_string(chat_jid_str)

    # Verify the structure of the sent message protobuf for reply
    # This requires knowledge of how WAWebMessage is structured for replies
    # (usually an ExtendedTextMessage with ContextInfo)
    # For now, checking top-level fields based on how send_reply constructs it.
    # WAWebMessage(extendedTextMessage=ExtendedTextMessage(...))
    assert hasattr(sent_message_proto, "extendedTextMessage")
    ext_text_msg = sent_message_proto.extendedTextMessage
    assert ext_text_msg.text == reply_content

    assert hasattr(ext_text_msg, "contextInfo")
    context_info = ext_text_msg.contextInfo
    assert context_info.stanzaId == mock_stanza_id
    assert context_info.participant == str(mock_participant_jid)
    assert context_info.quotedMessage == mock_quoted_message_proto

    # Assert the final result
    assert result == {"id": "reply_msg_id_123"}


@pytest.mark.asyncio
async def test_send_reply_get_quoted_ui_elements_fails():
    """Test that send_reply handles errors from _get_quoted_ui_elements."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    # Mock _get_quoted_ui_elements to raise an error
    mock_get_quoted_elements = AsyncMock(side_effect=PymeowError("Failed to get quoted elements"))
    client._get_quoted_ui_elements = mock_get_quoted_elements

    # Mock send_message (should not be called)
    mock_send_message_method = AsyncMock()
    client.send_message = mock_send_message_method

    chat_jid_str = "group_chat@g.us"
    to_message_id = "message_to_reply_to_id"
    reply_content = "This reply will fail."

    with pytest.raises(PymeowError, match="Failed to get quoted elements"):
        await client.send_reply(to_message_id=to_message_id, chat_jid=chat_jid_str, content=reply_content)

    mock_get_quoted_elements.assert_awaited_once_with(JID.from_string(chat_jid_str), to_message_id)
    mock_send_message_method.assert_not_called()


@pytest.mark.asyncio
async def test_send_reply_final_send_message_fails():
    """Test that send_reply handles errors from the final send_message call."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()
    client.auth_state.me = JID.from_string("test@s.whatsapp.net")

    # Mocked return values for _get_quoted_ui_elements
    mock_stanza_id = "quoted_message_stanza_id"
    mock_participant_jid = JID.from_string("participant@s.whatsapp.net")
    mock_quoted_message_proto = MagicMock(spec_set=["SerializeToString"])

    # Mock _get_quoted_ui_elements
    mock_get_quoted_elements = AsyncMock(return_value=(mock_stanza_id, mock_participant_jid, mock_quoted_message_proto))
    client._get_quoted_ui_elements = mock_get_quoted_elements

    # Mock send_message to raise an error
    mock_send_message_method = AsyncMock(side_effect=PymeowError("Final send failed"))
    client.send_message = mock_send_message_method

    chat_jid_str = "group_chat@g.us"
    to_message_id = "message_to_reply_to_id"
    reply_content = "This reply will also fail."

    with pytest.raises(PymeowError, match="Final send failed"):
        await client.send_reply(to_message_id=to_message_id, chat_jid=chat_jid_str, content=reply_content)

    mock_get_quoted_elements.assert_awaited_once_with(JID.from_string(chat_jid_str), to_message_id)
    mock_send_message_method.assert_awaited_once()  # It will be called before raising the error


@pytest.mark.asyncio
async def test_send_contact_success():
    """Test sending a single contact successfully."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")
    client.auth_state = MagicMock()  # Not strictly needed unless send_message relies on it.

    mock_send_message_method = AsyncMock(return_value={"id": "contact_msg_id_123"})
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contact_jid_str = "contact_to_send@s.whatsapp.net"  # JID of the contact
    name = "John Doe"
    phone_number = "+1 555-1234"  # Display phone number for vCard

    # The send_contact method might internally parse contact_jid_str to get the user part for waid
    contact_jid_obj = JID.from_string(contact_jid_str)

    expected_vcard = (
        f"BEGIN:VCARD\n"
        f"VERSION:3.0\n"
        f"FN:{name}\n"
        f"TEL;type=CELL;type=VOICE;waid={contact_jid_obj.user}:{phone_number}\n"  # Note: phone_number might be without '+' or spaces internally
        f"END:VCARD"
    )
    # Let's re-evaluate expected_vcard based on actual implementation of _build_vcard
    # _build_vcard(self, name: str, phone_number: str, contact_jid: JID)
    # It seems to strip non-digits from phone_number for the waid part.

    # Re-checking _build_vcard in client.py:
    # def _build_vcard(self, name: str, phone_number: str, contact_jid: JID) -> str:
    #     waid_phone = "".join(filter(str.isdigit, phone_number))
    #     vcard = (
    #         f"BEGIN:VCARD\nVERSION:3.0\nFN:{name}\n"
    #         f"TEL;type=CELL;type=VOICE;waid={contact_jid.user}:{waid_phone}\nEND:VCARD"
    #     )
    # So, the expected waid_phone should be "15551234"

    waid_phone_expected = "".join(filter(str.isdigit, phone_number))
    expected_vcard_revised = (
        f"BEGIN:VCARD\n"
        f"VERSION:3.0\n"
        f"FN:{name}\n"
        f"TEL;type=CELL;type=VOICE;waid={contact_jid_obj.user}:{waid_phone_expected}\n"
        f"END:VCARD"
    )

    result = await client.send_contact(JID.from_string(to_jid_str), contact_jid_str, name, phone_number)

    mock_send_message_method.assert_awaited_once()
    call_args = mock_send_message_method.call_args
    assert call_args is not None

    sent_to_jid, sent_message_proto = call_args.args
    assert sent_to_jid == JID.from_string(to_jid_str)

    assert hasattr(sent_message_proto, "contactMessage")
    contact_msg = sent_message_proto.contactMessage
    assert contact_msg.displayName == name
    assert contact_msg.vcard == expected_vcard_revised

    assert result == {"id": "contact_msg_id_123"}


@pytest.mark.asyncio
async def test_send_contact_send_message_fails():
    """Test that send_contact propagates errors from send_message."""
    client = Client(JID.from_string("test@s.whatsapp.net"), "test_password")

    mock_send_message_method = AsyncMock(side_effect=PymeowError("Send contact failed"))
    client.send_message = mock_send_message_method

    to_jid_str = "recipient@s.whatsapp.net"
    contact_jid_str = "contact_to_send@s.whatsapp.net"
    name = "John Doe"
    phone_number = "+1 555-1234"

    with pytest.raises(PymeowError, match="Send contact failed"):
        await client.send_contact(JID.from_string(to_jid_str), contact_jid_str, name, phone_number)

    mock_send_message_method.assert_awaited_once()
