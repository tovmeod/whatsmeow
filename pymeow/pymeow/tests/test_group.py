import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pymeow.client import Client
from pymeow.exceptions import PymeowError, ErrIQTimedOut
from pymeow.datatypes.jid import JID
from pymeow.binary.node import Node  # For constructing mock response nodes


@pytest.mark.usefixtures("event_loop")  # Assuming event_loop is from pytest-asyncio
class TestGroupManagement:
    @pytest.mark.asyncio
    async def test_create_group_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        subject = "Test Group Subject"
        participant_jids_str = ["participant1@s.whatsapp.net", "participant2@s.whatsapp.net"]

        # Prepare mock success response
        mock_group_id = "newgroup@g.us"
        mock_creator_jid_str = str(my_jid)  # Creator is the client user
        mock_creation_time = "1678886400"

        mock_resp_group_node = Node(
            "group",
            {
                "id": mock_group_id,
                "creator": mock_creator_jid_str,
                "creation": mock_creation_time,
                "subject": subject,
                "s_t": "subject_timestamp",  # subject_owner and subject_timestamp might be present
                "s_o": mock_creator_jid_str,
            },
        )
        # Simulate participants being returned in the response (though create_group might not use this part)
        # The actual create_group only parses attributes of the main <group> node.
        mock_success_node = Node(
            "iq", {"type": "result", "id": "some_iq_id", "to": str(my_jid)}, [mock_resp_group_node]
        )
        mock_send_node_iq.return_value = mock_success_node

        result = await client.create_group(subject, participant_jids_str)

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_group_participants_no_participants_node_in_response(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        actions = [{"action": "add", "jid": "add_me@s.whatsapp.net"}]

        # Successful IQ, but no <participants> child node
        mock_empty_success_node = Node(
            "iq", {"type": "result", "from": JID.from_string(group_jid_str).to_string(), "id": "update_empty_ack"}
        )
        mock_send_node_iq.return_value = mock_empty_success_node

        # The current implementation of _parse_group_participants_response would return an empty list
        # if resp_participants_node is None. This test verifies that behavior.
        results = await client.update_group_participants(group_jid_str, actions)
        assert results == []

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_group_participants_malformed_participant_in_response(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        actions = [
            {"action": "add", "jid": "add_me@s.whatsapp.net"},
            {"action": "remove", "jid": "remove_me@s.whatsapp.net"},
        ]

        # Mock response where one participant node is missing 'jid', another missing 'code'
        mock_resp_participants_children = [
            Node(
                "add",
                {},
                [
                    Node("participant", {"code": "200"}),  # Missing jid
                    Node("participant", {"jid": "add_ok@s.whatsapp.net", "code": "200"}),  # Valid
                ],
            ),
            Node(
                "remove",
                {},
                [
                    Node("participant", {"jid": "remove_me@s.whatsapp.net"}),  # Missing code
                ],
            ),
        ]
        mock_resp_participants_node = Node("participants", {}, mock_resp_participants_children)
        mock_malformed_response_node = Node(
            "iq",
            {"type": "result", "from": JID.from_string(group_jid_str).to_string(), "id": "update_malformed_ack"},
            [mock_resp_participants_node],
        )
        mock_send_node_iq.return_value = mock_malformed_response_node

        results = await client.update_group_participants(group_jid_str, actions)

        # The parser _parse_group_participants_response skips participants if jid or code is missing.
        # It logs a warning but continues.
        assert len(results) == 1  # Only the valid participant should be parsed.
        assert results[0]["jid"] == JID.from_string("add_ok@s.whatsapp.net")
        assert results[0]["status_code"] == 200
        assert results[0]["action"] == "add"

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_group_participants_success_all_actions(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)

        actions = [
            {"action": "add", "jid": "add@s.whatsapp.net"},
            {"action": "remove", "jid": "remove@s.whatsapp.net"},
            {"action": "promote", "jid": "promote@s.whatsapp.net"},
            {"action": "demote", "jid": "demote@s.whatsapp.net"},
        ]

        # Prepare mock success response
        mock_resp_participants_children = [
            Node("add", {}, [Node("participant", {"jid": "add@s.whatsapp.net", "code": "200"})]),
            Node("remove", {}, [Node("participant", {"jid": "remove@s.whatsapp.net", "code": "200"})]),
            Node(
                "promote", {}, [Node("participant", {"jid": "promote@s.whatsapp.net", "code": "200", "admin": "true"})]
            ),
            Node(
                "demote", {}, [Node("participant", {"jid": "demote@s.whatsapp.net", "code": "200", "admin": "false"})]
            ),
        ]
        mock_resp_participants_node = Node("participants", {}, mock_resp_participants_children)
        mock_success_node = Node(
            "iq", {"type": "result", "from": str(group_jid_obj), "id": "update_ack"}, [mock_resp_participants_node]
        )
        mock_send_node_iq.return_value = mock_success_node

        results = await client.update_group_participants(group_jid_str, actions)

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == str(group_jid_obj)
        assert req_node.attrs["type"] == "set"

        participants_req_node = req_node.child_by_tag("participants")
        assert participants_req_node is not None
        assert len(participants_req_node.children) == len(actions)

        # Check request node structure for each action
        action_tags_in_req = {child.tag for child in participants_req_node.children}
        assert action_tags_in_req == {"add", "remove", "promote", "demote"}

        for i, action_details in enumerate(actions):
            action_req_node = participants_req_node.child_by_tag(action_details["action"])
            assert action_req_node is not None
            participant_child_in_action = action_req_node.child_by_tag("participant")
            assert participant_child_in_action is not None
            assert participant_child_in_action.attrs["jid"] == JID.from_string(action_details["jid"]).to_string()
            # Request nodes for promote/demote do not have 'admin' attribute
            if action_details["action"] in ["promote", "demote"]:
                assert "admin" not in participant_child_in_action.attrs

                # Assert results
        assert len(results) == len(actions)
        expected_results = [
            {
                "jid": JID.from_string("add@s.whatsapp.net"),
                "action": "add",
                "status_code": 200,
                "error_text": None,
                "admin": None,
            },
            {
                "jid": JID.from_string("remove@s.whatsapp.net"),
                "action": "remove",
                "status_code": 200,
                "error_text": None,
                "admin": None,
            },
            {
                "jid": JID.from_string("promote@s.whatsapp.net"),
                "action": "promote",
                "status_code": 200,
                "error_text": None,
                "admin": "true",
            },
            {
                "jid": JID.from_string("demote@s.whatsapp.net"),
                "action": "demote",
                "status_code": 200,
                "error_text": None,
                "admin": "false",
            },
        ]
        for i, res in enumerate(results):
            assert res["jid"] == expected_results[i]["jid"]
            assert res["action"] == expected_results[i]["action"]
            assert res["status_code"] == expected_results[i]["status_code"]
            assert res["error_text"] == expected_results[i]["error_text"]
            assert (
                res.get("admin") == expected_results[i]["admin"]
            )  # Use .get for admin as it might not always be present

    @pytest.mark.asyncio
    async def test_update_group_participants_partial_success_mixed_codes(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)

        # Only testing 'add' and 'promote' for brevity, covering success and failure cases
        actions = [
            {"action": "add", "jid": "add_ok@s.whatsapp.net"},
            {"action": "add", "jid": "add_fail_403@s.whatsapp.net"},  # Will fail with 403
            {"action": "promote", "jid": "promote_ok@s.whatsapp.net"},
            {"action": "promote", "jid": "promote_fail_404@s.whatsapp.net"},  # Will fail with 404
        ]

        # Prepare mock response with mixed status codes
        mock_resp_participants_children = [
            Node(
                "add",
                {},
                [
                    Node("participant", {"jid": "add_ok@s.whatsapp.net", "code": "200"}),
                    Node(
                        "participant",
                        {"jid": "add_fail_403@s.whatsapp.net", "code": "403"},
                        [Node("error", {"text": "Not allowed"})],
                    ),
                ],
            ),
            Node(
                "promote",
                {},
                [
                    Node("participant", {"jid": "promote_ok@s.whatsapp.net", "code": "200", "admin": "true"}),
                    Node(
                        "participant",
                        {"jid": "promote_fail_404@s.whatsapp.net", "code": "404"},
                        [Node("error", {"text": "Not found"})],
                    ),
                ],
            ),
        ]
        mock_resp_participants_node = Node("participants", {}, mock_resp_participants_children)
        mock_success_node = Node(
            "iq",
            {"type": "result", "from": str(group_jid_obj), "id": "update_ack_partial"},
            [mock_resp_participants_node],
        )
        mock_send_node_iq.return_value = mock_success_node

        results = await client.update_group_participants(group_jid_str, actions)

        mock_send_node_iq.assert_awaited_once()
        # Request node structure validation is omitted for brevity, assumed covered by the "all_actions_success" test.

        assert len(results) == len(actions)
        # The number of results should match the number of participants in the response,
        # which might be different from len(actions) if the server groups them.
        # _parse_group_participants_response creates one entry per <participant> node.
        # So, len(results) should be 4 in this case.

        expected_results_data = [
            {"jid_str": "add_ok@s.whatsapp.net", "action": "add", "code": 200, "error": None, "admin": None},
            {
                "jid_str": "add_fail_403@s.whatsapp.net",
                "action": "add",
                "code": 403,
                "error": "Not allowed",
                "admin": None,
            },
            {"jid_str": "promote_ok@s.whatsapp.net", "action": "promote", "code": 200, "error": None, "admin": "true"},
            {
                "jid_str": "promote_fail_404@s.whatsapp.net",
                "action": "promote",
                "code": 404,
                "error": "Not found",
                "admin": None,
            },  # promote fail, admin might be absent or false
        ]

        # Flatten the results for easier comparison if actions are grouped in response
        # (which they are in this mock: one "add" node with two participants, one "promote" with two)

        assert len(results) == len(expected_results_data)

        for i, res_data in enumerate(expected_results_data):
            assert results[i]["jid"] == JID.from_string(res_data["jid_str"])
            assert results[i]["action"] == res_data["action"]
            assert results[i]["status_code"] == res_data["code"]
            assert results[i]["error_text"] == res_data["error"]
            # For a failed promote, the 'admin' status might not be present or could be 'false'
            # The current parsing logic sets admin status only if code is 200.
            if res_data["code"] == 200 and res_data["action"] == "promote":
                assert results[i].get("admin") == "true"
            elif res_data["code"] != 200 and res_data["action"] == "promote":
                assert results[i].get("admin") is None  # Or based on how parser handles failed promote
            else:
                assert results[i].get("admin") == res_data["admin"]

    @pytest.mark.asyncio
    async def test_update_group_participants_iq_error(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        actions = [{"action": "add", "jid": "add_me@s.whatsapp.net"}]

        mock_error_content_node = Node("error", {"code": "500", "text": "Internal Server Error"})
        mock_iq_error_node = Node(
            "iq",
            {"type": "error", "from": JID.from_string(group_jid_str).to_string(), "id": "update_err_ack"},
            [mock_error_content_node],
        )
        mock_send_node_iq.return_value = mock_iq_error_node

        with pytest.raises(PymeowError, match=r"Failed to update group participants.*code 500.*Internal Server Error"):
            await client.update_group_participants(group_jid_str, actions)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_update_group_participants_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock(side_effect=ErrIQTimedOut("Timeout updating participants"))
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        actions = [{"action": "add", "jid": "add_me_timeout@s.whatsapp.net"}]

        with pytest.raises(ErrIQTimedOut, match="Timeout updating participants"):
            await client.update_group_participants(group_jid_str, actions)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_description_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()  # For consistency
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        # Mock id_generator
        mock_generated_desc_id = "client_generated_desc_id_123"
        client.id_generator = MagicMock()
        client.id_generator.generate_id = MagicMock(return_value=mock_generated_desc_id)

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)
        description_text = "This is a new group description."

        # Prepare mock success response
        mock_server_desc_id = "server_returned_desc_id_456"  # Server can return its own ID for the description
        mock_timestamp = "1679000000"
        mock_resp_desc_node = Node("description", {"id": mock_server_desc_id, "time": mock_timestamp, "type": "text"})
        mock_success_response_node = Node(
            "iq", {"type": "result", "id": "set_desc_ack", "from": str(group_jid_obj)}, [mock_resp_desc_node]
        )
        mock_send_node_iq.return_value = mock_success_response_node

        result = await client.set_group_description(group_jid_str, description_text)

        # Assert id_generator was called
        client.id_generator.generate_id.assert_called_once()

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == str(group_jid_obj)
        assert req_node.attrs["type"] == "set"

        desc_node_req = req_node.child_by_tag("description")
        assert desc_node_req is not None
        assert desc_node_req.attrs["id"] == mock_generated_desc_id
        assert desc_node_req.content == description_text.encode("utf-8")

        # Assert the returned dictionary
        assert result["id"] == mock_server_desc_id
        assert result["time"] == int(mock_timestamp)
        assert result.get("type") == "text"  # from mock_resp_desc_node

    @pytest.mark.asyncio
    async def test_set_group_description_api_error(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_generated_desc_id = "client_generated_desc_id_err"
        client.id_generator = MagicMock()
        client.id_generator.generate_id = MagicMock(return_value=mock_generated_desc_id)

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        description_text = "This will fail."

        mock_error_content_node = Node("error", {"code": "403", "text": "Not allowed"})
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to set group description.*code 403.*Not allowed"):
            await client.set_group_description(group_jid_str, description_text)

        client.id_generator.generate_id.assert_called_once()
        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_description_no_desc_node_in_response(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_generated_desc_id = "client_gen_id_no_desc_node"
        client.id_generator = MagicMock()
        client.id_generator.generate_id = MagicMock(return_value=mock_generated_desc_id)

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        description_text = "Response will lack desc node."

        # Success IQ, but no <description> child
        mock_malformed_success_node = Node("iq", {"type": "result"})
        mock_send_node_iq.return_value = mock_malformed_success_node

        with pytest.raises(PymeowError, match="Invalid response from server when setting group description"):
            await client.set_group_description(group_jid_str, description_text)

        client.id_generator.generate_id.assert_called_once()
        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.parametrize(
        "missing_attr_data",
        [
            ({"time": "1679000000"}),  # Missing 'id'
            ({"id": "server_desc_id"}),  # Missing 'time'
        ],
    )
    @pytest.mark.asyncio
    async def test_set_group_description_desc_node_missing_attrs(self, missing_attr_data):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_generated_desc_id = "client_gen_id_missing_attr"
        client.id_generator = MagicMock()
        client.id_generator.generate_id = MagicMock(return_value=mock_generated_desc_id)

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        description_text = "Response desc node will miss attributes."

        mock_resp_desc_node_malformed = Node("description", missing_attr_data)
        mock_success_node_malformed_child = Node("iq", {"type": "result"}, [mock_resp_desc_node_malformed])
        mock_send_node_iq.return_value = mock_success_node_malformed_child

        with pytest.raises(PymeowError, match="Invalid response from server when setting group description"):
            await client.set_group_description(group_jid_str, description_text)

        client.id_generator.generate_id.assert_called_once()
        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_description_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_generated_desc_id = "client_generated_desc_id_timeout"
        client.id_generator = MagicMock()
        client.id_generator.generate_id = MagicMock(return_value=mock_generated_desc_id)

        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout setting description"))
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        description_text = "This will timeout."

        with pytest.raises(PymeowTimeoutError, match="Timeout setting description"):
            await client.set_group_description(group_jid_str, description_text)

        client.id_generator.generate_id.assert_called_once()
        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_subject_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout setting subject"))
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        new_subject = "Timeout Subject"

        with pytest.raises(PymeowTimeoutError, match="Timeout setting subject"):
            await client.set_group_subject(group_jid_str, new_subject)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_subject_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()  # For consistency
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)
        new_subject = "New Cool Subject!"

        # Prepare mock success response
        mock_success_response_node = Node(
            "iq",
            {
                "type": "result",
                "id": "set_subject_ack",
                "from": str(group_jid_obj),  # Response 'from' is usually the entity actioned upon
            },
        )
        mock_send_node_iq.return_value = mock_success_response_node

        result = await client.set_group_subject(group_jid_str, new_subject)

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == str(group_jid_obj)
        assert req_node.attrs["type"] == "set"

        subject_node = req_node.child_by_tag("subject")
        assert subject_node is not None
        assert subject_node.content == new_subject.encode("utf-8")  # Content should be bytes

        assert result is True

    @pytest.mark.parametrize(
        "error_code, error_text, expected_message_regex",
        [
            ("400", "bad-request", r"Cannot set group subject: Bad request \(400\)"),
            ("400", "subject_too_long", r"Cannot set group subject: Subject too long \(400\)"),
            ("401", "not-authorized", r"Cannot set group subject: Not authorized \(401\)"),
            ("403", "forbidden", r"Cannot set group subject: Forbidden, only admins can set subject \(403\)"),
            ("403", "linked-device-forbidden", r"Cannot set group subject: Linked device forbidden \(403\)"),
            ("406", "not-acceptable", r"Cannot set group subject: Not acceptable \(406\)"),
            # e.g. group not found by that JID
            ("408", "request-timeout", r"Cannot set group subject: Request timeout \(408\)"),
            ("500", "internal-server-error", r"Cannot set group subject: Server error \(500\)"),
        ],
    )
    @pytest.mark.asyncio
    async def test_set_group_subject_api_error_specific_codes(self, error_code, error_text, expected_message_regex):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        new_subject = "A Subject"

        mock_error_content_node = Node("error", {"code": error_code, "text": error_text})
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=expected_message_regex):
            await client.set_group_subject(group_jid_str, new_subject)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_set_group_subject_api_error_generic(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        new_subject = "Generic Error Subject"

        mock_error_content_node = Node("error", {"code": "405", "text": "Method Not Allowed"})  # Generic error
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to set group subject.*code 405.*Method Not Allowed"):
            await client.set_group_subject(group_jid_str, new_subject)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_leave_group_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout leaving group"))
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        with pytest.raises(PymeowTimeoutError, match="Timeout leaving group"):
            await client.leave_group(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_leave_group_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        # Mocking auth_state for consistency, though not directly used by leave_group's core logic
        # beyond what _send_node_with_iq_response might implicitly use (e.g. 'from' field in IQ).
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)

        # Prepare mock success response
        # A simple <iq type="result" from="g.us" id="..."> is enough.
        mock_success_response_node = Node(
            "iq",
            {
                "type": "result",
                "id": "leave_iq_ack",
                "from": str(JID.from_string("g.us")),  # 'from' is usually the entity that processed it
            },
        )
        mock_send_node_iq.return_value = mock_success_response_node

        result = await client.leave_group(group_jid_str)

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == "g.us"  # Target for group operations
        assert req_node.attrs["type"] == "set"

        leave_node = req_node.child_by_tag("leave")
        assert leave_node is not None

        group_node_in_leave = leave_node.child_by_tag("group")
        assert group_node_in_leave is not None
        assert group_node_in_leave.attrs["id"] == str(group_jid_obj)  # JID should be string here

        assert result is True

    @pytest.mark.parametrize(
        "error_code, error_text, expected_message_regex",
        [
            ("401", "not-authorized", r"Cannot leave group: Not authorized \(401\)"),
            ("403", "forbidden", r"Cannot leave group: Forbidden \(403\)"),
            ("404", "item-not-found", r"Cannot leave group: Group not found \(404\)"),
            # 'item-not-found' is common for 404
            ("404", "not-found", r"Cannot leave group: Group not found \(404\)"),  # Also covering 'not-found'
            ("406", "not-acceptable", r"Cannot leave group: Not acceptable \(406\)"),  # Not an admin / last admin
            ("500", "internal-server-error", r"Cannot leave group: Server error \(500\)"),
        ],
    )
    @pytest.mark.asyncio
    async def test_leave_group_api_error_specific_codes(self, error_code, error_text, expected_message_regex):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        mock_error_content_node = Node("error", {"code": error_code, "text": error_text})
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=expected_message_regex):
            await client.leave_group(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_leave_group_api_error_generic(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        mock_error_content_node = Node("error", {"code": "400", "text": "Bad Request"})  # Generic error
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to leave group.*code 400.*Bad Request"):
            await client.leave_group(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_join_group_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout joining group"))
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "TIMEOUTCODE"

        with pytest.raises(PymeowTimeoutError, match="Timeout joining group"):
            await client.join_group(invite_code)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_join_group_no_group_node_in_response(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "NOGROUPNODECODE"

        mock_success_no_group_node = Node("iq", {"type": "result"})  # No child 'group' node
        mock_send_node_iq.return_value = mock_success_no_group_node

        with pytest.raises(PymeowError, match="No group node in join group response"):
            await client.join_group(invite_code)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_join_group_group_node_missing_id(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "MISSINGIDCODE"

        # Success IQ with <group> child, but <group> node has no 'id' attribute
        mock_group_node_no_id = Node("group", {"subject": "Missing ID Group", "owner": "o", "creation": "1"})
        mock_success_missing_id_node = Node("iq", {"type": "result"}, [mock_group_node_no_id])
        mock_send_node_iq.return_value = mock_success_missing_id_node

        with pytest.raises(PymeowError, match="No group ID in join group response"):  # Or "missing 'id' attribute"
            await client.join_group(invite_code)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_join_group_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        # client.auth_state.me.jid might be used by _send_node_with_iq_response for 'from' in IQ.
        # Mocking it for completeness, though _send_node_with_iq_response is fully mocked.
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "TESTINVITECODE789"

        # Prepare mock success response
        mock_group_id = "joinedgroup@g.us"
        mock_subject = "Joined Group Subject"
        mock_owner_jid_str = "owner@s.whatsapp.net"
        mock_creation_time = "1678880000"

        # The actual response <group> node might have more attributes (e.g. s_t, s_o for subject)
        # and participant children. join_group parses these.
        mock_resp_group_node = Node(
            "group",
            {
                "id": mock_group_id,
                "subject": mock_subject,
                "owner": mock_owner_jid_str,
                "creation": mock_creation_time,
                "s_t": "subject_timestamp",
                "s_o": mock_owner_jid_str,
            },
            [Node("participant", {"jid": mock_owner_jid_str, "type": "admin"})],
        )  # Add a sample participant

        mock_success_node = Node(
            "iq", {"type": "result", "id": "join_iq_id", "to": str(my_jid)}, [mock_resp_group_node]
        )
        mock_send_node_iq.return_value = mock_success_node

        result = await client.join_group(invite_code)

        # Assert _send_node_with_iq_response was called
        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == "g.us"
        assert req_node.attrs["type"] == "set"

        join_node = req_node.child_by_tag("join")
        assert join_node is not None
        assert join_node.attrs["key"] == invite_code

        # Assert the returned dictionary
        assert result["id"] == JID.from_string(mock_group_id)  # join_group returns JID object for id
        assert result["subject"] == mock_subject
        assert result["owner"] == JID.from_string(mock_owner_jid_str)
        assert result["creation"] == int(mock_creation_time)
        assert result["s_t"] == "subject_timestamp"
        assert result["s_o"] == JID.from_string(mock_owner_jid_str)

        assert len(result["participants"]) == 1
        assert result["participants"][0]["jid"] == JID.from_string(mock_owner_jid_str)
        assert result["participants"][0]["type"] == "admin"

    @pytest.mark.parametrize(
        "error_code, error_text, expected_message_regex",
        [
            ("401", "not-authorized", r"Cannot join group: Not authorized \(401\)"),
            ("403", "forbidden", r"Cannot join group: Forbidden \(403\)"),
            ("403", "linked-device-forbidden", r"Cannot join group: Linked device forbidden \(403\)"),
            ("404", "not-found", r"Cannot join group: Group not found \(404\)"),
            ("409", "conflict", r"Cannot join group: Group is full \(409\)"),
            ("409", "locked", r"Cannot join group: Group is locked \(409\)"),
            ("410", "gone", r"Cannot join group: Invite link has been revoked \(410\)"),
            ("500", "internal-server-error", r"Cannot join group: Server error \(500\)"),
        ],
    )
    @pytest.mark.asyncio
    async def test_join_group_api_error_specific_codes(self, error_code, error_text, expected_message_regex):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "FAILINVITECODE"

        mock_error_content_node = Node("error", {"code": error_code, "text": error_text})
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=expected_message_regex):
            await client.join_group(invite_code)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_join_group_api_error_generic(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = JID.from_string("myself@s.whatsapp.net")

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        invite_code = "GENERICERRORCODE"

        mock_error_content_node = Node("error", {"code": "400", "text": "Bad Request"})
        mock_error_response_node = Node("iq", {"type": "error"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to join group.*code 400.*Bad Request"):
            await client.join_group(invite_code)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_group_invite_link_no_invite_node_in_response(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        # Success IQ, but no <invite> child
        mock_malformed_success_node = Node("iq", {"type": "result"})
        mock_send_node_iq.return_value = mock_malformed_success_node

        with pytest.raises(
            PymeowError, match="No invite code in response"
        ):  # Or "No invite node..." depending on exact error
            await client.get_group_invite_link(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_group_invite_link_no_code_in_invite_node(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        # Success IQ with <invite> child, but <invite> node has no 'code' attribute
        mock_resp_invite_node_no_code = Node("invite", {"expiration": "1679999999"})  # No 'code'
        mock_malformed_invite_node = Node("iq", {"type": "result"}, [mock_resp_invite_node_no_code])
        mock_send_node_iq.return_value = mock_malformed_invite_node

        with pytest.raises(PymeowError, match="No invite code in response"):
            await client.get_group_invite_link(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_group_invite_link_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        # No auth_state.me.jid needed for this specific client method directly,
        # but _send_node_with_iq_response might use it for 'from' in IQ.
        # For now, assuming _send_node_with_iq_response is fully mocked.

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)

        mock_invite_code = "SAMPLEINVITECODE123"
        mock_resp_invite_node = Node("invite", {"code": mock_invite_code, "expiration": "1679999999"})
        # The actual response structure might be <iq><query type="invite" code="..." .../></iq>
        # Based on client.py: resp_node = await self._send_node_with_iq_response(req_node)
        # invite_node = resp_node.child_by_tag("invite")
        # So, the mocked response node should be an <iq> node with <invite> as child.
        mock_success_node = Node(
            "iq", {"type": "result", "id": "some_iq_id", "to": str(client.jid)}, [mock_resp_invite_node]
        )
        mock_send_node_iq.return_value = mock_success_node

        expected_link = f"https://chat.whatsapp.com/{mock_invite_code}"

        result_link = await client.get_group_invite_link(group_jid_str, reset=False)

        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == str(group_jid_obj)
        assert req_node.attrs["type"] == "get"

        invite_req_child_node = req_node.child_by_tag("invite")
        assert invite_req_child_node is not None
        assert "action" not in invite_req_child_node.attrs  # No action for 'get'

        assert result_link == expected_link

    @pytest.mark.asyncio
    async def test_get_group_invite_link_reset_success(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"
        group_jid_obj = JID.from_string(group_jid_str)

        mock_new_invite_code = "NEWINVITECODE456"
        mock_resp_invite_node_reset = Node("invite", {"code": mock_new_invite_code, "expiration": "1689999999"})
        mock_success_node_reset = Node(
            "iq", {"type": "result"}, [mock_resp_invite_node_reset]
        )  # Corrected: Removed client.jid from 'to'
        mock_send_node_iq.return_value = mock_success_node_reset

        expected_link = f"https://chat.whatsapp.com/{mock_new_invite_code}"

        result_link = await client.get_group_invite_link(group_jid_str, reset=True)

        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == str(group_jid_obj)
        assert req_node.attrs["type"] == "set"  # Type is 'set' for actions like 'reset'

        invite_req_child_node = req_node.child_by_tag("invite")
        assert invite_req_child_node is not None
        assert invite_req_child_node.attrs.get("action") == "reset"

        assert result_link == expected_link

    @pytest.mark.asyncio
    async def test_get_group_invite_link_api_error(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        mock_error_content_node = Node("error", {"code": "403", "text": "Not allowed"})
        mock_error_response_node = Node(
            "iq", {"type": "error"}, [mock_error_content_node]
        )  # Removed id and to for simplicity in mock
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to get group invite link.*code 403.*Not allowed"):
            await client.get_group_invite_link(group_jid_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_get_group_invite_link_timeout(self):
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout getting invite link"))
        client._send_node_with_iq_response = mock_send_node_iq

        group_jid_str = "testgroup@g.us"

        with pytest.raises(PymeowTimeoutError, match="Timeout getting invite link"):
            await client.get_group_invite_link(group_jid_str)

        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        assert call_args is not None

        req_node = call_args.args[0]  # The first argument is the request node

        assert req_node.tag == "iq"
        assert req_node.attrs["to"] == "g.us"
        assert req_node.attrs["type"] == "set"

        group_action_node = req_node.child_by_tag("group")
        assert group_action_node is not None
        assert group_action_node.attrs["action"] == "create"
        assert group_action_node.attrs["subject"] == subject

        # Verify participants in the request node
        # Participants should include the client's JID + provided JIDs (if not duplicate)
        expected_participant_jids_in_node = {my_jid}
        for p_str in participant_jids_str:
            expected_participant_jids_in_node.add(JID.from_string(p_str))

        sent_participant_nodes = group_action_node.children_by_tag("participant")
        assert len(sent_participant_nodes) == len(expected_participant_jids_in_node)

        found_jids_in_req_node = set()
        for p_node in sent_participant_nodes:
            found_jids_in_req_node.add(JID.from_string(p_node.attrs["jid"]))

        assert found_jids_in_req_node == expected_participant_jids_in_node

        # Assert the returned dictionary
        assert result["id"] == mock_group_id
        assert result["subject"] == subject
        assert result["creator"] == JID.from_string(mock_creator_jid_str)
        assert result["creation_time"] == int(mock_creation_time)
        assert result["participants"] is not None  # create_group adds this key
        # The actual participants list in the result comes from parsing the <group> node's children
        # if they exist in the response. The provided mock_resp_group_node has no children.
        # The code for create_group initializes result["participants"] = [] and then fills it.
        # If the response <group> node has <participant> children, they are parsed.
        # Our current mock_resp_group_node doesn't have participant children, so this should be empty.
        assert result["participants"] == []  # Based on current mock_resp_group_node
        assert result["subject_timestamp"] == "subject_timestamp"
        assert result["subject_owner"] == JID.from_string(mock_creator_jid_str)

    @pytest.mark.asyncio
    async def test_create_group_only_self_as_participant(self):
        """Test creating a group where only the client user is a participant initially."""
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        subject = "Solo Group"
        participant_jids_str = []  # Empty list, or could be [str(my_jid)]

        # Mock response (similar to success case)
        mock_group_id = "solo_group@g.us"
        mock_creator_jid_str = str(my_jid)
        mock_creation_time = "1678886401"
        mock_resp_group_node = Node(
            "group",
            {
                "id": mock_group_id,
                "creator": mock_creator_jid_str,
                "creation": mock_creation_time,
                "subject": subject,
                "s_t": "st",
                "s_o": mock_creator_jid_str,
            },
        )
        mock_success_node = Node("iq", {"type": "result"}, [mock_resp_group_node])
        mock_send_node_iq.return_value = mock_success_node

        await client.create_group(subject, participant_jids_str)

        mock_send_node_iq.assert_awaited_once()
        call_args = mock_send_node_iq.call_args
        req_node = call_args.args[0]

        group_action_node = req_node.child_by_tag("group")
        assert group_action_node is not None

        # Verify participants in the request node - should only be the client's JID
        sent_participant_nodes = group_action_node.children_by_tag("participant")
        assert len(sent_participant_nodes) == 1
        assert sent_participant_nodes[0].attrs["jid"] == str(my_jid)

    @pytest.mark.asyncio
    async def test_create_group_api_error_response(self):
        """Test group creation failure due to API error response."""
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        subject = "Error Group"
        participant_jids_str = ["participant1@s.whatsapp.net"]

        # Prepare mock error response
        mock_error_content_node = Node("error", {"code": "500", "text": "Internal Server Error"})
        mock_error_response_node = Node("iq", {"type": "error", "id": "some_iq_id"}, [mock_error_content_node])
        mock_send_node_iq.return_value = mock_error_response_node

        with pytest.raises(PymeowError, match=r"Failed to create group.*code 500.*Internal Server Error"):
            await client.create_group(subject, participant_jids_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_group_timeout(self):
        """Test group creation failure due to timeout."""
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock(side_effect=PymeowTimeoutError("Timeout creating group"))
        client._send_node_with_iq_response = mock_send_node_iq

        subject = "Timeout Group"
        participant_jids_str = ["participant1@s.whatsapp.net"]

        with pytest.raises(PymeowTimeoutError, match="Timeout creating group"):
            await client.create_group(subject, participant_jids_str)

        mock_send_node_iq.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_create_group_no_group_node_in_response(self):
        """Test group creation failure due to missing group node in success response."""
        client = Client(JID.from_string("testclient@s.whatsapp.net"), "testpassword")
        client.auth_state = MagicMock()
        my_jid = JID.from_string("myself@s.whatsapp.net")
        client.auth_state.me = MagicMock()
        client.auth_state.me.jid = my_jid

        mock_send_node_iq = AsyncMock()
        client._send_node_with_iq_response = mock_send_node_iq

        subject = "No Group Node Group"
        participant_jids_str = ["participant1@s.whatsapp.net"]

        # Prepare mock success response but without the <group> child
        mock_empty_success_node = Node("iq", {"type": "result", "id": "some_iq_id"})
        mock_send_node_iq.return_value = mock_empty_success_node

        with pytest.raises(PymeowError, match="No group node in create group response"):
            await client.create_group(subject, participant_jids_str)

        mock_send_node_iq.assert_awaited_once()
