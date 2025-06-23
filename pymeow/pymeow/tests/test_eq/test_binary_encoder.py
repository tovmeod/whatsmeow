"""
Test binary encoder equivalence between Go and Python implementations.

This module tests that the Python binary encoder produces identical output
to the Go binary encoder by comparing encoder.writeNode().getData() output.
"""

from typing import Any, Dict

import pytest

from pymeow.binary.encoder import BinaryEncoder as PyBinaryEncoder
from pymeow.binary.node import Node, marshal
from pymeow.tests.test_eq.go_wrappers.binary.encoder import write_node_get_data


class TestBinaryEncoderEquivalence:
    """Test binary encoder equivalence between Go and Python"""

    @pytest.fixture
    def py_encoder(self):
        """Initialize Python encoder"""
        return PyBinaryEncoder()

    @pytest.mark.parametrize(
        "node_data",
        [
            {"tag": "iq", "attrs": {"id": "1234", "type": "get"}, "content": None},
            {"tag": "message", "attrs": {"to": "1234567890@s.whatsapp.net", "type": "text"}, "content": "Hello World"},
            {"tag": "presence", "attrs": {"type": "available"}, "content": None},
            {
                "tag": "0",  # Empty list case
                "attrs": {},
                "content": None,
            },
        ],
    )
    def test_encoder_write_node_get_data_equivalence(self, py_encoder: PyBinaryEncoder, node_data: Dict[str, Any]):
        """Test that Python and Go encoder writeNode().getData() produce identical output"""
        # Get Go result using encoder.writeNode().getData()
        go_result = write_node_get_data(node_data)

        # Get Python result
        python_node = Node(tag=node_data["tag"], attrs=node_data.get("attrs", {}), content=node_data.get("content"))

        py_encoder.write_node(python_node)
        python_result = py_encoder.get_data()

        # Compare binary data
        assert go_result == python_result, f"Go: {go_result.hex()}, Python: {python_result.hex()}"

    @pytest.mark.parametrize(
        "node_data",
        [
            {"tag": "iq", "attrs": {"id": "1234", "type": "get"}, "content": None},
            {"tag": "message", "attrs": {"to": "1234567890@s.whatsapp.net", "type": "text"}, "content": "Hello World"},
            {"tag": "presence", "attrs": {"type": "available"}, "content": None},
        ],
    )
    def test_python_marshal_vs_go_encoder(self, node_data: Dict[str, Any]):
        """Test that Python marshal function produces same output as Go encoder writeNode().getData()"""
        # Get Go encoder writeNode().getData() result
        go_result = write_node_get_data(node_data)

        # Get Python marshal result
        python_node = Node(tag=node_data["tag"], attrs=node_data.get("attrs", {}), content=node_data.get("content"))
        python_result = marshal(python_node)

        # Compare binary data
        assert go_result == python_result, f"Go: {go_result.hex()}, Python: {python_result.hex()}"

    def test_core_functionality_equivalence(self):
        """Test core encoder functionality produces identical results"""
        test_cases = [
            {"tag": "iq", "attrs": {"id": "test123", "type": "get"}, "content": None},
            {"tag": "message", "attrs": {"to": "user@s.whatsapp.net"}, "content": "Hello"},
            {"tag": "presence", "attrs": {"type": "available"}, "content": None},
        ]

        for case in test_cases:
            # Test Go encoder writeNode().getData()
            go_output = write_node_get_data(case)

            # Test Python marshal
            py_node = Node(tag=case["tag"], attrs=case.get("attrs", {}), content=case.get("content"))
            py_output = marshal(py_node)

            # Verify same input produces same output
            assert go_output == py_output, f"Encoder mismatch for {case}"

            # Verify output is valid binary data
            assert isinstance(go_output, bytes)
            assert isinstance(py_output, bytearray)
            assert len(go_output) > 0
            assert len(py_output) > 0
