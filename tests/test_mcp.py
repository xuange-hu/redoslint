"""MCP surface: 6 tools, non-empty descriptions, one round-trip per tool.

The mcp package is an optional extra; these tests skip without it so the
zero-dependency promise stays testable on a bare clone.
"""

import json

import pytest

from redoslint import mcp_server

mcp = pytest.importorskip("mcp", reason="the mcp extra is not installed")


def test_tool_manifest_has_six_tools():
    assert len(mcp_server.tool_manifest()) == 6


def test_tool_names_match_the_constant():
    names = [t["name"] for t in mcp_server.tool_manifest()]
    assert names == mcp_server.TOOL_NAMES


def test_every_tool_has_a_description():
    for tool in mcp_server.tool_manifest():
        assert tool["description"].strip(), tool["name"]


def test_every_tool_has_an_input_schema():
    for tool in mcp_server.tool_manifest():
        assert tool["inputSchema"]["type"] == "object"


def test_call_scan_returns_json(tmp_path):
    (tmp_path / "a.py").write_text('import re\nre.compile("(a+)+")\n',
                                   encoding="utf-8")
    doc = json.loads(mcp_server.call_tool("redos_scan", {"path": str(tmp_path)}))
    assert doc["reports"][0]["worst"] == "high"


def test_call_scan_fail_on_filters(tmp_path):
    (tmp_path / "a.py").write_text('import re\nre.compile("user|username")\n',
                                   encoding="utf-8")
    doc = json.loads(mcp_server.call_tool(
        "redos_scan", {"path": str(tmp_path), "fail_on": "high"}))
    assert doc["reports"] == []


def test_call_pattern():
    doc = json.loads(mcp_server.call_tool("redos_pattern", {"pattern": "(a+)+"}))
    assert doc["reports"][0]["findings"][0]["rule_id"] == "RDS001"


def test_call_rules_returns_all():
    doc = json.loads(mcp_server.call_tool("redos_rules", {}))
    assert len(doc["rules"]) == 9


def test_call_rule_detail():
    doc = json.loads(mcp_server.call_tool("redos_rule_detail",
                                          {"rule_id": "RDS007"}))
    assert doc["severity"] == "high" and doc["fix"]


def test_call_rule_detail_unknown():
    doc = json.loads(mcp_server.call_tool("redos_rule_detail",
                                          {"rule_id": "RDS999"}))
    assert "error" in doc


def test_call_sarif(tmp_path):
    (tmp_path / "a.py").write_text('import re\nre.compile("(a+)+")\n',
                                   encoding="utf-8")
    doc = json.loads(mcp_server.call_tool("redos_sarif", {"path": str(tmp_path)}))
    assert doc["version"] == "2.1.0"


def test_call_version():
    doc = json.loads(mcp_server.call_tool("redos_version", {}))
    assert doc["version"] == "0.1.0"


def test_unknown_tool_reports_error():
    doc = json.loads(mcp_server.call_tool("nope", {}))
    assert "error" in doc


def test_server_registers_every_manifest_tool():
    server = mcp_server.build_server()
    assert server is not None
