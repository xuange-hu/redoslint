"""MCP server: 7 tools so an agent can audit regexes without leaving chat.

Run standalone:  uvx --from "redoslint[mcp]" redoslint-mcp
Or from code:    build_server().run()  (stdio transport)
"""

from __future__ import annotations

import json

from . import __version__
from . import engine as eng

TOOL_NAMES = [
    "redos_scan",
    "redos_pattern",
    "redos_rules",
    "redos_rule_detail",
    "redos_sarif",
    "redos_version",
    "redos_demo",
]


def tool_manifest() -> list[dict]:
    """The single source of truth for the tool surface; tests pin the count."""
    return [
        {
            "name": "redos_scan",
            "description": (
                "Scan a file or directory for regexes with catastrophic "
                "backtracking risk (ReDoS). Returns findings with rule id, "
                "severity and the exact pattern fragment that causes them."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string",
                             "description": "File or directory to scan"},
                    "fail_on": {
                        "type": "string",
                        "enum": ["none", "info", "low", "medium", "high"],
                        "description": "Severity floor to report on",
                    },
                },
                "required": ["path"],
            },
        },
        {
            "name": "redos_pattern",
            "description": (
                "Audit a single regular-expression string for catastrophic "
                "backtracking. Use this when the regex is already in hand."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "pattern": {"type": "string",
                                "description": "The regex to audit"},
                },
                "required": ["pattern"],
            },
        },
        {
            "name": "redos_rules",
            "description": "List all redoslint rules with severity and title.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "redos_rule_detail",
            "description": "Full description and fix guidance for one rule.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "rule_id": {"type": "string",
                                "description": "e.g. RDS001"},
                },
                "required": ["rule_id"],
            },
        },
        {
            "name": "redos_sarif",
            "description": (
                "Scan a path and return findings as a SARIF 2.1.0 document "
                "(GitHub code-scanning compatible)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string",
                             "description": "File or directory to scan"},
                },
                "required": ["path"],
            },
        },
        {
            "name": "redos_version",
            "description": "Return the redoslint version.",
            "inputSchema": {"type": "object", "properties": {}},
        },
        {
            "name": "redos_demo",
            "description": (
                "Run the built-in vulnerable fixtures and return every finding as "
                "JSON, with which rules the corpus does not cover. No network, no "
                "input needed - the fastest way to see the output shape."
            ),
            "inputSchema": {"type": "object", "properties": {}},
        },
    ]


def call_tool(name: str, args: dict) -> str:
    """In-process dispatcher — the MCP tools and the tests both go through
    this, so there is exactly one behaviour to verify."""
    if name == "redos_scan":
        reports = eng.scan_path(args["path"])
        fail_on = args.get("fail_on", "none")
        reports = [r for r in reports if r.findings]
        if fail_on != "none":
            floor = eng.SEVERITY_ORDER[fail_on]
            reports = [
                r for r in reports
                if max((eng.SEVERITY_ORDER[f.severity] for f in r.findings),
                       default=0) >= floor
            ]
        return eng.dumps_json(eng.to_json(reports))
    if name == "redos_pattern":
        report = eng.scan_pattern(args["pattern"])
        return eng.dumps_json(eng.to_json([report]))
    if name == "redos_rules":
        return eng.dumps_json({
            "rules": [
                {"id": r.rule_id, "severity": r.severity, "title": r.title}
                for r in eng.RULES_BY_ID.values()
            ]
        })
    if name == "redos_rule_detail":
        rule = eng.RULES_BY_ID.get(args["rule_id"])
        if rule is None:
            return json.dumps({"error": f"unknown rule {args['rule_id']}"})
        return eng.dumps_json({
            "id": rule.rule_id, "severity": rule.severity, "title": rule.title,
            "description": rule.description, "fix": rule.fix,
        })
    if name == "redos_sarif":
        reports = eng.scan_path(args["path"])
        return eng.dumps_json(eng.to_sarif(reports))
    if name == "redos_version":
        return json.dumps({"tool": "redoslint", "version": __version__})
    if name == "redos_demo":
        from . import demo as demo_mod

        reports, tmp = demo_mod.run_demo()
        payload = json.loads(eng.dumps_json(eng.to_json(reports)))
        # coverage is about the fixture, not about the caller - report it
        # explicitly so a missing rule is never mistaken for a clean scan
        payload["missingRules"] = demo_mod.missing_rules(reports)
        payload["fixtureDir"] = tmp
        return json.dumps(payload, indent=2, ensure_ascii=False)
    return json.dumps({"error": f"unknown tool {name}"})


def build_server():
    """Build the FastMCP server (mcp 1.x)."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:  # pragma: no cover
        raise SystemExit(
            "the mcp package is required: pip install 'redoslint[mcp]'"
        ) from exc

    mcp = FastMCP("redoslint")

    @mcp.tool()
    def redos_scan(path: str, fail_on: str = "none") -> str:
        """Scan a file or directory for catastrophic-backtracking regexes."""
        return call_tool("redos_scan", {"path": path, "fail_on": fail_on})

    @mcp.tool()
    def redos_pattern(pattern: str) -> str:
        """Audit a single regex pattern for ReDoS risk."""
        return call_tool("redos_pattern", {"pattern": pattern})

    @mcp.tool()
    def redos_rules() -> str:
        """List all redoslint rules."""
        return call_tool("redos_rules", {})

    @mcp.tool()
    def redos_rule_detail(rule_id: str) -> str:
        """Full description and fix guidance for one redoslint rule."""
        return call_tool("redos_rule_detail", {"rule_id": rule_id})

    @mcp.tool()
    def redos_sarif(path: str) -> str:
        """Scan a path and return SARIF 2.1.0."""
        return call_tool("redos_sarif", {"path": path})

    @mcp.tool()
    def redos_version() -> str:
        """Return the redoslint version."""
        return call_tool("redos_version", {})

    @mcp.tool()
    def redos_demo() -> str:
        """Run the built-in vulnerable fixtures and return findings as JSON."""
        return call_tool("redos_demo", {})

    return mcp


def main() -> None:
    """Console-script entry point (`redoslint-mcp`).

    Kept import-light on purpose: `mcp` is only imported inside build_server,
    so `pip install redoslint` does not drag the SDK in and the script still
    exists for the `[mcp]` extra to satisfy.
    """
    build_server().run()


if __name__ == "__main__":
    main()
