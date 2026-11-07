"""Scan orchestration: parse, run both passes, collect findings, render.

The two passes share one walk. Pass 1 rules fire on local shape; pass 2
rules receive a context carrying `in_quant` (an unbounded-capable quantifier
somewhere above) — that is what lets RDS002 see an alternation buried three
levels deep inside `(?: ... )+`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field

from . import analyze as an
from . import extract
from . import rules as rl
from .parser import Quant
from .rules import Finding, Rule

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1, "info": 0}

RULES_BY_ID: dict[str, Rule] = {r.rule_id: r for r in rl.RULES}
PASS1 = [r.check for r in rl.RULES if r.check and r.rule_id in
         ("RDS003", "RDS004", "RDS005", "RDS007", "RDS008")]
PASS2 = [r.check for r in rl.RULES if r.check and r.rule_id in
         ("RDS001", "RDS002", "RDS006")]


@dataclass
class Context:
    in_quant: bool = False


@dataclass
class PatternReport:
    pattern: str
    origin: str
    path: str | None
    line: int | None
    col: int | None
    findings: list[Finding] = field(default_factory=list)
    parse_error: str | None = None

    @property
    def worst(self) -> str | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings),
                   key=lambda s: SEVERITY_ORDER[s])


def scan_pattern(pattern: str, origin: str = "<pattern>",
                 path: str | None = None, line: int | None = None,
                 col: int | None = None) -> PatternReport:
    """Parse one pattern and run both passes. Parse failures become RDS099
    findings — a coverage gap must be visible, not silent."""
    from . import parser as pr

    report = PatternReport(pattern, origin, path, line, col)
    try:
        ast, _groups, _names = pr.parse(pattern)
    except pr.ParseError as exc:
        report.findings.append(Finding(
            "RDS099", "info", (exc.pos, exc.pos + 1),
            f"pattern could not be parsed: {exc.msg}",
            "check the pattern syntax; if it is valid but unsupported, "
            "please open an issue",
        ))
        report.parse_error = exc.msg
        return report
    findings: list[Finding] = []

    def visit(node, ctx: Context) -> None:
        for check in PASS1:
            findings.extend(check(node, ctx))
        for check in PASS2:
            findings.extend(check(node, ctx))
        # in_quant propagates downward: once any loose quantifier is above a
        # node, its alternations re-enter per iteration. A bounded {0,1}
        # quantifier does not re-enter, so it does not flip the flag.
        child_ctx = ctx
        if isinstance(node, Quant) and _loose(node):
            child_ctx = Context(True)
        for child in an.children(node):
            visit(child, child_ctx)

    visit(ast, Context())
    # de-duplicate identical (rule, span) pairs — two rules can legitimately
    # flag the same construct, but never the same rule twice.
    seen: set[tuple[str, tuple[int, int]]] = set()
    for f in findings:
        key = (f.rule_id, f.span)
        if key not in seen:
            seen.add(key)
            report.findings.append(f)
    report.findings.sort(
        key=lambda f: (-SEVERITY_ORDER[f.severity], f.span[0]))
    return report


def _loose(q: Quant) -> bool:
    return q.max is None or q.max >= 2


def _subtree(node):
    yield node
    for child in an.children(node):
        yield from _subtree(child)


def scan_text(text: str, path: str, lang: str) -> list[PatternReport]:
    reports = []
    for hit in extract.extract(text, lang):
        reports.append(scan_pattern(hit.pattern, hit.origin, path, hit.line,
                                    hit.col))
    return reports


def scan_path(path: str) -> list[PatternReport]:
    """Scan a file or walk a directory (skipping caches and vendor trees)."""
    if os.path.isfile(path):
        return _scan_file(path)
    reports = []
    for root, dirs, files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in extract.SKIP_DIRS]
        for name in sorted(files):
            reports.extend(_scan_file(os.path.join(root, name)))
    return reports


def _scan_file(path: str) -> list[PatternReport]:
    lang = extract.LANG_BY_EXT.get(os.path.splitext(path)[1].lower())
    if lang is None:
        return []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(text, path, lang)


def to_json(reports: list[PatternReport]) -> dict:
    return {
        "tool": "redoslint",
        "version": _version(),
        "reports": [
            {
                "path": r.path, "line": r.line, "col": r.col,
                "origin": r.origin,
                "pattern": r.pattern,
                "parse_error": r.parse_error,
                "worst": r.worst,
                "findings": [
                    {
                        "rule_id": f.rule_id, "severity": f.severity,
                        "span": list(f.span), "message": f.message,
                        "suggestion": f.suggestion,
                    }
                    for f in r.findings
                ],
            }
            for r in reports
        ],
    }


def _version() -> str:
    from . import __version__
    return __version__


def to_sarif(reports: list[PatternReport]) -> dict:
    """SARIF 2.1.0 — the shape GitHub's code-scanning UI ingests."""
    rules_seen = sorted({f.rule_id for r in reports for f in r.findings})
    results = []
    for r in reports:
        for f in r.findings:
            region = {
                "startLine": r.line or 1,
            }
            if r.col:
                region["startColumn"] = r.col + f.span[0]
            results.append({
                "ruleId": f.rule_id,
                "level": {"high": "error", "medium": "warning",
                          "low": "note", "info": "note"}[f.severity],
                "message": {"text": f"{f.message}. Fix: {f.suggestion}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": _sarif_uri(r.path)},
                        "region": region,
                    }
                }],
                "partialFingerprints": {
                    "redoslintRule/v1": f"{f.rule_id}:{r.pattern}:{f.span[0]}",
                },
            })
    rules_json = []
    for rid in rules_seen:
        rule = RULES_BY_ID[rid]
        rules_json.append({
            "id": rid,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": f"Fix: {rule.fix}"},
            "defaultConfiguration": {"level": {"high": "error",
                                               "medium": "warning",
                                               "low": "note",
                                               "info": "note"}[rule.severity]},
        })
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "redoslint",
                "informationUri": "https://github.com/xuange-hu/redoslint",
                "version": _version(),
                "rules": rules_json,
            }},
            "results": [
                {k: v for k, v in res.items() if not k.startswith("_")}
                for res in results
            ],
        }],
    }
    return sarif


def _sarif_uri(path: str | None) -> str:
    if not path:
        return "<pattern>"
    return path.replace("\\", "/")


def fail_level(reports: list[PatternReport], fail_on: str) -> bool:
    """True when the scan should exit non-zero. fail_on 'none' never fails;
    otherwise it fails at or above the named severity."""
    if fail_on == "none":
        return False
    threshold = SEVERITY_ORDER[fail_on]
    return any(
        SEVERITY_ORDER[f.severity] >= threshold
        for r in reports for f in r.findings
    )


def dumps_json(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
