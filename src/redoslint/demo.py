"""`redoslint demo` — the zero-configuration tour.

The fixture is embedded rather than read from `examples/` because the wheel
does not ship `examples/` (it is outside the package root). A test pins this
copy against the checked-in fixture so the two cannot drift.

Nothing here touches the network, executes a pattern, or writes a file outside
`tempfile.mkdtemp()` — a visitor's first command must be safe on a jump host.
"""

from __future__ import annotations

import os
import shutil
import tempfile

from . import engine as eng
from .rules import RULES

# The demo source, one rule per line, with the pattern that triggers it.
# Every RDS id below is asserted in tests/test_demo.py against RULES.
VULNERABLE_SRC = '''\
"""Deliberately vulnerable regexes — every redoslint rule fires at least once
in this file. It is the demo fixture and the CI demo-contract target; the
last pattern is a real parse error, hence the try/except.
"""

import re

# RDS001 — nested quantifier, ambiguous inner boundary
USERNAME = re.compile(r"^(a+)+$")

# RDS002 — overlapping alternation branches under a quantifier
TOKEN = re.compile(r"^(a|aa)+b$")

# RDS003 — branch is a prefix of another branch
COMMAND = re.compile(r"user|username")

# RDS004 — adjacent quantified atoms with overlapping characters
NUMBER = re.compile(r"^\\d*\\d*:\\d+$")

# RDS005 — stacked bounded repetitions
GRID = re.compile(r"^(a{1,10}){1,10}z$")

# RDS006 — backreference to a group captured inside the same loop
REPEAT = re.compile(r"^(?:(\\w)\\1)+$")

# RDS007 — quantifier over a fragment that can match empty
LABEL = re.compile(r"^(a*)+b$")

# RDS008 — very large minimum bound
PAD = re.compile(r"^a{5000,}b$")

# RDS099 — unparseable: the coverage gap is reported, not hidden
try:
    BROKEN = re.compile(r"^[unclosed")
except re.error:
    BROKEN = None
'''

SAFE_SRC = '''\
"""The same tasks, written without an ambiguous boundary. The demo asserts
this file is clean: a scanner that cannot say "fine" is a scanner nobody runs.
"""

import re

USERNAME = re.compile(r"^[a-z0-9_]{1,32}$")
TOKEN = re.compile(r"^(?:a{2})*b$")
COMMAND = re.compile(r"^(?:username|user)$")
NUMBER = re.compile(r"^(\\d+):(\\d+)$")
GRID = re.compile(r"^a{1,10}z$")
REPEAT = re.compile(r"^(\\w)+$")
LABEL = re.compile(r"^a*b$")
PAD = re.compile(r"^a{1,5000}b$")
'''


def run_demo() -> tuple[list, str]:
    """Scan both fixtures in a temp dir; return (reports, their path)."""
    tmp = tempfile.mkdtemp(prefix="redoslint-demo-")
    try:
        bad = os.path.join(tmp, "vulnerable.py")
        good = os.path.join(tmp, "safe.py")
        with open(bad, "w", encoding="utf-8") as fh:
            fh.write(VULNERABLE_SRC)
        with open(good, "w", encoding="utf-8") as fh:
            fh.write(SAFE_SRC)
        reports = eng.scan_path(bad) + eng.scan_path(good)
        return reports, tmp
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def missing_rules(reports: list) -> list[str]:
    """Rule ids that the demo fixture does not reach — CI fails on a non-empty list."""
    hit = {f.rule_id for r in reports for f in r.findings}
    return sorted({r.rule_id for r in RULES} - hit)


def render(reports: list) -> str:
    """The text a visitor sees. Paths are temp-dir noise, so they are trimmed."""
    lines = []
    for r in reports:
        if not r.findings:
            continue
        name = os.path.basename(r.path or "pattern")
        lines.append(f"{name}:{r.line}  {r.pattern!r}")
        for f in r.findings:
            frag = r.pattern[f.span[0]:f.span[1]]
            off = f" (offset {f.span[0]}, {frag!r})" if frag else ""
            lines.append(f"  {f.rule_id} [{f.severity}]{off}: {f.message}")
            lines.append(f"    fix: {f.suggestion}")
        lines.append("")
    n = sum(len(r.findings) for r in reports)
    clean = sum(1 for r in reports if not r.findings)
    lines.append(f"{n} finding(s) across {len(reports)} patterns; "
                 f"{clean} clean.")
    lines.append("no network, no execution, no files written outside a temp dir.")
    return "\n".join(lines)
