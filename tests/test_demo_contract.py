"""Demo contract and dogfood: the fixtures must keep telling the truth.

A visitor's first command is `redoslint scan examples/vulnerable.py`; if a
rule stops firing there, the demo silently under-delivers. These assertions
are the guard, and `test_self_scan_is_clean` keeps redoslint honest about
its own source.
"""

import os

from redoslint import engine as eng
from redoslint.rules import RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VULNERABLE = os.path.join(ROOT, "examples", "vulnerable.py")
SAFE = os.path.join(ROOT, "examples", "safe.py")

ALL_RULES = {r.rule_id for r in RULES}


def test_demo_hits_every_rule():
    fired = {
        f.rule_id
        for report in eng.scan_path(VULNERABLE)
        for f in report.findings
    }
    assert fired == ALL_RULES, f"missing from the demo: {ALL_RULES - fired}"


def test_demo_has_a_high_severity_finding():
    reports = eng.scan_path(VULNERABLE)
    assert any(f.severity == "high" for r in reports for f in r.findings)


def test_safe_fixture_is_clean():
    bad = [
        (r.path, r.line, f.rule_id)
        for r in eng.scan_path(SAFE)
        for f in r.findings
    ]
    assert bad == []


def test_self_scan_has_no_high_or_medium():
    """redoslint must be clean on its own source at the levels that gate CI."""
    reports = eng.scan_path(os.path.join(ROOT, "src"))
    offenders = [
        (r.path, r.line, r.pattern, f.rule_id, f.severity)
        for r in reports
        for f in r.findings
        if f.severity in ("high", "medium")
    ]
    assert offenders == []


def test_self_scan_actually_finds_patterns():
    # an empty walk would make the previous test vacuous
    assert len(eng.scan_path(os.path.join(ROOT, "src"))) >= 3


def test_every_rule_has_a_description_and_fix():
    for rule in RULES:
        assert rule.title and rule.description and rule.fix, rule.rule_id


def test_rule_ids_are_unique():
    ids = [r.rule_id for r in RULES]
    assert len(ids) == len(set(ids))
