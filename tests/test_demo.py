"""The `redoslint demo` contract.

A demo is the first command a visitor runs, so it has three jobs: reach every
rule, prove the safe fixture is clean, and do it without touching the network
or leaving files behind.
"""

import os
import re
import subprocess
import sys

from redoslint import demo
from redoslint import engine as eng
from redoslint.rules import RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_demo_reaches_every_rule():
    reports, _ = demo.run_demo()
    assert demo.missing_rules(reports) == []


def test_demo_safe_fixture_is_clean():
    reports, _ = demo.run_demo()
    clean = [r for r in reports if not r.findings]
    assert len(clean) == 8
    assert all(r.path.endswith("safe.py") for r in clean)


def test_demo_does_not_leave_files_behind():
    _reports, tmp = demo.run_demo()
    assert not os.path.exists(tmp)


def test_demo_render_says_what_it_does():
    reports, _ = demo.run_demo()
    text = demo.render(reports)
    assert "no network" in text
    assert "no execution" in text
    # The temp path is noise in a demo transcript.
    assert "/tmp" not in text and "redoslint-demo-" not in text


def _patterns(text):
    return sorted(re.findall(r're\.compile\(r"([^"]*)"\)', text))


def test_demo_fixture_matches_the_checked_in_one():
    """The embedded copy exists because wheels do not ship examples/. If the
    two drift, the demo stops being evidence for the checked-in fixture."""
    with open(os.path.join(ROOT, "examples", "vulnerable.py"),
              encoding="utf-8") as fh:
        on_disk = _patterns(fh.read())
    embedded = _patterns(demo.VULNERABLE_SRC)
    assert embedded == on_disk


def test_demo_reports_every_rule_id_exactly_once():
    reports, _ = demo.run_demo()
    ids = sorted(f.rule_id for r in reports for f in r.findings)
    assert ids == sorted(r.rule_id for r in RULES)


def test_cli_demo_exits_zero_and_prints_every_rule():
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "from redoslint.cli import main;"
        "sys.exit(main(['demo']))"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    for rule in RULES:
        assert rule.rule_id in proc.stdout


def test_cli_demo_json_is_parseable():
    import json
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "from redoslint.cli import main;"
        "sys.exit(main(['demo', '--json']))"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["tool"] == "redoslint"
    findings = sum(len(r["findings"]) for r in doc["reports"])
    assert findings == len(RULES) == 9


def test_engine_still_sees_the_demo_patterns():
    """Guard against the demo passing because scanning silently stopped."""
    reports, _ = demo.run_demo()
    assert sum(len(r.findings) for r in reports) == 9
    assert eng.fail_level(reports, "high") is True
