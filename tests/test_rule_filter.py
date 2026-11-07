"""`--rule` is a roll-out switch, so its contract is about agreement:

text, JSON, SARIF and the exit code must all describe the same (filtered)
findings. A filter that only changes the pretty printer would let a team
believe CI is clean while the gate still fails on an excluded rule.
"""

import json

import pytest

from redoslint import engine as eng
from redoslint.cli import main
from redoslint.rules import RULES

FIXTURE = "examples/vulnerable.py"


def run(capsys, argv):
    rc = main(argv)
    out, err = capsys.readouterr()
    return rc, out, err


def test_filter_only_keeps_selected_findings():
    reports = eng.scan_path(FIXTURE)
    kept = eng.filter_rules(reports, {"RDS001", "RDS002"})
    ids = {f.rule_id for r in kept for f in r.findings}
    assert ids == {"RDS001", "RDS002"}


def test_filter_preserves_report_metadata():
    reports = eng.scan_path(FIXTURE)
    kept = eng.filter_rules(reports, {"RDS001"})
    assert len(kept) == len(reports)
    for before, after in zip(reports, kept, strict=True):
        assert after.pattern == before.pattern
        assert after.path == before.path
        assert after.line == before.line
        assert after.parse_error == before.parse_error


def test_filter_does_not_mutate_the_original_reports():
    reports = eng.scan_path(FIXTURE)
    before = [len(r.findings) for r in reports]
    eng.filter_rules(reports, {"RDS001"})
    assert [len(r.findings) for r in reports] == before


def test_filter_empty_selection_means_everything_is_removed():
    reports = eng.scan_path(FIXTURE)
    kept = eng.filter_rules(reports, set())
    assert all(not r.findings for r in kept)


def test_scan_rule_json_contains_only_selected_ids(capsys):
    rc, out, _ = run(capsys, ["scan", FIXTURE, "--rule", "RDS001,RDS002",
                              "--json", "--fail-on", "none"])
    assert rc == 0
    doc = json.loads(out)
    ids = {f["rule_id"] for r in doc["reports"] for f in r["findings"]}
    assert ids == {"RDS001", "RDS002"}


def test_scan_rule_sarif_contains_only_selected_ids(tmp_path, capsys):
    sarif = tmp_path / "out.sarif"
    rc, _out, _ = run(capsys, ["scan", FIXTURE, "--rule", "RDS001",
                               "--sarif", str(sarif), "--fail-on", "none"])
    assert rc == 0
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    results = doc["runs"][0]["results"]
    assert results and {x["ruleId"] for x in results} == {"RDS001"}


def test_exit_code_follows_the_filter(capsys):
    # RDS001 is high; excluding it must make a default --fail-on high gate pass.
    rc_all, _, _ = run(capsys, ["pattern", "^(a+)+$"])
    rc_filtered, _, _ = run(capsys, ["pattern", "^(a+)+$",
                                     "--rule", "RDS008"])
    assert rc_all == 1
    assert rc_filtered == 0


def test_repeated_and_comma_flags_combine(capsys):
    rc, out, _ = run(capsys, ["scan", FIXTURE, "--rule", "RDS001,RDS002",
                              "--rule", "RDS008", "--json", "--fail-on", "none"])
    assert rc == 0
    doc = json.loads(out)
    ids = {f["rule_id"] for r in doc["reports"] for f in r["findings"]}
    assert ids == {"RDS001", "RDS002", "RDS008"}


def test_unknown_rule_is_a_usage_error_not_a_clean_scan(capsys):
    rc, _out, err = run(capsys, ["pattern", "^(a+)+$", "--rule", "RDS999"])
    assert rc == 2
    assert "unknown rule RDS999" in err


def test_unknown_rule_is_rejected_before_any_output(capsys):
    rc, out, _ = run(capsys, ["scan", FIXTURE, "--json", "--rule", "NOPE"])
    assert rc == 2
    assert out.strip() == ""


@pytest.mark.parametrize("command", [[], ["--json"]])
def test_demo_respects_the_filter_and_exits_zero(capsys, command):
    rc, out, err = run(capsys, ["demo", "--rule", "RDS001"] + command)
    assert rc == 0
    assert "RDS001" in out
    assert "RDS002" not in out
    # Coverage of the *fixture* is not affected by the user's selection.
    assert "no longer reaches" not in err


def test_demo_repeated_flags_show_exactly_two_rules(capsys):
    rc, out, _ = run(capsys, ["demo", "--rule", "RDS003",
                              "--rule", "RDS008"])
    assert rc == 0
    assert "RDS003" in out and "RDS008" in out
    assert "RDS001" not in out


def test_every_declared_rule_id_is_selectable(capsys, tmp_path):
    """A rule that cannot be named on --rule cannot be rolled out on its own."""
    for rule in RULES:
        rc, out, _ = run(capsys, ["scan", FIXTURE, "--rule", rule.rule_id,
                                  "--json", "--fail-on", "none"])
        assert rc == 0, rule.rule_id
        doc = json.loads(out)
        ids = {f["rule_id"] for r in doc["reports"] for f in r["findings"]}
        assert ids == {rule.rule_id}, rule.rule_id


def test_filter_does_not_hide_parse_errors_from_json(capsys):
    rc, out, _ = run(capsys, ["scan", FIXTURE, "--rule", "RDS001",
                              "--json", "--fail-on", "none"])
    assert rc == 0
    doc = json.loads(out)
    # The unparseable pattern is still reported as a coverage gap in the
    # document, even though its RDS099 finding is filtered out of results.
    assert any(r.get("parse_error") for r in doc["reports"])
