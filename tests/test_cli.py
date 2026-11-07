"""CLI: exit codes, text output, JSON, SARIF on disk."""

import json

import pytest

from redoslint.cli import build_parser, main


def test_version_command(capsys):
    assert main(["version"]) == 0
    assert "redoslint 0.1.0" in capsys.readouterr().out


def test_rules_command_lists_all(capsys):
    assert main(["rules"]) == 0
    out = capsys.readouterr().out
    for rule in ("RDS001", "RDS002", "RDS003", "RDS004", "RDS005",
                 "RDS006", "RDS007", "RDS008", "RDS099"):
        assert rule in out


def test_rules_detail(capsys):
    assert main(["rules", "--id", "RDS001"]) == 0
    out = capsys.readouterr().out
    assert "nested" in out.lower() and "fix:" in out


def test_rules_unknown_id_exits_2(capsys):
    assert main(["rules", "--id", "RDS999"]) == 2
    assert "unknown rule" in capsys.readouterr().err


def test_pattern_reports_finding(capsys):
    rc = main(["pattern", "(a+)+"])
    out = capsys.readouterr().out
    assert rc == 1  # default --fail-on is high
    assert "RDS001" in out and "high" in out


def test_pattern_clean_exits_zero(capsys):
    assert main(["pattern", "^[a-z]+$"]) == 0
    assert "no findings" in capsys.readouterr().out


def test_pattern_shows_offset_and_fragment(capsys):
    main(["pattern", "^(a+)+$"])
    out = capsys.readouterr().out
    assert "offset 1" in out and "(a+)+" in out


def test_pattern_fail_on_none_never_fails(capsys):
    assert main(["pattern", "(a+)+", "--fail-on", "none"]) == 0


def test_pattern_fail_on_medium(capsys):
    assert main(["pattern", r"^\d*\d*:\d+$", "--fail-on", "medium"]) == 1


def test_pattern_json_output(capsys):
    main(["pattern", "(a+)+", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert doc["reports"][0]["worst"] == "high"


def test_scan_writes_sarif_file(tmp_path, capsys):
    out = tmp_path / "r.sarif"
    main(["scan", "examples/vulnerable.py", "--sarif", str(out)])
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"]


def test_scan_clean_file_exits_zero(capsys):
    assert main(["scan", "examples/safe.py", "--fail-on", "low"]) == 0


def test_scan_vulnerable_exits_one(capsys):
    assert main(["scan", "examples/vulnerable.py"]) == 1


def test_scan_counts_findings(capsys):
    main(["scan", "examples/vulnerable.py"])
    out = capsys.readouterr().out
    assert "9 finding(s)" in out


def test_scan_prints_path_line_col(capsys):
    main(["scan", "examples/vulnerable.py"])
    out = capsys.readouterr().out
    assert "examples/vulnerable.py:9:23" in out


def test_missing_subcommand_is_a_usage_error():
    with pytest.raises(SystemExit) as exc:
        build_parser().parse_args([])
    assert exc.value.code == 2


def test_invalid_fail_on_is_rejected():
    with pytest.raises(SystemExit):
        build_parser().parse_args(["pattern", "a", "--fail-on", "nope"])


def test_scan_json_is_parseable(capsys):
    main(["scan", "examples/vulnerable.py", "--json"])
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["reports"]) == 9
