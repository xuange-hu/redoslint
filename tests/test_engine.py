"""Engine: JSON shape, SARIF contract, fail-on thresholds, directory walks."""

import json
import os

from redoslint import engine as eng
from redoslint.parser import parse as parse_pattern_ast  # noqa: F401


def scan(pattern):
    return [eng.scan_pattern(pattern)]


# -- fail-on thresholds ---------------------------------------------------

def test_fail_on_high_triggers_on_high():
    assert eng.fail_level(scan("(a+)+"), "high") is True


def test_fail_on_high_ignores_medium():
    assert eng.fail_level(scan(r"^\d*\d*:\d+$"), "high") is False


def test_fail_on_medium_triggers_on_high():
    assert eng.fail_level(scan("(a+)+"), "medium") is True


def test_fail_on_low_triggers_on_low():
    assert eng.fail_level(scan("user|username"), "low") is True


def test_fail_on_none_never_fails():
    assert eng.fail_level(scan("(a+)+"), "none") is False


def test_fail_level_clean_scan():
    assert eng.fail_level(scan("^[a-z]+$"), "low") is False


# -- JSON ----------------------------------------------------------------

def test_json_has_tool_and_reports():
    doc = eng.to_json(scan("(a+)+"))
    assert doc["tool"] == "redoslint"
    assert isinstance(doc["reports"], list) and doc["reports"]


def test_json_report_fields():
    rep = eng.to_json(scan("(a+)+"))["reports"][0]
    assert rep["worst"] == "high"
    f = rep["findings"][0]
    assert {"rule_id", "severity", "span", "message", "suggestion"} <= set(f)


def test_json_span_is_a_list_for_serialization():
    f = eng.to_json(scan("(a+)+"))["reports"][0]["findings"][0]
    assert isinstance(f["span"], list) and len(f["span"]) == 2


def test_json_is_valid_json():
    text = eng.dumps_json(eng.to_json(scan("(a+)+")))
    assert json.loads(text)["tool"] == "redoslint"


# -- SARIF ---------------------------------------------------------------

def test_sarif_version_and_schema():
    doc = eng.to_sarif(scan("(a+)+"))
    assert doc["version"] == "2.1.0"
    assert "sarif" in doc["$schema"]


def test_sarif_tool_driver():
    driver = eng.to_sarif(scan("(a+)+"))["runs"][0]["tool"]["driver"]
    assert driver["name"] == "redoslint"
    assert driver["version"] == "0.1.0"


def test_sarif_result_level_mapping():
    doc = eng.to_sarif(scan("(a+)+"))
    assert doc["runs"][0]["results"][0]["level"] == "error"


def test_sarif_medium_maps_to_warning():
    doc = eng.to_sarif(scan(r"^\d*\d*:\d+$"))
    assert doc["runs"][0]["results"][0]["level"] == "warning"


def test_sarif_low_maps_to_note():
    doc = eng.to_sarif(scan("user|username"))
    assert doc["runs"][0]["results"][0]["level"] == "note"


def test_sarif_declares_only_fired_rules():
    doc = eng.to_sarif(scan("(a+)+"))
    rules = doc["runs"][0]["tool"]["driver"]["rules"]
    assert [r["id"] for r in rules] == ["RDS001"]


def test_sarif_rule_has_description_and_fix():
    rule = eng.to_sarif(scan("(a+)+"))["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["fullDescription"]["text"]
    assert "Fix:" in rule["help"]["text"]


def test_sarif_result_has_location_and_fingerprint():
    res = eng.to_sarif(scan("(a+)+"))["runs"][0]["results"][0]
    assert res["locations"][0]["physicalLocation"]["region"]["startLine"] == 1
    assert "redoslintRule/v1" in res["partialFingerprints"]


def test_sarif_windows_paths_use_forward_slashes():
    report = eng.scan_pattern("(a+)+", path="C:\\repo\\app.py", line=3, col=5)
    uri = eng.to_sarif([report])["runs"][0]["results"][0][
        "locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert "\\" not in uri


def test_sarif_is_json_serializable():
    assert json.loads(eng.dumps_json(eng.to_sarif(scan("(a+)+"))))


# -- file and directory scan ---------------------------------------------

def test_scan_path_on_single_file():
    reports = eng.scan_path("examples/vulnerable.py")
    assert reports and all(r.path for r in reports)


def test_scan_path_skips_unknown_extensions(tmp_path):
    f = tmp_path / "notes.txt"
    f.write_text('re.compile("(a+)+")', encoding="utf-8")
    assert eng.scan_path(str(tmp_path)) == []


def test_scan_path_walks_directories(tmp_path):
    (tmp_path / "a.py").write_text('import re\nre.compile("(a+)+")',
                                   encoding="utf-8")
    reports = eng.scan_path(str(tmp_path))
    assert len(reports) == 1


def test_scan_path_skips_vendor_directories(tmp_path):
    vendor = tmp_path / "node_modules" / "x"
    vendor.mkdir(parents=True)
    (vendor / "a.js").write_text('const r = new RegExp("(a+)+");',
                                 encoding="utf-8")
    assert eng.scan_path(str(tmp_path)) == []


def test_scan_path_missing_path_is_empty():
    assert eng.scan_path("does/not/exist.py") == []


def test_scan_path_tolerates_undecodable_bytes(tmp_path):
    p = tmp_path / "b.py"
    p.write_bytes(b"import re\nre.compile(b'\\xff\\xfe')\n")
    eng.scan_path(str(p))  # must not raise


def test_scan_records_line_and_column(tmp_path):
    p = tmp_path / "c.py"
    p.write_text('import re\nx = re.compile("(a+)+")\n', encoding="utf-8")
    reports = eng.scan_path(str(p))
    assert reports[0].line == 2 and reports[0].col == 16


def test_scan_text_returns_one_report_per_literal():
    text = 'import re\nre.compile("a")\nre.compile("b")\n'
    assert len(eng.scan_text(text, "f.py", "python")) == 2


def test_scan_path_handles_relative_and_absolute():
    rel = eng.scan_path("examples/safe.py")
    abso = eng.scan_path(os.path.abspath("examples/safe.py"))
    assert len(rel) == len(abso)
