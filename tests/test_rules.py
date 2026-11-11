"""Rules: every trigger, and the near-misses that must stay clean.

The negative cases are the point of the character-set approach: shapes that
look catastrophic but cannot be, because the sets do not overlap.
"""

import pytest

from redoslint import engine as eng


def ids(pattern):
    return sorted({f.rule_id for f in eng.scan_pattern(pattern).findings})


def findings(pattern, rule_id):
    return [f for f in eng.scan_pattern(pattern).findings if f.rule_id == rule_id]


# -- RDS001 nested quantifier ---------------------------------------------

@pytest.mark.parametrize("pattern", [
    r"^(a+)+$",
    r"^(a+)+b",
    r"^(?:\d+)+$",
    r"^(?:a+)+$",
    r"((a+)a)+",
])
def test_rds001_fires(pattern):
    assert "RDS001" in ids(pattern)


@pytest.mark.parametrize("pattern", [
    r"^(a+)b+$",            # quantifier, then a different quantifier
    r"^(a{1,3}b)+c$",       # the 'b' pins the inner boundary
    r"^(a+\.)+$",           # dot pins the boundary
    r"^(ab+)+$",
])
def test_rds001_does_not_fire(pattern):
    assert "RDS001" not in ids(pattern)


def test_rds001_is_high_severity():
    assert findings(r"(a+)+", "RDS001")[0].severity == "high"


def test_rds001_span_covers_the_outer_quantifier():
    f = findings(r"^(a+)+$", "RDS001")[0]
    assert f.span == (1, 6)  # (a+)+ starts at the '(' of the outer group


# -- RDS002 overlapping alternation under a quantifier --------------------

@pytest.mark.parametrize("pattern", [
    r"^(a|aa)+b$",
    r"^(?:a|ab)+c$",
    r"^(foo|foobar)+$",
    r"^(\w+|abc)+$",        # 'a' is inside \w
])
def test_rds002_fires(pattern):
    assert "RDS002" in ids(pattern)


@pytest.mark.parametrize("pattern", [
    r"^(a|b)+c$",
    r"^(?:foo|bar)+$",
    r"^(?:\d+|x)+$",
])
def test_rds002_does_not_fire(pattern):
    assert "RDS002" not in ids(pattern)


def test_rds002_sees_deeply_nested_alternation():
    # the alternation is three levels inside the quantifier
    assert "RDS002" in ids(r"^(?:x(?:y(?:a|aa)))+$")


def test_rds002_is_high_severity():
    assert findings(r"(a|aa)+", "RDS002")[0].severity == "high"


# -- RDS003 shadowed branch ----------------------------------------------

def test_rds003_fires_on_shadowed_branch():
    assert "RDS003" in ids("user|username")


def test_rds003_does_not_fire_when_the_longer_branch_comes_first():
    # abc|ab is the correct order: "abc" wins where it can, "ab" catches the
    # rest — neither branch is dead.
    assert "RDS003" not in ids("abc|ab")


def test_rds003_does_not_fire_on_correct_order():
    assert "RDS003" not in ids("username|user")


def test_rds003_does_not_fire_on_unrelated_branches():
    assert "RDS003" not in ids("cat|dog")


def test_rds003_span_is_the_shadowed_branch():
    f = findings("user|username", "RDS003")[0]
    assert f.span == (5, 13)


def test_rds003_is_low_severity():
    assert findings("user|username", "RDS003")[0].severity == "low"


# -- RDS004 adjacent quantified atoms ------------------------------------

@pytest.mark.parametrize("pattern", [
    r"^\d*\d*:\d+$",
    r"^a*a*b$",
    r"^.*.*$",
    r"^[a-z]+[a-z]+$",
])
def test_rds004_fires(pattern):
    assert "RDS004" in ids(pattern)


@pytest.mark.parametrize("pattern", [
    r"^(\d{1,3}\.){3}\d{1,3}$",   # IPv4: the trailing dot pins the boundary
    r"^.*abc.*$",                  # literals between the dots
    r"^a+b+c$",                    # disjoint sets
    r"^\d+\s+\d+$",
])
def test_rds004_does_not_fire(pattern):
    assert "RDS004" not in ids(pattern)


def test_rds004_two_atoms_is_medium():
    assert findings(r"^\d*\d*:\d+$", "RDS004")[0].severity == "medium"


def test_rds004_three_atoms_is_high():
    assert findings(r"^a*a*a*b$", "RDS004")[0].severity == "high"


# -- RDS005 stacked bounded repetitions ----------------------------------

def test_rds005_fires_on_stacked_bounds():
    assert "RDS005" in ids(r"^(a{1,10}){1,10}z$")


def test_rds005_high_when_product_is_large():
    assert findings(r"^(a{1,100}){1,100}$", "RDS005")[0].severity == "high"


def test_rds005_medium_when_product_is_small():
    assert findings(r"^(a{1,10}){1,10}z$", "RDS005")[0].severity == "medium"


def test_rds005_does_not_fire_on_flat_bounds():
    assert "RDS005" not in ids(r"^a{1,100}$")


# -- RDS006 backreference inside its own loop ----------------------------

def test_rds006_fires_on_repeated_double():
    assert "RDS006" in ids(r"^(?:(\w)\1)+$")


def test_rds006_does_not_fire_when_capture_is_outside_loop():
    assert "RDS006" not in ids(r"^(\w)\1$")


def test_rds006_is_high_severity():
    assert findings(r"^(?:(\w)\1)+$", "RDS006")[0].severity == "high"


# -- RDS007 nullable body ------------------------------------------------

@pytest.mark.parametrize("pattern", [
    r"^(a*)+b$",
    r"^(a?)*$",
    r"^(a*b*)+$",
])
def test_rds007_fires(pattern):
    assert "RDS007" in ids(pattern)


def test_rds007_does_not_fire_on_non_nullable_body():
    assert "RDS007" not in ids(r"^(a+)+b$")


def test_rds007_does_not_fire_on_zero_width_body():
    # a body that can only ever match zero characters never trips an
    # engine's progress guard — the iteration is linear, not a blowup
    assert "RDS007" not in ids(r"^(\b)*$")
    assert "RDS007" not in ids(r"^(?=a)*$")
    assert "RDS007" not in ids(r"^(?:(?!b))*$")


def test_rds007_is_high_severity():
    assert findings(r"(a*)+", "RDS007")[0].severity == "high"


# -- RDS008 large minimum bound ------------------------------------------

def test_rds008_fires_on_large_min():
    assert "RDS008" in ids(r"^a{5000,}b$")


def test_rds008_threshold_is_1000():
    assert "RDS008" not in ids(r"^a{999,}b$")
    assert "RDS008" in ids(r"^a{1000,}b$")


def test_rds008_is_low_severity():
    assert findings(r"^a{5000,}b$", "RDS008")[0].severity == "low"


# -- RDS099 unparseable --------------------------------------------------

def test_rds099_reports_parse_failure():
    report = eng.scan_pattern("^[unclosed")
    assert report.parse_error is not None
    assert [f.rule_id for f in report.findings] == ["RDS099"]


def test_rds099_is_info_level():
    assert eng.scan_pattern("[a-").findings[0].severity == "info"


# -- ordering and de-duplication ----------------------------------------

def test_findings_sorted_by_severity_then_offset():
    report = eng.scan_pattern(r"^(a+)+$")
    sev = [f.severity for f in report.findings]
    assert sev == sorted(sev, key=lambda s: -eng.SEVERITY_ORDER[s])


def test_no_duplicate_rule_span_pairs():
    report = eng.scan_pattern(r"^(a+)+$")
    keys = [(f.rule_id, f.span) for f in report.findings]
    assert len(keys) == len(set(keys))


def test_clean_pattern_has_no_findings():
    assert eng.scan_pattern(r"^[a-z0-9]{3,16}$").findings == []


def test_worst_severity_property():
    assert eng.scan_pattern(r"^(a+)+$").worst == "high"
    assert eng.scan_pattern("user|username").worst == "low"
    assert eng.scan_pattern("^a+$").worst is None


def test_rds001_ignores_fixed_length_bodies():
    """A body that always consumes the same number of characters has no
    ambiguous split, so nested quantifiers there are linear."""
    assert "RDS001" not in ids("^(?:a{2})*b$")
    assert "RDS001" not in ids("^(?:ab){2,}$")
    assert "RDS001" not in ids("^(?:a{2}|b{2})+$")


def test_rds001_still_fires_when_the_body_length_is_free():
    assert "RDS001" in ids("^(a+)+$")
    assert "RDS001" in ids("^(?:a+)+b$")
