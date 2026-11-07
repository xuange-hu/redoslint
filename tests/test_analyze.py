"""charset algebra and the three semantic queries."""

import pytest

from redoslint import analyze as an
from redoslint import charset as cs
from redoslint import parser as pr


def parse(pattern):
    """parser.parse returns (ast, group_count, names); tests want the ast."""
    return pr.parse(pattern)[0]


def ranges(pattern):
    return an.full_charset(parse(pattern))


# -- range algebra ---------------------------------------------------------

def test_union_merges_overlapping():
    assert cs.union([(1, 5)], [(4, 9)]) == [(1, 9)]


def test_union_merges_adjacent():
    assert cs.union([(1, 5)], [(6, 9)]) == [(1, 9)]


def test_union_keeps_disjoint():
    assert cs.union([(1, 5)], [(7, 9)]) == [(1, 5), (7, 9)]


def test_negate_is_exact_complement():
    comp = cs.negate([(65, 90)])
    assert comp == [(0, 64), (91, 0x10FFFF)]


def test_negate_of_empty_is_everything():
    assert cs.negate([]) == [(0, 0x10FFFF)]


def test_double_negate_round_trips():
    original = [(48, 57), (97, 122)]
    assert cs.negate(cs.negate(original)) == original


def test_intersect():
    assert cs.intersect([(48, 57)], [(53, 60)]) == [(53, 57)]


def test_intersect_disjoint():
    assert cs.intersect([(48, 57)], [(97, 122)]) == []


def test_overlaps():
    assert cs.overlaps([(48, 57)], [(53, 60)])
    assert not cs.overlaps([(48, 57)], [(97, 122)])


def test_is_subset():
    assert cs.is_subset([(48, 57)], [(48, 57), (97, 122)])
    assert not cs.is_subset([(48, 57)], [(97, 122)])


def test_is_subset_of_everything():
    assert cs.is_subset([(1, 2)], [(0, 0x10FFFF)])


def test_describe_is_readable():
    text = cs.describe([(48, 57)])
    assert "'0'" in text and "'9'" in text


def test_describe_truncates():
    many = [(i * 10, i * 10) for i in range(10)]
    assert "more)" in cs.describe(many, limit=3)


# -- full charset ----------------------------------------------------------

def test_full_charset_literal():
    assert ranges("a") == [(97, 97)]


def test_full_charset_concat_is_union():
    assert ranges("ab") == [(97, 98)]


def test_full_charset_alternation_is_union():
    assert ranges("a|z") == [(97, 97), (122, 122)]


def test_full_charset_dot_excludes_newline():
    dot = ranges(".")
    assert not any(lo <= 10 <= hi for lo, hi in dot)
    assert any(lo <= 65 <= hi for lo, hi in dot)


def test_full_charset_anchor_is_empty():
    assert ranges("^") == []


def test_full_charset_lookaround_is_empty():
    assert ranges("(?=a)") == []


def test_full_charset_class_negation():
    neg = ranges("[^a]")
    assert not any(lo <= 97 <= hi for lo, hi in neg)


# -- start / end -----------------------------------------------------------

def test_start_charset_of_concat_uses_first_part():
    assert an.start_charset(parse("abc")) == [(97, 97)]


def test_start_charset_skips_nullable_prefix():
    # a?b — the b can be first when the optional part matches empty
    assert an.start_charset(parse("a?b")) == [(97, 98)]


def test_start_charset_of_alternation_is_union():
    assert an.start_charset(parse("a|z")) == [(97, 97), (122, 122)]


def test_end_charset_uses_last_part():
    assert an.end_charset(parse("abc")) == [(99, 99)]


def test_end_charset_skips_nullable_suffix():
    assert an.end_charset(parse("ab?")) == [(97, 98)]


def test_end_charset_of_quantified_group_is_its_last_char():
    # (\d{1,3}\.){3} ends with a dot — this is what keeps the IPv4 pattern
    # from being reported as adjacent ambiguity
    assert an.end_charset(parse(r"(\d{1,3}\.){3}")) == [(46, 46)]


# -- nullable --------------------------------------------------------------

@pytest.mark.parametrize("pattern,expected", [
    ("a", False),
    ("a*", True),
    ("a+", False),
    ("a?", True),
    ("^", True),
    (r"\b", True),
    ("(?:)", True),
    ("a|b", False),
    ("a|", True),
    ("(a*)", True),
])
def test_nullable(pattern, expected):
    assert an.nullable(parse(pattern)) is expected


# -- traversal helpers -----------------------------------------------------

def test_unwrap_groups_reaches_inner_node():
    node = an.unwrap_groups(parse("(?:(?:a))"))
    assert type(node).__name__ == "Lit"


def test_children_of_concat():
    assert len(an.children(parse("abc"))) == 3


def test_iter_all_counts_every_node():
    nodes = list(an.iter_all(parse("(a|b)+")))
    assert len(nodes) >= 4


def test_contains_backref():
    assert an.contains_backref(parse(r"(\w)\1"), 1)
    assert not an.contains_backref(parse(r"(\w)"), 1)


def test_fixed_length_constant_iterations():
    # (?:a{2})* consumes exactly two characters per iteration: the split points
    # are pinned, so it cannot be the nested-quantifier blowup RDS001 looks for.
    assert an.fixed_length(parse("(?:a{2})*")) is None  # the quantifier itself
    from redoslint.parser import Group, Quant
    node = parse("(?:a{2})")
    assert an.fixed_length(node) == 2
    assert isinstance(parse("(?:a{2})"), Group)
    assert isinstance(parse("(?:a{2})").child, Quant)


def test_fixed_length_of_variable_fragments_is_none():
    assert an.fixed_length(parse("a+")) is None
    assert an.fixed_length(parse("a{1,3}")) is None
    assert an.fixed_length(parse(r"\w")) == 1
    assert an.fixed_length(parse("^")) == 0
    assert an.fixed_length(parse("abc")) == 3


def test_fixed_length_alternation_needs_equal_branches():
    assert an.fixed_length(parse("(?:a{2}|b{2})")) == 2
    assert an.fixed_length(parse("(?:a|bb)")) is None


def test_fixed_length_rejects_backreferences():
    # A backreference consumes as much as the group captured: never fixed.
    assert an.fixed_length(parse(r"(a)\1")) is None
