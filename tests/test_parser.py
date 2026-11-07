"""Parser: spans, node kinds, quantifier forms, and the errors that must stay
errors (a silently misparsed pattern would poison every rule downstream)."""

import pytest

from redoslint import parser as pr
from redoslint.parser import (
    Alt,
    Anchor,
    Backref,
    Class,
    Concat,
    Dot,
    Group,
    Lit,
    Look,
    Quant,
)


def parse(pattern):
    return pr.parse(pattern)[0]


def kinds(node):
    return [type(n).__name__ for n in _walk(node)]


def _walk(node):
    yield node
    from redoslint import analyze as an
    for child in an.children(node):
        yield from _walk(child)


# -- literals and spans ----------------------------------------------------

def test_single_literal_span():
    node = parse("a")
    assert isinstance(node, Lit) and node.ch == "a"
    assert node.span == (0, 1)


def test_concat_spans_are_per_character():
    node = parse("abc")
    assert isinstance(node, Concat)
    assert [(p.ch, p.span) for p in node.parts] == [
        ("a", (0, 1)), ("b", (1, 2)), ("c", (2, 3))]


def test_dot():
    assert isinstance(parse("."), Dot)


def test_unicode_literal_span_is_character_based():
    # spans are offsets into the pattern string, not bytes
    node = parse("é")
    assert node.span == (0, 1)


# -- character classes -----------------------------------------------------

def test_class_expands_members():
    node = parse("[abc]")
    assert isinstance(node, Class)
    assert node.ranges == [(97, 99)]  # adjacent members merge into one range


def test_class_range():
    assert parse("[a-z]").ranges == [(97, 122)]


def test_class_multiple_ranges():
    assert parse("[a-zA-Z0-9_]").ranges == [
        (48, 57), (65, 90), (95, 95), (97, 122)]


def test_class_negation_complements():
    node = parse("[^a]")
    inside = lambda cp: any(lo <= cp <= hi for lo, hi in node.ranges)  # noqa: E731
    assert not inside(97) and inside(98) and inside(0x10FFFF)
    assert node.ranges[0][0] == 0


def test_class_named_set_inside():
    assert parse(r"[\d.]").ranges == [(46, 46), (48, 57)]


def test_class_leading_bracket_is_literal():
    assert (93, 93) in parse("[]]").ranges


def test_class_escaped_dash_is_literal():
    assert (45, 45) in parse(r"[a\-z]").ranges


def test_class_trailing_dash_is_literal():
    assert (45, 45) in parse("[a-]").ranges


def test_negated_named_class_inside_class():
    ranges = parse(r"[\D]").ranges
    assert (48, 57) not in ranges  # \D excludes digits


def test_class_hex_escape():
    assert parse(r"[\x41]").ranges == [(65, 65)]


# -- quantifiers -----------------------------------------------------------

@pytest.mark.parametrize("pattern,lo,hi,lazy", [
    ("a*", 0, None, False),
    ("a+", 1, None, False),
    ("a?", 0, 1, False),
    ("a{2}", 2, 2, False),
    ("a{2,}", 2, None, False),
    ("a{2,5}", 2, 5, False),
    ("a*?", 0, None, True),
    ("a+?", 1, None, True),
    ("a??", 0, 1, True),
    ("a{2,5}?", 2, 5, True),
])
def test_quantifier_forms(pattern, lo, hi, lazy):
    node = parse(pattern)
    assert isinstance(node, Quant)
    assert (node.min, node.max, node.lazy) == (lo, hi, lazy)


def test_quantifier_span_covers_atom():
    node = parse("ab+")
    assert isinstance(node, Concat)
    assert node.parts[1].span == (1, 3)


def test_malformed_brace_is_literal():
    node = parse("a{b}")
    assert isinstance(node, Concat)
    # a, {, b, } — Python matches a malformed quantifier literally
    assert [type(p).__name__ for p in node.parts] == ["Lit"] * 4


def test_multiple_repeat_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("a**")


def test_min_greater_than_max_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("a{5,2}")


# -- alternation and groups ------------------------------------------------

def test_alternation_branches():
    node = parse("a|b|c")
    assert isinstance(node, Alt) and len(node.branches) == 3


def test_empty_alternative():
    node = parse("a|")
    assert isinstance(node, Alt)
    assert len(node.branches) == 2


def test_capturing_group_numbering():
    ast, count, names = pr.parse("(a)(b)")
    assert count == 2
    groups = [n for n in _walk(ast) if isinstance(n, Group)]
    assert sorted(g.index for g in groups) == [1, 2]


def test_named_group_and_numbering():
    ast, count, names = pr.parse("(?P<user>a)(b)")
    assert names == {"user": 1}
    assert count == 2


def test_noncapturing_group_has_no_index():
    ast, count, _ = pr.parse("(?:a)")
    assert count == 0
    assert parse("(?:a)").index is None


def test_atomic_group():
    assert parse("(?>a)").kind == "atomic"


@pytest.mark.parametrize("pattern,kind", [
    ("(?=a)", "ahead"),
    ("(?!a)", "nagahead"),
    ("(?<=a)", "behind"),
    ("(?<!a)", "negbehind"),
])
def test_lookarounds(pattern, kind):
    node = parse(pattern)
    assert isinstance(node, Look) and node.kind == kind


@pytest.mark.parametrize("pattern,kind", [
    ("^", "^"), ("$", "$"), (r"\b", "b"), (r"\B", "B"),
    (r"\A", "A"), (r"\Z", "Z"),
])
def test_anchors(pattern, kind):
    node = parse(pattern)
    assert isinstance(node, Anchor) and node.kind == kind


# -- backreferences --------------------------------------------------------

def test_numeric_backreference():
    node = parse(r"(a)\1")
    refs = [n for n in _walk(node) if isinstance(n, Backref)]
    assert refs and refs[0].index == 1


def test_named_backreference_via_g():
    node = parse(r"(?P<x>a)\g<x>")
    refs = [n for n in _walk(node) if isinstance(n, Backref)]
    assert refs and refs[0].index == 1 and refs[0].name == "x"


def test_named_backreference_via_p_equals():
    node = parse(r"(?P<x>a)(?P=x)")
    refs = [n for n in _walk(node) if isinstance(n, Backref)]
    assert refs and refs[0].index == 1


def test_unknown_named_backreference_is_an_error():
    with pytest.raises(pr.ParseError):
        parse(r"(?P=x)")


# -- escapes ---------------------------------------------------------------

@pytest.mark.parametrize("pattern,ch", [
    (r"\n", "\n"), (r"\t", "\t"), (r"\r", "\r"),
    (r"\x41", "A"), (r"\u0041", "A"), (r"\.", "."),
])
def test_escapes(pattern, ch):
    node = parse(pattern)
    assert isinstance(node, Lit) and node.ch == ch


@pytest.mark.parametrize("pattern,member,absent", [
    (r"\d", 48, 97), (r"\w", 95, 45), (r"\s", 32, 65),
])
def test_named_classes(pattern, member, absent):
    node = parse(pattern)
    assert isinstance(node, Class)
    inside = lambda cp: any(lo <= cp <= hi for lo, hi in node.ranges)  # noqa: E731
    assert inside(member)
    assert not inside(absent)


def test_unknown_letter_escape_is_an_error():
    with pytest.raises(pr.ParseError):
        parse(r"\q")


# -- inline flags ----------------------------------------------------------

def test_inline_flags_are_transparent():
    node = parse("(?i)abc")
    assert "Concat" in kinds(node) or isinstance(node, Concat)


def test_inline_flag_inside_group():
    node = parse("((?i)a)b")
    assert isinstance(node, Concat)


# -- errors ----------------------------------------------------------------

@pytest.mark.parametrize("pattern", [
    "(", "a)", "*a", "a**", "[a", "a\\", "(?z)a", "a{5,2}", "(?P=nope)",
])
def test_invalid_patterns_raise(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


def test_error_carries_position():
    with pytest.raises(pr.ParseError) as exc:
        parse("[unclosed")
    assert exc.value.pos == 0
