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


def test_g_backreference_is_rejected_like_python():
    # Python's re has no \g<...> inside patterns (that is replacement-template
    # syntax); accepting it here would analyse a pattern Python refuses.
    with pytest.raises(pr.ParseError):
        parse(r"(?P<x>a)\g<x>")
    with pytest.raises(pr.ParseError):
        parse(r"\g<1>")


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


def test_global_flag_inside_group_is_an_error():
    # Python: "global flags not at the start of the expression"
    with pytest.raises(pr.ParseError):
        parse("((?i)a)b")


# -- comments, scoped flags, verbose --------------------------------------

def test_comment_produces_no_node():
    # a comment contributes nothing; the quantifier still binds to `a`
    node = parse("a(?#note)*")
    assert isinstance(node, Quant)


def test_comment_with_unbalanced_parenthesis_inside():
    # the comment ends at the FIRST ')', the rest is a stray ')'
    with pytest.raises(pr.ParseError):
        parse("(?#(weird )syntax)")


def test_unterminated_comment_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("(?#oops")


def test_scoped_flags_wrap_content():
    node = parse("(?i:ab)")
    assert isinstance(node, Group)
    assert node.kind == "scoped" and node.index is None
    assert isinstance(node.child, Concat)


def test_scoped_flag_turn_off_is_allowed():
    assert isinstance(parse("(?-i:x)"), Group)


def test_scoped_flag_turned_on_and_off_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("(?im-i:x)")


def test_scoped_missing_colon_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("(?i-m)")


def test_locale_flag_rejected_for_str_pattern():
    with pytest.raises(pr.ParseError):
        parse("(?L)")
    with pytest.raises(pr.ParseError):
        parse("(?L:x)")


def test_type_flags_are_mutually_exclusive():
    with pytest.raises(pr.ParseError):
        parse("(?au:x)")


def test_verbose_mode_skips_whitespace_and_comments():
    node = parse("(?x) a b # trailing\n c")
    assert isinstance(node, Concat)
    assert [p.ch for p in node.parts] == ["a", "b", "c"]


def test_verbose_keeps_class_whitespace():
    node = parse("(?x)[a b]")
    assert (32, 32) in node.ranges


def test_verbose_scoped_turn_off():
    # (?-x:) re-enables literal whitespace inside its body
    node = parse("(?x)(?-x:a b)")
    parts = node.child.parts
    assert [p.ch for p in parts] == ["a", " ", "b"]


# -- possessive quantifiers ------------------------------------------------

@pytest.mark.parametrize("pattern,lo,hi", [
    ("a*+", 0, None),
    ("a++", 1, None),
    ("a?+", 0, 1),
    ("a{2,5}+", 2, 5),
])
def test_possessive_quantifiers(pattern, lo, hi):
    node = parse(pattern)
    assert isinstance(node, Quant)
    assert (node.min, node.max, node.lazy, node.possessive) == (
        lo, hi, False, True)


@pytest.mark.parametrize("pattern", [
    "a*?+", "a++?", "a*+?", "a{2}??", "a*++", "a?+?",
])
def test_possessive_then_more_quantifiers_is_multiple_repeat(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


# -- nothing to repeat / multiple repeat -----------------------------------

@pytest.mark.parametrize("pattern", [
    "^*", "$*", r"\b*", r"\B?", "(?i){2}", "(?#x)*", "{2}", "a|*",
])
def test_nothing_to_repeat(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


@pytest.mark.parametrize("pattern", [
    "a{2}{3}", "a*{2}", "a?{2}", "a{2,}{3}", "a*?{2}", "a??{2}", "a{2}*",
    "a{,5}{2}",
])
def test_multiple_repeat(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


def test_comma_bounds_are_valid():
    node = parse("a{,5}")
    assert isinstance(node, Quant)
    assert (node.min, node.max) == (0, 5)
    node = parse("a{,}")
    assert (node.min, node.max) == (0, None)


def test_lookaround_is_quantifiable():
    # Python allows it (assertions are not AT codes); zero-width bodies are
    # engine-guarded, so rules must stay quiet on it — parser accepts.
    assert isinstance(parse("(?=a)*"), Quant)
    assert isinstance(parse("(?<=a){2}"), Quant)


# -- backreference validation ----------------------------------------------

@pytest.mark.parametrize("pattern", [
    r"\1|(a)",      # forward reference
    r"(a)\10",      # group 10 does not exist
    r"(a)\108",     # two-digit group ref 10, not octal 108
    r"(a)\777",     # octal escape above 0o377
    r"(a)\778",     # group ref 77
    r"(a\1)",       # referring to an open group
    r"((a)\1)",
    r"(a|b\1)",
    r"(?P<n>(?P=n))",
    r"\8",          # group 8 never existed
])
def test_bad_backreferences(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


def test_octal_escape_wins_over_group_ref():
    # three octal digits = a character, not a reference
    node = parse(r"(a)\100")
    assert isinstance(node, Concat)
    assert node.parts[1].ch == chr(0o100)
    # \0 is always octal, even with a following non-octal digit
    node = parse(r"\08")
    assert isinstance(node, Concat)
    assert node.parts[0].ch == "\0" and node.parts[1].ch == "8"


def test_backref_in_lookbehind_must_predate_it():
    with pytest.raises(pr.ParseError):
        parse(r"(?<=(a)(?<=\1))")   # same-lookbehind definition
    node = parse(r"(a)(?<=(?<=\1))")
    looks = [n for n in _walk(node) if isinstance(n, Look)]
    assert looks


# -- lookbehind fixed width ------------------------------------------------

@pytest.mark.parametrize("pattern", [
    r"(?<=a*)",
    r"(?<=a|)",
    r"(?<=a{2,4})",
    r"(?<=aa|a)",
    r"((aa)|a)(?<=\1)",
])
def test_variable_width_lookbehind(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


@pytest.mark.parametrize("pattern", [
    r"(?<=a)", r"(?<=aa)", r"(?<=())", r"(?<=)", r"(?<=a{2})",
    r"(?<=\b)", r"(?<=^)", r"(?<=())",
])
def test_fixed_width_lookbehind(pattern):
    assert parse(pattern) is not None


# -- group names ------------------------------------------------------------

@pytest.mark.parametrize("pattern", [
    "(?P<x-1>a)", "(?P< >a)", "(?P<>a)", "(?P<1a>x)",
    "(?P<n>a)(?P<n>b)",   # redefinition
])
def test_bad_group_names(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


def test_unicode_group_names_ok():
    assert parse("(?P<名字>a)") is not None


# -- global flags position ---------------------------------------------------

@pytest.mark.parametrize("pattern", [
    "x(?i)y", "a|(?i)b", "|(?i)a", "((?i)a)", "a(?i)b",
    "(?i:x)(?s)a", "(?i)x|(?i)y",
])
def test_global_flags_not_at_start(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


@pytest.mark.parametrize("pattern", [
    "(?i)abc", "(?i)(?s)a", "(?i)(?#x)a", "(?i)(?i)a", "(?x)a b",
    "(?i)(?x)a b",
])
def test_global_flags_at_start_ok(pattern):
    assert parse(pattern) is not None


# -- conditionals -----------------------------------------------------------

def test_conditional_group_parses():
    node = parse("(a)(?(1)b|c)")
    conds = [n for n in _walk(node) if isinstance(n, pr.Cond)]
    assert conds and conds[0].ref == 1
    assert isinstance(conds[0].yes, Lit) and conds[0].yes.ch == "b"
    assert isinstance(conds[0].no, Lit) and conds[0].no.ch == "c"


def test_conditional_without_else():
    node = parse("(a)(?(1)b)")
    conds = [n for n in _walk(node) if isinstance(n, pr.Cond)]
    assert conds and conds[0].no is None


def test_conditional_forward_reference_is_checked_at_end():
    with pytest.raises(pr.ParseError):
        parse("(?(2)a)")   # no group 2 anywhere
    assert parse("(?(1)x)(a)") is not None  # forward ref is legal


def test_conditional_named_ref_must_exist():
    with pytest.raises(pr.ParseError):
        parse("(?(name)x)")


def test_conditional_three_branches_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("(a)(?(1)x|y|z)")


def test_conditional_zero_group_number_is_an_error():
    with pytest.raises(pr.ParseError):
        parse("(a)(?(0)x)")


# -- \U and \N escapes -------------------------------------------------------

def test_U_escape():
    assert parse(r"\U0001F600").ch == "\U0001F600"
    assert (0x1F600, 0x1F600) in parse(r"[\U0001F600]").ranges
    assert parse(r"a-\U0010FFFF") is not None


def test_U_escape_beyond_codepoint_is_an_error():
    with pytest.raises(pr.ParseError):
        parse(r"\UFFFFFFFF")


def test_N_escape():
    assert parse(r"\N{BULLET}").ch == "•"
    assert (0x2022, 0x2022) in parse(r"[\N{BULLET}]").ranges
    with pytest.raises(pr.ParseError):
        parse(r"\N{NO SUCH NAME}")
    with pytest.raises(pr.ParseError):
        parse(r"\N")
    with pytest.raises(pr.ParseError):
        parse(r"\N{")


def test_class_digit_escapes_are_octal():
    assert parse(r"[\101]").ranges == [(65, 65)]
    with pytest.raises(pr.ParseError):
        parse(r"[\8]")
    with pytest.raises(pr.ParseError):
        parse(r"[\400]")


# -- errors ----------------------------------------------------------------

@pytest.mark.parametrize("pattern", [
    "(", "a)", "*a", "a**", "[a", "a\\", "(?z)a", "a{5,2}", "(?P=nope)",
    "a{4294967295}", "(?i", "(?-x)",
])
def test_invalid_patterns_raise(pattern):
    with pytest.raises(pr.ParseError):
        parse(pattern)


def test_error_carries_position():
    with pytest.raises(pr.ParseError) as exc:
        parse("[unclosed")
    assert exc.value.pos == 0
