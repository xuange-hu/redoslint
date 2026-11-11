"""Canonical acceptance parity: every pattern's accept/reject verdict is
pinned to what CPython 3.12's `re.compile` returns.

Why pinned instead of compared live: the CI matrix spans 3.10-3.13 and
`re` itself changed between them (possessive quantifiers and atomic groups
arrived in 3.11). The expectations below were diffed against re on 3.12;
our parser implements that surface, so a divergence on any supported
Python version is a bug in the parser, not in `re`.
"""

import pytest

from redoslint import parser as pr


def _accepts(pattern: str) -> bool:
    try:
        pr.parse(pattern)
        return True
    except pr.ParseError:
        return False


# (pattern, "OK" if python accepts, human label)
CASES = [
    ('(a)(?(1)b)', 'OK'),  # cond no-else
    ('(a)(?(1)b|c)', 'OK'),  # cond with else
    ('(?(1)x)(a)', 'OK'),  # cond forward numeric
    ('(a)(?(0)x)', 'REJ'),  # cond zero
    ('(?(2)a)', 'REJ'),  # cond missing group
    ('(?P<n>a)(?(n)x)', 'OK'),  # cond named
    ('(?(name)x)', 'REJ'),  # cond unknown name
    ('(a)(?(1)x|y|z)', 'REJ'),  # cond three branches
    ('(?P<n>a(?(n)x))', 'OK'),  # cond inside own group
    ('(a)(?(1)x', 'REJ'),  # cond unterminated
    ('(a)(?(<n>x))', 'REJ'),  # cond angle name
    ('(?x)a b', 'OK'),  # verbose space
    ('(?x)a # c\nb', 'OK'),  # verbose comment
    ('(?x)[a b]', 'OK'),  # verbose class keeps space
    ('(?x:a b)', 'OK'),  # verbose scoped
    ('(?x)a(?-x: b)', 'OK'),  # verbose scoped off
    ('(?x) a * ?', 'REJ'),  # verbose multiple repeat
    ('(?x)(?i) a b', 'OK'),  # verbose after global i
    ('(?-x)a b', 'REJ'),  # global del-only
    ('(?x)a{,3}', 'OK'),  # verbose brace
    ('(?x)\n a', 'OK'),  # verbose newline
    ('a*+', 'OK'),  # poss star
    ('a++', 'OK'),  # poss plus
    ('a?+', 'OK'),  # poss opt
    ('a{2,5}+', 'OK'),  # poss bounded
    ('a{,5}+', 'OK'),  # poss comma bound
    ('a*?+', 'REJ'),  # poss after lazy
    ('a++?', 'REJ'),  # lazy after poss
    ('a*++', 'REJ'),  # double poss
    ('(?:ab)*+c', 'OK'),  # poss group
    ('(a+)*+b', 'OK'),  # poss outer nested
    ('a{,5}', 'OK'),  # comma min
    ('a{,}', 'OK'),  # comma unbounded
    ('a{}', 'OK'),  # empty braces
    ('{,5}', 'REJ'),  # comma at start
    ('a{,5}{2}', 'REJ'),  # comma then repeat
    ('a{b}', 'OK'),  # malformed literal
    ('a{4294967295}', 'REJ'),  # maxrepeat edge
    ('a{4294967296}', 'REJ'),  # maxrepeat over
    ('\\U0001F600', 'OK'),  # U escape
    ('[\\U0001F600]', 'OK'),  # U in class
    ('a-\\U0001F600', 'OK'),  # U range endpoint
    ('\\UFFFFFFFF', 'REJ'),  # U overflow
    ('\\U00110000', 'REJ'),  # U beyond codepoint
    ('\\N{BULLET}', 'OK'),  # N escape
    ('[\\N{BULLET}]', 'OK'),  # N in class
    ('\\N{NO SUCH}', 'REJ'),  # N unknown
    ('\\N', 'REJ'),  # N bare
    ('\\N{', 'REJ'),  # N unterminated
    ('(?<=(a)(?<=\\1))', 'REJ'),  # lb inner ref
    ('(a)(?<=(?<=\\1))', 'OK'),  # lb outer ref
    ('(?<=\\1)', 'REJ'),  # lb forward ref
    ('(?<=a{2})', 'OK'),  # lb fixed bounded
    ('(?<=a{,2})', 'REJ'),  # lb comma bound
    ('(?<=())', 'OK'),  # lb empty group
    ('(?<=a|)', 'REJ'),  # lb empty branch
    ('((aa)|a)(?<=\\1)', 'REJ'),  # lb variable via ref
    ('(?<=\\b)', 'OK'),  # lb anchor
    ('(?<=a*)', 'REJ'),  # lb star
    ('(?<=a){2}', 'OK'),  # quantified lb
    ('(?<!a{2})', 'OK'),  # neg lb fixed
    ('(?i)(?s)a', 'OK'),  # two globals
    ('(?i)(?#x)a', 'OK'),  # global after comment
    ('(?i:x)(?s)a', 'REJ'),  # global after scoped
    ('x(?i)y', 'REJ'),  # global mid
    ('((?i)a)', 'REJ'),  # global in group
    ('(?=a)(?i)b', 'REJ'),  # global in look
    ('(?i)(?P<n>a)', 'OK'),  # global before named
    ('(?t)a', 'OK'),  # template global
    ('(?u)a', 'OK'),  # unicode global
    ('(?au)x', 'REJ'),  # type conflict
    ('(?iL:x)', 'REJ'),  # L scoped
    ('(?t:x)', 'REJ'),  # global in scoped
    ('(?-t:x)', 'REJ'),  # del global in scoped
    ('(?it)a', 'OK'),  # two globals chars
    ('(?id)a', 'REJ'),  # unknown flag char
    ('(?i:', 'REJ'),  # scoped unterminated
    ('(?im-s:x)', 'OK'),  # scoped mixed
    ('(?i-m:x)', 'OK'),  # scoped del only
    ('(?-ims:x)', 'OK'),  # scoped pure del
    ('(a)\\100', 'OK'),  # octal 100
    ('(a)\\108', 'REJ'),  # ref 10
    ('(a)\\777', 'REJ'),  # octal over
    ('(a)\\778', 'REJ'),  # ref 77
    ('\\0', 'OK'),  # nul
    ('\\08', 'OK'),  # nul then 8
    ('\\012', 'OK'),  # octal 012
    ('\\8', 'REJ'),  # ref 8 bare
    ('[\\101]', 'OK'),  # class octal
    ('[\\8]', 'REJ'),  # class bad 8
    ('[\\400]', 'REJ'),  # class octal over
    ('(a)\\400', 'REJ'),  # octal 400 outside
    ('(?P<名字>a)', 'OK'),  # unicode name
    ('(?P<n>a)(?P<n>b)', 'REJ'),  # redefine
    ('(?P<>a)', 'REJ'),  # empty name
    ('(?P<x-1>a)', 'REJ'),  # bad name
    ('(?P<n>(?P=n))', 'REJ'),  # self ref open
    ('a(?#x)*', 'OK'),  # comment then quant
    ('(?#x){2}', 'REJ'),  # comment nothing repeat
    ('(?#(a)b)', 'REJ'),  # comment unbalanced in
    ('^*', 'REJ'),  # anchor quant
    ('\\b*', 'REJ'),  # backslash b quant
    ('(?=a)*', 'OK'),  # look quant
    ('(?#x)(?i)a', 'OK'),  # comment then global
]


@pytest.mark.parametrize("pattern,expected", CASES, ids=[c[1] for c in CASES])
def test_acceptance_matches_python(pattern, expected):
    got = "OK" if _accepts(pattern) else "REJ"
    assert got == expected, (
        f"{pattern!r}: python={expected} redoslint={got}")
