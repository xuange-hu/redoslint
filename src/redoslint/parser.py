"""Hand-written parser for the Python-flavoured regex subset.

Why hand-written: the AST has to carry byte offsets for every node (the
evidence contract: a finding must point at the exact characters that cause
it), and `re.sre_parse` gives neither spans nor stability across versions.

Supported syntax — everything that appears in day-to-day application code:
  literals, ., character classes with ranges/negation/escapes (\\x \\u \\U
  \\N{NAME} and octal), alternation, groups (capturing / non-capturing /
  named / atomic / conditional (?(n)yes|no)), lookarounds with Python's
  fixed-width lookbehind rule enforced, quantifiers * + ? {m} {m,} {m,n}
  {,n} with lazy (?) and possessive (+) variants, anchors ^ $ \\A \\Z \\b
  \\B, backreferences \\1.. / (?P=name) with CPython's exact
  octal-vs-group-ref digit algorithm, comments (?#...), and inline flags:
  global (?imsxu..) only at the very start of the expression, scoped
  (?flags:...) / (?-flags:...) with full add/del validation, verbose mode
  honouring whitespace and #-comments.
Anything else raises ParseError; callers surface that as RDS099 instead of
guessing about a pattern we cannot see clearly.

Acceptance is kept in lock-step with CPython `re._parser` (3.10-3.13): every
accept/reject decision here was diffed against `re.compile` and is pinned by
tests/test_parser_parity.py.
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from . import charset as cs

# CPython re._constants values that shape acceptance.
MAXREPEAT = 4294967295
MAXGROUPS = 1073741823

_DIGITS = frozenset("0123456789")
_OCT = frozenset("01234567")
_WHITESPACE = frozenset(" \t\n\r\v\f")
_FLAGS = frozenset("aiLmsuxt")  # re._parser.FLAGS keys
_TYPE_FLAGS = frozenset("aLu")  # mutually exclusive (re._parser.TYPE_FLAGS)
# re._parser.GLOBAL_FLAGS = DEBUG|TEMPLATE; only 't' is reachable from a
# pattern (there is no 'd' flag character), and it may only appear in the
# self-contained (?t) form.
_GLOBAL_FLAGS = frozenset("t")


@dataclass
class Node:
    span: tuple[int, int]


@dataclass
class Lit(Node):
    ch: str


@dataclass
class Class(Node):
    ranges: list[tuple[int, int]]  # always in positive (matched) form


@dataclass
class Dot(Node):
    pass


@dataclass
class Anchor(Node):
    kind: str  # '^' '$' 'A' 'Z' 'b' 'B'


@dataclass
class Backref(Node):
    index: int
    name: str | None = None


@dataclass
class Group(Node):
    kind: str  # 'cap' | 'noncap' | 'named' | 'atomic' | 'scoped'
    index: int | None  # capturing groups only
    name: str | None
    child: Node


@dataclass
class Look(Node):
    kind: str  # 'ahead' 'nagahead' 'behind' 'negbehind'
    child: Node


@dataclass
class Quant(Node):
    child: Node
    min: int
    max: int | None  # None = unbounded
    lazy: bool
    possessive: bool = False  # a*+ — commits, never backtracks


@dataclass
class Cond(Node):
    """Conditional group (?(ref)yes|no). `no` is None when the else-branch
    is absent — the pattern then matches only when the group is set."""

    ref: int  # group number (names resolve at parse time)
    yes: Node
    no: Node | None


@dataclass
class Concat(Node):
    parts: list[Node]


@dataclass
class Alt(Node):
    branches: list[Node]


class ParseError(ValueError):
    def __init__(self, msg: str, pos: int):
        super().__init__(f"{msg} at offset {pos}")
        self.msg = msg
        self.pos = pos


_ESCAPES = {
    "n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a",
}

# \b inside a class is backspace, not a word boundary.
_CLASS_CHAR_ESCAPES = dict(_ESCAPES, b="\b")


class Parser:
    def __init__(self, pattern: str):
        self.pat = pattern
        self.pos = 0
        self.group_count = 0
        self.group_names: dict[str, int] = {}
        self.open_groups: set[int] = set()       # captures not yet closed
        self.group_nodes: dict[int, Node] = {}   # closed group number -> body
        # state.groups at outer-most lookbehind entry (None = not in one);
        # mirrors re._parser.State.lookbehindgroups save/restore semantics.
        self.lb_watermark: int | None = None
        # numeric condition refs ((?(3)...)) validated at end of pattern,
        # because Python allows them to point forward: grouprefpos.
        self.grouprefpos: dict[int, int] = {}
        self.verbose = False  # set by a leading (?x)
        self._wmemo: dict[int, tuple[int, int | None]] = {}

    # -- low-level helpers ------------------------------------------------

    def peek(self) -> str | None:
        return self.pat[self.pos] if self.pos < len(self.pat) else None

    def take(self) -> str:
        if self.pos >= len(self.pat):
            raise ParseError("pattern ends unexpectedly", self.pos)
        ch = self.pat[self.pos]
        self.pos += 1
        return ch

    def expect(self, ch: str, what: str) -> None:
        if self.peek() != ch:
            raise ParseError(f"expected {what}", self.pos)
        self.pos += 1

    # -- grammar ----------------------------------------------------------

    def parse(self) -> Node:
        node = self.parse_alt(0)
        if self.pos < len(self.pat):
            # parse_alt stops at ')' — anything left is an unbalanced one.
            raise ParseError("unbalanced parenthesis", self.pos)
        # Numeric condition refs may point forward, so they are only checked
        # once the whole pattern (and hence group_count) is known.
        for g, at in self.grouprefpos.items():
            if g > self.group_count:
                raise ParseError(f"invalid group reference {g}", at)
        return node

    def parse_alt(self, depth: int) -> Node:
        start = self.pos
        # Python: first = not nested and not items — global flags are only
        # allowed in the first branch of the outermost alternation.
        branches = [self.parse_concat(depth == 0)]
        while self.peek() == "|":
            self.take()
            branches.append(self.parse_concat(False))
        if len(branches) == 1:
            return branches[0]
        return Alt((start, self.pos), branches)

    def parse_concat(self, first: bool) -> Node:
        start = self.pos
        parts: list[Node] = []
        while True:
            self._skip_verbose_noise()
            ch = self.peek()
            if ch is None or ch in "|)":
                break
            if ch == "(" and self.pat.startswith("(?#", self.pos):
                self._skip_comment()
                continue  # comments produce no node, exactly like Python
            if ch == "(" and self._at_global_flags():
                self._parse_global_flags(first and not parts)
                continue
            if ch in "*+?{":
                self._bind_quantifier(parts)
                continue
            parts.append(self.parse_atom())
        if len(parts) == 1:
            return parts[0]
        return Concat((start, self.pos), parts)

    def _skip_verbose_noise(self) -> None:
        """In verbose mode whitespace and #-comments are not tokens."""
        if not self.verbose:
            return
        while True:
            ch = self.peek()
            if ch is None:
                return
            if ch in _WHITESPACE:
                self.pos += 1
                continue
            if ch == "#":
                # to end of line (consuming the newline), or to EOF —
                # then keep scanning: whitespace after the newline counts
                # as noise too.
                while self.pos < len(self.pat):
                    if self.take() == "\n":
                        break
                continue
            return

    def _skip_comment(self) -> None:
        """(?#...) runs to the first ')' and contributes nothing."""
        start = self.pos
        self.pos += 3  # consume '(?#'
        while True:
            if self.pos >= len(self.pat):
                raise ParseError("missing ), unterminated comment", start)
            if self.pat[self.pos] == ")":
                self.pos += 1
                return
            self.pos += 1

    def _at_global_flags(self) -> bool:
        """True when the pattern at self.pos is the self-contained form
        (?flags) — a '(' '?' flag-chars ')' sequence with no ':' or '-'."""
        if self.pos + 3 >= len(self.pat) or self.pat[self.pos + 1] != "?":
            return False  # need at least "(?X" before we can even look
        i = self.pos + 2
        if self.pat[i] not in _FLAGS:
            return False
        while i < len(self.pat) and self.pat[i] in _FLAGS:
            i += 1
        return i < len(self.pat) and self.pat[i] == ")"

    def _parse_global_flags(self, allowed: bool) -> None:
        """Consume (?flags). Mirrors _parse_flags + the position check:
        flag validation runs first, then 'global flags not at the start'."""
        start = self.pos
        i = self.pos + 2
        add: set[str] = set()
        while True:
            ch = self.pat[i]
            i += 1
            if ch == "L":
                raise ParseError(
                    "bad inline flags: cannot use 'L' flag with a str pattern",
                    start)
            add.add(ch)
            if ch in _TYPE_FLAGS and (add & _TYPE_FLAGS) != {ch}:
                raise ParseError(
                    "bad inline flags: flags 'a', 'u' and 'L' are "
                    "incompatible", start)
            if self.pat[i] == ")":
                break
        self.pos = i + 1
        if not allowed:
            raise ParseError(
                "global flags not at the start of the expression", start)
        if "x" in add:
            # verbose changes how the rest of the pattern is *tokenized*,
            # so it must be applied immediately (case/dotall do not).
            self.verbose = True

    def _bind_quantifier(self, parts: list[Node]) -> None:
        """The quantifier branch of CPython's _parse: bounds are read before
        the item check, then exactly one quantifier (greedy/lazy/possessive)
        is folded into the previous item."""
        qstart = self.pos
        ch = self.take()
        if ch == "{":
            bounds = self._try_bounds()
            if bounds is None:
                # Python treats a malformed {..} as a literal brace.
                parts.append(Lit((qstart, self.pos), "{"))
                return
            lo, hi, end = bounds
            if lo >= MAXREPEAT or (hi is not None and hi >= MAXREPEAT):
                raise ParseError("the repetition number is too large", qstart)
            self.pos = end + 1
            if hi is not None and lo > hi:
                raise ParseError("min repeat greater than max repeat", end)
        elif ch == "*":
            lo, hi = 0, None
        elif ch == "+":
            lo, hi = 1, None
        else:  # '?'
            lo, hi = 0, 1
        if not parts or isinstance(parts[-1], Anchor):
            raise ParseError("nothing to repeat", qstart)
        if isinstance(parts[-1], Quant):
            raise ParseError("multiple repeat", qstart)
        lazy = possessive = False
        if self.peek() == "?":
            self.take()
            lazy = True
        elif self.peek() == "+":
            self.take()
            possessive = True
        prev = parts[-1]
        parts[-1] = Quant(
            (prev.span[0], self.pos), prev, lo, hi, lazy, possessive)

    def _try_bounds(self) -> tuple[int, int | None, int] | None:
        """Parse {m}, {m,}, {m,n}, {,n}, {,} — self.pos sits just *past* the
        '{' the caller consumed. Returns (lo, hi, index_of_closing_brace),
        or None when it is not valid bounds — then the brace is a literal,
        matching Python's own behaviour."""
        pat = self.pat
        i = self.pos
        if i < len(pat) and pat[i] == "}":
            return None  # {} — Python emits a literal '{' only
        lo_digits = ""
        while i < len(pat) and pat[i] in _DIGITS:
            lo_digits += pat[i]
            i += 1
        if i < len(pat) and pat[i] == "}":
            if not lo_digits:
                return None
            lo = int(lo_digits)
            return (lo, lo, i)
        if i < len(pat) and pat[i] == ",":
            i += 1
            hi_digits = ""
            while i < len(pat) and pat[i] in _DIGITS:
                hi_digits += pat[i]
                i += 1
            if i < len(pat) and pat[i] == "}":
                lo = int(lo_digits) if lo_digits else 0
                hi = int(hi_digits) if hi_digits else None
                return (lo, hi, i)
        return None

    def parse_atom(self) -> Node:
        ch = self.take()
        start = self.pos - 1
        if ch == "(":
            return self.parse_group(start)
        if ch == "[":
            return self.parse_class(start)
        if ch == ".":
            return Dot((start, self.pos))
        if ch == "^":
            return Anchor((start, self.pos), "^")
        if ch == "$":
            return Anchor((start, self.pos), "$")
        if ch == "\\":
            return self.parse_escape(start)
        if ch in "*+?{":
            # unreachable — parse_concat intercepts quantifier tokens —
            # kept as a guard so a future call site cannot misparse one.
            raise ParseError("nothing to repeat", start)
        return Lit((start, self.pos), ch)

    # -- escapes ----------------------------------------------------------

    def parse_escape(self, start: int) -> Node:
        if self.pos >= len(self.pat):
            raise ParseError("pattern ends with a bare backslash", start)
        esc = self.take()
        if esc in cs.NAMED_CLASSES:
            return Class((start, self.pos), list(cs.NAMED_CLASSES[esc]))
        if esc in "dwsDWS":
            base = cs.NAMED_CLASSES[esc.lower()]
            ranges = base if esc.islower() else cs.negate(base)
            return Class((start, self.pos), ranges)
        if esc in "bBAZ":
            return Anchor((start, self.pos), esc)
        if esc == "x":
            return Lit((start, self.pos), self._hex(start, 2))
        if esc == "u":
            return Lit((start, self.pos), self._hex(start, 4))
        if esc == "U":
            return Lit((start, self.pos), self._hex(start, 8))
        if esc == "N":
            return Lit((start, self.pos), self._charname(start))
        if esc == "0":
            # \0.. — pure octal, no group-ref alternative and no 0-0o377
            # range check (at most two more octal digits fit under 0o377).
            digits = "0" + self._read_octal(2)
            return Lit((start, self.pos), chr(int(digits, 8)))
        if esc in _DIGITS:
            first = esc
            if self.peek() in _DIGITS:
                second = self.take()
                if (first in _OCT and second in _OCT
                        and self.peek() in _OCT):
                    # three octal digits — an octal escape, not a group ref
                    third = self.take()
                    digits = first + second + third
                    val = int(digits, 8)
                    if val > 0o377:
                        raise ParseError(
                            f"octal escape value \\{digits} outside of "
                            "range 0-0o377", start)
                    return Lit((start, self.pos), chr(val))
                group = int(first + second)  # up to two digits = group ref
            else:
                group = int(first)
            return self._backref(group, start)
        if esc in _ESCAPES:
            return Lit((start, self.pos), _ESCAPES[esc])
        if esc.isalpha():
            # Python's re rejects unknown letter escapes; so do we — guessing
            # a charset here would poison every overlap decision downstream.
            raise ParseError(f"bad escape \\{esc}", start)
        return Lit((start, self.pos), esc)

    def _read_octal(self, n: int) -> str:
        out = ""
        while len(out) < n and self.peek() in _OCT:
            out += self.take()
        return out

    def _hex(self, start: int, width: int) -> str:
        digits = self.pat[self.pos:self.pos + width]
        if len(digits) < width:
            raise ParseError("incomplete \\x/\\u/\\U escape", start)
        self.pos += width
        try:
            return chr(int(digits, 16))
        except (ValueError, OverflowError):
            # ValueError: > 0x10FFFF; OverflowError: huge hex literals
            raise ParseError("bad hex escape", start) from None

    def _charname(self, start: int) -> str:
        """\\N{NAME} — resolved through unicodedata, like Python does."""
        if self.peek() != "{":
            raise ParseError("missing {", self.pos)
        self.pos += 1
        end = self.pat.find("}", self.pos)
        if end == -1:
            raise ParseError("missing character name", len(self.pat))
        name = self.pat[self.pos:end]
        if not name:
            raise ParseError("missing character name", end)
        self.pos = end + 1
        try:
            return unicodedata.lookup(name)
        except (KeyError, TypeError):
            raise ParseError(
                f"undefined character name {name!r}", start) from None

    def _backref(self, group: int, start: int) -> Backref:
        """Validate a numeric group reference exactly where Python does:
        existence first (no forward refs), then closed, then the lookbehind
        watermark."""
        if group > self.group_count:
            raise ParseError(f"invalid group reference {group}", start)
        return Backref((start, self.pos), self._checked_ref(group, start))

    def _checked_ref(self, group: int, start: int) -> int:
        if group in self.open_groups:
            raise ParseError("cannot refer to an open group", start)
        if self.lb_watermark is not None and group >= self.lb_watermark:
            raise ParseError(
                "cannot refer to group defined in the same lookbehind "
                "subpattern", start)
        return group

    # -- groups -----------------------------------------------------------

    def parse_group(self, start: int) -> Node:
        kind, name = "cap", None
        if self.peek() == "?":
            self.take()
            c = self.take()
            if c == ":":
                kind = "noncap"
            elif c == "P":
                n = self.take()
                if n == "=":  # (?P=name) — a backreference, not a group
                    ref = ""
                    while True:
                        ch = self.take()
                        if ch == ")":
                            break
                        ref += ch
                    self._check_groupname(ref)
                    if ref not in self.group_names:
                        raise ParseError(
                            f"unknown group name {ref!r}", start)
                    return Backref(
                        (start, self.pos),
                        self._checked_ref(self.group_names[ref], start),
                        ref,
                    )
                if n != "<":
                    raise ParseError("expected '<' or '=' after (?P", start)
                name = ""
                while True:
                    ch = self.take()
                    if ch == ">":
                        break
                    name += ch
                self._check_groupname(name)
                if name in self.group_names:
                    was = self.group_names[name]
                    raise ParseError(
                        f"redefinition of group name {name!r} as group "
                        f"{self.group_count + 1}; was group {was}", start)
                kind = "named"
            elif c == "=":
                child = self.parse_alt(1)
                self.expect(")", "')'")
                return Look((start, self.pos), "ahead", child)
            elif c == "!":
                child = self.parse_alt(1)
                self.expect(")", "')'")
                return Look((start, self.pos), "nagahead", child)
            elif c == "<":
                n = self.take()
                if n not in "=!":
                    raise ParseError("bad lookbehind", start)
                return self._parse_lookbehind(
                    start, "behind" if n == "=" else "negbehind")
            elif c == ">":
                kind = "atomic"
            elif c == "(":
                return self.parse_conditional(start)
            elif c in _FLAGS or c == "-":
                # Scoped flags (?flags:...) / (?-flags:...). The global
                # self-contained (?flags) form never reaches parse_group —
                # parse_concat routes it through _parse_global_flags.
                add, dels = self._parse_flags(c, start)
                prev_verbose = self.verbose
                self.verbose = (
                    (prev_verbose or "x" in add) and "x" not in dels)
                child = self.parse_alt(1)
                self.verbose = prev_verbose
                self.expect(")", "')'")
                return Group((start, self.pos), "scoped", None, None, child)
            else:
                raise ParseError(f"unknown group modifier '?{c}'", start)
        index = None
        if kind in ("cap", "named"):
            self.group_count += 1
            index = self.group_count
            if kind == "named":
                self.group_names[name] = index
            self.open_groups.add(index)
        child = self.parse_alt(1)
        self.expect(")", "')'")
        if index is not None:
            self.open_groups.discard(index)
            self.group_nodes[index] = child
        return Group((start, self.pos), kind, index, name, child)

    def _check_groupname(self, name: str) -> None:
        if not name:
            raise ParseError("missing group name", self.pos)
        if not name.isidentifier():
            raise ParseError(f"bad character in group name {name!r}", self.pos)

    def _parse_flags(self, first_flag: str, start: int) -> tuple[set, set]:
        """CPython's _parse_flags for str patterns: returns (add, del).
        'L' is rejected for str, type flags are mutually exclusive, only the
        (?flags) form may carry global flags, and add∩del is an error."""
        add: set[str] = set()
        dels: set[str] = set()
        ch = first_flag
        if ch != "-":
            while True:
                if ch == "L":
                    raise ParseError(
                        "bad inline flags: cannot use 'L' flag with a str "
                        "pattern", start)
                add.add(ch)
                if ch in _TYPE_FLAGS and (add & _TYPE_FLAGS) != {ch}:
                    raise ParseError(
                        "bad inline flags: flags 'a', 'u' and 'L' are "
                        "incompatible", start)
                ch = self.take()  # EOF -> pattern ends unexpectedly
                if ch in ")-:":
                    break
                if ch not in _FLAGS:
                    raise ParseError(
                        "unknown flag" if ch.isalpha()
                        else "missing -, : or )", self.pos - 1)
        if ch == ")":
            # unreachable: parse_concat routes (?flags) away from here
            raise ParseError(
                "global flags not at the start of the expression", start)
        if add & _GLOBAL_FLAGS:
            raise ParseError(
                "bad inline flags: cannot turn on global flag", start)
        if ch == "-":
            ch = self.take()
            if ch not in _FLAGS:
                raise ParseError(
                    "unknown flag" if ch.isalpha() else "missing flag",
                    self.pos - 1)
            while True:
                if ch in _TYPE_FLAGS:
                    raise ParseError(
                        "bad inline flags: cannot turn off flags 'a', 'u' "
                        "and 'L'", start)
                dels.add(ch)
                ch = self.take()
                if ch == ":":
                    break
                if ch not in _FLAGS:
                    raise ParseError(
                        "unknown flag" if ch.isalpha() else "missing :",
                        self.pos - 1)
        # ch == ':' in both entry paths
        if dels & _GLOBAL_FLAGS:
            raise ParseError(
                "bad inline flags: cannot turn off global flag", start)
        if add & dels:
            raise ParseError(
                "bad inline flags: flag turned on and off", start)
        return add, dels

    def _parse_lookbehind(self, start: int, kind: str) -> Look:
        """Lookbehind: record the group watermark on entry (only for the
        outer-most one, exactly like State.lookbehindgroups), then enforce
        Python's compile-time fixed-width rule on the way out."""
        saved = self.lb_watermark
        if saved is None:
            # state.groups counts group 0, hence group_count + 1.
            self.lb_watermark = self.group_count + 1
        child = self.parse_alt(1)
        self.lb_watermark = saved
        self.expect(")", "')'")
        lo, hi = self._width(child)
        if lo != hi:
            raise ParseError(
                "look-behind requires fixed-width pattern", start)
        return Look((start, self.pos), kind, child)

    def parse_conditional(self, start: int) -> Node:
        """(?(ref)yes|no). Numeric refs are checked at the end of the
        pattern (they may point forward); named refs must already exist.
        Absent else-branch = matches only when the group is set, so the node
        keeps `no = None` instead of inventing an empty alternative."""
        name = ""
        while True:
            ch = self.take()
            if ch == ")":
                break
            name += ch
        if not name:
            raise ParseError("missing group name", start)
        if name.isascii() and name.isdigit():
            ref = int(name)
            if ref == 0:
                raise ParseError("bad group number", start)
            if ref >= MAXGROUPS:
                raise ParseError(f"invalid group reference {ref}", start)
            self.grouprefpos[ref] = start
            if self.lb_watermark is not None:
                # inside a lookbehind the ref must already exist and be
                # closed — checklookbehindgroup runs for conditionals too.
                self._checked_ref_existence(ref, start)
        else:
            self._check_groupname(name)
            if name not in self.group_names:
                raise ParseError(f"unknown group name {name!r}", start)
            ref = self.group_names[name]
            if self.lb_watermark is not None:
                self._checked_ref(ref, start)
        yes = self.parse_concat(False)
        no = None
        if self.peek() == "|":
            self.take()
            no = self.parse_concat(False)
            if self.peek() == "|":
                raise ParseError(
                    "conditional backref with more than two branches", self.pos)
        self.expect(")", "')'")
        return Cond((start, self.pos), ref, yes, no)

    def _checked_ref_existence(self, group: int, start: int) -> None:
        if group > self.group_count or group in self.open_groups:
            raise ParseError("cannot refer to an open group", start)
        if group >= self.lb_watermark:  # type: ignore[operator]
            raise ParseError(
                "cannot refer to group defined in the same lookbehind "
                "subpattern", start)

    # -- character classes ------------------------------------------------

    def parse_class(self, start: int) -> Node:
        ranges: list[tuple[int, int]] = []
        negated = False
        if self.peek() == "^":
            self.take()
            negated = True
        first = True
        while True:
            c = self.peek()
            if c is None:
                raise ParseError("unterminated character set", start)
            self.take()
            if c == "]" and not first:
                break
            first = False
            self._class_item(c, ranges, start)
            # range "a-z"?
            if self.peek() == "-" and self.pos + 1 < len(self.pat) \
                    and self.pat[self.pos + 1] != "]":
                self.take()  # '-'
                hi_raw = self.take()
                hi = self._single_class_char(hi_raw, start)
                lo = ranges[-1]
                # ranges is a flat list of (lo, hi) tuples; the previous item
                # must be a single point for "a-z" to be a well-formed range.
                if lo[0] != lo[1] or lo[0] > ord(hi):
                    raise ParseError("bad character range", start)
                ranges[-1] = (lo[0], ord(hi))
        if negated:
            ranges = cs.negate(ranges)
        return Class((start, self.pos), cs.normalize(ranges))

    def _class_item(self, raw: str, ranges: list[tuple[int, int]], start: int) -> None:
        """Append the range(s) one class member contributes. Inside a class
        every digit sequence is octal (never a group ref), and 8/9 are bad."""
        if raw != "\\":
            ranges.extend(cs.char(raw))
            return
        if self.pos >= len(self.pat):
            raise ParseError("pattern ends with a bare backslash", start)
        esc = self.take()
        if esc in _CLASS_CHAR_ESCAPES:
            ranges.extend(cs.char(_CLASS_CHAR_ESCAPES[esc]))
            return
        if esc in "dws":
            ranges.extend(cs.NAMED_CLASSES[esc])
            return
        if esc in "DWS":
            ranges.extend(cs.negate(cs.NAMED_CLASSES[esc.lower()]))
            return
        if esc == "x":
            ranges.extend(cs.char(self._hex(start, 2)))
            return
        if esc == "u":
            ranges.extend(cs.char(self._hex(start, 4)))
            return
        if esc == "U":
            ranges.extend(cs.char(self._hex(start, 8)))
            return
        if esc == "N":
            ranges.extend(cs.char(self._charname(start)))
            return
        if esc in _DIGITS:
            ranges.extend(cs.char(self._class_octal(esc, start)))
            return
        if esc.isalpha():
            raise ParseError(f"bad escape \\{esc} in class", start)
        ranges.extend(cs.char(esc))

    def _class_octal(self, first: str, start: int) -> str:
        if first not in _OCT:
            # \8 / \9 inside a class: Python's _class_escape raises
            # ValueError here, which surfaces as "bad escape".
            raise ParseError(f"bad escape \\{first} in class", start)
        digits = first + self._read_octal(2)
        val = int(digits, 8)
        if val > 0o377:
            raise ParseError(
                f"octal escape value \\{digits} outside of range 0-0o377",
                start)
        return chr(val)

    def _single_class_char(self, raw: str, start: int) -> str:
        """The high end of an a-z range must be a single character."""
        if raw != "\\":
            return raw
        if self.pos >= len(self.pat):
            raise ParseError("pattern ends with a bare backslash", start)
        esc = self.take()
        if esc in _CLASS_CHAR_ESCAPES:
            return _CLASS_CHAR_ESCAPES[esc]
        if esc == "x":
            return self._hex(start, 2)
        if esc == "u":
            return self._hex(start, 4)
        if esc == "U":
            return self._hex(start, 8)
        if esc == "N":
            return self._charname(start)
        if esc in _DIGITS:
            return self._class_octal(esc, start)
        if esc.isalpha():
            raise ParseError(f"bad escape \\{esc} in class", start)
        return esc

    # -- widths (the lookbehind fixed-width rule) -------------------------

    def _width(self, node: Node) -> tuple[int, int | None]:
        """(min, max) characters this node consumes — None max = unbounded.
        Same shape as SubPattern.getwidth(): anchors/assertions consume
        nothing, alternations take min/max across branches, backreferences
        take the referenced group's width. Memoized because backref chains
        re-walk shared subpatterns."""
        key = id(node)
        cached = self._wmemo.get(key)
        if cached is not None:
            return cached
        w = self._width_uncached(node)
        self._wmemo[key] = w
        return w

    def _width_uncached(self, node: Node) -> tuple[int, int | None]:
        if isinstance(node, (Lit, Class, Dot)):
            return (1, 1)
        if isinstance(node, (Anchor, Look)):
            return (0, 0)
        if isinstance(node, Backref):
            child = self.group_nodes.get(node.index)
            if child is None:
                return (0, None)
            return self._width(child)
        if isinstance(node, Group):
            return self._width(node.child)
        if isinstance(node, Cond):
            if node.no is None:
                # no else-branch: only matches when the group is set, so
                # the only reachable widths are the yes-branch's.
                return self._width(node.yes)
            ylo, yhi = self._width(node.yes)
            nlo, nhi = self._width(node.no)
            hi = None if yhi is None or nhi is None else max(yhi, nhi)
            return (min(ylo, nlo), hi)
        if isinstance(node, Concat):
            lo = 0
            hi: int | None = 0
            for part in node.parts:
                plo, phi = self._width(part)
                lo += plo
                if phi is None or hi is None:
                    hi = None
                else:
                    hi += phi
            return (lo, hi)
        if isinstance(node, Alt):
            if not node.branches:
                return (0, 0)
            los, his = zip(
                *(self._width(b) for b in node.branches), strict=True)
            hi = None if any(h is None for h in his) else max(
                h for h in his if h is not None)
            return (min(los), hi)
        if isinstance(node, Quant):
            clo, chi = self._width(node.child)
            lo = clo * node.min
            if node.max is None or chi is None:
                return (lo, None)
            return (lo, chi * node.max)
        return (0, 0)


def parse(pattern: str) -> tuple[Node, int, dict[str, int]]:
    """Parse `pattern`; returns (ast, group_count, name->index)."""
    p = Parser(pattern)
    ast = p.parse()
    return ast, p.group_count, p.group_names
