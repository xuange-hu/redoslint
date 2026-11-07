"""Hand-written parser for the Python-flavoured regex subset.

Why hand-written: the AST has to carry byte offsets for every node (the
evidence contract: a finding must point at the exact characters that cause
it), and `re.sre_parse` gives neither spans nor stability across versions.

Supported syntax — everything that appears in day-to-day application code:
  literals, ., character classes with ranges/negation/escapes/named sets,
  alternation, groups (capturing / non-capturing / named / atomic),
  lookarounds, quantifiers * + ? {m} {m,} {m,n} with lazy variants,
  anchors ^ $ \\A \\Z \\b \\B, backreferences \\1..\\9, \\g<name>, (?P=name),
  inline flags (?imsx).
Anything else raises ParseError; callers surface that as RDS099 instead of
guessing about a pattern we cannot see clearly.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import charset as cs


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
    kind: str  # 'cap' | 'noncap' | 'named' | 'atomic'
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
    "n": "\n", "t": "\t", "r": "\r", "f": "\f", "v": "\v", "a": "\a", "0": "\0",
}

# \b inside a class is backspace, not a word boundary.
_CLASS_CHAR_ESCAPES = dict(_ESCAPES, b="\b")


class Parser:
    def __init__(self, pattern: str):
        self.pat = pattern
        self.pos = 0
        self.group_count = 0
        self.group_names: dict[str, int] = {}

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
        node = self.parse_alt()
        if self.pos < len(self.pat):
            # parse_alt stops at ')' — anything left is an unbalanced one.
            raise ParseError("unbalanced parenthesis", self.pos)
        return node

    def parse_alt(self) -> Node:
        start = self.pos
        branches = [self.parse_concat()]
        while self.peek() == "|":
            self.take()
            branches.append(self.parse_concat())
        if len(branches) == 1:
            return branches[0]
        return Alt((start, self.pos), branches)

    def parse_concat(self) -> Node:
        start = self.pos
        parts: list[Node] = []
        while True:
            ch = self.peek()
            if ch is None or ch in "|)":
                break
            atom = self.parse_atom()
            atom = self.parse_quantifiers(atom)
            parts.append(atom)
        if len(parts) == 1:
            return parts[0]
        return Concat((start, self.pos), parts)

    def parse_quantifiers(self, atom: Node) -> Node:
        """Bind exactly one quantifier; a second on the same atom is Python's
        'multiple repeat' error, so raise instead of misreading the shape."""
        ch = self.peek()
        if ch == "*":
            lo, hi = 0, None
        elif ch == "+":
            lo, hi = 1, None
        elif ch == "?":
            lo, hi = 0, 1
        elif ch == "{":
            bounds = self._try_bounds()
            if bounds is None:
                # Python treats a malformed {..} as a literal brace.
                return atom
            lo, hi, end = bounds
            self.pos = end + 1
            if hi is not None and lo > hi:
                raise ParseError("min repeat greater than max repeat", end)
        else:
            return atom
        if isinstance(atom, Quant):
            raise ParseError("multiple repeat", atom.span[1])
        if ch == "{":
            pass
        else:
            self.pos += 1  # consume the quantifier character
        lazy = False
        if self.peek() == "?":
            self.take()
            lazy = True
        return Quant((atom.span[0], self.pos), atom, lo, hi, lazy)

    def _try_bounds(self) -> tuple[int, int | None, int] | None:
        """Parse {m}, {m,}, {m,n} at self.pos (which points at '{').
        Returns (lo, hi, index_of_closing_brace), or None (without consuming)
        when it is not valid bounds — then the brace is a literal, matching
        Python's own behaviour."""
        pat = self.pat
        i = self.pos + 1
        lo_digits = ""
        while i < len(pat) and pat[i].isdigit():
            lo_digits += pat[i]
            i += 1
        if not lo_digits:
            return None
        lo = int(lo_digits)
        if i < len(pat) and pat[i] == "}":
            return (lo, lo, i)
        if i < len(pat) and pat[i] == ",":
            i += 1
            hi_digits = ""
            while i < len(pat) and pat[i].isdigit():
                hi_digits += pat[i]
                i += 1
            if i < len(pat) and pat[i] == "}":
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
        if ch in "*+?":
            raise ParseError("nothing to repeat", start)
        return Lit((start, self.pos), ch)

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
        if esc.isdigit() and esc != "0":
            return Backref((start, self.pos), int(esc))
        if esc == "g":
            return self.parse_gref(start)
        if esc == "x":
            return Lit((start, self.pos), self._hex(start, 2))
        if esc == "u":
            return Lit((start, self.pos), self._hex(start, 4))
        if esc in _ESCAPES:
            return Lit((start, self.pos), _ESCAPES[esc])
        if esc.isalpha():
            # Python's re rejects unknown letter escapes; so do we — guessing
            # a charset here would poison every overlap decision downstream.
            raise ParseError(f"bad escape \\{esc}", start)
        return Lit((start, self.pos), esc)

    def _hex(self, start: int, width: int) -> str:
        digits = self.pat[self.pos:self.pos + width]
        if len(digits) < width:
            raise ParseError("incomplete \\x/\\u escape", start)
        self.pos += width
        try:
            return chr(int(digits, 16))
        except ValueError:
            raise ParseError("bad hex escape", start) from None

    def parse_gref(self, start: int) -> Node:
        self.expect("<", "'<' after \\g")
        name = ""
        while True:
            c = self.take()  # take() raises ParseError on unterminated
            if c == ">":
                break
            name += c
        if name.lstrip("-").isdigit():
            return Backref((start, self.pos), int(name))
        if name not in self.group_names:
            raise ParseError(f"unknown group name '{name}'", start)
        return Backref((start, self.pos), self.group_names[name], name)

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
                    if ref not in self.group_names:
                        raise ParseError(f"unknown group name '{ref}'", start)
                    return Backref((start, self.pos), self.group_names[ref], ref)
                if n != "<":
                    raise ParseError("expected '<' or '=' after (?P", start)
                name = ""
                while True:
                    ch = self.take()
                    if ch == ">":
                        break
                    name += ch
                kind = "named"
            elif c == "=":
                child = self.parse_alt()
                self.expect(")", "')'")
                return Look((start, self.pos), "ahead", child)
            elif c == "!":
                child = self.parse_alt()
                self.expect(")", "')'")
                return Look((start, self.pos), "nagahead", child)
            elif c == "<":
                n = self.take()
                if n == "=":
                    child = self.parse_alt()
                    self.expect(")", "')'")
                    return Look((start, self.pos), "behind", child)
                if n == "!":
                    child = self.parse_alt()
                    self.expect(")", "')'")
                    return Look((start, self.pos), "negbehind", child)
                raise ParseError("bad lookbehind", start)
            elif c == ">":
                kind = "atomic"
            elif c in "aiLmsux":
                # Inline flags: (?i) is self-contained. Flags do not change
                # which characters a fragment can match except (?s) on dot,
                # which is approximated (see module docstring).
                while self.peek() and self.peek() in "aiLmsux":
                    self.take()
                self.expect(")", "')'")
                return self.parse_concat()  # rest continues at the same level
            else:
                raise ParseError(f"unknown group modifier '?{c}'", start)
        index = None
        if kind in ("cap", "named"):
            self.group_count += 1
            index = self.group_count
            if kind == "named":
                self.group_names[name] = index
        child = self.parse_alt()
        self.expect(")", "')'")
        return Group((start, self.pos), kind, index, name, child)

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
        """Append the range(s) one class member contributes."""
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
        if esc.isalpha():
            raise ParseError(f"bad escape \\{esc} in class", start)
        ranges.extend(cs.char(esc))

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
        if esc.isalpha():
            raise ParseError(f"bad escape \\{esc} in class", start)
        return esc


def parse(pattern: str) -> tuple[Node, int, dict[str, int]]:
    """Parse `pattern`; returns (ast, group_count, name->index)."""
    p = Parser(pattern)
    ast = p.parse()
    return ast, p.group_count, p.group_names
