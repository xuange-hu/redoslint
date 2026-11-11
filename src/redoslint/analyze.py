"""Semantic queries over the parsed AST.

Three questions drive every rule:
  * full_charset(node) — which characters can this fragment match at all?
  * start_charset(node) — which characters can it match *first*?
  * nullable(node) — can it match the empty string?
"""

from __future__ import annotations

from . import charset as cs
from .parser import (
    Alt,
    Anchor,
    Backref,
    Class,
    Concat,
    Cond,
    Dot,
    Group,
    Lit,
    Look,
    Node,
    Quant,
)


def full_charset(node: Node) -> list[tuple[int, int]]:
    if isinstance(node, Lit):
        return cs.char(node.ch)
    if isinstance(node, Class):
        return node.ranges
    if isinstance(node, Dot):
        return cs.negate([(10, 10)])  # dot excludes \n (approximation)
    if isinstance(node, Concat):
        out: list[tuple[int, int]] = []
        for part in node.parts:
            out = cs.union(out, full_charset(part))
        return out
    if isinstance(node, Alt):
        out = []
        for branch in node.branches:
            out = cs.union(out, full_charset(branch))
        return out
    if isinstance(node, Quant):
        return full_charset(node.child)
    if isinstance(node, Group):
        return full_charset(node.child)
    if isinstance(node, Cond):
        # the group is set or it is not: both branches stay reachable
        out = full_charset(node.yes)
        if node.no is not None:
            out = cs.union(out, full_charset(node.no))
        return out
    if isinstance(node, Look):
        return []  # consumes nothing
    return []  # Anchor, Backref


def start_charset(node: Node) -> list[tuple[int, int]]:
    """Characters the fragment can match first. Nullable prefixes chain into
    whatever follows, so a nullable part contributes the next part's start."""
    if isinstance(node, Concat):
        out: list[tuple[int, int]] = []
        for part in node.parts:
            out = cs.union(out, start_charset(part))
            if not nullable(part):
                break
        return out
    if isinstance(node, Alt):
        out = []
        for branch in node.branches:
            out = cs.union(out, start_charset(branch))
        return out
    if isinstance(node, Quant):
        return start_charset(node.child)
    if isinstance(node, Group):
        return start_charset(node.child)
    if isinstance(node, Cond):
        out = start_charset(node.yes)
        if node.no is not None:
            out = cs.union(out, start_charset(node.no))
        return out
    if isinstance(node, (Anchor, Look)):
        return []
    return full_charset(node)


def end_charset(node: Node) -> list[tuple[int, int]]:
    """Characters the fragment can match last — the mirror of start_charset.
    Two adjacent quantifiers are only ambiguous when the left one's *last*
    character can also be the right one's first; comparing whole character
    sets instead produces false positives on patterns like
    (\\d{1,3}\\.){3}\\d{1,3}, where the trailing dot pins the boundary."""
    if isinstance(node, Concat):
        out: list[tuple[int, int]] = []
        for part in reversed(node.parts):
            out = cs.union(out, end_charset(part))
            if not nullable(part):
                break
        return out
    if isinstance(node, Alt):
        out = []
        for branch in node.branches:
            out = cs.union(out, end_charset(branch))
        return out
    if isinstance(node, Quant):
        return end_charset(node.child)
    if isinstance(node, Group):
        return end_charset(node.child)
    if isinstance(node, Cond):
        out = end_charset(node.yes)
        if node.no is not None:
            out = cs.union(out, end_charset(node.no))
        return out
    if isinstance(node, (Anchor, Look)):
        return []
    return full_charset(node)


def nullable(node: Node) -> bool:
    if isinstance(node, Lit):
        return False
    if isinstance(node, (Class, Dot)):
        return False
    if isinstance(node, Concat):
        return all(nullable(p) for p in node.parts)
    if isinstance(node, Alt):
        return any(nullable(b) for b in node.branches)
    if isinstance(node, Quant):
        return node.min == 0 or nullable(node.child)
    if isinstance(node, Group):
        return nullable(node.child)
    if isinstance(node, Cond):
        # set -> must match yes; unset -> matches only when there is an
        # else-branch (otherwise the whole conditional fails).
        return nullable(node.yes) or (
            node.no is not None and nullable(node.no))
    return True  # Anchor, Look, Backref(when the group matched empty)


def fixed_length(node: Node) -> int | None:
    """Characters this fragment consumes, if that number is the same for every
    match — else None.

    This is what separates a real nested-quantifier blowup from a fixed one:
    in `(?:a{2})*` every iteration consumes exactly two characters, so the
    split points are pinned and nothing backtracks. In `(a+)+` the inner
    length is free, so every split is a new branch.
    """
    if isinstance(node, Lit):
        return len(node.ch)
    if isinstance(node, (Class, Dot)):
        return 1
    if isinstance(node, (Anchor, Look)):
        return 0
    if isinstance(node, Group):
        return fixed_length(node.child)
    if isinstance(node, Cond):
        if node.no is None:
            return fixed_length(node.yes)
        y, n = fixed_length(node.yes), fixed_length(node.no)
        return y if y == n else None
    if isinstance(node, Backref):
        return None  # depends on what the referenced group matched
    if isinstance(node, Concat):
        total = 0
        for part in node.parts:
            n = fixed_length(part)
            if n is None:
                return None
            total += n
        return total
    if isinstance(node, Alt):
        lengths = {fixed_length(branch) for branch in node.branches}
        if len(lengths) == 1:
            (only,) = lengths
            return only
        return None
    if isinstance(node, Quant):
        if node.max is None or node.max != node.min:
            return None
        inner = fixed_length(node.child)
        return None if inner is None else inner * node.min
    return None


def unwrap_groups(node: Node) -> Node:
    """Look through plain groups (not looks) to the first structural node."""
    while isinstance(node, Group):
        node = node.child
    return node


def iter_all(node: Node):
    """Pre-order walk over every node in the tree."""
    yield node
    for child in children(node):
        yield from iter_all(child)


def children(node: Node) -> list[Node]:
    if isinstance(node, Concat):
        return list(node.parts)
    if isinstance(node, Alt):
        return list(node.branches)
    if isinstance(node, Quant):
        return [node.child]
    if isinstance(node, Group):
        return [node.child]
    if isinstance(node, Look):
        return [node.child]
    if isinstance(node, Cond):
        return [node.yes] + ([node.no] if node.no is not None else [])
    return []


def contains_backref(node: Node, group_index: int) -> bool:
    """Does this subtree reference `group_index` via \\n or (?P=name)?"""
    for sub in iter_all(node):
        if isinstance(sub, Backref) and sub.index == group_index:
            return True
    return False
