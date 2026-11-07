"""The rules: nine deterministic checks for catastrophic backtracking.

Pass 1 checks look at a single node's local shape (RDS003, RDS004, RDS005,
RDS007, RDS008). Pass 2 walks the tree with quantifier ancestry and group
context, catching what a local view cannot see: an alternation three levels
deep inside a quantifier (RDS002), a nested quantifier whose boundary is
ambiguous (RDS001), a backreference iterating over its own capture (RDS006).

Severity semantics are kept honest on purpose:
  high   = exponential blowup potential (nested ambiguity),
  medium = polynomial blowup (adjacent ambiguity),
  low    = style / hygiene / coverage gaps.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import analyze as an
from . import charset as cs
from .parser import Alt, Concat, Group, Lit, Node, Quant


@dataclass
class Finding:
    rule_id: str
    severity: str  # high | medium | low | info
    span: tuple[int, int]  # offsets into the pattern
    message: str
    suggestion: str


@dataclass
class Rule:
    rule_id: str
    title: str
    severity: str
    description: str
    fix: str
    check: object  # fn(node, ctx) -> list[Finding]


def _q_is_loose(q: Quant) -> bool:
    """A quantifier that can iterate more than once."""
    return q.max is None or q.max >= 2


def _parts(node: Node) -> list[Node]:
    node = an.unwrap_groups(node)
    if isinstance(node, Concat):
        return list(node.parts)
    return [node]


# -- pass 1 ----------------------------------------------------------------


def check_rds003(node: Node, ctx) -> list[Finding]:
    """Prefix-redundant alternation branches, e.g. user|username — outside a
    quantifier this is dead weight rather than a DoS, so low severity."""
    if not isinstance(node, Alt) or ctx.in_quant:
        return []
    lits: dict[int, str] = {}
    for b in node.branches:
        u = an.unwrap_groups(b)
        if isinstance(u, Lit):
            lits[id(b)] = u.ch
        elif isinstance(u, Concat) and all(isinstance(p, Lit) for p in u.parts) \
                and u.parts:
            lits[id(b)] = "".join(p.ch for p in u.parts)
    strings = list(lits.values())
    if len(strings) < 2:
        return []
    findings = []
    # Leftmost-first semantics: the earlier branch wins, so the branch that
    # gets shadowed is the *later*, longer one (user|username — "username"
    # is unreachable; username|user is the correct spelling).
    for idx in range(len(node.branches)):
        s = lits.get(id(node.branches[idx]))
        if s is None:
            continue
        for later in range(idx + 1, len(node.branches)):
            other = lits.get(id(node.branches[later]))
            if other is None or other == s:
                continue
            if other.startswith(s):
                findings.append(Finding(
                    "RDS003", "low", node.branches[later].span,
                    f"branch {other!r} (position {later + 1}) can never be "
                    f"reached: the earlier branch {s!r} (position {idx + 1}) "
                    "matches its prefix and wins",
                    "put the longest branch first, or merge them into one "
                    "branch",
                ))
                break
    return findings


def check_rds004(node: Node, ctx) -> list[Finding]:
    """Adjacent quantified atoms that can match the same characters — the
    splitter positions between them are ambiguous, giving polynomial
    backtracking (a*a*b, \\d*\\d*, .*.*)."""
    if not isinstance(node, Concat):
        return []
    findings = []
    i = 0
    parts = node.parts
    while i < len(parts):
        run = _quant_run_at(parts, i)
        if run >= 2:
            a, b = parts[i], parts[i + 1]
            # the left atom's last character against the right atom's first:
            # that is the only boundary the backtracker can move.
            overlap = cs.intersect(an.end_charset(a), an.start_charset(b))
            if overlap:
                sev = "high" if run >= 3 else "medium"
                findings.append(Finding(
                    "RDS004", sev, (parts[i].span[0], parts[i + run - 1].span[1]),
                    f"{run} adjacent quantified atoms share the characters "
                    f"{cs.describe(overlap)}; the match length of each is "
                    "ambiguous, so a failing match backtracks polynomially",
                    "make the atoms mutually exclusive, or collapse them into "
                    "one quantifier",
                ))
            i += run
        else:
            i += 1
    return findings


def _quant_run_at(parts: list[Node], i: int) -> int:
    """Length of the run of loose quantifiers starting at i whose neighbours
    share characters. Returns 0 when parts[i] does not start a run."""
    if not isinstance(an.unwrap_groups(parts[i]), Quant):
        return 0
    q1 = an.unwrap_groups(parts[i])
    if not (isinstance(q1, Quant) and _q_is_loose(q1)):
        return 0
    run = 1
    while i + run < len(parts):
        q2 = an.unwrap_groups(parts[i + run])
        if not (isinstance(q2, Quant) and _q_is_loose(q2)):
            break
        if not cs.overlaps(an.end_charset(q1), an.start_charset(q2)):
            break
        run += 1
    return run if run >= 2 else 0


def check_rds005(node: Node, ctx) -> list[Finding]:
    """Stacked bounded repetitions — (a{1,10}){1,10} — where the ambiguity
    multiplies: k nested bounds give product**n candidate splits."""
    if not isinstance(node, Quant) or node.max is None or not _q_is_loose(node):
        return []
    inner = an.unwrap_groups(node.child)
    if not (isinstance(inner, Quant) and inner.min >= 1
            and inner.max is not None and inner.max >= 2):
        return []
    product = node.max * inner.max
    sev = "high" if product >= 10000 else "medium"
    return [Finding(
        "RDS005", sev, node.span,
        f"bounded repetition stacked inside bounded repetition: up to "
        f"{node.max}x{inner.max} = {product} ways to split each repetition",
        "flatten into a single quantifier with the equivalent bound",
    )]


def check_rds007(node: Node, ctx) -> list[Finding]:
    """A fragment that can match the empty string under an unbounded
    quantifier — (a*)+, (|a)+, (a?)* — empty-match iteration; engines either
    loop forever or pay quadratic guards."""
    if not isinstance(node, Quant) or not _q_is_loose(node):
        return []
    if an.nullable(an.unwrap_groups(node.child)):
        return [Finding(
            "RDS007", "high", node.span,
            "quantifier iterates a fragment that can match the empty string; "
            "engines either spin on empty iterations or backtrack badly",
            "make the inner fragment non-nullable, e.g. (a+)+ instead of "
            "(a*)+ — better: a+",
        )]
    return []


def check_rds008(node: Node, ctx) -> list[Finding]:
    """Very large minimum bounds — a{5000,} — a memory/latency floor on every
    match attempt even without backtracking."""
    if not isinstance(node, Quant) or node.min < 1000:
        return []
    return [Finding(
        "RDS008", "low", node.span,
        f"minimum bound of {node.min} iterations forces the engine to commit "
        "to a large amount of work before the match can even fail",
        "reconsider the bound; a{1000,} is almost always a typo or a DoS "
        "invitation",
    )]


# -- pass 2 ----------------------------------------------------------------


def check_rds001(node: Node, ctx) -> list[Finding]:
    """Nested quantifier whose inner boundary is ambiguous — (a+)+, (a+)+b,
    ((a+)a)+. The engine cannot decide how many characters the inner
    quantifier should take, and every choice spawns the same choice again."""
    if not isinstance(node, Quant) or not _q_is_loose(node):
        return []
    # A body of fixed length has no ambiguous split: `(?:a{2})*` can only break
    # between character pairs, so there is exactly one way to parse the input.
    # Without this the rule flags a linear pattern, which is the fastest way to
    # teach a user to ignore the tool.
    if an.fixed_length(node.child) is not None:
        return []
    parts = _parts(node.child)
    for i, part in enumerate(parts):
        inner = an.unwrap_groups(part)
        if not (isinstance(inner, Quant) and inner.min >= 1 and _q_is_loose(inner)):
            continue
        if inner.max is not None and node.max is not None:
            continue  # purely bounded stacking is RDS005's finding
        rest = parts[i + 1:]
        if not rest:
            # The inner quantifier is the last thing in the iteration body, so
            # the ambiguity is between its end and the *next iteration's*
            # start. (ab+)+ is safe: b+ cannot eat the 'a' that must begin the
            # next iteration, so the boundary is pinned. (a+)+ is not: the
            # next iteration can consume the same characters.
            overlap = cs.intersect(an.end_charset(inner), an.start_charset(node.child))
            ambiguous = bool(overlap)
            why = (f"the inner quantifier's end shares the characters "
                   f"{cs.describe(overlap)} with the start of the next outer "
                   "iteration")
        else:
            overlap = cs.intersect(
                an.end_charset(inner), an.start_charset(rest[0]))
            ambiguous = bool(overlap)
            why = (f"the inner quantifier shares the characters "
                   f"{cs.describe(overlap)} with what follows it inside the "
                   "outer quantifier")
        if not ambiguous:
            continue
        return [Finding(
            "RDS001", "high", node.span,
            f"quantifier nested inside quantifier: {why}; a failing match "
            "splits the input every possible way — exponential time",
            "rewrite as a single quantifier, e.g. a+ instead of (a+)+; if "
            "the group exists for a capture, consider atomic groups or "
            "possessive quantifiers where the engine supports them",
        )]
    return []


def check_rds002(node: Node, ctx) -> list[Finding]:
    """Overlapping alternation branches under a quantifier — (a|aa)+,
    (foo|foobar)+, (abc|\\w+). The quantifier re-enters the alternation, and
    two branches that can start with the same character multiply the ways a
    match can be split."""
    if not isinstance(node, Alt) or not ctx.in_quant:
        return []
    branches = [(b, an.start_charset(b)) for b in node.branches]
    for i in range(len(branches)):
        bi, si = branches[i]
        if an.nullable(bi):
            continue  # empty-iteration ambiguity is RDS007's finding
        for j in range(i + 1, len(branches)):
            bj, sj = branches[j]
            if an.nullable(bj):
                continue
            overlap = cs.intersect(si, sj)
            if overlap:
                return [Finding(
                    "RDS002", "high", node.span,
                    f"alternation under a quantifier with branches sharing "
                    f"the starting characters {cs.describe(overlap)}; a "
                    "failing match explores every branch order — exponential "
                    "time",
                    "factor out the common prefix ((?:a|aa)+ -> a+), or "
                    "order the branches so the longer one is tried first "
                    "and drop the overlap",
                )]
    return []


def check_rds006(node: Node, ctx) -> list[Finding]:
    """A quantifier whose body contains a backreference to a group captured
    inside the same body — (?:(a+)\\1)+ — each iteration re-solves an
    already ambiguous split with the previous iteration's answer pinned in."""
    if not isinstance(node, Quant) or not _q_is_loose(node):
        return []
    groups: set[int] = set()
    refs: set[int] = set()
    for sub in an.iter_all(node.child):
        if isinstance(sub, Group) and sub.index is not None:
            groups.add(sub.index)
        from .parser import Backref  # local import to keep the top flat
        if isinstance(sub, Backref):
            refs.add(sub.index)
    both = groups & refs
    if not both:
        return []
    return [Finding(
        "RDS006", "high", node.span,
        f"quantifier body references its own capture group(s) "
        f"{sorted(both)}; the referenced text is re-validated against an "
        "ambiguous split on every iteration",
        "capture outside the loop, or restructure so the backreference "
        "cannot be re-interpreted",
    )]


RULES: list[Rule] = [
    Rule("RDS001", "Quantifier nested in quantifier with an ambiguous boundary",
         "high",
         "The inner quantifier and the rest of the outer iteration can match "
         "the same characters, so the engine explores every way to split the "
         "input between them — 2**n work for n characters.",
         "Collapse into one quantifier (a+ not (a+)+); use atomic groups or "
         "possessive quantifiers where supported.", check_rds001),
    Rule("RDS002", "Alternation with overlapping branches under a quantifier",
         "high",
         "Two branches of an alternation inside a quantifier can start with "
         "the same characters; a failing match re-enters the alternation in "
         "every combination.",
         "Factor out the shared prefix, or drop the redundant branch.",
         check_rds002),
    Rule("RDS003", "Alternation branch is a prefix of another branch",
         "low",
         "With leftmost-first semantics the shorter branch shadows the "
         "longer one; the second branch is dead code.",
         "Reorder (longest first) or merge the branches.", check_rds003),
    Rule("RDS004", "Adjacent quantified atoms with overlapping characters",
         "medium",
         "Two or more neighbouring quantifiers can absorb the same "
         "characters, so the split points between them are ambiguous — "
         "polynomial backtracking on failure.",
         "Make the atoms mutually exclusive or merge them.", check_rds004),
    Rule("RDS005", "Stacked bounded repetitions", "medium",
         "A bounded repetition inside a bounded repetition multiplies the "
         "candidate splits: k x m bounds mean (k*m)**n work on failure.",
         "Flatten into a single quantifier.", check_rds005),
    Rule("RDS006", "Backreference to a group captured inside the same loop",
         "high",
         "The loop body re-validates its own previous capture, multiplying "
         "the ambiguity of the body by every iteration.",
         "Capture outside the loop or restructure the pattern.",
         check_rds006),
    Rule("RDS007", "Quantifier over a nullable fragment", "high",
         "The body can match the empty string, so iterations can loop on "
         "empty matches or explode the backtrack state.",
         "Make the body non-nullable (a+ not a*).", check_rds007),
    Rule("RDS008", "Very large minimum bound", "low",
         "A minimum bound of 1000+ iterations commits the engine to a large "
         "amount of work before a match can even fail.",
         "Reconsider the bound.", check_rds008),
    Rule("RDS099", "Pattern could not be parsed", "info",
         "redoslint refuses to guess about syntax it does not fully "
         "understand; the pattern is reported so the coverage gap is visible "
         "instead of silent.",
         "Check the pattern syntax; if it is valid but unsupported, please "
         "open an issue.", None),
]
