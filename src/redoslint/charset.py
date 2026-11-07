"""Character-set algebra.

Every ReDoS decision in redoslint reduces to one question: can these two
fragments match the same characters? If not, the backtracker can never get
stuck oscillating between them and the shape that looks dangerous is safe.

Sets are kept as sorted, merged lists of inclusive (lo, hi) code-point
ranges. Unicode is approximated: the named classes (\\w, \\d, \\s) expand to
their ASCII members only, which is the common case in source code and the
conservative direction for *most* patterns (a Unicode letter is inside our
\\w approximation's complement, never the other way around). The README
documents this limitation.
"""

ANY_RANGE = (0x00, 0x10FFFF)

RANGES_DIGIT = [(0x30, 0x39)]
RANGES_WORD = [(0x30, 0x39), (0x41, 0x5A), (0x5F, 0x5F), (0x61, 0x7A)]
RANGES_SPACE = [(0x09, 0x0D), (0x20, 0x20)]

NAMED_CLASSES = {
    "d": RANGES_DIGIT,
    "w": RANGES_WORD,
    "s": RANGES_SPACE,
}


def char(ch: str) -> list[tuple[int, int]]:
    """A single character as a one-point range."""
    return [(ord(ch), ord(ch))]


def _merge(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Sort and merge overlapping/adjacent ranges. O(n log n) on range count."""
    if not ranges:
        return []
    rs = sorted(ranges)
    out = [rs[0]]
    for lo, hi in rs[1:]:
        plo, phi = out[-1]
        if lo <= phi + 1:
            if hi > phi:
                out[-1] = (plo, hi)
        else:
            out.append((lo, hi))
    return out


def normalize(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Public form of the internal merge: sorted, non-overlapping ranges.
    Class ranges are normalized at parse time so every downstream comparison
    (and every evidence line) sees one canonical shape."""
    return _merge(ranges)


def union(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    return _merge(a + b)


def negate(a: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Complement within the full code-point space."""
    out: list[tuple[int, int]] = []
    pos = 0x00
    for lo, hi in _merge(a):
        if lo > pos:
            out.append((pos, lo - 1))
        pos = hi + 1
    if pos <= ANY_RANGE[1]:
        out.append((pos, ANY_RANGE[1]))
    return out


def intersect(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Two sorted, merged range lists — linear two-pointer walk."""
    out: list[tuple[int, int]] = []
    i = j = 0
    while i < len(a) and j < len(b):
        lo = max(a[i][0], b[j][0])
        hi = min(a[i][1], b[j][1])
        if lo <= hi:
            out.append((lo, hi))
        if a[i][1] < b[j][1]:
            i += 1
        else:
            j += 1
    return out


def overlaps(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    return bool(intersect(a, b))


def is_subset(a: list[tuple[int, int]], b: list[tuple[int, int]]) -> bool:
    """True when every code point in `a` is also in `b`."""
    return not intersect(a, negate(b))


def describe(ranges: list[tuple[int, int]], limit: int = 6) -> str:
    """Human-readable form for evidence lines, longest ranges first."""
    shown = sorted(ranges, key=lambda r: r[0] - r[1])[:limit]
    parts = []
    for lo, hi in shown:
        if lo == hi:
            parts.append(repr(chr(lo)))
        else:
            parts.append(f"{chr(lo)!r}-{chr(hi)!r}")
    tail = f" (+{len(ranges) - limit} more)" if len(ranges) > limit else ""
    return "{" + ", ".join(parts) + tail + "}"
