"""Reproduce the timing table in docs/rules.md.

Each measurement runs in its own subprocess with a hard timeout: a pattern
that takes 7 seconds at n=28 would take minutes at n=40, and a benchmark must
never be able to hang the CI runner that invoked it.

    python docs/bench.py

No dependencies, no arguments, no network. Numbers are wall-clock of a single
`re.match()` on CPython; absolute values vary by machine, the doubling does not.
"""

from __future__ import annotations

import subprocess
import sys

PATTERNS = [
    ("(a+)+b", r"^(a+)+b$"),
    ("(a|aa)+b", r"^(a|aa)+b$"),
    ("a+b", r"^a+b$"),
    ("(ab+)+b", r"^(ab+)+b$"),
    ("(?:a{2})*b", r"^(?:a{2})*b$"),
]

# The child measures itself so the number does not include interpreter startup.
CHILD = r"""
import re, sys, time
pattern, n = sys.argv[1], int(sys.argv[2])
rx = re.compile(pattern)
t = time.perf_counter()
rx.match('a' * n)
print(f'{(time.perf_counter() - t) * 1000:.3f}')
"""

TIMEOUT_SECONDS = 10.0


def measure(pattern: str, n: int) -> str:
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, pattern, str(n)],
            capture_output=True, text=True, timeout=TIMEOUT_SECONDS,
            encoding="utf-8",
        )
    except subprocess.TimeoutExpired:
        return f">{TIMEOUT_SECONDS:.0f}s"
    if proc.returncode != 0:
        return "ERROR"
    return f"{float(proc.stdout.strip()):.3f} ms"


def main() -> int:
    print(f"python {sys.version.split()[0]}  |  input = 'a' * n  |  "
          f"failing match (final 'b' never appears)")
    print(f"{'n':>3} " + " ".join(f"{name:>14}" for name, _ in PATTERNS))
    for n in range(10, 29, 2):
        row = [measure(pattern, n) for _, pattern in PATTERNS]
        print(f"{n:>3} " + " ".join(f"{value:>14}" for value in row))
    print()
    print("(a+)+b doubles roughly every 2 characters. (ab+)+b and")
    print("(?:a{2})*b stay flat — nested quantifiers alone are not a finding.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
