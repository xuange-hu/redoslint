"""docs/rules.md is a contract, not prose.

Every section lists a shape that must fire and a near-miss that must not. Those
claims are executable: parse them out of the markdown and run them through the
engine. A rule change that breaks an example in the docs fails here instead of
shipping a manual that lies.
"""

import os
import re

import pytest

from redoslint import engine as eng
from redoslint.rules import RULES

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC = os.path.join(ROOT, "docs", "rules.md")

SECTION = re.compile(r"^### (RDS\d{3})\b", re.M)
TOKEN = re.compile(r"`([^`]+)`")


def sections():
    """[(rule_id, [(kind, pattern), ...]), ...] from the markdown."""
    with open(DOC, encoding="utf-8") as fh:
        text = fh.read()
    heads = list(SECTION.finditer(text))
    out = []
    for i, head in enumerate(heads):
        body = text[head.end():heads[i + 1].start() if i + 1 < len(heads)
                    else len(text)]
        claims = []
        for line in body.splitlines():
            if line.startswith("- **Fires:**"):
                kind = "fires"
            elif line.startswith("- **Does not fire:**"):
                kind = "clean"
            else:
                continue
            for token in TOKEN.findall(line):
                # Skip prose tokens such as `min >= 1000` — every pattern in
                # these lists is a single space-free backtick span.
                if " " in token:
                    continue
                claims.append((kind, token))
        out.append((head.group(1), claims))
    return out


ALL = sections()


def test_docs_exists_and_covers_every_rule():
    ids = {rid for rid, _ in ALL}
    assert os.path.isfile(DOC)
    assert ids == {r.rule_id for r in RULES}


def test_docs_has_both_directions_for_every_section():
    for rid, claims in ALL:
        assert any(k == "fires" for k, _ in claims), f"{rid} has no example"
        assert any(k == "clean" for k, _ in claims) or rid == "RDS099", \
            f"{rid} has no near-miss"


CASES = [(rid, kind, pat) for rid, claims in ALL for kind, pat in claims]


@pytest.mark.parametrize("rid,kind,pattern", CASES,
                         ids=[f"{r}-{k}-{i}" for i, (r, k, _) in enumerate(CASES)])
def test_doc_example(rid, kind, pattern):
    ids = {f.rule_id for f in eng.scan_pattern(pattern).findings}
    if kind == "fires":
        assert rid in ids, f"{rid} no longer fires on {pattern!r}: {ids}"
    else:
        assert rid not in ids, f"{rid} false positive on {pattern!r}: {ids}"


def test_benchmark_script_is_runnable_and_bounded():
    """docs/bench.py must exist and must have a timeout, or the doc's own
    reproduction command can hang a CI runner."""
    path = os.path.join(ROOT, "docs", "bench.py")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    assert "TIMEOUT_SECONDS" in text
    assert "subprocess" in text
    assert "timeout=TIMEOUT_SECONDS" in text
