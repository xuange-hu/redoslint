# Rules

Nine rules, two passes. Every section below states the **shape that fires**,
the **near-miss that must not fire**, and **what the code actually compares**.
If a section disagrees with `src/redoslint/rules.py`, the code is authoritative —
open an issue.

Severities are literal, not decorative:

| Severity | Complexity in input length | What it means operationally |
|---|---|---|
| `high` | exponential | ~30 characters of attacker-controlled input can pin a worker |
| `medium` | polynomial | real, but needs a longer input to hurt |
| `low` | hygiene | dead branches, absurd bounds |
| `info` | coverage gap | the tool could not decide, and says so |

## First, measured evidence

Numbers below are a real `re.compile(...).match()` run on CPython 3.12.10,
Windows, input `'a' * n` (the match always fails at the final `b`). Reproduce
with `docs/bench.py`.

| n | `^(a+)+b$` | `^(a\|aa)+b$` | `^a+b$` | `^(ab+)+b$` | `^(?:a{2})*b$` |
|---:|---:|---:|---:|---:|---:|
| 10 | 0.026 ms | 0.011 ms | 0.002 ms | 0.003 ms | 0.003 ms |
| 14 | 0.309 ms | 0.038 ms | 0.002 ms | 0.003 ms | 0.003 ms |
| 18 | 5.369 ms | 0.241 ms | 0.002 ms | 0.003 ms | 0.008 ms |
| 22 | 118.346 ms | 1.901 ms | 0.004 ms | 0.003 ms | 0.009 ms |
| 26 | 1508.787 ms | 11.319 ms | 0.003 ms | 0.003 ms | 0.008 ms |
| 28 | **6989.927 ms** | 30.113 ms | 0.003 ms | 0.003 ms | 0.006 ms |

Two conclusions drive the whole design:

1. `(a+)+` roughly quadruples every four characters — 0.027 ms → 7.0 s while
   the input grows from 10 to 28 bytes. That is the DoS.
2. `^(ab+)+b$` and `^(?:a{2})*b$` stay flat at ~0.001 ms. Both contain nested
   quantifiers. **A shape matcher reports them anyway.** redoslint does not —
   that is the difference between a tool you gate CI on and one you mute.

## Pass 1 — local shape

### RDS001 · high · nested quantifier with an ambiguous boundary

`check_rds001` runs in pass 2 (it needs the enclosing quantifier context), but
its decision is about a single iteration body, so it belongs in this discussion.

- **Fires:** `^(a+)+$`, `^(?:a+)+b$`, `((a+)a)+`
- **Does not fire:** `^(ab+)+b$`, `(\d{1,3}\.){3}\d{1,3}` (IPv4),
  `^(?:a{2})*b$`, `^(?:ab){2,}$`
- **Compares:** `analyze.fixed_length(body)` first — a body whose length is
  the same for every match has pinned split points and is skipped. Otherwise
  it intersects `end_charset(inner_quantifier)` with either the next sibling
  inside the body or `start_charset(outer_body)` when the inner quantifier is
  last. A non-empty intersection means the same character can end one
  iteration and start the next: ambiguous.
- **Fix:** collapse to one quantifier (`a+`), or use atomic groups /
  possessive quantifiers where the engine supports them.

### RDS002 · high · overlapping alternation branches under a quantifier

- **Fires:** `^(a|aa)+b$`, `(foo|foobar)+`, `(?:x(?:y(?:a|aa)))+`
- **Does not fire:** `^(a|b)+$`, `^(?:a|aa)$` (no quantifier)
- **Compares:** the start charsets of each pair of branches; pass 2 contributes
  the `in_quant` flag, so an alternation buried three groups deep is still
  caught. A local-only view misses that case entirely.
- **Fix:** factor out the common prefix, or drop the redundant branch.
- **Measured:** 34.404 ms at n=28 in the table above — exponential, just with
  a smaller base than RDS001.

### RDS003 · low · branch shadowed by an earlier prefix branch

- **Fires:** `user|username` (the second branch is dead code)
- **Does not fire:** `username|user` (correct spelling, longest first)
- **Compares:** literal-prefix branches only, and **only when the shadowing
  branch comes first**. This direction was wrong in the first implementation
  and produced both a false positive and a false negative at once; it is now
  pinned by `tests/test_rules.py`.
- **Fix:** reorder longest-first, or merge.
- **Note:** this is correctness, not DoS. It is `low` on purpose.

### RDS004 · medium · adjacent quantified atoms sharing characters

- **Fires:** `^\d*\d*:\d+$`, `a*a*b`, `\w+\w+` (three in a row: `a*a*a*`)
- **Does not fire:** `(\d{1,3}\.){3}\d{1,3}` (the literal `.` pins the
  boundary), `^[a-z]+[0-9]+$` (disjoint charsets), `.*a.*` (a literal sits
  between the two dots, so they are not adjacent atoms)
- **Compares:** full charsets of consecutive quantified atoms. Escalates from
  `medium` to `high` at three overlapping quantifiers in a row.
- **Fix:** make the atoms mutually exclusive, or collapse them into one.

### RDS005 · medium · stacked bounded repetitions

- **Fires:** `^(a{1,10}){1,10}z$`
- **Does not fire:** `^a{1,10}z$`, `^(ab){2,10}$` (fixed-length body)
- **Compares:** bounded quantifier inside bounded quantifier; both bounds
  finite. Purely bounded stacking is this rule's finding, not RDS001's —
  unbounded outer iterations are handed to RDS001.
- **Fix:** flatten into one quantifier with the equivalent bound.

### RDS007 · high · quantifier over a nullable fragment

- **Fires:** `(a*)+`, `(a?)*`
- **Does not fire:** `(a+)+` (that is RDS001), `a*b` (no outer quantifier)
- **Compares:** `analyze.nullable(body)` — a body that can match empty makes
  engines either spin on empty iterations or explode the backtracking state.
- **Fix:** make the body non-nullable (`a+` instead of `a*`).

### RDS008 · low · very large minimum bound

- **Fires:** `a{5000,}`, any `min >= 1000`
- **Does not fire:** `a{1,5000}`
- **Compares:** `node.min` only. The upper bound is irrelevant here: the
  engine must consume at least `min` characters before it can fail.
- **Fix:** reconsider the bound. This is usually a typo or a DoS invitation.

## Pass 2 — enclosing context

### RDS006 · high · backreference to a group captured in the same loop

- **Fires:** `^(?:(\w)\1)+$`
- **Does not fire:** `^(\w)\1$` (no loop), `^(\w)\1+$` (backreference outside
  the loop body)
- **Compares:** capture group indices inside the quantified body against the
  indices referenced by backrefs in that same body. The loop re-validates its
  own capture on every iteration, multiplying the ambiguity.
- **Fix:** capture outside the loop, or restructure so the referenced text
  cannot be re-interpreted.

## Coverage

### RDS099 · info · pattern could not be parsed

- **Fires:** `^[unclosed`, `\p{Lu}` (unsupported property), `(?(a))`
- **Compares:** nothing. This is a **coverage marker**, not a vulnerability
  claim. redoslint refuses to guess about syntax it does not fully understand,
  and reports the offset of the fragment it stopped at.
- **Why it matters:** a scanner that silently drops a pattern turns "clean"
  into "not looked at". `RDS099` makes the gap visible in SARIF and JSON.

## Rolling out one rule at a time

`--rule` filters findings **before** rendering, so text, JSON, SARIF and the
`--fail-on` exit code all describe the same set. A typo is exit 2, not a clean
scan.

```bash
redoslint scan . --rule RDS001 --fail-on high        # week 1: exponential only
redoslint scan . --rule RDS001,RDS002 --sarif r.sarif
redoslint rules --id RDS004                          # full description + fix
redoslint demo --rule RDS001                         # one rule, zero setup
```

## Benchmarking a confirmed hit

Static analysis never executes a pattern; a confirmed finding should be
reproduced with a timeout in a subprocess (never in the CI runner's own
process). `docs/bench.py` does exactly that and prints the table above.

```bash
python docs/bench.py
```

## Known approximations

- `\w`, `\d`, `\s` expand to ASCII members; `.` excludes `\n` regardless of
  `(?s)`.
- Case-insensitive matching is not modelled: `(?i)` is only relevant when the
  pattern's own branches differ in case.
- Lookbehind content is treated as non-consuming. That is correct for
  ambiguity, but a pattern dangerous *only inside* a lookaround is not reported.
- Character sets are ranges over codepoints, not a full Unicode property
  database. Unsupported syntax becomes `RDS099`.
