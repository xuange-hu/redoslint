# redoslint

[![CI](https://github.com/xuange-hu/redoslint/actions/workflows/ci.yml/badge.svg)](https://github.com/xuange-hu/redoslint/actions/workflows/ci.yml)
![tests-281%20passing](https://img.shields.io/badge/tests-281%20passing-brightgreen)
![python-3.10%2B](https://img.shields.io/badge/python-3.10%2B-blue)
![dependencies-0](https://img.shields.io/badge/dependencies-0-brightgreen)
![rules-9](https://img.shields.io/badge/rules-9-informational)
[![MCP](https://img.shields.io/badge/MCP-6%20tools-purple)](src/redoslint/mcp_server.py)

[中文说明](README_CN.md) · **Catastrophic backtracking audit that shows you the bytes.** Point it at a
repository, get the exact pattern fragment that can hang your service — with
the character sets that prove it, not just a shape match.

```
$ redoslint pattern "^(a+)+$"
pattern: '^(a+)+$'
  RDS001 [high] (offset 1, '(a+)+'): quantifier nested inside quantifier: the
  inner quantifier's end shares the characters {'a'} with the start of the next
  outer iteration; a failing match splits the input every possible way —
  exponential time
    fix: rewrite as a single quantifier, e.g. a+ instead of (a+)+; ...
```

## Why this exists

Every LLM writes regexes like `^(\w+\s?)+$` and every one of those is a
one-line DoS if the input is attacker-controlled. The existing tooling does
not fit the workflow:

| Tool | What it is | Why it is not this |
|---|---|---|
| [regexploit](https://github.com/doyensec/regexploit) | research REPL | you paste one pattern at a time by hand |
| [recheck](https://github.com/makenowjust-labs/recheck) | Scala/JS, automaton-based | Node toolchain, different niche |
| `redos` (npm) | JS-only scanner | JS ecosystem only |
| rxxr2 | academic, unmaintained | Java, last release 2016 |

`redoslint` is a zero-dependency Python CLI that scans a tree, keeps line and
column for every literal, and gates CI on the result.

## Quickstart

```bash
# 1. install (no runtime dependencies)
pip install git+https://github.com/xuange-hu/redoslint

# 2. audit one pattern, or a whole repository
redoslint pattern "^(\w+\s?)+$"
redoslint scan ./src --fail-on medium

# 3. wire it into CI — exits 1 when something at or above the threshold fires
redoslint scan . --sarif redoslint.sarif --fail-on high
```

Or skip the setup entirely — the demo ships inside the package and needs no
network, no fixtures, no arguments:

```bash
redoslint demo                          # 9 finding(s) across 17 patterns, exit 0
```

The same fixtures are checked in, so they double as the CI contract:

```bash
redoslint scan examples/vulnerable.py   # 9 finding(s), exit 1
redoslint scan examples/safe.py         # no findings, exit 0
```

## How it decides

A shape-only matcher flags `(a+)+` and also flags `(ab+)+`, which is linear.
redoslint parses the pattern into an AST with byte offsets and then asks one
question per candidate: **can these two fragments match the same characters?**

- `(a+)+` — the inner `a+` can end anywhere and the next iteration can start
  with `a` again → ambiguous → **RDS001, high**.
- `(ab+)+` — `b+` cannot consume the `a` that must begin the next iteration,
  so the boundary is pinned → nothing.
- `(\d{1,3}\.){3}\d{1,3}` (IPv4) — the trailing `.` pins the boundary between
  the group and the final octet → nothing.
- `.*abc.*` — two dots, but literals sit between them → nothing.
- `(?:a{2})*` — nested, but every iteration consumes exactly two characters,
  so the split points are pinned → nothing. A fixed-length body is checked
  before the charsets are compared (`analyze.fixed_length`).

That is the whole design: character-set algebra instead of regex golf. It is
also why the second pass can see structure a local view cannot — an
alternation three groups deep inside a quantifier still re-enters per
iteration, and `(?:x(?:y(?:a|aa)))+` is reported.

**Approximation, stated plainly:** `\w`, `\d`, `\s` expand to their ASCII
members, and `.` excludes `\n` regardless of `(?s)`. Patterns using Unicode
properties (`\p{...}`) or syntax outside the supported subset are reported as
**RDS099** instead of being silently skipped — a coverage gap you can see is
better than one you cannot.

## Rules

| ID | Severity | What it catches | Typical shape |
|---|---|---|---|
| RDS001 | high | quantifier nested in quantifier, ambiguous boundary | `(a+)+`, `((a+)a)+` |
| RDS002 | high | overlapping alternation branches under a quantifier | `(a\|aa)+`, `(foo\|foobar)+` |
| RDS003 | low | a branch shadowed by an earlier prefix branch | `user\|username` |
| RDS004 | medium | adjacent quantified atoms sharing characters | `\d*\d*`, `a*a*b` |
| RDS005 | medium | stacked bounded repetitions | `(a{1,10}){1,10}` |
| RDS006 | high | backreference to a group captured in the same loop | `(?:(\w)\1)+` |
| RDS007 | high | quantifier over a nullable fragment | `(a*)+`, `(a?)*` |
| RDS008 | low | very large minimum bound | `a{5000,}` |
| RDS099 | info | pattern outside the supported subset | (coverage gap) |

Severity means what it says: **high** is exponential in the input length,
**medium** is polynomial (real, but slower to hurt), **low** is hygiene.
RDS004 escalates to high at three overlapping quantifiers in a row.

## Samples it understands

Python via `ast` (only real `re.*` call sites — comments and lookalike
strings never leak in), Go `regexp.Compile`, Java/Kotlin `Pattern.compile`,
JS/TS `new RegExp(...)` and `/.../flags` literals. Anything else: use
`redoslint pattern "..."` or `--json` in a pipeline.

```bash
redoslint scan . --json | jq '.reports[] | select(.worst=="high")'
redoslint scan . --sarif out.sarif --fail-on medium
```

## MCP server

Six tools, so an agent can audit regexes without a shell:

```bash
uvx --from "redoslint[mcp]" redoslint-mcp
```

| Tool | Purpose |
|---|---|
| `redos_scan` | scan a file or directory |
| `redos_pattern` | audit one pattern string |
| `redos_rules` | list rules |
| `redos_rule_detail` | description + fix for one rule |
| `redos_sarif` | SARIF 2.1.0 document |
| `redos_version` | version |

The CLI has the same tour: `redoslint demo [--json]`.

The core stays zero-dependency; `mcp` lives in an extra and is pinned to
`>=1.2,<2` (2.x renamed `FastMCP` to `MCPServer`).

## GitHub Actions

```yaml
- run: pip install git+https://github.com/xuange-hu/redoslint
- run: redoslint scan . --fail-on high --sarif redoslint.sarif
- uses: github/codeql-action/upload-sarif@v3
  if: always()
  with:
    sarif_file: redoslint.sarif
```

Exit codes: `0` clean or below threshold, `1` findings at or above
`--fail-on`, `2` usage error.

## Layout

```
src/redoslint/parser.py     hand-written regex parser, spans for every node
src/redoslint/charset.py    range-set algebra (union/intersect/negate)
src/redoslint/analyze.py    full/start/end charsets, nullability
src/redoslint/rules.py      nine rules, two passes
src/redoslint/engine.py     orchestration, JSON, SARIF
src/redoslint/extract.py    per-language literal extraction
src/redoslint/cli.py        scan / pattern / rules / demo / version
src/redoslint/demo.py       embedded fixtures for `redoslint demo`
src/redoslint/mcp_server.py six MCP tools
examples/vulnerable.py      every rule fires here (CI asserts it)
examples/safe.py            the same tasks written safely (CI asserts clean)
```

## Limitations

- Character sets are ASCII-approximated, and case-insensitive matching is not
  modelled: `(?i)` removes a real overlap only when the pattern's own
  alternatives differ in case.
- `redoslint` is static. It does not execute patterns, so it cannot measure an
  actual payload — for a confirmed hit, reproduce with a timeout in a
  subprocess.
- Lookbehind content is treated as non-consuming, which is correct for
  ambiguity purposes but means a pattern that is only dangerous *inside* a
  lookaround is not reported.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports: see
[SECURITY.md](SECURITY.md). 中文说明：[README_CN.md](README_CN.md).

MIT.
