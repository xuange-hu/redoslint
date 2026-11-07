# Security policy

## What counts as a vulnerability here

`redoslint` makes claims, so its own failure modes are the security surface:

| Class | Example | Why it matters |
|---|---|---|
| **False negative** | a pattern that is exponential but reported clean | someone ships a DoS believing they were checked |
| **Crash / hang on input** | a pattern that makes the parser itself backtrack | a scanner that hangs cannot be run in CI |
| **Silent coverage loss** | syntax dropped instead of reported as RDS099 | the user cannot tell "clean" from "not looked at" |
| **Wrong offset** | a span pointing at the wrong fragment | the fix lands in the wrong place |

False positives matter too, but they are a quality bug, not a security bug —
file them as regular issues with the pattern and the input.

## Reporting

Open a private advisory: **Security → Advisories → Report a vulnerability** on
`https://github.com/xuange-hu/redoslint`. Include:

1. the pattern (verbatim, in a fenced block),
2. the input that makes it slow, if the claim is a false negative,
3. what redoslint reported (rule ids, spans) versus what it should have said,
4. `redoslint version` output.

Expect an acknowledgement within 7 days. This is a single-maintainer project;
there is no bounty.

## Scope

In scope:

- `src/redoslint/` — parser, charset algebra, rules, engine, extractors
- `src/redoslint/mcp_server.py` — path handling in `redos_scan` / `redos_sarif`
- the CI workflows in `.github/workflows/`

Out of scope:

- A vulnerable regex *found by* redoslint in a third-party project — report it
  to that project.
- Missing rules for exotic engines (PCRE-only constructs, backreference
  counting). File an issue; these are coverage, not vulnerabilities.
- Resource exhaustion from scanning a deliberately enormous tree. `scan` reads
  files sequentially and does not follow symlinks; point it at a real target.

## Design commitments

These are the properties a report will be measured against:

- **Offsets are exact.** Every finding carries `(start, end)` into the pattern
  string; no finding is emitted without one.
- **No silent skips.** Unsupported syntax becomes RDS099 with the offset.
- **No execution.** Patterns are parsed, never run. There is no code path in
  `redoslint` that calls `re.compile` on scanned input.
- **No network, no filesystem writes** except the SARIF path you name on the
  command line.
- **Zero runtime dependencies.** `pip install redoslint` pulls nothing; the MCP
  SDK is an opt-in extra pinned to `>=1.2,<2`.
