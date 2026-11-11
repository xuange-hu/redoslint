# Contributing

The thing this project sells is trust: if `redoslint` says a pattern is
exponential, that claim has to hold up when someone benchmarks it. So the bar
for a rule change is higher than for a feature.

## Setup

```bash
git clone https://github.com/xuange-hu/redoslint
cd redoslint
python -m pip install -e ".[mcp]" pytest ruff
python -m pytest -q
```

A bare clone also works — the root `conftest.py` puts `src/` on `sys.path`, and
CI has a job whose only purpose is to keep that true.

## Adding or changing a rule

1. **Add the rule** in `src/redoslint/rules.py`. Put it in `PASS1` if it only
   needs the node itself, in `PASS2` if it needs enclosing context.
2. **Add the shape and its counter-shape to `tests/test_rules.py`.** Every rule
   needs at least one case that must fire and one near-miss that must not. A
   rule without a near-miss is a false-positive generator.
3. **Reach it from `examples/vulnerable.py`.** `tests/test_demo_contract.py`
   asserts all nine rules fire there; the CI `demo-contract` job asserts the
   same thing from a clean install.
4. **Keep `examples/safe.py` clean.** It is the same set of tasks written
   without ambiguity. If a new rule fires on it, the rule is wrong, not the
   fixture.

Severity is not a judgement call:

- `high` — exponential in input length. A 30-character payload hangs a thread.
- `medium` — polynomial. Real, but needs a long input to hurt.
- `low` — hygiene: dead branches, absurd bounds.
- `info` — coverage gap (RDS099), never a vulnerability claim.

## Character-set decisions

`charset.py` is the core of the tool and the one place where an approximation
becomes a wrong answer. If you widen or narrow an expansion (`\w`, `\s`, `.`),
state the trade-off in the docstring and add a test that pins it. Silent
approximation changes are how a scanner starts lying.

Anything the parser cannot represent must surface as **RDS099** — never be
silently dropped on the floor.

## Style

- `ruff check .` must pass (config in `pyproject.toml`, line length 100).
- Standard library only in `src/redoslint/`. `mcp` lives in the `[mcp]` extra
  and is imported lazily inside `build_server()`; `tests/test_packaging.py`
  pins both facts.
- Comments explain *why*. A comment that restates the next line is noise.

## Tests

```bash
python -m pytest -q                       # 541 tests
python -m pytest -q --durations=5         # the suite must stay fast
redoslint scan src --fail-on low          # the scanner must not flag itself
```

The last one matters: a false positive in its own source is the fastest way to
lose a visitor's trust. There is a CI job for it.

## Commit messages

`area: what changed and why`. Examples:

```
rules: stop RDS004 from firing on IPv4 literals
parser: treat {m,1} as a syntax error instead of a literal
cli: keep the offset in the text renderer's finding line
```

## Pull requests

Include the fixture that proves the change. For a false positive, paste the
pattern, the input that triggers it, and what the tool said before the fix. If
a rule change alters output on the checked-in examples, say which findings
disappeared and why that is correct.

## Reporting a ReDoS in the wild

This tool finds patterns; it does not host disclosures. If you found a
vulnerable pattern in a third-party project, report it to that project.
