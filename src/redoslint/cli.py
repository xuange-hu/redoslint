"""redoslint command line.

Exit codes (CI-friendly, same contract as the rest of the family):
  0  clean (or findings below --fail-on)
  1  findings at or above --fail-on
  2  usage error or internal error
"""

from __future__ import annotations

import argparse
import sys

from . import __version__
from . import engine as eng

FAIL_CHOICES = ["none", "info", "low", "medium", "high"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redoslint",
        description="ReDoS audit with the bytes that prove each finding.",
    )
    p.add_argument("--version", action="version",
                   version=f"redoslint {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    sp = sub.add_parser("scan", help="scan files or directories")
    sp.add_argument("paths", nargs="+", help="files or directories to scan")
    sp.add_argument("--fail-on", choices=FAIL_CHOICES, default="high",
                    help="exit 1 at or above this severity (default: high)")
    sp.add_argument("--sarif", metavar="FILE",
                    help="also write findings as SARIF 2.1.0")
    sp.add_argument("--json", action="store_true",
                    help="machine-readable JSON output")
    sp.add_argument("--rule", action="append", metavar="RDSxxx[,RDSyyy]",
                    help="only report these rules (repeatable, comma-separated)")

    pp = sub.add_parser("pattern", help="audit a single pattern string")
    pp.add_argument("pattern", help="the regex to audit")
    pp.add_argument("--fail-on", choices=FAIL_CHOICES, default="high")
    pp.add_argument("--sarif", metavar="FILE")
    pp.add_argument("--json", action="store_true")
    pp.add_argument("--rule", action="append", metavar="RDSxxx[,RDSyyy]",
                    help="only report these rules (repeatable, comma-separated)")

    rp = sub.add_parser("rules", help="list the rules")
    rp.add_argument("--id", dest="rule_id", metavar="RDSxxx",
                    help="show one rule in full")

    dp = sub.add_parser("demo", help="run the built-in fixtures (no network)")
    dp.add_argument("--json", action="store_true",
                    help="machine-readable JSON output")
    dp.add_argument("--rule", action="append", metavar="RDSxxx[,RDSyyy]",
                    help="only report these rules (repeatable, comma-separated)")

    sub.add_parser("version", help="print the version")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return _dispatch(args)
    except BrokenPipeError:
        return 0
    except Exception as exc:  # pragma: no cover - defensive
        print(f"redoslint: internal error: {exc}", file=sys.stderr)
        return 2


def _apply_rule_filter(reports, args) -> int | None:
    """Return None on success, or the exit code for a bad --rule value.

    A typo in a rule id is a usage error (exit 2), not a clean scan. Silently
    filtering everything down to zero findings would be the dangerous failure.
    """
    values = getattr(args, "rule", None)
    if not values:
        return None
    ids = [item.strip() for value in values
           for item in value.split(",") if item.strip()]
    unknown = [rid for rid in ids if rid not in eng.RULES_BY_ID]
    if unknown:
        print(f"unknown rule {unknown[0]}; try 'redoslint rules'",
              file=sys.stderr)
        return 2
    if not ids:
        return None
    reports[:] = eng.filter_rules(reports, set(ids))
    return None


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "version":
        print(f"redoslint {__version__}")
        return 0

    if args.command == "rules":
        return _cmd_rules(args)

    if args.command == "demo":
        return _cmd_demo(args)

    if args.command == "pattern":
        reports = [eng.scan_pattern(args.pattern)]
        bad = _apply_rule_filter(reports, args)
        return bad if bad is not None else _emit(reports, args)

    reports: list = []
    for path in args.paths:
        reports.extend(eng.scan_path(path))
    bad = _apply_rule_filter(reports, args)
    return bad if bad is not None else _emit(reports, args)


def _emit(reports, args) -> int:
    if args.json:
        print(eng.dumps_json(eng.to_json(reports)))
    else:
        _print_text(reports)
    if getattr(args, "sarif", None):
        with open(args.sarif, "w", encoding="utf-8") as fh:
            fh.write(eng.dumps_json(eng.to_sarif(reports)))
    fail_on = getattr(args, "fail_on", "high")
    return 1 if eng.fail_level(reports, fail_on) else 0


def _print_text(reports) -> None:
    for r in reports:
        if not r.findings:
            continue
        where = r.path or "<pattern>"
        if r.line:
            where += f":{r.line}:{r.col}"
        print(f"{where}  [{r.origin}]" if r.path else f"pattern: {r.pattern!r}")
        if r.path:
            print(f"  pattern: {r.pattern!r}")
        for f in r.findings:
            frag = r.pattern[f.span[0]:f.span[1]]
            off = f" (offset {f.span[0]}, {frag!r})" if frag else ""
            print(f"  {f.rule_id} [{f.severity}]{off}: {f.message}")
            print(f"    fix: {f.suggestion}")
        print()
    counted = sum(len(r.findings) for r in reports)
    if counted == 0:
        print("no findings")
    else:
        print(f"{counted} finding(s)")


def _cmd_demo(args: argparse.Namespace) -> int:
    """The visitor's first command: runs on a bare install, exits 0.

    Deliberately not gated on findings — a demo that fails is a demo a visitor
    reads as "the tool is broken".
    """
    from . import demo as demo_mod

    reports, _tmp = demo_mod.run_demo()
    # The coverage warning is about the fixture, not about the user's --rule
    # selection. Compute it before filtering, otherwise selecting one rule
    # looks like eight rules broke.
    missing = demo_mod.missing_rules(reports)
    bad = _apply_rule_filter(reports, args)
    if bad is not None:
        return bad
    if args.json:
        print(eng.dumps_json(eng.to_json(reports)))
        return 0
    print(demo_mod.render(reports))
    if missing:  # pragma: no cover - CI catches this before a user does
        print(f"warning: demo no longer reaches {', '.join(missing)}",
              file=sys.stderr)
    return 0


def _cmd_rules(args: argparse.Namespace) -> int:
    from .engine import RULES_BY_ID

    if args.rule_id:
        rule = RULES_BY_ID.get(args.rule_id)
        if rule is None:
            print(f"unknown rule {args.rule_id}", file=sys.stderr)
            return 2
        print(f"{rule.rule_id} [{rule.severity}] {rule.title}")
        print(rule.description)
        print(f"fix: {rule.fix}")
        return 0
    for rule in eng.RULES_BY_ID.values():
        print(f"{rule.rule_id}  [{rule.severity:6}]  {rule.title}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
