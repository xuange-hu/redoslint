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

    pp = sub.add_parser("pattern", help="audit a single pattern string")
    pp.add_argument("pattern", help="the regex to audit")
    pp.add_argument("--fail-on", choices=FAIL_CHOICES, default="high")
    pp.add_argument("--sarif", metavar="FILE")
    pp.add_argument("--json", action="store_true")

    rp = sub.add_parser("rules", help="list the rules")
    rp.add_argument("--id", dest="rule_id", metavar="RDSxxx",
                    help="show one rule in full")

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


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "version":
        print(f"redoslint {__version__}")
        return 0

    if args.command == "rules":
        return _cmd_rules(args)

    if args.command == "pattern":
        reports = [eng.scan_pattern(args.pattern)]
        return _emit(reports, args)

    reports: list = []
    for path in args.paths:
        reports.extend(eng.scan_path(path))
    return _emit(reports, args)


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
