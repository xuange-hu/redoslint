"""Pull regex literals out of source files.

Per-language extractors return Hit(line, col, pattern) with 1-based
line/col. Python goes through the stdlib `ast` module (precise, no
false hits from comments or strings that merely look like regexes); the
other languages use conservative line patterns.

`--pattern` on the CLI covers anything the extractors do not.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

RE_FUNCS = {
    "compile", "search", "match", "fullmatch", "findall", "finditer",
    "sub", "subn", "split", "template",
}

LANG_BY_EXT = {
    ".py": "python",
    ".go": "go",
    ".java": "java",
    ".kt": "java",  # Kotlin's Pattern.compile is close enough for extraction
    ".js": "js",
    ".ts": "js",
    ".jsx": "js",
    ".tsx": "js",
    ".mjs": "js",
    ".cjs": "js",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".mypy_cache", ".pytest_cache", "dist", "build", ".tox", ".idea",
}


@dataclass
class Hit:
    line: int  # 1-based
    col: int   # 1-based
    pattern: str
    origin: str  # e.g. "re.compile"


def extract(text: str, lang: str) -> list[Hit]:
    if lang == "python":
        return extract_python(text)
    if lang == "go":
        return extract_go(text)
    if lang == "java":
        return extract_java(text)
    if lang == "js":
        return extract_js(text)
    return []


def extract_python(text: str) -> list[Hit]:
    """String constants passed as the first argument of re.<func>(...) —
    via ast, so comments and unrelated strings never leak in."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return []
    hits: list[Hit] = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in RE_FUNCS and node.args):
            continue
        arg = node.args[0]
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            hits.append(Hit(
                arg.lineno, arg.col_offset + 1, arg.value,
                f"re.{node.func.attr}",
            ))
    return hits


def _string_after(text: str, call: re.Pattern[str], origin: str) -> list[Hit]:
    """Extract the string literal that follows a call on the *same line*.
    Searching further than the line boundary would pick up the next
    statement's quotes and silently report the wrong pattern."""
    hits = []
    for m in call.finditer(text):
        line = text.count("\n", 0, m.start()) + 1
        col = m.start() - text.rfind("\n", 0, m.start()) + 1
        line_end = text.find("\n", m.end())
        tail = text[m.end():line_end if line_end != -1 else len(text)]
        for q in ('"', "'", "`"):
            idx = tail.find(q)
            if idx == -1:
                continue
            end = tail.find(q, idx + 1)
            if end == -1:
                continue
            hits.append(Hit(line, col + idx + 1, tail[idx + 1:end], origin))
            break
    return hits


_GO_CALL = re.compile(r"regexp?\.(?:Must)?Compile\(")
_JAVA_CALL = re.compile(r"Pattern\.compile\(")


def extract_go(text: str) -> list[Hit]:
    return _string_after(text, _GO_CALL, "regexp.Compile")


def extract_java(text: str) -> list[Hit]:
    return _string_after(text, _JAVA_CALL, "Pattern.compile")


# JS/TS: new RegExp('...') plus regex literals at the end of a statement.
# The literal heuristic is deliberately narrow: it must sit at end-of-line
# after = ( : or return, which keeps URLs, division and comments out.
_JS_CALL = re.compile(r"new\s+RegExp\(")
_JS_LITERAL = re.compile(
    r"(?:[=(:]|return)\s*/([^/\n]+?)/([gimsuy]*)\s*(?:;|,?\s*(?:#.*)?$)",
)


def extract_js(text: str) -> list[Hit]:
    hits = _string_after(text, _JS_CALL, "new RegExp")
    for i, line in enumerate(text.splitlines(), 1):
        m = _JS_LITERAL.search(line)
        if m:
            hits.append(Hit(i, m.start(1) + 1, m.group(1), "/.../ literal"))
    return hits
