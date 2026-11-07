"""Packaging contract: the console script must not need any extra installed.

This is the class of bug that ships silently — CI installs `.[all]`, so a
script whose module-scope imports sit in an optional extra looks fine there
and explodes for the first user who runs `pip install redoslint`.
"""

import ast
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PYPROJECT = os.path.join(ROOT, "pyproject.toml")


def pyproject_text():
    with open(PYPROJECT, encoding="utf-8") as fh:
        return fh.read()


def test_console_script_points_at_cli_main():
    text = pyproject_text()
    assert re.search(r'^redoslint\s*=\s*"redoslint\.cli:main"', text, re.M)


def test_core_has_no_runtime_dependencies():
    text = pyproject_text()
    block = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.M | re.S)
    assert block is not None
    declared = [line for line in block.group(1).splitlines()
                if line.strip() and not line.strip().startswith("#")]
    assert declared == [], f"core declares runtime deps: {declared}"


def test_version_matches_package_init():
    text = pyproject_text()
    declared = re.search(r'^version\s*=\s*"([^"]+)"', text, re.M).group(1)
    sys.path.insert(0, os.path.join(ROOT, "src"))
    import redoslint
    assert redoslint.__version__ == declared


def test_cli_imports_only_stdlib_and_package():
    """Static import audit of the module the console script resolves to."""
    path = os.path.join(ROOT, "src", "redoslint", "cli.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    third_party = {
        n for n in names
        if n not in sys.stdlib_module_names and n != "redoslint"
    }
    assert not third_party, f"cli.py imports third-party modules: {third_party}"


def test_cli_runs_without_optional_deps():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "from redoslint.cli import main;"
        "sys.exit(main(['pattern', 'a+']))"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


def test_mcp_extra_is_pinned_below_two():
    # mcp 2.x renamed FastMCP -> MCPServer and moved the import path.
    assert 'mcp>=1.2,<2' in pyproject_text()


def test_mcp_script_is_declared():
    text = pyproject_text()
    assert re.search(r'^redoslint-mcp\s*=\s*"redoslint\.mcp_server:main"',
                     text, re.M)


def test_mcp_server_imports_no_third_party_at_module_scope():
    """`redoslint-mcp` must not explode before it can print its own error.

    The SDK is imported inside build_server(); if that ever moves to the top of
    the module, the console script becomes import-time-broken for everyone who
    installed the core package without the extra.
    """
    path = os.path.join(ROOT, "src", "redoslint", "mcp_server.py")
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    names = set()
    for node in tree.body:  # module scope only, not inside functions
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module.split(".")[0])
    third_party = {n for n in names
                   if n not in sys.stdlib_module_names and n != "redoslint"}
    assert not third_party, f"mcp_server.py imports {third_party} at module scope"


def test_requires_python_matches_ci_matrix():
    assert 'requires-python = ">=3.10"' in pyproject_text()
