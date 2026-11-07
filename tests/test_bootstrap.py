"""A fresh clone must be able to run its own tests.

The src/ layout only works because the root conftest.py puts src/ on
sys.path; every other CI job installs the package, which hides a broken
bootstrap. This test re-runs collection in a subprocess with PYTHONPATH
stripped, so the failure shows up locally too.
"""

import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CORE = ["tests/test_parser.py", "tests/test_rules.py"]


def test_collection_works_without_pythonpath():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", *CORE],
        cwd=ROOT, env=env, capture_output=True, text=True, timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_package_imports_from_source_tree():
    env = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    code = (
        "import sys; sys.path.insert(0, 'src');"
        "import redoslint, redoslint.cli, redoslint.engine;"
        "print(redoslint.__version__)"
    )
    proc = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                          capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip() == "0.1.0"
