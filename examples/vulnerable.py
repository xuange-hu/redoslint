"""Deliberately vulnerable regexes — every redoslint rule fires at least once
in this file. It is the demo fixture and the CI demo-contract target; the
last pattern is a real parse error, hence the try/except.
"""

import re

# RDS001 — nested quantifier, ambiguous inner boundary
USERNAME = re.compile(r"^(a+)+$")

# RDS002 — overlapping alternation branches under a quantifier
TOKEN = re.compile(r"^(a|aa)+b$")

# RDS003 — branch is a prefix of another branch
COMMAND = re.compile(r"user|username")

# RDS004 — adjacent quantified atoms with overlapping characters
NUMBER = re.compile(r"^\d*\d*:\d+$")

# RDS005 — stacked bounded repetitions
GRID = re.compile(r"^(a{1,10}){1,10}z$")

# RDS006 — backreference to a group captured inside the same loop
REPEAT = re.compile(r"^(?:(\w)\1)+$")

# RDS007 — quantifier over a fragment that can match empty
LABEL = re.compile(r"^(a*)+b$")

# RDS008 — very large minimum bound
PAD = re.compile(r"^a{5000,}b$")

# RDS099 — unparseable: the coverage gap is reported, not hidden
try:
    BROKEN = re.compile(r"^[unclosed")
except re.error:
    BROKEN = None
