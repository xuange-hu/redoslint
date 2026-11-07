"""Safe regexes — the same tasks as examples/vulnerable.py, written without
the ambiguity. redoslint reports nothing on this file.
"""

import re

USERNAME = re.compile(r"^[a-z]+$")          # one quantifier, no nesting
TOKEN = re.compile(r"^a+b$")                # prefix factored out
COMMAND = re.compile(r"username|user")      # longest branch first
NUMBER = re.compile(r"^\d+:\d+$")           # single quantifier per field
GRID = re.compile(r"^a{1,100}z$")           # flattened bounds
REPEAT = re.compile(r"^(\w)\1$")            # capture outside any loop
LABEL = re.compile(r"^a+b$")                # non-nullable body
PAD = re.compile(r"^a{1,64}b$")             # sane bounds
