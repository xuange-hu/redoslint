"""Extraction: the right literals from each language, nothing from comments."""

from redoslint import extract


def py(src):
    return [(h.line, h.pattern) for h in extract.extract(source(src), "python")]


def source(text):
    return text


PY_SAMPLE = """import re
# re.compile("(a+)+")  -- a comment, must not be extracted
PATTERN = re.compile(r"(a+)+")
HIT = re.search("(b|bb)+", text)
SPLIT = re.split(r"\\s+", line)
NOT_A_CALL = "(c|cc)+"
"""

GO_SAMPLE = '''
package main
import "regexp"
var re1 = regexp.MustCompile(`(a+)+`)
var re2 = regexp.Compile("(b|bb)+")
'''

JAVA_SAMPLE = '''
class A {
  static final Pattern P = Pattern.compile("(a+)+");
}
'''

JS_SAMPLE = '''
const re1 = new RegExp("(a+)+");
const re2 = /(b|bb)+/gi;
const url = "https://example.com/a/b";
// /(c|cc)+/ is in a comment
const ratio = total / count;
'''


# -- python --------------------------------------------------------------

def test_python_extracts_compile():
    assert (3, "(a+)+") in py(PY_SAMPLE)


def test_python_extracts_search():
    assert (4, "(b|bb)+") in py(PY_SAMPLE)


def test_python_skips_non_re_calls():
    patterns = [p for _, p in py(PY_SAMPLE)]
    assert "(c|cc)+" not in patterns


def test_python_skips_comments():
    patterns = [p for _, p in py(PY_SAMPLE)]
    assert "(a+)+" in patterns
    assert len([p for p in patterns if p == "(a+)+"]) == 1


def test_python_origin_is_recorded():
    origins = {h.origin for h in extract.extract(PY_SAMPLE, "python")}
    assert "re.compile" in origins and "re.search" in origins


def test_python_line_numbers_are_one_based():
    hits = extract.extract('import re\nX = re.compile("a")\n', "python")
    assert hits[0].line == 2


def test_python_syntax_error_yields_nothing():
    assert extract.extract("def broken(:\n", "python") == []


def test_python_fstring_argument_is_skipped():
    src = 'import re\nre.compile(f"{x}")\n'
    assert extract.extract(src, "python") == []


def test_python_multiline_pattern():
    src = 'import re\nre.compile(\n    "(a+)+"\n)\n'
    hits = extract.extract(src, "python")
    assert hits and hits[0].pattern == "(a+)+"


# -- go ------------------------------------------------------------------

def test_go_must_compile_backtick():
    hits = extract.extract(GO_SAMPLE, "go")
    assert any(h.pattern == "(a+)+" for h in hits)


def test_go_compile_double_quote():
    hits = extract.extract(GO_SAMPLE, "go")
    assert any(h.pattern == "(b|bb)+" for h in hits)


# -- java ----------------------------------------------------------------

def test_java_pattern_compile():
    hits = extract.extract(JAVA_SAMPLE, "java")
    assert [h.pattern for h in hits] == ["(a+)+"]


# -- js ------------------------------------------------------------------

def test_js_new_regexp():
    hits = extract.extract(JS_SAMPLE, "js")
    assert any(h.pattern == "(a+)+" for h in hits)


def test_js_regex_literal():
    hits = extract.extract(JS_SAMPLE, "js")
    assert any(h.pattern == "(b|bb)+" for h in hits)


def test_js_does_not_extract_urls():
    hits = extract.extract(JS_SAMPLE, "js")
    assert not any("example.com" in h.pattern for h in hits)


def test_js_does_not_extract_division():
    hits = extract.extract(JS_SAMPLE, "js")
    assert not any(h.pattern == " count" for h in hits)


# -- dispatch ------------------------------------------------------------

def test_language_by_extension():
    assert extract.LANG_BY_EXT[".py"] == "python"
    assert extract.LANG_BY_EXT[".tsx"] == "js"
    assert extract.LANG_BY_EXT[".go"] == "go"


def test_unknown_language_yields_nothing():
    assert extract.extract("whatever", "rust") == []


def test_skip_dirs_cover_vendor_trees():
    assert ".git" in extract.SKIP_DIRS
    assert "node_modules" in extract.SKIP_DIRS
