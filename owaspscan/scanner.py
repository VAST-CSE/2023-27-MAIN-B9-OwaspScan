import ast
import os
import re
from pathlib import Path
from typing import Iterable, Iterator, List

from .models import Finding, Severity
from .rules import AST_CHECKS, REGEX_RULES

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv",
    "__pycache__", "dist", "build", ".tox", "tests",
    ".pytest_cache", ".mypy_cache", ".ruff_cache",
}
MAX_BYTES = 1_000_000
SUPPRESS = re.compile(r"(#|//)\s*noscan\b")
COMMENT = re.compile(r"^\s*(#|//|\*|/\*)")
UNPINNED = re.compile(r"^\s*[A-Za-z0-9_.\-]+(\[[^\]]+\])?\s*(>=|~=|>|<|<=)?[^=]*$")


def iter_files(root: Path) -> Iterator[Path]:
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
        for name in filenames:
            yield Path(dirpath) / name


def _read(path: Path):
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def scan_regex(path: Path, lines: List[str]) -> Iterator[Finding]:
    ext = path.suffix.lower() if path.suffix else path.name.lower()
    rules = [r for r in REGEX_RULES if ext in r.exts]
    if not rules:
        return
    for i, line in enumerate(lines, 1):
        if COMMENT.match(line) or SUPPRESS.search(line):
            continue
        for r in rules:
            if r.regex.search(line):
                yield Finding(r.id, r.owasp, r.severity, r.title, str(path), i, line.strip()[:160], r.fix)


def scan_ast(path: Path, source: str, lines: List[str]) -> Iterator[Finding]:
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError):
        return
    for check in AST_CHECKS:
        for line, rid, owasp, sev, title, fix in check(tree):
            text = lines[line - 1] if 0 < line <= len(lines) else ""
            if SUPPRESS.search(text):
                continue
            yield Finding(rid, owasp, sev, title, str(path), line, text.strip()[:160], fix)


def scan_manifest(path: Path, lines: List[str]) -> Iterator[Finding]:
    """A06: unpinned dependencies in requirements files."""
    if not re.match(r"requirements.*\.txt$", path.name):
        return
    for i, line in enumerate(lines, 1):
        s = line.strip()
        if not s or s.startswith(("#", "-")):
            continue
        if "==" not in s and UNPINNED.match(s):
            yield Finding("OWS-A06-001", "A06", Severity.LOW, "Unpinned dependency version",
                          str(path), i, s, "Pin exact versions (==) and audit with pip-audit / OSV.")


def scan_file(path: Path) -> List[Finding]:
    source = _read(path)
    if source is None:
        return []
    lines = source.splitlines()
    out: List[Finding] = list(scan_manifest(path, lines))
    out += scan_regex(path, lines)
    if path.suffix == ".py":
        out += scan_ast(path, source, lines)
    return out


def scan_paths(paths: Iterable[str]) -> List[Finding]:
    findings: List[Finding] = []
    for p in paths:
        for f in iter_files(Path(p)):
            findings.extend(scan_file(f))
    # de-duplicate (same rule on same line)
    uniq = {(f.rule_id, f.path, f.line): f for f in findings}
    return sorted(uniq.values(), key=lambda f: (-f.severity, f.path, f.line))
