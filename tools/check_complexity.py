#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Check tracked Rust functions against the HISS-04 cyclomatic complexity cap.

Check:
    Analyse git-tracked crates/*.rs with the pinned lizard library. Every
    function must have cyclomatic complexity at most 10, including Rust's ?.

Why:
    The existing audit measures function length, and Clippy measures cognitive
    complexity. Neither enforces the separate HISS-04 McCabe limit.

Exit codes:
    0 = all functions within the cap, or all planted selftest cases passed
    1 = a function exceeds the cap, or a selftest verdict was wrong
    2 = could not run: git/analysis failed, lizard version differs from its
        requirement pin, file/function bounds exceeded, empty file list,
        or no functions analysed
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import subprocess  # nosec B404  # runs only git, fixed argv list, never a shell
import sys
import tempfile
from pathlib import Path

try:
    import lizard
except ImportError as error:  # main() reports it and exits 2
    lizard = None
    LIZARD_IMPORT_ERROR: ImportError | None = error
else:
    LIZARD_IMPORT_ERROR = None

CAP = 10
MAX_FILES = 4096
MAX_FUNCTIONS_PER_FILE = 65536
GIT_TIMEOUT_SECONDS = 60
ROOT = Path(__file__).resolve().parent.parent


def version_problem(text: str, installed: str) -> str | None:
    """Name why `installed` does not match the exact lizard pin in `text`."""
    pin = re.search(r"(?m)^lizard==([0-9]+(?:\.[0-9]+){2})$", text)
    if pin is None:
        return "missing exact lizard version pin"
    if installed != pin.group(1):
        return f"lizard version {installed!r} != pinned {pin.group(1)!r}"
    return None


def check_version() -> None:
    """Refuse an analyser version different from the direct requirement pin."""
    requirements = ROOT / "tools/complexity/requirements.in"
    problem = version_problem(requirements.read_text(encoding="utf-8"), lizard.version)
    if problem is not None:
        raise ValueError(f"{requirements}: {problem}")


def tracked_rust_files(root: Path) -> list[str]:
    """List tracked Rust sources with fixed git arguments and a deadline."""
    result = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
        ["git", "ls-files", "-z", "--", "crates/*.rs"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=True,
    )
    names = result.stdout.split("\0")
    if names[-1] == "":
        names.pop()
    return names


def check_file(path: Path, name: str) -> tuple[int, list[str]]:
    """Analyse one file, refusing lizard's otherwise swallowed read errors."""
    diagnostics = io.StringIO()
    with contextlib.redirect_stderr(diagnostics):
        result = lizard.analyze_file(str(path))
    if diagnostics.getvalue():
        raise ValueError(f"{name}: lizard analysis failed: {diagnostics.getvalue().strip()}")
    functions = result.function_list
    if len(functions) > MAX_FUNCTIONS_PER_FILE:
        raise ValueError(f"{name}: more than {MAX_FUNCTIONS_PER_FILE} functions")
    findings = []
    for function in functions[:MAX_FUNCTIONS_PER_FILE]:
        complexity = function.cyclomatic_complexity
        if complexity > CAP:
            findings.append(f"{name}:{function.start_line}: {function.name} CCN {complexity} > {CAP}")
    return len(functions), findings


def analyse_paths(root: Path, files: list[str]) -> tuple[int, str]:
    """Apply the same bounded analysis to tracked sources and planted files."""
    if not files:
        return 2, "ERROR: empty Rust file list"
    if len(files) > MAX_FILES:
        return 2, f"ERROR: more than {MAX_FILES} Rust files"
    total = 0
    findings = []
    for name in files[:MAX_FILES]:
        try:
            count, messages = check_file(root / name, name)
        except (OSError, ValueError, RuntimeError, IndexError) as error:
            return 2, f"ERROR: {name}: {error}"
        total += count
        findings.extend(messages)
    if total == 0:
        return 2, "ERROR: zero functions analysed"
    if findings:
        return 1, "\n".join(findings)
    return 0, f"PASS: {total} functions in {len(files)} Rust files have CCN <= {CAP}."


def selftest() -> int:
    """Plant above-cap, boundary, ?-only and empty inputs without invoking git."""
    cases = (
        ("CCN 11 refused", "fn planted() {" + "if true {}" * 10 + "}", 1, "CCN 11 > 10"),
        ("CCN 10 accepted", "fn planted() {" + "if true {}" * 9 + "}", 0, "PASS:"),
        (
            "question-mark CCN 11 refused",
            "fn planted() -> Result<(), ()> {" + "step()?;" * 10 + "Ok(())}",
            1,
            "CCN 11 > 10",
        ),
        ("empty file list refused", None, 2, "empty Rust file list"),
        ("zero functions refused", "// No functions here.\n", 2, "zero functions analysed"),
    )
    failures = 0
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for label, source, expected, message in cases[:5]:
            files = []
            if source is not None:
                (root / "planted.rs").write_text(source, encoding="utf-8")
                files = ["planted.rs"]
            status, output = analyse_paths(root, files)
            if status != expected or message not in output:
                print(f"FAIL: {label}: expected {expected} with {message!r}; got {status}: {output}")
                failures += 1
            else:
                print(f"PASS: {label}")
    return int(failures + version_selftest() != 0)


def version_selftest() -> int:
    """Plant a drifted and a missing pin; the matching pin must pass."""
    cases = (
        ("matching pin accepted", "lizard==1.26.0\n", "1.26.0", None),
        ("drifted version refused", "lizard==1.26.0\n", "1.27.0", "!= pinned"),
        ("range pin refused", "lizard>=1.26.0\n", "1.26.0", "missing exact"),
    )
    failures = 0
    for label, text, installed, expected in cases[:3]:
        problem = version_problem(text, installed)
        if (problem is None) != (expected is None) or (expected and expected not in str(problem)):
            print(f"FAIL: {label}: expected {expected!r}; got {problem!r}")
            failures += 1
        else:
            print(f"PASS: {label}")
    return failures


def main() -> int:
    """Validate the analyser pin, then run the requested bounded check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="run planted Rust cases")
    args = parser.parse_args()
    if lizard is None:
        print(f"ERROR: cannot import pinned lizard: {LIZARD_IMPORT_ERROR}", file=sys.stderr)
        return 2
    try:
        check_version()
        if args.selftest:
            return selftest()
        status, output = analyse_paths(ROOT, tracked_rust_files(ROOT))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"ERROR: complexity check could not run: {error}", file=sys.stderr)
        return 2
    print(output, file=sys.stdout if status == 0 else sys.stderr)
    return status


if __name__ == "__main__":
    sys.exit(main())
