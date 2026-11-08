#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
# Adapted from tools/ci/nosec_check.py in lusoris/SnatchArr.
"""Validate inline Bandit and Prospector nosec suppressions across Python files.

Check:
    Ensures every # nosec suppression directive specifies rule IDs and a reason.

Form:
    # nosec Bxxx[ Bxxx]  # <reason>

Why:
    Bandit and Prospector run in Codacy. An unexplained nosec hides a finding.
    Bandit reads every word between nosec and the next # as a test id or name,
    so a reason there (after -- or bare) can widen the suppression; a reason
    after a second # is never read.

Exit codes:
    0 = valid or none
    1 = invalid comment
    2 = could not run
"""

from __future__ import annotations

import argparse
import io
import re
import subprocess  # nosec B404  # runs only git, fixed argv list, never a shell
import sys
import tokenize
from pathlib import Path

GIT_TIMEOUT_SECONDS = 60
MAX_FILES = 5000
DIRECTIVE_RE = re.compile(r"#\s*nosec", re.IGNORECASE)
VALID_RE = re.compile(r"#\s*nosec(?:[ \t,]+B\d{3})+[ \t]+#[ \t]*\S")
DASH_FORM_RE = re.compile(r"#\s*nosec(?:[ \t,]+B\d{3})+[ \t]+--")

SELFTEST_CASES: tuple[tuple[str, int, int, str], ...] = (
    # accepted (1, 0, "")
    ("import subprocess  # nosec B404  # runs only git", 1, 0, ""),
    ("x = run()  # nosec B603 B607  # fixed argv", 1, 0, ""),
    ("x = run()  # nosec B404,B603  # why", 1, 0, ""),
    ("#nosec B603 #why", 1, 0, ""),
    ("x = run()  # nosec B603  # reason may name eval now", 1, 0, ""),
    # refused, needs (0, 1, "needs rule ids")
    ("x = run()  # nosec B603", 0, 1, "needs rule ids"),
    ("import subprocess  # nosec", 0, 1, "needs rule ids"),
    ("x = run()  # nosec  # why", 0, 1, "needs rule ids"),
    ("x = run()  # nosec B603  #", 0, 1, "needs rule ids"),
    ("x = run()  # nosec B603 fixed argv", 0, 1, "needs rule ids"),
    ("x = run()  # nosec B603 eval", 0, 1, "needs rule ids"),
    ("x = run()  # nosec b603  # why", 0, 1, "needs rule ids"),
    ("x = run()  # nosec: B603  # why", 0, 1, "needs rule ids"),
    ("x = run()  # NOSEC B603  # why", 0, 1, "needs rule ids"),
    ("x = run()  # nosecurity review", 0, 1, "needs rule ids"),
    ("x = run()  # noqa: E501  # nosec B603", 0, 1, "needs rule ids"),
    # refused, dash (0, 1, "after --")
    ("x = run()  # nosec B603 -- why", 0, 1, "after --"),
    ("x = run()  # nosec B603 B607 -- fixed argv", 0, 1, "after --"),
    ("import subprocess  # nosec B404 -- runs only git", 0, 1, "after --"),
    # ignored (0, 0, "")
    ('s = "# nosec"', 0, 0, ""),
    ('s = "# nosec B603 -- why"', 0, 0, ""),
    ("x = 1  # nanosecond budget", 0, 0, ""),
    ("x = 1  # no suppression here", 0, 0, ""),
)


def tracked_python_files(root: Path) -> list[str]:
    """Return tracked Python files in root via git ls-files."""
    proc = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
        ["git", "ls-files", "-z", "--", "*.py"],
        cwd=root,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip()
        raise RuntimeError(f"git ls-files failed with code {proc.returncode}: {err}")
    files = [f for f in proc.stdout.split("\0") if f]
    if len(files) > MAX_FILES:
        raise RuntimeError(f"too many files: {len(files)} exceeds limit of {MAX_FILES}")
    return files


def _classify_comment(name: str, line: int, comment: str) -> tuple[int, str | None]:
    """Classify a comment matching DIRECTIVE_RE into (is_annotated, finding)."""
    if VALID_RE.search(comment):
        return 1, None
    if DASH_FORM_RE.search(comment):
        msg = (
            f"{name}:{line}: nosec reason after -- is read as test names; "
            "write # nosec Bxxx  # <reason>"
        )
        return 0, msg
    msg = f"{name}:{line}: nosec needs rule ids and a reason: # nosec Bxxx  # <reason>"
    return 0, msg


def check_source(name: str, text: str) -> tuple[int, list[str]]:
    """Scan text for inline nosec comments, returning (annotated_count, findings)."""
    annotated = 0
    findings: list[str] = []
    try:
        tokens = tokenize.generate_tokens(io.StringIO(text).readline)
        for tok_type, tok_str, start, _end, _line in tokens:
            if tok_type == tokenize.COMMENT and DIRECTIVE_RE.search(tok_str):
                ann, finding = _classify_comment(name, start[0], tok_str)
                annotated += ann
                if finding is not None:
                    findings.append(finding)
    except (tokenize.TokenError, SyntaxError, IndentationError) as exc:
        raise ValueError(f"{name}: cannot tokenize: {exc}") from exc
    return annotated, findings


def scan(root: Path) -> tuple[int, list[str]]:
    """Scan tracked Python files under root for nosec comments."""
    files = tracked_python_files(root)
    total_annotated = 0
    all_findings: list[str] = []
    for rel_path in files:
        file_path = root / rel_path
        if not file_path.is_file():
            continue
        try:
            text = file_path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"cannot read {file_path}: {exc}") from exc
        try:
            annotated, findings = check_source(rel_path, text)
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc
        total_annotated += annotated
        all_findings.extend(findings)
    return total_annotated, all_findings


def selftest() -> int:
    """Run in-memory test cases through check_source."""
    failures = 0
    total = len(SELFTEST_CASES) + 2

    for source, exp_ann, exp_fnd, exp_sub in SELFTEST_CASES:
        ann, fnd = check_source("test", source)
        mismatch = ann != exp_ann or len(fnd) != exp_fnd
        if not mismatch and exp_sub:
            mismatch = any(exp_sub not in item for item in fnd)
        if mismatch:
            print(f"FAIL: {source}")
            failures += 1

    two_line = "import subprocess  # nosec B404  # valid\nx = run()  # nosec B603"
    ann, fnd = check_source("test", two_line)
    if ann != 1 or len(fnd) != 1 or ":2:" not in fnd[0]:
        print(f"FAIL: {two_line}")
        failures += 1

    try:
        check_source("test", "x = (")
        print("FAIL: x = (")
        failures += 1
    except ValueError:
        pass

    if failures > 0:
        return 1
    print(f"PASS: nosec check selftest ({total} cases)")
    return 0


def main() -> int:
    """Parse arguments and run selftest or repo scan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest", action="store_true", help="run in-memory test suite"
    )
    parser.add_argument(
        "--root", type=Path, default=Path("."), help="repository root to scan"
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    try:
        annotated, findings = scan(args.root)
    except RuntimeError as exc:
        print(f"check_nosec: cannot run: {exc}", file=sys.stderr)
        return 2

    if findings:
        for finding in findings:
            print(finding, file=sys.stderr)
        print(f"check_nosec: {len(findings)} invalid nosec comment(s)", file=sys.stderr)
        return 1

    print(f"check_nosec: ok ({annotated} annotated lines)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
