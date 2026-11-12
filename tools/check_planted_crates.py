#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Validate directory placement of planted Cargo crates across the repository.

Check:
    Ensures every planted crate sits under a directory segment named fixtures.
    Every tracked Cargo.toml that is nested (path holds a /), has a [package]
    table, has its own [workspace] table, and is not publishable, must sit under
    a fixtures/ segment (regex (^|/)fixtures/). The root Cargo.toml is never a
    planted crate.

Why:
    The praetor library layer (tools/planning/library_units.py:140 in the engine)
    makes a library node of every named tracked Cargo.toml. Its reader drops paths
    with a fixtures/ segment (eco_edges.SKIP, regex
    (^|/)(vendor|third_party|node_modules|testdata|fixtures|examples?)/).
    A planted crate outside fixtures (such as node
    LIB-plurano-saeptum-saeptum-refused-licence on 2026-11-12) becomes a phantom
    library node and a verification unit for nothing. The repository convention
    is the fixtures/ segment; a nested crate with its own workspace that is
    publishable is a real crate and passes.

Exit codes:
    0 = every planted crate sits under a fixtures/ directory
    1 = planted crate outside a fixtures/ directory
    2 = could not run
"""

from __future__ import annotations

import argparse
import contextlib
import io
import re
import subprocess  # nosec B404  # runs only git, fixed argv list, never a shell
import sys
import tempfile
import tomllib
from pathlib import Path

GIT_TIMEOUT_SECONDS = 60
MAX_FILES = 5000
MAX_BYTES = 1_000_000
FIXTURES_RE = re.compile(r"(^|/)fixtures/")

PLANTED_TOML = """[package]
name = "planted"
version = "0.0.0"
publish = false

[workspace]
"""

MEMORY_CASES: tuple[tuple[str, str, str, str], ...] = (
    ("planted outside fixtures", "tools/deny/refused/Cargo.toml", PLANTED_TOML, "fail"),
    (
        "same under tools/deny/fixtures/x/Cargo.toml",
        "tools/deny/fixtures/x/Cargo.toml",
        PLANTED_TOML,
        "pass",
    ),
    ("top-level fixtures/x/Cargo.toml", "fixtures/x/Cargo.toml", PLANTED_TOML, "pass"),
    (
        "tools/myfixtures/x/Cargo.toml",
        "tools/myfixtures/x/Cargo.toml",
        PLANTED_TOML,
        "fail",
    ),
    (
        "tools/fixtures-old/x/Cargo.toml",
        "tools/fixtures-old/x/Cargo.toml",
        PLANTED_TOML,
        "fail",
    ),
    (
        "root Cargo.toml with [package] publish = false and [workspace]",
        "Cargo.toml",
        PLANTED_TOML,
        "pass",
    ),
    (
        "nested publish = [] with [workspace]",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = []\n\n[workspace]\n',
        "fail",
    ),
    (
        "nested publish = false without [workspace] (a workspace member)",
        "crates/a/Cargo.toml",
        '[package]\nname = "a"\npublish = false\n',
        "pass",
    ),
    (
        "nested [workspace] with publish = true",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = true\n\n[workspace]\n',
        "pass",
    ),
    (
        'with publish = ["crates-io"]',
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = ["crates-io"]\n\n[workspace]\n',
        "pass",
    ),
    (
        "with publish absent",
        "nested/Cargo.toml",
        '[package]\nname = "p"\n\n[workspace]\n',
        "pass",
    ),
    (
        "[workspace] without [package] (virtual nested workspace)",
        "nested/Cargo.toml",
        '[workspace]\nmembers = ["crates/*"]\n',
        "pass",
    ),
    (
        "publish = { workspace = true } with [workspace.package] publish = false",
        "nested/Cargo.toml",
        (
            '[package]\nname = "p"\npublish = { workspace = true }\n\n[workspace]\n'
            "[workspace.package]\npublish = false\n"
        ),
        "fail",
    ),
    (
        "same with [workspace.package] lacking publish",
        "nested/Cargo.toml",
        (
            '[package]\nname = "p"\npublish = { workspace = true }\n\n[workspace]\n'
            '[workspace.package]\nname = "ws"\n'
        ),
        "pass",
    ),
    (
        'publish = "no"',
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = "no"\n\n[workspace]\n',
        "error",
    ),
    (
        "publish = [1]",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = [1]\n\n[workspace]\n',
        "error",
    ),
    (
        "publish = { workspace = false }",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = { workspace = false }\n\n[workspace]\n',
        "error",
    ),
    (
        "publish = { workspace = 1 }",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = { workspace = 1 }\n\n[workspace]\n',
        "error",
    ),
    (
        "publish = { workspace = true, extra = 1 }",
        "nested/Cargo.toml",
        '[package]\nname = "p"\npublish = { workspace = true, extra = 1 }\n\n[workspace]\n',
        "error",
    ),
    (
        "publish = { workspace = true } with [workspace.package] publish = 1",
        "nested/Cargo.toml",
        (
            '[package]\nname = "p"\npublish = { workspace = true }\n\n[workspace]\n'
            "[workspace.package]\npublish = 1\n"
        ),
        "error",
    ),
    (
        "invalid TOML",
        "nested/Cargo.toml",
        "[package\n",
        "error",
    ),
)

SCAN_CASES: tuple[tuple[str, list[tuple[str, str, bool]], int, str], ...] = (
    (
        "a planted crate under a/fixtures/p/ only -> 0",
        [("a/fixtures/p/Cargo.toml", PLANTED_TOML, True)],
        0,
        "PASS:",
    ),
    (
        "a planted crate under a/p/ -> 1",
        [("a/p/Cargo.toml", PLANTED_TOML, True)],
        1,
        (
            "FAIL: a/p/Cargo.toml: planted crate (publish = false, own [workspace]) "
            "outside a fixtures/ directory; move it under a/fixtures/"
        ),
    ),
    (
        "an untracked planted crate under a/p/ -> 0",
        [("a/p/Cargo.toml", PLANTED_TOML, False)],
        0,
        "PASS:",
    ),
    (
        "a planted file named Cargo.toml.in under a/p/ -> 0",
        [("a/p/Cargo.toml.in", PLANTED_TOML, True)],
        0,
        "PASS:",
    ),
    (
        "an invalid TOML tracked nested Cargo.toml -> 2",
        [("a/p/Cargo.toml", "[package\n", True)],
        2,
        "ERROR: a/p/Cargo.toml",
    ),
)


def _is_publish_literal(val: object) -> bool | None:
    """Return True if publishable, False if unpublishable, None if other shape."""
    if isinstance(val, bool):
        return val
    if isinstance(val, list):
        if not val:
            return False
        if all(isinstance(x, str) for x in val):
            return True
        return None
    return None


def _resolve_workspace_publish(path: str, data: dict[str, object], raw: object) -> bool:
    """Resolve publish when package.publish inherits from workspace."""
    # `is True` and the length keep `{ workspace = 1 }` and extra keys out.
    if not (isinstance(raw, dict) and len(raw) == 1 and raw.get("workspace") is True):
        raise ValueError(f"{path}: unknown publish shape: {raw!r}")
    ws = data.get("workspace")
    ws_pkg = ws.get("package") if isinstance(ws, dict) else None
    if not isinstance(ws_pkg, dict) or "publish" not in ws_pkg:
        return True
    ws_lit = _is_publish_literal(ws_pkg["publish"])
    if ws_lit is not None:
        return ws_lit
    raise ValueError(
        f"{path}: unknown publish shape in [workspace.package]: {ws_pkg['publish']!r}"
    )


def _resolve_publishable(path: str, data: dict[str, object]) -> bool:
    """Resolve whether package.publish permits publishing.

    Raises ValueError when publish has an unrecognised shape.
    """
    pkg = data.get("package")
    if not isinstance(pkg, dict) or "publish" not in pkg:
        return True
    raw = pkg["publish"]
    lit = _is_publish_literal(raw)
    if lit is not None:
        return lit
    return _resolve_workspace_publish(path, data, raw)


def check_manifest(path: str, text: str) -> tuple[str, str]:
    """Classify a Cargo.toml manifest into (status, message).

    Status is 'pass', 'fail', or 'error'.
    """
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return "error", f"ERROR: {path}: invalid TOML: {exc}"

    if "/" not in path:
        return "pass", ""
    if not isinstance(data.get("package"), dict):
        return "pass", ""

    try:
        is_pub = _resolve_publishable(path, data)
    except ValueError as exc:
        return "error", f"ERROR: {exc}"

    if not isinstance(data.get("workspace"), dict):
        return "pass", ""
    if is_pub:
        return "pass", ""
    if FIXTURES_RE.search(path):
        return "pass", ""

    parent_dir = Path(path).parent.parent
    prefix = f"{parent_dir}/" if str(parent_dir) not in ("", ".") else ""
    msg = (
        f"FAIL: {path}: planted crate (publish = false, own [workspace]) "
        f"outside a fixtures/ directory; move it under {prefix}fixtures/"
    )
    return "fail", msg


def tracked_cargo_manifests(root: Path) -> list[str]:
    """Return tracked Cargo.toml files in root via git ls-files."""
    try:
        proc = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
            ["git", "ls-files", "-z", "--", "Cargo.toml", "*/Cargo.toml"],
            cwd=root,
            capture_output=True,
            encoding="utf-8",
            timeout=GIT_TIMEOUT_SECONDS,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError, ValueError) as exc:
        raise RuntimeError(f"git ls-files failed: {exc}") from exc
    if proc.returncode != 0:
        err = proc.stderr.strip()
        raise RuntimeError(f"git ls-files failed with code {proc.returncode}: {err}")
    files = [f for f in proc.stdout.split("\0") if f]
    if len(files) > MAX_FILES:
        raise RuntimeError(
            f"too many manifests: {len(files)} exceeds limit of {MAX_FILES}"
        )
    return files


def _read_and_check(root: Path, rel_path: str) -> tuple[bool, str, str]:
    """Read a manifest from disk and check it.

    Returns (was_read, status, msg).
    """
    file_path = root / rel_path
    if not file_path.is_file():
        return False, "pass", ""
    try:
        st = file_path.stat()
        if st.st_size > MAX_BYTES:
            err = f"ERROR: {rel_path}: file size {st.st_size} exceeds limit of {MAX_BYTES} bytes"
            return False, "error", err
        text = file_path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return False, "error", f"ERROR: {rel_path}: non-UTF-8 content: {exc}"
    except OSError as exc:
        return False, "error", f"ERROR: {rel_path}: {exc}"

    status, msg = check_manifest(rel_path, text)
    return True, status, msg


def scan(root: Path) -> tuple[int, str]:
    """Scan tracked Cargo.toml manifests under root, returning (exit_code, output)."""
    try:
        files = tracked_cargo_manifests(root)
    except RuntimeError as exc:
        return 2, f"ERROR: {root}: {exc}"

    manifests_read = 0
    findings: list[str] = []
    errors: list[str] = []

    for rel_path in files:
        was_read, status, msg = _read_and_check(root, rel_path)
        if was_read:
            manifests_read += 1
        if status == "error":
            errors.append(msg)
        elif status == "fail":
            findings.append(msg)

    if errors:
        return 2, "\n".join(errors)
    if findings:
        return 1, "\n".join(findings)
    return (
        0,
        f"PASS: every planted crate sits under a fixtures/ directory ({manifests_read} manifests read).",
    )


def run_scan(root: Path) -> int:
    """Scan root, print the PASS line on stdout or the findings on stderr."""
    status, output = scan(root)
    print(output, file=sys.stdout if status == 0 else sys.stderr)
    return status


def _run_git(argv: list[str], cwd: Path) -> None:
    """Run a git command with timeout and error checking."""
    proc = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
        argv,
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=False,
    )
    if proc.returncode != 0:
        err = proc.stderr.strip()
        raise RuntimeError(f"git command failed ({' '.join(argv)}): {err}")


def _run_single_scan_case(
    scratch: Path,
    case_name: str,
    files: list[tuple[str, str, bool]],
    exp_status: int,
    exp_sub: str,
) -> tuple[int, int]:
    """Run a single scan case in an isolated git repo under scratch."""
    repo = scratch / case_name
    repo.mkdir(parents=True, exist_ok=True)
    _run_git(["git", "-c", "init.defaultBranch=main", "init", "-q"], cwd=repo)
    for rel, content, tracked in files:
        fpath = repo / rel
        fpath.parent.mkdir(parents=True, exist_ok=True)
        fpath.write_text(content, encoding="utf-8")
        if tracked:
            _run_git(["git", "add", rel], cwd=repo)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        status = run_scan(repo)
    # The PASS line belongs on stdout, every FAIL or ERROR line on stderr.
    output = out.getvalue() if exp_status == 0 else err.getvalue()
    mismatch = status != exp_status or exp_sub not in output
    if mismatch:
        print(
            f"FAIL: {case_name}: expected status {exp_status} containing {exp_sub!r}, "
            f"got {status}: {output!r}",
            file=sys.stderr,
        )
        return 0, 1
    return 1, 0


def _run_scan_cases(scratch: Path) -> tuple[int, int]:
    """Run all scratch repository scan cases."""
    passed = 0
    failed = 0
    for idx, (label, files, exp_status, exp_sub) in enumerate(SCAN_CASES):
        case_name = f"case_{idx}"
        p, f = _run_single_scan_case(scratch, case_name, files, exp_status, exp_sub)
        passed += p
        failed += f
        if f > 0:
            print(f"FAIL: {label}", file=sys.stderr)
    return passed, failed


def selftest() -> int:
    """Run memory classifier cases and scratch repository scan cases."""
    failures = 0
    total = 0

    for label, path, toml_text, exp_status in MEMORY_CASES:
        status, msg = check_manifest(path, toml_text)
        total += 1
        if status != exp_status:
            print(
                f"FAIL: {label}: expected {exp_status}, got {status} ({msg})",
                file=sys.stderr,
            )
            failures += 1

    try:
        with tempfile.TemporaryDirectory() as td:
            passed_scans, failed_scans = _run_scan_cases(Path(td))
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f"ERROR: selftest scratch repository: {exc}", file=sys.stderr)
        return 2
    total += passed_scans + failed_scans
    failures += failed_scans

    if failures > 0:
        return 1
    print(f"PASS: {total} selftest cases.")
    return 0


def main() -> int:
    """Parse CLI arguments and run selftest or repo scan."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--selftest",
        action="store_true",
        help="run in-memory and scratch repo selftests",
    )
    default_root = Path(__file__).resolve().parent.parent
    parser.add_argument(
        "--root",
        type=Path,
        default=default_root,
        help="repository root to scan (default: parent of tools/)",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    return run_scan(args.root)


if __name__ == "__main__":
    sys.exit(main())
