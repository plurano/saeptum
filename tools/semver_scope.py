#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Determine package scope and breaking status for cargo-semver-checks.

Inspects the cargo workspace metadata to select published library crates while
excluding internal test plumbing crates (such as test-support) that other
workspace members only depend on as dev-dependencies.

Evaluates git commit subjects or PR title for breaking change markers:
`^[a-z]+(\\([^)]*\\))?!:`.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys

BREAKING_PATTERN = re.compile(r"^[a-z]+(\([^)]*\))?!:")


def is_breaking(subject: str) -> bool:
    """Return True if subject follows the breaking commit convention."""
    return bool(BREAKING_PATTERN.match(subject))


def select_packages(metadata: dict) -> list[str]:
    """Select workspace library packages, excluding dev-only test plumbing."""
    all_pkgs = metadata.get("packages", [])
    workspace_members = metadata.get("workspace_members")
    if workspace_members is not None:
        member_ids = set(workspace_members)
        pkgs = [
            p
            for p in all_pkgs
            if p.get("id") in member_ids or p.get("name") in member_ids
        ]
    else:
        pkgs = list(all_pkgs)

    lib_pkgs: list[dict] = []
    for pkg in pkgs:
        targets = pkg.get("targets", [])
        if any("lib" in t.get("kind", []) for t in targets):
            lib_pkgs.append(pkg)

    pkg_names = {p["name"] for p in lib_pkgs}
    dep_kinds: dict[str, list[str | None]] = {name: [] for name in pkg_names}
    for pkg in pkgs:
        for dep in pkg.get("dependencies", []):
            dep_name = dep.get("name")
            if dep_name in dep_kinds and dep_name != pkg.get("name"):
                dep_kinds[dep_name].append(dep.get("kind"))

    selected: list[str] = []
    for name in sorted(pkg_names):
        kinds = dep_kinds[name]
        if kinds and all(k == "dev" for k in kinds):
            continue
        selected.append(name)
    return selected


def build_check_argv(
    rev: str,
    packages: list[str],
    subjects: list[str],
) -> tuple[list[str], str, str]:
    """Construct the cargo-semver-checks command and release-type rationale.

    Raises ValueError if packages is empty.
    Returns (argv, release_type, reason).
    """
    if not packages:
        raise ValueError("empty package selection: no library packages to check")
    breaking_subjects = [s for s in subjects if is_breaking(s)]
    is_major = len(breaking_subjects) > 0
    argv = [
        "cargo",
        "semver-checks",
        "check-release",
        "--baseline-rev",
        rev,
        "--color",
        "never",
    ]
    for pkg in packages:
        argv.extend(["--package", pkg])
    if is_major:
        argv.extend(["--release-type", "major"])
        reason = f"breaking change allowed by subject: {breaking_subjects[0]!r}"
        release_type = "major"
    else:
        reason = "no breaking change indicator matching '^[a-z]+(\\([^)]*\\))?!:' in subjects"
        release_type = "default"
    return argv, release_type, reason


def fetch_metadata(timeout: int = 120) -> dict:
    """Run cargo metadata and return the parsed JSON."""
    cmd = ["cargo", "metadata", "--format-version", "1", "--no-deps", "--locked"]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return json.loads(res.stdout)


def get_commit_subjects(rev: str, timeout: int = 60) -> list[str]:
    """Retrieve commit subjects between rev and HEAD."""
    cmd = ["git", "log", "--format=%s", f"{rev}..HEAD"]
    res = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return [line.strip() for line in res.stdout.splitlines() if line.strip()]


def cmd_packages(timeout: int = 120) -> int:
    """List library packages in scope."""
    metadata = fetch_metadata(timeout=timeout)
    packages = select_packages(metadata)
    for name in packages:
        print(name)
    return 0


def cmd_check(
    baseline_rev: str,
    cli_subjects: list[str],
    timeout: int = 1800,
) -> int:
    """Run cargo-semver-checks across all selected packages."""
    packages = select_packages(fetch_metadata(timeout=120))
    subjects = cli_subjects or get_commit_subjects(baseline_rev, timeout=60)
    try:
        argv, release_type, reason = build_check_argv(
            rev=baseline_rev,
            packages=packages,
            subjects=subjects,
        )
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    print(f"argv: {argv}")
    # Flushed so the decision precedes cargo's output in a piped CI log.
    print(f"release-type: {release_type} ({reason})", flush=True)
    proc = subprocess.run(argv, timeout=timeout, check=False)
    return proc.returncode


def _package(name: str, kind: str, deps: list[tuple[str, str | None]]) -> dict:
    """One package entry shaped like `cargo metadata` output."""
    return {
        "name": name,
        "id": name,
        "targets": [{"kind": [kind]}],
        "dependencies": [{"name": dep, "kind": dep_kind} for dep, dep_kind in deps],
    }


def _fixture(t_kind_from_b: str | None) -> dict:
    """Lib A (normal dependency of B), lib B, lib T (dev dependency of A, and
    of B with `t_kind_from_b`), bin-only C."""
    return {
        "workspace_members": ["A", "B", "T", "C"],
        "packages": [
            _package("A", "lib", [("T", "dev")]),
            _package("B", "lib", [("A", None), ("T", t_kind_from_b)]),
            _package("T", "lib", []),
            _package("C", "bin", []),
        ],
    }


def _selection_failures() -> list[str]:
    """Cases (a) and (b): the package selection rule."""
    failures = []
    cases = [
        ("(a) T only a dev dependency", _fixture("dev"), ["A", "B"]),
        ("(b) T a normal dependency of B", _fixture(None), ["A", "B", "T"]),
    ]
    for label, metadata, expected in cases:
        got = select_packages(metadata)
        if got != expected:
            failures.append(f"{label}: expected {expected}, got {got}")
    return failures


def _subject_failures() -> list[str]:
    """Case (c): the breaking-subject rule."""
    cases = [
        ("feat(capsule)!: x", True),
        ("fix!: y", True),
        ("feat(capsule): x", False),
        ("docs: a!b", False),
        ("Feat!: x", False),
    ]
    return [
        f"(c) subject {subject!r}: expected breaking={expected}"
        for subject, expected in cases
        if is_breaking(subject) != expected
    ]


def _refusal_failures() -> list[str]:
    """Case (d): an empty selection is refused, never a silent pass."""
    try:
        build_check_argv("HEAD", [], ["feat!: breaking"])
    except ValueError:
        return []
    return ["(d) empty selection did not refuse"]


def selftest() -> bool:
    """Run planted cases verifying package selection, subject logic, and refusal."""
    failures = _selection_failures() + _subject_failures() + _refusal_failures()
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return False
    print(
        "PASS: semver scope package selection, subject classification, and refusal verified."
    )
    return True


def _parse_args() -> argparse.Namespace:
    """The command line: `packages`, or `check --baseline-rev REV [--subject TEXT]...`."""
    parser = argparse.ArgumentParser(
        description="Filter and check public Rust API semver scope."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("packages", help="List library packages in scope")
    check_parser = subparsers.add_parser("check", help="Run cargo semver-checks")
    check_parser.add_argument(
        "--baseline-rev",
        required=True,
        help="Git revision to compare public API against",
    )
    check_parser.add_argument(
        "--subject",
        action="append",
        default=[],
        help="Commit or PR subject line to evaluate for breaking change",
    )
    return parser.parse_args()


def main() -> int:
    if "--selftest" in sys.argv:
        return 0 if selftest() else 1

    args = _parse_args()
    try:
        if args.command == "packages":
            return cmd_packages()
        return cmd_check(baseline_rev=args.baseline_rev, cli_subjects=args.subject)
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        print(f"FAIL: {exc.cmd[0]} exited {exc.returncode}: {detail}", file=sys.stderr)
    except subprocess.TimeoutExpired as exc:
        print(
            f"FAIL: {exc.cmd[0]} exceeded its {exc.timeout} s deadline", file=sys.stderr
        )
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
