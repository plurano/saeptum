#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Determine package scope and breaking status for cargo-semver-checks.

Inspects cargo workspace metadata to select library crates, excluding
crates marked with `[package.metadata.saeptum] public-api = false`.

Evaluates git commit subjects or PR title for breaking change markers:
`^[a-z]+(\\([^)]*\\))?!:`.

Validates inputs against strict formats: baseline revisions are validated and
resolved to concrete commit IDs before any command execution, package names
are verified against Cargo package naming rules, and target triples are validated
before execution.
"""

from __future__ import annotations

import argparse
import itertools
import json
import re
import subprocess  # nosec B404  # runs only git and cargo, fixed argv list, never a shell
import sys

BREAKING_PATTERN = re.compile(r"^[a-z]+(\([^)]*\))?!:")

# A branch, tag, remote ref or abbreviated or full commit id: no leading `-`
# (never read as an option), no `..` (never a range), no shell metacharacter.
REVISION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,199}")
# What `git rev-parse` prints for a commit: SHA-1 or SHA-256 hex.
COMMIT_ID_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
# Cargo's package-name grammar, ASCII subset, crates.io length cap.
PACKAGE_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_-]{0,63}")
# A rustc target triple; no leading '-', no shell metacharacter.
TARGET_PATTERN = re.compile(r"[a-z0-9_]+(-[a-z0-9_.]+){1,3}")


def _run_git(args: list[str], timeout: int) -> str:
    """`git` with `args`: no shell, deadline `timeout`; stdout, or CalledProcessError."""
    done = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
        ["git", *args],
        shell=False,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )
    return done.stdout


def _run_cargo(
    args: list[str], timeout: int, capture: bool
) -> subprocess.CompletedProcess[str]:
    """`cargo` with `args`: no shell, deadline `timeout`; the exit code is the caller's to judge."""
    return subprocess.run(  # nosec B603 B607  # fixed cargo argv, no shell, cargo found on PATH
        ["cargo", *args],
        shell=False,
        capture_output=capture,
        text=True,
        timeout=timeout,
        check=False,
    )


def _program_name(cmd: object) -> str:
    """Extract program name from a command list, tuple, or string."""
    if isinstance(cmd, (list, tuple)):
        return str(cmd[0]) if cmd else "command"
    parts = str(cmd).split()
    return parts[0] if parts else "command"


def describe_failure(exc: BaseException) -> str:
    """The `FAIL:` text for a failed command, a missed deadline or a refusal."""
    if isinstance(exc, subprocess.CalledProcessError):
        cmd0 = _program_name(exc.cmd)
        detail = (exc.stderr or "").strip()
        return f"{cmd0} exited {exc.returncode}: {detail}"
    if isinstance(exc, subprocess.TimeoutExpired):
        cmd0 = _program_name(exc.cmd)
        return f"{cmd0} exceeded its {exc.timeout} s deadline"
    return str(exc)


def is_breaking(subject: str) -> bool:
    """Return True if subject follows the breaking commit convention."""
    return bool(BREAKING_PATTERN.match(subject))


def _opted_out(pkg: dict) -> bool:
    """Return True if package is opted out via public-api = false."""
    pkg_meta = pkg.get("metadata")
    if not isinstance(pkg_meta, dict):
        return False
    saeptum_meta = pkg_meta.get("saeptum")
    if not isinstance(saeptum_meta, dict) or "public-api" not in saeptum_meta:
        return False
    val = saeptum_meta["public-api"]
    if val is False:
        return True
    if val is True:
        return False
    name = pkg.get("name", "")
    raise ValueError(f"package {name!r}: invalid saeptum.public-api value {val!r}")


def select_packages(metadata: dict) -> list[str]:
    """Select workspace library packages, excluding those marked public-api = false."""
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

    selected: list[str] = []
    for pkg in pkgs:
        targets = pkg.get("targets", [])
        if not any("lib" in t.get("kind", []) for t in targets):
            continue
        if _opted_out(pkg):
            continue
        selected.append(pkg.get("name", ""))

    return sorted(selected)


def check_revision(raw: str) -> str:
    """Validate that raw is a safe git revision without options, ranges, or metacharacters."""
    if ".." in raw or not REVISION_PATTERN.fullmatch(raw):
        raise ValueError(
            f"baseline revision {raw!r} refused: malformed revision format"
        )
    return raw


def resolve_revision(raw: str, timeout: int = 60) -> str:
    """Resolve raw revision to a verified commit ID."""
    check_revision(raw)
    try:
        out = _run_git(
            [
                "rev-parse",
                "--verify",
                "--quiet",
                "--end-of-options",
                f"{raw}^{{commit}}",
            ],
            timeout=timeout,
        ).strip()
    except subprocess.CalledProcessError as exc:
        raise ValueError(
            f"baseline revision {raw!r} names no commit in this repository"
        ) from exc
    if not COMMIT_ID_PATTERN.fullmatch(out):
        raise ValueError(f"resolved revision {out!r} is not a valid commit id")
    return out


def get_commit_subjects(commit_id: str, timeout: int = 60) -> list[str]:
    """Retrieve commit subjects between commit_id and HEAD."""
    out = _run_git(
        ["log", "--format=%s", "--end-of-options", f"{commit_id}..HEAD"],
        timeout=timeout,
    )
    return [line.strip() for line in out.splitlines() if line.strip()]


def build_check_argv(
    commit_id: str,
    packages: list[str],
    subjects: list[str],
    target: str | None = None,
) -> tuple[list[str], str, str]:
    """Construct the cargo-semver-checks command and release-type rationale.

    Raises ValueError if packages is empty, commit_id is invalid, or any package name is invalid.
    Returns (argv, release_type, reason).
    """
    if not packages:
        raise ValueError("empty package selection: no library packages to check")
    if not COMMIT_ID_PATTERN.fullmatch(commit_id):
        raise ValueError(f"expected commit id, got {commit_id!r}")
    for pkg in packages:
        if not PACKAGE_PATTERN.fullmatch(pkg):
            raise ValueError(f"invalid package name {pkg!r}")
    if target is not None and (
        len(target) > 64 or not TARGET_PATTERN.fullmatch(target)
    ):
        raise ValueError(f"target {target!r} refused: not a target triple")

    breaking_subjects = [s for s in subjects if is_breaking(s)]
    is_major = len(breaking_subjects) > 0
    argv = [
        "cargo",
        "semver-checks",
        "check-release",
        "--baseline-rev",
        commit_id,
        "--color",
        "never",
    ]
    if target is not None:
        argv.extend(["--target", target])
    for pkg in packages:
        argv.extend(["--package", pkg])
    if is_major:
        argv.extend(["--release-type", "major"])
        reason = f"breaking change allowed by subject: {breaking_subjects[0]!r}"
        release_type = "major"
    else:
        reason = (
            "no breaking change indicator matching '^[a-z]+(\\([^)]*\\))?!:'"
            " in subjects"
        )
        release_type = "default"
    return argv, release_type, reason


def fetch_metadata(timeout: int = 120) -> dict:
    """Run cargo metadata and return the parsed JSON."""
    done = _run_cargo(
        ["metadata", "--format-version", "1", "--no-deps", "--locked"],
        timeout=timeout,
        capture=True,
    )
    done.check_returncode()
    return json.loads(done.stdout)


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
    target: str | None = None,
    timeout: int = 1800,
) -> int:
    """Run cargo-semver-checks across all selected packages."""
    try:
        commit_id = resolve_revision(baseline_rev)
        packages = select_packages(fetch_metadata(timeout=120))
        subjects = cli_subjects or get_commit_subjects(commit_id, timeout=60)
        argv, release_type, reason = build_check_argv(
            commit_id=commit_id,
            packages=packages,
            subjects=subjects,
            target=target,
        )
    except ValueError as exc:
        print(f"FAIL: {describe_failure(exc)}", file=sys.stderr)
        return 1

    print(f"argv: {argv}")
    # Flushed so the decision precedes cargo's output in a piped CI log.
    print(f"release-type: {release_type} ({reason})", flush=True)
    proc = _run_cargo(argv[1:], timeout=timeout, capture=False)
    return proc.returncode


def _package(
    name: str,
    kind: str,
    deps: list[tuple[str, str | None]] | None = None,
    metadata: dict | None = None,
) -> dict:
    """One package entry shaped like `cargo metadata` output."""
    pkg: dict = {
        "name": name,
        "id": name,
        "targets": [{"kind": [kind]}],
        "dependencies": [
            {"name": dep, "kind": dep_kind} for dep, dep_kind in (deps or [])
        ],
    }
    if metadata is not None:
        pkg["metadata"] = metadata
    return pkg


def _fixture(t_meta: dict | None = None) -> dict:
    """Lib A, lib B (dev-depends on T), lib T (dev-only user, metadata t_meta), bin C."""
    return {
        "workspace_members": ["A", "B", "T", "C"],
        "packages": [
            _package("A", "lib"),
            _package("B", "lib", [("A", None), ("T", "dev")]),
            _package("T", "lib", metadata=t_meta),
            _package("C", "bin"),
        ],
    }


def _selection_failures() -> list[str]:
    """Cases (a) and (b): the package selection and metadata opt-out rules."""
    failures = []
    cases = [
        (
            "(a) package with public-api = false excluded",
            _fixture({"saeptum": {"public-api": False}}),
            ["A", "B"],
        ),
        (
            "(b) same package with no metadata included (dev-only users, no opt-out)",
            _fixture(None),
            ["A", "B", "T"],
        ),
        (
            "(b) public-api = true allowed",
            _fixture({"saeptum": {"public-api": True}}),
            ["A", "B", "T"],
        ),
    ]
    for label, metadata, expected in cases:
        got = select_packages(metadata)
        if got != expected:
            failures.append(f"{label}: expected {expected}, got {got}")

    try:
        select_packages(_fixture({"saeptum": {"public-api": "no"}}))
        failures.append("(b) public-api = 'no' did not raise ValueError")
    except ValueError as exc:
        msg = str(exc)
        if "T" not in msg or "'no'" not in msg:
            failures.append(
                f"(b) ValueError did not name package 'T' and value 'no': {msg!r}"
            )

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


def _revision_failures() -> list[str]:
    """Case (e): check_revision refuses dangerous or malformed input."""
    failures = []
    refusals = [
        "--output=x",
        "-x",
        "a..b",
        "",
        "main;id",
        "$(id)",
        "a b",
        "x" * 201,
    ]
    for raw in refusals:
        try:
            check_revision(raw)
            failures.append(f"(e) check_revision accepted invalid revision {raw!r}")
        except ValueError:
            pass

    accepts = [
        "origin/main",
        "997a1b3",
        "v1.2.3",
        "a" * 40,
    ]
    for raw in accepts:
        try:
            got = check_revision(raw)
            if got != raw:
                failures.append(f"(e) check_revision({raw!r}) returned {got!r}")
        except ValueError as exc:
            failures.append(f"(e) check_revision refused valid revision {raw!r}: {exc}")
    return failures


def _package_name_failures() -> list[str]:
    """Case (f): package names validated against PACKAGE_PATTERN."""
    failures = []
    cid = "a" * 40
    refusals = [["--all"], ["a;b"], ["1abc"]]
    for pkgs in refusals:
        try:
            build_check_argv(cid, pkgs, [])
            failures.append(f"(f) build_check_argv accepted invalid packages {pkgs!r}")
        except ValueError:
            pass

    accepted = ["saeptum-capsule", "test_support"]
    try:
        build_check_argv(cid, accepted, [])
    except ValueError as exc:
        failures.append(
            f"(f) build_check_argv refused valid packages {accepted!r}: {exc}"
        )
    return failures


def _argv_failures() -> list[str]:
    """Case (g): argv and release-type generation and non-commit refusal."""
    failures = []
    cid = "a" * 40
    expected_argv = [
        "cargo",
        "semver-checks",
        "check-release",
        "--baseline-rev",
        cid,
        "--color",
        "never",
        "--package",
        "A",
        "--package",
        "B",
    ]
    argv, rel_type, _ = build_check_argv(cid, ["A", "B"], ["feat: x"])
    if argv != expected_argv or rel_type != "default":
        failures.append(
            f"(g) default argv/release-type mismatch: got {argv!r}, {rel_type!r}"
        )

    argv_major, rel_type_major, _ = build_check_argv(cid, ["A", "B"], ["feat!: x"])
    if argv_major[-2:] != ["--release-type", "major"] or rel_type_major != "major":
        failures.append(
            f"(g) major argv/release-type mismatch: got {argv_major!r}, {rel_type_major!r}"
        )

    try:
        build_check_argv("origin/main", ["A"], [])
        failures.append(
            "(g) build_check_argv accepted non-commit revision 'origin/main'"
        )
    except ValueError:
        pass
    return failures


def _failure_text_failures() -> list[str]:
    """Case (h): describe_failure provides contextual error messages."""
    failures = []
    cpe = subprocess.CalledProcessError(
        128, ["git", "rev-parse"], stderr="fatal: bad\n"
    )
    if describe_failure(cpe) != "git exited 128: fatal: bad":
        failures.append(
            f"(h) CalledProcessError text mismatch: got {describe_failure(cpe)!r}"
        )

    te = subprocess.TimeoutExpired(["cargo", "metadata"], 120)
    if describe_failure(te) != "cargo exceeded its 120 s deadline":
        failures.append(
            f"(h) TimeoutExpired text mismatch: got {describe_failure(te)!r}"
        )

    ve = ValueError("x")
    if describe_failure(ve) != "x":
        failures.append(f"(h) ValueError text mismatch: got {describe_failure(ve)!r}")
    return failures


def _unknown_revision_failures() -> list[str]:
    """Case (i): fail closed on an unknown revision."""
    try:
        resolve_revision("0" * 40)
    except ValueError as exc:
        if "names no commit" in str(exc):
            return []
        return [
            f"(i) resolve_revision('0'*40) raised ValueError without 'names no commit': {exc}"
        ]
    except subprocess.CalledProcessError as exc:
        return [
            f"(i) resolve_revision('0'*40) raised CalledProcessError instead of ValueError: {exc}"
        ]
    return ["(i) resolve_revision('0'*40) succeeded unexpectedly"]


def _subcommand_failures() -> list[str]:
    """Case (j): selftest subcommand and check --subject=--selftest argument parsing."""
    failures = []
    args_check = _parse_args(["check", "--baseline-rev", "a", "--subject=--selftest"])
    if args_check.command != "check" or args_check.subject != ["--selftest"]:
        failures.append(
            f"(j) check subcommand mismatch: got command={args_check.command!r}, subject={args_check.subject!r}"
        )

    args_selftest = _parse_args(["selftest"])
    if args_selftest.command != "selftest":
        failures.append(
            f"(j) selftest subcommand mismatch: got command={args_selftest.command!r}"
        )
    return failures


_SELFTEST_TARGETS = ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
_SELFTEST_REFUSED_TARGETS = (
    "--x",
    "a;b",
    "",
    "x86_64",
    "X86_64-unknown-linux-gnu",
    "a-" + "b" * 70,
)


def _target_accepted_failure(cid: str, target: str) -> str | None:
    """Case (k) helper: check that valid target is accepted and placed in argv."""
    try:
        argv, _, _ = build_check_argv(cid, ["a"], [], target)
    except ValueError as exc:
        return f"(k) build_check_argv refused valid target {target!r}: {exc}"
    if ("--target", target) not in itertools.pairwise(argv):
        return f"(k) build_check_argv '--target' not followed by {target!r}"
    return None


def _target_failures() -> list[str]:
    """Case (k): target triple validation and argv generation."""
    failures = []
    cid = "a" * 40
    for target in _SELFTEST_TARGETS:
        fail = _target_accepted_failure(cid, target)
        if fail is not None:
            failures.append(fail)

    argv_none, _, _ = build_check_argv(cid, ["a"], [], None)
    if "--target" in argv_none:
        failures.append("(k) build_check_argv included '--target' when target is None")

    for bad_target in _SELFTEST_REFUSED_TARGETS:
        try:
            build_check_argv(cid, ["a"], [], bad_target)
            failures.append(
                f"(k) build_check_argv accepted invalid target {bad_target!r}"
            )
        except ValueError:
            pass
    return failures


def selftest() -> bool:
    """Run planted cases verifying package selection, subject logic, and refusal."""
    failures = (
        _selection_failures()
        + _subject_failures()
        + _refusal_failures()
        + _revision_failures()
        + _package_name_failures()
        + _argv_failures()
        + _failure_text_failures()
        + _unknown_revision_failures()
        + _subcommand_failures()
        + _target_failures()
    )
    for failure in failures:
        print(f"FAIL: {failure}", file=sys.stderr)
    if failures:
        return False
    print(
        "PASS: semver scope selection, subjects, refusal, input formats, argv, failure text and target verified."
    )
    return True


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """The command line: `packages`, `selftest`, or `check --baseline-rev REV [--subject TEXT]... [--target TRIPLE]`."""
    parser = argparse.ArgumentParser(
        description="Filter and check public Rust API semver scope."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("packages", help="List library packages in scope")
    subparsers.add_parser("selftest", help="Run self-tests")
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
    check_parser.add_argument(
        "--target",
        default=None,
        metavar="TRIPLE",
        help="rustc target triple to check platform-specific APIs for",
    )
    return parser.parse_args(argv)


def main() -> int:
    args = _parse_args()
    if args.command == "selftest":
        return 0 if selftest() else 1

    try:
        if args.command == "packages":
            return cmd_packages()
        return cmd_check(
            baseline_rev=args.baseline_rev,
            cli_subjects=args.subject,
            target=args.target,
        )
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        ValueError,
        OSError,
        json.JSONDecodeError,
    ) as exc:
        print(f"FAIL: {describe_failure(exc)}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
