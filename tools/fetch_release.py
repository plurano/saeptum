#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Fetch one pinned GitHub release asset and verify its pinned sha256 digest.

Routes tried in order:
    1. release download route (curl against github.com releases/download)
    2. API asset route (gh release download)

Why:
    GitHub release download routes experience intermittent HTTP 504 gateway
    timeouts, while the API asset route remains available as a fallback.

Exit codes:
    0 = fetched and verified
    1 = every route failed or digest mismatch
    2 = bad arguments
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import re
import subprocess  # nosec B404  # runs only curl and gh, fixed argv list, never a shell
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

REPO_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$")
TAG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
ASSET_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.+-]*$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

CHUNK_SIZE = 64 * 1024
Runner = Callable[[list[str], int], int]
ArgvBuilder = Callable[[str, str, str, str], list[str]]


def default_runner(argv: list[str], timeout: int) -> int:
    """Execute command with timeout, returning returncode."""
    proc = subprocess.run(  # nosec B603  # fixed curl or gh argv, no shell, found on PATH
        argv,
        check=False,
        timeout=timeout,
    )
    return proc.returncode


def _web_route_argv(repo: str, tag: str, asset: str, out: str) -> list[str]:
    """Build argv list for curl release download route."""
    return [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-time",
        "120",
        "--retry",
        "3",
        "--retry-max-time",
        "300",
        "--output",
        out,
        f"https://github.com/{repo}/releases/download/{tag}/{asset}",
    ]


def _api_route_argv(repo: str, tag: str, asset: str, out: str) -> list[str]:
    """Build argv list for gh API asset route."""
    return [
        "gh",
        "release",
        "download",
        tag,
        "--repo",
        repo,
        "--pattern",
        asset,
        "--output",
        out,
        "--clobber",
    ]


ROUTES: tuple[tuple[str, int, ArgvBuilder], ...] = (
    ("release download route", 600, _web_route_argv),
    ("API asset route (gh release download)", 300, _api_route_argv),
)


def compute_sha256(path: Path) -> str:
    """Calculate sha256 hex digest of file, bounded by file size."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise RuntimeError(f"cannot stat {path}: {exc}") from exc
    max_chunks = (size // CHUNK_SIZE) + 1
    hasher = hashlib.sha256()
    try:
        with path.open("rb") as f:
            for _ in range(max_chunks):
                chunk = f.read(CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError as exc:
        raise RuntimeError(f"cannot read {path}: {exc}") from exc
    return hasher.hexdigest()


def validate_arguments(repo: str, tag: str, asset: str, sha256: str) -> tuple[int, str]:
    """Validate arguments against allow-lists; return (rc, error_message)."""
    if not REPO_RE.match(repo):
        return 2, f"error: invalid --repo: {repo}"
    if not TAG_RE.match(tag):
        return 2, f"error: invalid --tag: {tag}"
    if not ASSET_RE.match(asset):
        return 2, f"error: invalid --asset: {asset}"
    if not SHA256_RE.match(sha256):
        return 2, f"error: invalid --sha256: {sha256}"
    return 0, ""


def _execute_route(
    runner: Runner, argv: list[str], timeout: int, out_path: Path
) -> tuple[bool, str]:
    """Execute route runner, returning (failed, failure_reason)."""
    try:
        rc = runner(argv, timeout)
    except subprocess.TimeoutExpired:
        return True, "timeout"
    except OSError as exc:
        return True, str(exc)

    if rc != 0:
        return True, f"rc {rc}"
    if not out_path.is_file():
        return True, "file absent"
    return False, ""


def fetch_release(
    repo: str,
    tag: str,
    asset: str,
    pinned_sha256: str,
    out: Path,
    runner: Runner = default_runner,
) -> int:
    """Fetch one pinned release asset and verify its digest."""
    rc, err_msg = validate_arguments(repo, tag, asset, pinned_sha256)
    if rc != 0:
        sys.stderr.write(f"{err_msg}\n")
        return rc

    try:
        out.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        sys.stderr.write(f"error: cannot create output directory {out.parent}: {exc}\n")
        return 1
    for route_idx, (route_name, timeout, build) in enumerate(ROUTES):
        out.unlink(missing_ok=True)
        argv = build(repo, tag, asset, str(out))
        failed, reason = _execute_route(runner, argv, timeout, out)
        if failed:
            out.unlink(missing_ok=True)
            if route_idx + 1 < len(ROUTES):
                next_route = ROUTES[route_idx + 1][0]
                sys.stdout.write(
                    f"::warning::{asset}: {route_name} failed ({reason}); "
                    f"trying {next_route}\n"
                )
                continue
            sys.stderr.write(f"error: {asset}: every route failed\n")
            return 1

        got_sha256 = compute_sha256(out)
        if got_sha256 != pinned_sha256:
            out.unlink(missing_ok=True)
            sys.stderr.write(
                f"error: {asset} sha256 {got_sha256} differs from "
                f"pinned {pinned_sha256} ({route_name})\n"
            )
            return 1

        sys.stdout.write(f"fetched {asset} via {route_name}, sha256 verified\n")
        return 0

    return 1


class FakeStep:
    """Scripted action for a single runner invocation."""

    def __init__(
        self,
        rc: int = 0,
        write_bytes: bytes | None = None,
        exc: Exception | None = None,
    ) -> None:
        self.rc = rc
        self.write_bytes = write_bytes
        self.exc = exc


class ScriptedRunner:
    """Runner mock that returns scripted steps and records invocations."""

    def __init__(self, steps: list[FakeStep]) -> None:
        self.steps = steps
        self.calls: list[tuple[list[str], int]] = []

    def __call__(self, argv: list[str], timeout: int) -> int:
        idx = len(self.calls)
        self.calls.append((argv, timeout))
        if idx >= len(self.steps):
            raise RuntimeError(f"unexpected runner call {idx}")
        step = self.steps[idx]
        if step.exc is not None:
            raise step.exc
        if step.write_bytes is not None:
            out_idx = argv.index("--output")
            out_path = Path(argv[out_idx + 1])
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_bytes(step.write_bytes)
        return step.rc


class SelftestCase:
    """Test case configuration for selftest."""

    def __init__(
        self,
        name: str,
        steps: list[FakeStep],
        expected_rc: int,
        expected_calls: int,
        expected_out_exists: bool,
        repo: str = "owner/repo",
        tag: str = "v1.0.0",
        asset: str = "asset-1.0.0.tar.gz",
        sha256: str = "",
        check_warning: bool = False,
        check_argv: bool = False,
    ) -> None:
        self.name = name
        self.steps = steps
        self.expected_rc = expected_rc
        self.expected_calls = expected_calls
        self.expected_out_exists = expected_out_exists
        self.repo = repo
        self.tag = tag
        self.asset = asset
        self.sha256 = sha256 or _VALID_SHA256
        self.check_warning = check_warning
        self.check_argv = check_argv


_VALID_BYTES = b"sample valid archive content"
_VALID_SHA256 = hashlib.sha256(_VALID_BYTES).hexdigest()

SELFTEST_CASES: tuple[SelftestCase, ...] = (
    SelftestCase(
        "web route ok, right bytes",
        [FakeStep(0, write_bytes=_VALID_BYTES)],
        expected_rc=0,
        expected_calls=1,
        expected_out_exists=True,
    ),
    SelftestCase(
        "web route rc 22, gh ok right bytes",
        [FakeStep(22), FakeStep(0, write_bytes=_VALID_BYTES)],
        expected_rc=0,
        expected_calls=2,
        expected_out_exists=True,
        check_warning=True,
    ),
    SelftestCase(
        "web route timeout, gh ok",
        [
            FakeStep(exc=subprocess.TimeoutExpired(["curl"], 600)),
            FakeStep(0, write_bytes=_VALID_BYTES),
        ],
        expected_rc=0,
        expected_calls=2,
        expected_out_exists=True,
    ),
    SelftestCase(
        "web route OSError (curl missing), gh ok",
        [
            FakeStep(exc=OSError("curl: command not found")),
            FakeStep(0, write_bytes=_VALID_BYTES),
        ],
        expected_rc=0,
        expected_calls=2,
        expected_out_exists=True,
    ),
    SelftestCase(
        "web route rc 0 but writes nothing, gh ok",
        [FakeStep(0), FakeStep(0, write_bytes=_VALID_BYTES)],
        expected_rc=0,
        expected_calls=2,
        expected_out_exists=True,
    ),
    SelftestCase(
        "web route rc 22 after writing partial bytes, gh rc 1",
        [FakeStep(22, write_bytes=b"partial"), FakeStep(1)],
        expected_rc=1,
        expected_calls=2,
        expected_out_exists=False,
    ),
    SelftestCase(
        "web route rc 22, gh rc 1 after writing partial bytes",
        [FakeStep(22), FakeStep(1, write_bytes=b"partial")],
        expected_rc=1,
        expected_calls=2,
        expected_out_exists=False,
    ),
    SelftestCase(
        "web route ok wrong bytes",
        [FakeStep(0, write_bytes=b"wrong content")],
        expected_rc=1,
        expected_calls=1,
        expected_out_exists=False,
    ),
    SelftestCase(
        "web route rc 22, gh ok wrong bytes",
        [FakeStep(22), FakeStep(0, write_bytes=b"wrong content")],
        expected_rc=1,
        expected_calls=2,
        expected_out_exists=False,
    ),
    SelftestCase(
        "argv matches expected route-1 and route-2 lists",
        [FakeStep(22), FakeStep(0, write_bytes=_VALID_BYTES)],
        expected_rc=0,
        expected_calls=2,
        expected_out_exists=True,
        check_argv=True,
    ),
    SelftestCase(
        "bad argument sha256 63 hex",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        sha256="a" * 63,
    ),
    SelftestCase(
        "bad argument sha256 uppercase",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        sha256=_VALID_SHA256.upper(),
    ),
    SelftestCase(
        "bad argument repo owner",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        repo="owner",
    ),
    SelftestCase(
        "bad argument repo ../x",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        repo="../x",
    ),
    SelftestCase(
        "bad argument repo owner/name/extra",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        repo="owner/name/extra",
    ),
    SelftestCase(
        "bad argument tag -v1",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        tag="-v1",
    ),
    SelftestCase(
        "bad argument asset a b",
        [],
        expected_rc=2,
        expected_calls=0,
        expected_out_exists=False,
        asset="a b",
    ),
)


def _check_argv_match(
    case: SelftestCase, runner: ScriptedRunner, case_out: Path
) -> bool:
    """Assert argv and timeouts for route 1 and route 2."""
    exp_argv_1 = [
        "curl",
        "--fail",
        "--silent",
        "--show-error",
        "--location",
        "--max-time",
        "120",
        "--retry",
        "3",
        "--retry-max-time",
        "300",
        "--output",
        str(case_out),
        f"https://github.com/{case.repo}/releases/download/{case.tag}/{case.asset}",
    ]
    exp_argv_2 = [
        "gh",
        "release",
        "download",
        case.tag,
        "--repo",
        case.repo,
        "--pattern",
        case.asset,
        "--output",
        str(case_out),
        "--clobber",
    ]
    if runner.calls[0] != (exp_argv_1, 600):
        return False
    return runner.calls[1] == (exp_argv_2, 300)


def _run_single_case(case: SelftestCase, case_out: Path) -> bool:
    """Run one selftest case and return True if all assertions hold."""
    runner = ScriptedRunner(case.steps)
    buf_out = io.StringIO()
    buf_err = io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        rc = fetch_release(
            repo=case.repo,
            tag=case.tag,
            asset=case.asset,
            pinned_sha256=case.sha256,
            out=case_out,
            runner=runner,
        )

    if rc != case.expected_rc:
        return False
    if len(runner.calls) != case.expected_calls:
        return False
    if case_out.exists() != case.expected_out_exists:
        return False
    if case.check_warning:
        out_txt = buf_out.getvalue()
        if "::warning::" not in out_txt or "trying API asset route" not in out_txt:
            return False
    if case.check_argv:
        return _check_argv_match(case, runner, case_out)
    return True


def selftest() -> int:
    """Run in-memory selftest suite across all test cases."""
    failures = 0
    with tempfile.TemporaryDirectory() as tmp_str:
        tmpdir = Path(tmp_str)
        for idx, case in enumerate(SELFTEST_CASES):
            case_out = tmpdir / f"case_{idx}" / case.asset
            if not _run_single_case(case, case_out):
                print(f"FAIL: {case.name}")
                failures += 1

    if failures > 0:
        return 1
    print(f"PASS: release fetch selftest ({len(SELFTEST_CASES)} cases)")
    return 0


def main(argv: list[str] | None = None) -> int:
    """Parse CLI arguments and fetch asset or run selftest."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run in-memory selftest suite"
    )
    parser.add_argument("--repo", help="repository in OWNER/NAME format")
    parser.add_argument("--tag", help="release tag")
    parser.add_argument("--asset", help="release asset file name")
    parser.add_argument("--sha256", help="expected 64-char hex sha256 digest")
    parser.add_argument("--out", help="destination file path")

    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()

    if not all((args.repo, args.tag, args.asset, args.sha256, args.out)):
        sys.stderr.write(
            "error: --repo, --tag, --asset, --sha256, and --out are all required\n"
        )
        return 2

    return fetch_release(
        repo=args.repo,
        tag=args.tag,
        asset=args.asset,
        pinned_sha256=args.sha256,
        out=Path(args.out),
        runner=default_runner,
    )


if __name__ == "__main__":
    sys.exit(main())
