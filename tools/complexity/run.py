#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Build and atomically publish a hash-locked lizard environment, then run the check."""

from __future__ import annotations

import contextlib
import hashlib
import io
import os
import shutil
import subprocess  # nosec B404  # Runs fixed Python argv lists without a shell and with deadlines.
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOCK = ROOT / "tools/complexity/requirements.txt"
CACHE = ROOT / ".cache/lizard-venv"
VENV_TIMEOUT_SECONDS = 300
PIP_TIMEOUT_SECONDS = 600
CHECK_TIMEOUT_SECONDS = 600


def venv_key(lock: bytes, implementation: str, version: tuple[int, int]) -> str:
    """Key the environment by lock content, Python implementation and major/minor version."""
    return hashlib.sha256(lock + f"\0{implementation}\0{version[0]}.{version[1]}".encode()).hexdigest()[:16]


def interpreter(venv: Path, windows: bool) -> Path:
    """Locate the environment's Python interpreter on the requested platform."""
    return venv / "Scripts/python.exe" if windows else venv / "bin/python"


def publish(scratch: Path, target: Path) -> None:
    """Publish a completed environment or discard it when another builder won."""
    try:
        os.rename(scratch, target)
    except OSError:
        if not target.is_dir():
            raise
        shutil.rmtree(scratch)


def build(cache: Path, lock: Path) -> Path:
    """Reuse a completed key or build privately before making it visible atomically."""
    target = cache / venv_key(lock.read_bytes(), sys.implementation.name, sys.version_info[:2])
    if target.is_dir():
        return target
    cache.mkdir(parents=True, exist_ok=True)
    scratch = Path(tempfile.mkdtemp(prefix="build-", dir=cache))
    try:
        subprocess.run(  # nosec B603  # Uses the current Python with fixed venv arguments and no shell.
            [sys.executable, "-m", "venv", str(scratch)], timeout=VENV_TIMEOUT_SECONDS, check=True,
        )
        subprocess.run(  # nosec B603  # Uses private Python with hash-locked requirements and no shell.
            [str(interpreter(scratch, os.name == "nt")), "-m", "pip", "install", "--quiet",
             "--disable-pip-version-check", "--require-hashes", "--no-deps", "-r", str(lock)],
            timeout=PIP_TIMEOUT_SECONDS, check=True,
        )
        publish(scratch, target)
    finally:
        if scratch.exists():
            shutil.rmtree(scratch)
    return target


def key_selftest() -> bool:
    """Check stable keys, lock and interpreter invalidation, and hexadecimal shape."""
    key = venv_key(b"lock", "cpython", (3, 12))
    return (
        key == venv_key(b"lock", "cpython", (3, 12))
        and key != venv_key(b"changed", "cpython", (3, 12))
        and key != venv_key(b"lock", "cpython", (3, 13))
        and key != venv_key(b"lock", "pypy", (3, 12))
        and len(key) == 16 and all(char in "0123456789abcdef" for char in key[:16])
    )


def interpreter_selftest() -> bool:
    """Check both platform layouts without invoking their interpreters."""
    root = Path("venv")
    return interpreter(root, False) == root / "bin/python" and interpreter(root, True) == root / "Scripts/python.exe"


def publish_selftest(existing: bool) -> bool:
    """Check publication and collision handling with distinct marker contents."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scratch, target = root / "scratch", root / "target"
        scratch.mkdir()
        (scratch / "marker").write_bytes(b"new")
        if existing:
            target.mkdir()
            (target / "marker").write_bytes(b"existing")
        publish(scratch, target)
        return not scratch.exists() and (target / "marker").read_bytes() == (b"existing" if existing else b"new")


def publish_failure_selftest() -> bool:
    """Refuse a rename failure when no completed target exists."""
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        scratch = root / "scratch"
        scratch.mkdir()
        try:
            publish(scratch, root / "missing/target")
        except OSError:
            return scratch.is_dir()
        return False


def cached_selftest() -> bool:
    """An existing key must avoid subprocesses and leave no build directories."""
    from unittest.mock import patch  # Selftest only; the gate path never loads unittest.

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        lock = root / "requirements.txt"
        lock.write_bytes(b"fixture lock")
        cache = root / "cache"
        target = cache / venv_key(lock.read_bytes(), sys.implementation.name, sys.version_info[:2])
        target.mkdir(parents=True)
        with patch("subprocess.run", side_effect=OSError("cached build invoked a subprocess")):
            result = build(cache, lock)
        return result == target and list(cache.iterdir()) == [target]


def failed_build_selftest(step: str) -> bool:
    """A failing venv or pip step must raise and leave nothing in the cache."""
    from unittest.mock import patch  # Selftest only; the gate path never loads unittest.

    def fake_run(argv: list[str], *, timeout: int, check: bool) -> subprocess.CompletedProcess:
        """Fail only `step`, honouring check=True like subprocess.run; timeout must be passed."""
        returncode = int(argv[2] == step)
        if check and returncode:
            raise subprocess.CalledProcessError(returncode, argv)
        return subprocess.CompletedProcess(argv, returncode)

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        lock = root / "requirements.txt"
        lock.write_bytes(b"fixture lock")
        cache = root / "cache"
        try:
            with patch("subprocess.run", side_effect=fake_run):
                build(cache, lock)
        except subprocess.CalledProcessError:
            return list(cache.iterdir()) == []
        return False


def passthrough_selftest() -> bool:
    """`check` forwards its arguments and exit status; build failures and timeouts exit 2."""
    from unittest.mock import patch  # Selftest only; the gate path never loads unittest.

    checker = [str(interpreter(Path("venv"), os.name == "nt")), "-I", "-B", str(ROOT / "tools/check_complexity.py")]
    with contextlib.redirect_stderr(io.StringIO()), patch(f"{__name__}.build", return_value=Path("venv")):
        with patch("subprocess.run", return_value=subprocess.CompletedProcess([], 7)) as run:
            status = main(["check", "--selftest"])
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("check", 1)):
            timed_out = main(["check"])
        with patch(f"{__name__}.build", side_effect=OSError("no venv module")):
            unbuilt = main(["check"])
        usage = main([])
    return status == 7 and run.call_args.args[0] == [*checker, "--selftest"] and [timed_out, unbuilt, usage] == [2, 2, 2]


def selftest() -> int:
    """Run bounded cache tests, including collisions and unsuccessful publication."""
    cases = (
        ("venv key stability, invalidation and hexadecimal shape", key_selftest),
        ("interpreter paths on POSIX and Windows", interpreter_selftest),
        ("publish absent target", lambda: publish_selftest(False)),
        ("publish existing target preserves its marker", lambda: publish_selftest(True)),
        ("publish missing parent refuses", publish_failure_selftest),
        ("cached build starts no subprocess and leaves no scratch", cached_selftest),
        ("failed venv step raises and publishes nothing", lambda: failed_build_selftest("venv")),
        ("failed pip step raises and publishes nothing", lambda: failed_build_selftest("pip")),
        ("check forwards arguments and exit status, fails closed", passthrough_selftest),
    )
    failures = 0
    for label, case in cases[:9]:
        try:
            passed = case()
        except (OSError, subprocess.SubprocessError) as error:
            print(f"FAIL: {label}: {error}")
            failures += 1
        else:
            print(f"{'PASS' if passed else 'FAIL'}: {label}")
            failures += int(not passed)
    return int(failures != 0)


def main(argv: list[str]) -> int:
    """Dispatch cache selftests or the isolated checker with a bounded deadline."""
    if argv == ["selftest"]:
        return selftest()
    if not argv or argv[0] != "check":
        print("usage: run.py selftest | check [ARGS...]", file=sys.stderr)
        return 2
    try:
        venv = build(CACHE, LOCK)
    except (OSError, subprocess.SubprocessError) as error:
        print(f"ERROR: cannot build the lizard venv in {CACHE} (Debian and Ubuntu need python3-venv): {error}", file=sys.stderr)
        return 2
    try:
        result = subprocess.run(  # nosec B603  # Uses keyed Python with a fixed checker path and no shell.
            [str(interpreter(venv, os.name == "nt")), "-I", "-B", str(ROOT / "tools/check_complexity.py"), *argv[1:]],
            timeout=CHECK_TIMEOUT_SECONDS, check=False,
        )
    except subprocess.TimeoutExpired as error:
        print(f"ERROR: complexity check timed out: {error}", file=sys.stderr)
        return 2
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
