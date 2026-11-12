#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Check tracked Rust functions against the HISS-04 cyclomatic complexity cap.

Check:
    Analyse git-tracked crates/*.rs with the pinned lizard library. Every
    function must have cyclomatic complexity at most 10, including Rust's ?.
    Each source is read here, bounded and strict UTF-8, and handed to lizard
    as text, so lizard never drops bytes or swallows a read error.
    Git names use os.fsdecode; diagnostics escape non-UTF-8 filename bytes.
    Planted CLI cases cover listing, output streams and exit codes together.

Why:
    The existing audit measures function length, and Clippy measures cognitive
    complexity. Neither enforces the separate HISS-04 McCabe limit.

Exit codes:
    0 = all functions within the cap, or all planted selftest cases passed
    1 = a function exceeds the cap, or a selftest verdict was wrong
    2 = could not run: git failed, lizard version differs from its
        requirement pin, a source is missing, not .rs, larger than the byte
        bound or not UTF-8, lizard wrote a diagnostic, file/function bounds
        exceeded, empty file list, or no functions analysed
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import subprocess  # nosec B404  # runs only git, fixed argv list, never a shell
import sys
import tempfile
from collections.abc import Mapping
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
MAX_FILE_BYTES = 4 * 1024 * 1024
GIT_TIMEOUT_SECONDS = 60
PIN = re.compile(r"(?m)^lizard==([0-9]+(?:\.[0-9]+){2})$")
# Variables the scratch-repository selftest passes to git. Hooks export GIT_DIR,
# GIT_INDEX_FILE and the like (githooks(5)); inherited, they would point the
# scratch commands at the outer repository.
SCRATCH_ENV_KEYS = ("PATH", "SYSTEMROOT", "HOME", "TMPDIR")
ROOT = Path(__file__).resolve().parent.parent


class ScratchFilenameError(OSError):
    """A filesystem refused creation of a scratch fixture's filename."""


def version_problem(text: str, installed: str) -> str | None:
    """Name why `installed` does not match the exact lizard pin in `text`."""
    pin = PIN.search(text)
    if pin is None:
        return "missing exact lizard version pin"
    if installed != pin.group(1):
        return f"lizard version {installed!r} != pinned {pin.group(1)!r}"
    return None


def check_version(requirements: Path, installed: str) -> None:
    """Refuse an analyser version different from the direct requirement pin."""
    problem = version_problem(requirements.read_text(encoding="utf-8"), installed)
    if problem is not None:
        raise ValueError(f"{requirements}: {problem}")


def git(root: Path, *args: str, env: dict[str, str] | None) -> bytes:
    """Run git with a fixed argv, no shell and a deadline; return stdout bytes.

    `env` has no default, so no call can drop the scratch environment by omission;
    None inherits this process's variables.
    """
    result = subprocess.run(  # nosec B603 B607  # fixed git argv, no shell, git found on PATH
        ["git", *args],
        cwd=root,
        env=env,
        capture_output=True,
        timeout=GIT_TIMEOUT_SECONDS,
        check=True,
    )
    return result.stdout


def tracked_rust_files(root: Path, env: dict[str, str] | None = None, max_files: int = MAX_FILES) -> list[str]:
    """List tracked Rust sources under crates/ (git's * also matches /); refuse more than max_files."""
    names = git(root, "ls-files", "-z", "--", "crates/*.rs", env=env).split(b"\0")
    if names[-1] == b"":
        names.pop()
    if len(names) > max_files:
        raise ValueError(f"git listed {len(names)} Rust files, more than {max_files}")
    return [os.fsdecode(name) for name in names[:max_files]]


def printable(text: str) -> str:
    """Escape undecodable filename bytes while preserving valid UTF-8 text."""
    return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")


def read_source(path: Path, max_bytes: int) -> str:
    """Read at most `max_bytes` bytes of strict UTF-8, refusing anything longer."""
    with path.open("rb") as handle:
        data = handle.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise ValueError(f"more than {max_bytes} bytes")
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(f"not UTF-8: {error}") from error


def check_file(
    path: Path,
    name: str,
    *,
    max_functions: int = MAX_FUNCTIONS_PER_FILE,
    max_bytes: int = MAX_FILE_BYTES,
) -> tuple[int, list[str]]:
    """Analyse one source, refusing every lizard diagnostic and bound overrun."""
    if not name.endswith(".rs"):
        raise ValueError("not a .rs file; lizard would fall back to its C reader")
    text = read_source(path, max_bytes)
    diagnostics = io.StringIO()
    with contextlib.redirect_stderr(diagnostics):
        result = lizard.analyze_file.analyze_source_code(name, text)
    if diagnostics.getvalue():
        raise ValueError(f"lizard analysis failed: {diagnostics.getvalue().strip()}")
    functions = result.function_list
    if len(functions) > max_functions:
        raise ValueError(f"more than {max_functions} functions")
    findings = []
    for function in functions[:max_functions]:
        complexity = function.cyclomatic_complexity
        if complexity > CAP:
            findings.append(f"{name}:{function.start_line}: {function.name} CCN {complexity} > {CAP}")
    return len(functions), findings


def analyse_paths(
    root: Path,
    files: list[str],
    *,
    max_files: int = MAX_FILES,
    max_functions: int = MAX_FUNCTIONS_PER_FILE,
    max_bytes: int = MAX_FILE_BYTES,
) -> tuple[int, str]:
    """Apply the same bounded analysis to tracked sources and planted files."""
    if not files:
        return 2, "ERROR: empty Rust file list"
    if len(files) > max_files:
        return 2, f"ERROR: more than {max_files} Rust files"
    total = 0
    findings = []
    for name in files[:max_files]:
        try:
            count, messages = check_file(root / name, name, max_functions=max_functions, max_bytes=max_bytes)
        except (OSError, ValueError, RuntimeError, IndexError) as error:
            return 2, f"ERROR: {name}: {error}"
        total += count
        findings.extend(messages)
    if total == 0:
        return 2, "ERROR: zero functions analysed"
    if findings:
        return 1, "\n".join(findings)
    return 0, f"PASS: {total} functions in {len(files)} Rust files have CCN <= {CAP}."


def planted(ccn: int, name: str = "planted") -> bytes:
    """Rust function `name` with cyclomatic complexity `ccn`."""
    return (f"fn {name}() {{" + "if true {}" * (ccn - 1) + "}\n").encode("utf-8")


def gate(root: Path, env: dict[str, str] | None) -> int:
    """List tracked sources, analyse them and emit the full CLI verdict."""
    try:
        status, output = analyse_paths(root, tracked_rust_files(root, env=env))
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(printable(f"ERROR: complexity check could not run: {error}"), file=sys.stderr)
        return 2
    print(printable(output), file=sys.stdout if status == 0 else sys.stderr)
    return status


def cap_cases() -> tuple:
    """Cases for the cap itself: (label, files, listed names, bounds, exit, message)."""
    question_marks = b"fn planted() -> Result<(), ()> {" + b"step()?;" * 10 + b"Ok(())}\n"
    return (
        ("CCN 11 refused", {"planted.rs": planted(11)}, None, {}, 1, "planted CCN 11 > 10"),
        ("CCN 10 accepted", {"planted.rs": planted(10)}, None, {}, 0, "PASS: 1 functions in 1 Rust files"),
        ("question-mark CCN 11 refused", {"planted.rs": question_marks}, None, {}, 1, "CCN 11 > 10"),
        (
            "second function over cap refused",
            {"planted.rs": planted(1, "first") + planted(11, "second")},
            None,
            {},
            1,
            "second CCN 11 > 10",
        ),
        ("empty file list refused", {}, [], {}, 2, "empty Rust file list"),
        ("zero functions refused", {"planted.rs": b"// No functions here.\n"}, None, {}, 2, "zero functions analysed"),
    )


def bound_cases() -> tuple:
    """Cases for bounds and refused input; every refusal sits beside a valid file."""
    two = {"a.rs": planted(1, "a"), "b.rs": planted(1, "b")}
    three = {**two, "c.rs": planted(1, "c")}
    exact = planted(1).ljust(64)
    deep = ("fn deep() {" + "{" * 2000 + "}" * 2000 + "}\n").encode("utf-8")
    files_two = {"max_files": 2}
    functions_two = {"max_functions": 2}
    return (
        ("file bound accepted", two, None, files_two, 0, "PASS: 2 functions in 2 Rust files"),
        ("file bound refused", three, None, files_two, 2, "more than 2 Rust files"),
        ("function bound accepted", {"a.rs": two["a.rs"] + two["b.rs"]}, None, functions_two, 0, "PASS: 2 functions"),
        ("function bound refused", {"a.rs": b"".join(three.values())}, None, functions_two, 2, "more than 2 functions"),
        ("byte bound accepted", {"a.rs": exact}, None, {"max_bytes": 64}, 0, "PASS: 1 functions"),
        ("byte bound refused", {"a.rs": exact + b" "}, None, {"max_bytes": 64}, 2, "a.rs: more than 64 bytes"),
        ("non-UTF-8 refused", {**two, "c.rs": b"fn c() {}\n\xff\n"}, None, {}, 2, "c.rs: not UTF-8"),
        ("missing file refused", two, ["a.rs", "b.rs", "missing.rs"], {}, 2, "missing.rs"),
        ("lizard diagnostic refused", {**two, "deep.rs": deep}, None, {}, 2, "deep.rs: lizard analysis failed"),
        ("non-Rust name refused", {**two, "c.txt": planted(1, "c")}, None, {}, 2, "c.txt: not a .rs file"),
    )


def run_case(case: tuple) -> int:
    """Plant one case's files in a fresh directory; return 1 on a wrong verdict."""
    label, files, names, bounds, expected, message = case
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        for name, data in files.items():
            (root / name).write_bytes(data)
        status, output = analyse_paths(root, list(files) if names is None else names, **bounds)
    if status != expected or message not in output:
        print(f"FAIL: {label}: expected {expected} with {message!r}; got {status}: {output}")
        return 1
    print(f"PASS: {label}")
    return 0


def version_selftest() -> int:
    """Plant drifted, missing, prefixed and suffixed pins; the matching pin must pass."""
    cases = (
        ("matching pin accepted", "lizard==1.26.0\n", "1.26.0", None),
        ("drifted version refused", "lizard==1.26.0\n", "1.27.0", "!= pinned"),
        ("range pin refused", "lizard>=1.26.0\n", "1.26.0", "missing exact"),
        ("prefixed name refused", "xlizard==1.26.0\n", "1.26.0", "missing exact"),
        ("suffixed version refused", "lizard==1.26.0.post1\n", "1.26.0", "missing exact"),
    )
    failures = 0
    for label, text, installed, expected in cases:
        problem = version_problem(text, installed)
        if (problem is None) != (expected is None) or (expected and expected not in str(problem)):
            print(f"FAIL: {label}: expected {expected!r}; got {problem!r}")
            failures += 1
        else:
            print(f"PASS: {label}")
    return failures + check_version_selftest()


def check_version_selftest() -> int:
    """check_version must raise on a drifted pin file and accept the matching one."""
    with tempfile.TemporaryDirectory() as directory:
        requirements = Path(directory) / "requirements.in"
        requirements.write_text("lizard==1.26.0\n", encoding="utf-8")
        try:
            check_version(requirements, "1.27.0")
        except ValueError as error:
            drift = "!= pinned" in str(error) and "requirements.in" in str(error)
        else:
            drift = False
        check_version(requirements, "1.26.0")
    print(f"{'PASS' if drift else 'FAIL'}: check_version refuses a drifted pin file")
    return int(not drift)


def scratch_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Keep the scratch Git environment isolated from hook and user config."""
    env = {key: source[key] for key in SCRATCH_ENV_KEYS if key in source}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    env.update(GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="selftest.scratch", GIT_CONFIG_VALUE_0="yes")
    return env


def scratch_repository(
    root: Path, source: Mapping[str, str], files: dict[str, bytes], tracked: tuple[str, ...],
) -> dict[str, str]:
    """Write fixture files and track the requested names in an isolated repository."""
    env = scratch_environment(source)
    try:
        for name, data in list(files.items())[:MAX_FILES]:
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(data)
    except (OSError, UnicodeError) as error:
        raise ScratchFilenameError(str(error)) from error
    git(root, "init", "-q", env=env)
    git(root, "add", "--", *tracked, env=env)
    return env


def listing_refused(root: Path, env: dict[str, str], max_files: int) -> bool:
    """True when the tracked listing refuses a bound below the number of files."""
    try:
        tracked_rust_files(root, env=env, max_files=max_files)
    except ValueError:
        return True
    return False


def git_selftest(source: Mapping[str, str], label: str) -> int:
    """Check tracked Rust selection, its file bound and environment forwarding on every Git call."""
    tracked = ("crates/a/src/lib.rs", "crates/a/tests/t.rs", "crates/a/Cargo.toml", "x.rs")
    expected = ["crates/a/src/lib.rs", "crates/a/tests/t.rs"]
    files = {name: planted(1) for name in (*tracked, "crates/a/src/new.rs")}
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        env = scratch_repository(root, source, files, tracked)
        forwarded = git(root, "config", "--get", "selftest.scratch", env=env)
        listed = tracked_rust_files(root, env=env, max_files=2)
        refused = listing_refused(root, env, 1)
    if listed != expected or forwarded != b"yes\n" or not refused:
        print(
            f"FAIL: tracked crates/*.rs listing ({label}): expected {expected} at bound 2 and a refusal at 1; "
            f"got {listed}, refused {refused}, config {forwarded!r}"
        )
        return 1
    print(f"PASS: tracked crates/*.rs listing ({label})")
    return 0


def hook_selftest() -> int:
    """Hook-exported GIT_* variables and the user's global config must not reach the scratch repository.

    The decoy global config ignores *.rs, so reading it makes `git add` refuse.
    """
    with tempfile.TemporaryDirectory() as decoy:
        (Path(decoy) / "ignore").write_text("*.rs\n", encoding="utf-8")
        (Path(decoy) / ".gitconfig").write_text(f"[core]\n\texcludesFile = {decoy}/ignore\n", encoding="utf-8")
        hook = {
            **os.environ,
            "HOME": decoy,
            "GIT_DIR": os.path.join(decoy, ".git"),
            "GIT_WORK_TREE": decoy,
            "GIT_INDEX_FILE": os.path.join(decoy, "index"),
        }
        failures = git_selftest(hook, "hook environment")
        extra = sorted(entry.name for entry in list(Path(decoy).iterdir())[:MAX_FILES] if entry.name not in {"ignore", ".gitconfig"})
        if extra:
            print(f"FAIL: hook variables reached the scratch repository: {extra}")
            return 1
        print("PASS: hook variables left no scratch artifacts in the decoy")
        return int(failures != 0)


def cli_cases() -> tuple:
    """Cover cap boundaries, Git failure and undecodable filenames through gate()."""
    non_utf8 = os.fsdecode(b"crates/a/src/\xff.rs")
    return (
        ("CLI over cap", {"crates/a/src/lib.rs": planted(11), "crates/a/src/ok.rs": planted(1)}, 1,
         "crates/a/src/lib.rs:1: planted CCN 11 > 10"),
        ("CLI within cap", {"crates/a/src/lib.rs": planted(10)}, 0, "PASS: 1 functions in 1 Rust files"),
        ("CLI git failure", {}, 2, "complexity check could not run"),
        ("CLI non-UTF-8 path", {non_utf8: planted(11)}, 1, r"crates/a/src/\xff.rs:1: planted CCN 11 > 10"),
    )


def run_cli_case(case: tuple) -> int:
    """Capture the full gate's streams and check its exit mapping in a scratch directory."""
    label, files, expected, message = case
    stdout, stderr = io.StringIO(), io.StringIO()
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        if files:
            try:
                env = scratch_repository(root, os.environ, files, tuple(files))
            except ScratchFilenameError:
                if label != "CLI non-UTF-8 path":
                    raise
                print("SKIP: non-UTF-8 path case: this filesystem refuses non-UTF-8 file names")
                return 0
        else:
            env = scratch_environment(os.environ)
            env["GIT_CEILING_DIRECTORIES"] = str(root.parent)
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = gate(root, env)
    output = stdout.getvalue() if expected == 0 else stderr.getvalue()
    other = stderr.getvalue() if expected == 0 else stdout.getvalue()
    if status != expected or message not in output or other:
        print(printable(f"FAIL: {label}: expected {expected} with {message!r}; got {status}: {output}; other: {other}"))
        return 1
    print(f"PASS: {label}")
    return 0


def selftest() -> int:
    """Plant analysis and CLI cases; Git runs only in isolated scratch repositories."""
    failures = sum(run_case(case) for case in (*cap_cases(), *bound_cases()))
    failures += version_selftest() + git_selftest(os.environ, "clean environment") + hook_selftest()
    failures += sum(run_cli_case(case) for case in cli_cases()[:4])
    return int(failures != 0)


def main() -> int:
    """Validate the analyser pin, then run the requested bounded check."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="run planted cases")
    args = parser.parse_args()
    if lizard is None:
        print(f"ERROR: cannot import pinned lizard: {LIZARD_IMPORT_ERROR}", file=sys.stderr)
        return 2
    try:
        check_version(ROOT / "tools/complexity/requirements.in", lizard.version)
        if args.selftest:
            return selftest()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(printable(f"ERROR: complexity check could not run: {error}"), file=sys.stderr)
        return 2
    return gate(ROOT, None)


if __name__ == "__main__":
    sys.exit(main())
