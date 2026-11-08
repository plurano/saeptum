#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Validate cargo-deny JSON output for planted advisory findings.

Check:
    Ensures cargo-deny exited 1 and reported every expected advisory finding
    with the specified severity, code, and subject.

Why:
    cargo-deny exits 1 on errors of its own and when checks fail. Weakening
    an advisory level in deny.toml still leaves the command exiting 1 when
    other planted findings are present. Exit status alone cannot prove a
    level is enforced; each finding must be verified in the JSON stream.

Exit codes:
    0 = every expected finding was reported and cargo-deny exited 1
    1 = cargo-deny exited with unexpected status or an expected finding was missing
    2 = malformed spec, invalid JSON line, unrecognized type, or I/O error
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_LINES = 10000
MAX_EXPECT = 32
ALLOWED_TYPES = frozenset({"diagnostic", "summary", "log"})
SUBJECT_ADVISORY_RE = re.compile(r"^RUSTSEC-\d{4}-\d{4,}$")
SUBJECT_CRATE_RE = re.compile(r"^[a-zA-Z0-9_-]+@[a-zA-Z0-9._+-]+$")
SEVERITY_RE = re.compile(r"^[a-z]+$")
CODE_RE = re.compile(r"^[a-z0-9-]+$")


class Spec:
    """An expected diagnostic specification."""

    def __init__(self, severity: str, code: str, subject: str, raw: str) -> None:
        self.severity = severity
        self.code = code
        self.subject = subject
        self.raw = raw

    def __repr__(self) -> str:
        return f"Spec({self.raw!r})"


def parse_spec(raw: str) -> Spec:
    """Parse a SPEC string of the form severity:code:subject."""
    parts = raw.split(":")
    if len(parts) != 3:
        raise ValueError(
            f"malformed spec {raw!r}: expected <severity>:<code>:<subject>"
        )
    sev, code, subj = parts[0], parts[1], parts[2]
    if not SEVERITY_RE.match(sev):
        raise ValueError(f"malformed spec {raw!r}: invalid severity {sev!r}")
    if not CODE_RE.match(code):
        raise ValueError(f"malformed spec {raw!r}: invalid code {code!r}")
    valid_subj = (
        subj == "-"
        or SUBJECT_ADVISORY_RE.match(subj) is not None
        or SUBJECT_CRATE_RE.match(subj) is not None
    )
    if not valid_subj:
        raise ValueError(f"malformed spec {raw!r}: invalid subject {subj!r}")
    return Spec(sev, code, subj, raw)


def match_diagnostic(spec: Spec, diag: dict[str, Any]) -> bool:
    """Check whether a single diagnostic matches the expected spec."""
    fields = diag.get("fields")
    if not isinstance(fields, dict):
        return False
    if fields.get("severity") != spec.severity or fields.get("code") != spec.code:
        return False
    if spec.subject == "-":
        return True
    advisory = fields.get("advisory")
    if isinstance(advisory, dict) and advisory.get("id") == spec.subject:
        return True
    graphs = fields.get("graphs")
    if isinstance(graphs, list):
        for graph in graphs:
            if isinstance(graph, dict):
                krate = graph.get("Krate")
                if isinstance(krate, dict):
                    name = krate.get("name")
                    ver = krate.get("version")
                    if f"{name}@{ver}" == spec.subject:
                        return True
    return False


def parse_lines(lines: list[str], source_name: str) -> list[dict[str, Any]]:
    """Parse JSON lines according to allow-list of types, returning diagnostics."""
    if len(lines) > MAX_LINES:
        raise ValueError(
            f"{source_name}: line count {len(lines)} exceeds limit of {MAX_LINES}"
        )
    diagnostics: list[dict[str, Any]] = []
    for lineno, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            item = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"{source_name}:{lineno}: non-JSON line: {exc}"
            ) from exc
        if not isinstance(item, dict):
            raise TypeError(
                f"{source_name}:{lineno}: expected JSON object, got {type(item).__name__}"
            )
        item_type = item.get("type")
        if item_type not in ALLOWED_TYPES:
            raise ValueError(f"{source_name}:{lineno}: unknown type {item_type!r}")
        if item_type == "diagnostic":
            fields = item.get("fields")
            if not isinstance(fields, dict):
                raise TypeError(
                    f"{source_name}:{lineno}: diagnostic missing fields object"
                )
            sev = fields.get("severity")
            code = fields.get("code")
            if not isinstance(sev, str) or not isinstance(code, str):
                raise TypeError(
                    f"{source_name}:{lineno}: diagnostic fields missing string severity or code"
                )
            diagnostics.append(item)
    return diagnostics


def evaluate(
    status: int, specs: list[Spec], diagnostics: list[dict[str, Any]]
) -> list[str]:
    """Verify exit status and that all expected specs matched, returning failure messages."""
    failures: list[str] = []
    if status != 1:
        failures.append(f"FAIL: cargo-deny exited {status}, expected 1")
    for spec in specs:
        matched = False
        for diag in diagnostics:
            if match_diagnostic(spec, diag):
                matched = True
                break
        if not matched:
            failures.append(f"FAIL: unmatched expected diagnostic: {spec.raw}")
    return failures


def read_input_file(path: Path) -> list[str]:
    """Read lines from a file path."""
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"cannot read {path}: {exc}") from exc
    return text.splitlines()


def check(
    status: int, spec_strs: list[str], lines: list[str], source_name: str
) -> tuple[int, list[str]]:
    """Run the whole check, returning (exit_code, messages); used by CLI and selftest."""
    if not spec_strs:
        return 2, ["at least one --expect is required"]
    if len(spec_strs) > MAX_EXPECT:
        return 2, [f"too many specs: {len(spec_strs)} exceeds limit of {MAX_EXPECT}"]
    try:
        specs = [parse_spec(raw) for raw in spec_strs]
        diagnostics = parse_lines(lines, source_name)
    except (ValueError, TypeError) as exc:
        return 2, [str(exc)]
    failures = evaluate(status, specs, diagnostics)
    if failures:
        return 1, failures
    return 0, ["PASS: cargo-deny reported every planted finding."]


def _run_selftest_cases() -> tuple[int, list[str]]:
    """Execute all selftest cases and return any failure descriptions."""
    f_vuln = (
        '{"type":"diagnostic","fields":{"severity":"error","code":"vulnerability",'
        '"advisory":{"id":"RUSTSEC-2021-0003"}}}'
    )
    f_unsound = (
        '{"type":"diagnostic","fields":{"severity":"error","code":"unsound",'
        '"advisory":{"id":"RUSTSEC-2021-0145"}}}'
    )
    f_unmaint = (
        '{"type":"diagnostic","fields":{"severity":"error","code":"unmaintained",'
        '"advisory":{"id":"RUSTSEC-2024-0375"}}}'
    )
    f_yanked = (
        '{"type":"diagnostic","fields":{"severity":"error","code":"yanked",'
        '"graphs":[{"Krate":{"name":"scopeguard","version":"0.3.0"}}]}}'
    )
    f_yanked_warn = (
        '{"type":"diagnostic","fields":{"severity":"warning","code":"yanked",'
        '"graphs":[{"Krate":{"name":"scopeguard","version":"0.3.0"}}]}}'
    )
    all_content = f"{f_vuln}\n{f_unsound}\n{f_unmaint}\n{f_yanked}\n"
    std_specs = [
        "error:vulnerability:RUSTSEC-2021-0003",
        "error:unsound:RUSTSEC-2021-0145",
        "error:unmaintained:RUSTSEC-2024-0375",
        "error:yanked:scopeguard@0.3.0",
    ]
    cases: list[tuple[str, int, list[str], str, int]] = [
        ("all present", 1, std_specs, all_content, 0),
        ("one missing", 1, std_specs, f"{f_unsound}\n{f_unmaint}\n{f_yanked}\n", 1),
        ("yanked as warning", 1, std_specs, f"{f_vuln}\n{f_unsound}\n{f_unmaint}\n{f_yanked_warn}\n", 1),
        ("status 0 with all present", 0, std_specs, all_content, 1),
        ("status 2 with all present", 2, std_specs, all_content, 1),
        ("non-JSON line", 1, std_specs, "invalid json\n", 2),
        ("unknown type", 1, std_specs, '{"type":"unknown"}\n', 2),
        ("diagnostic without fields.code", 1, std_specs, '{"type":"diagnostic","fields":{"severity":"error"}}\n', 2),
        ("empty file", 1, std_specs, "", 1),
        ("malformed spec", 1, ["invalid:spec"], all_content, 2),
        (
            "- subject matches code only",
            1,
            ["error:advisory-not-detected:-"],
            '{"type":"diagnostic","fields":{"severity":"error","code":"advisory-not-detected"}}\n',
            0,
        ),
        ("crate subject matches through graphs", 1, ["error:yanked:scopeguard@0.3.0"], f"{f_yanked}\n", 0),
        ("diagnostic missing fields", 1, std_specs, '{"type":"diagnostic"}\n', 2),
        ("too many lines", 1, std_specs, "\n".join(['{"type":"log"}'] * (MAX_LINES + 1)), 2),
        ("too many specs", 1, [f"error:vulnerability:RUSTSEC-2021-{i:04d}" for i in range(MAX_EXPECT + 1)], all_content, 2),
        ("non-object JSON", 1, std_specs, "[1, 2, 3]\n", 2),
        ("no spec", 1, [], all_content, 2),
    ]
    failures: list[str] = []
    for name, st, sp, content, exp_rc in cases:
        rc, _msgs = check(st, sp, content.splitlines(), "<test>")
        if rc != exp_rc:
            failures.append(f"FAIL: case {name!r}: expected rc {exp_rc}, got {rc}")
    return len(cases), failures


def selftest() -> int:
    """Run in-memory test cases."""
    count, failures = _run_selftest_cases()
    if failures:
        for failure in failures:
            print(failure, file=sys.stderr)
        return 1
    print(f"PASS: {count} selftest cases.")
    return 0


def main() -> int:
    """Parse CLI arguments and check deny output or run selftest."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true", help="run in-memory test suite")
    parser.add_argument("--status", type=int, help="exit status of cargo-deny")
    parser.add_argument(
        "--expect",
        action="append",
        default=[],
        help="expected finding spec: severity:code:subject",
    )
    parser.add_argument("file", nargs="?", type=Path, help="cargo-deny JSON output file")
    args = parser.parse_args()

    if args.selftest:
        return selftest()
    if args.status is None or args.file is None:
        print("check_deny_output: --status and FILE are required", file=sys.stderr)
        return 2
    try:
        rc, msgs = check(args.status, args.expect, read_input_file(args.file), str(args.file))
    except ValueError as exc:
        rc, msgs = 2, [str(exc)]
    prefix = "check_deny_output: " if rc == 2 else ""
    for msg in msgs:
        print(f"{prefix}{msg}", file=sys.stdout if rc == 0 else sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main())
