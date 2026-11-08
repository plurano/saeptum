#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Validate that GitHub pull-request workflow jobs match required status checks.

Check:
    Ensures every job in every pull-request workflow is required by branch
    protection rulesets or explicitly listed in EXEMPT, and every required
    status check corresponds to an existing pull-request job.

Why:
    Pull-request jobs that are not required status checks can fail silently
    without blocking merges. Conversely, required checks naming non-existent
    jobs can deadlock pull requests. Both directions must stay in sync.

Exit codes:
    0 = every pull-request job is a required check, and every required check
        names one (or selftest passed)
    1 = mismatch between jobs and required checks, or invalid EXEMPT entry
    2 = could not run or parse workflow/ruleset file
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_WORKFLOWS = 64
MAX_LINES = 20000

# Context -> reason. An entry in EXEMPT is a decision taken in this file
# documenting why a specific pull-request job is exempt from branch protection.
EXEMPT: dict[str, str] = {}

TOP_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:(.*)$")
JOB_ID_RE = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*)\s*:(.*)$")
ATTR_RE = re.compile(r"^    ([A-Za-z0-9_-]+)\s*:(.*)$")


@dataclass(frozen=True)
class Job:
    """Represents a job found in a pull-request workflow."""

    file: str
    line: int
    job_id: str
    name: str | None
    is_uses: bool

    @property
    def context(self) -> str:
        """Return the effective context name of this job."""
        return self.name if self.name is not None else self.job_id


def parse_job_name(val: str, filename: str, line_num: int) -> str:
    """Parse and validate a job 'name:' attribute value."""
    s = val.strip()
    if not s:
        raise ValueError(f"{filename}:{line_num}: empty job name")
    if "${{" in s:
        raise ValueError(f"{filename}:{line_num}: dynamic '${{{{...}}}}' in job name")
    if s[0] in ("&", "*", "!"):
        raise ValueError(f"{filename}:{line_num}: anchor/alias/tag in job name")
    if s[0] in ("|", ">"):
        raise ValueError(f"{filename}:{line_num}: block scalar in job name")

    if s.startswith("'"):
        second = s.find("'", 1)
        if second == -1:
            raise ValueError(f"{filename}:{line_num}: unterminated single-quoted name")
        rest = s[second + 1 :].strip()
        if rest and not rest.startswith("#"):
            raise ValueError(f"{filename}:{line_num}: trailing content after quote")
        inner = s[1:second]
        if "\\" in inner or "'" in inner:
            raise ValueError(f"{filename}:{line_num}: escapes not allowed in quoted name")
        if not inner:
            raise ValueError(f"{filename}:{line_num}: empty job name")
        return inner

    if s.startswith('"'):
        second = s.find('"', 1)
        if second == -1:
            raise ValueError(f"{filename}:{line_num}: unterminated double-quoted name")
        rest = s[second + 1 :].strip()
        if rest and not rest.startswith("#"):
            raise ValueError(f"{filename}:{line_num}: trailing content after quote")
        inner = s[1:second]
        if "\\" in inner or '"' in inner:
            raise ValueError(f"{filename}:{line_num}: escapes not allowed in quoted name")
        if not inner:
            raise ValueError(f"{filename}:{line_num}: empty job name")
        return inner

    if " #" in s:
        s = s.split(" #", 1)[0].rstrip()
    if not s:
        raise ValueError(f"{filename}:{line_num}: empty job name")
    if s[0] in ("&", "*", "!") or s[0] in ("|", ">") or s[0] in ("'", '"'):
        raise ValueError(f"{filename}:{line_num}: invalid plain scalar job name")
    return s


def _parse_on_inline(filename: str, line_num: int, remainder: str) -> set[str]:
    """Parse inline scalar or flow list form of 'on:'."""
    rem = remainder.strip()
    if " #" in rem:
        rem = rem.split(" #", 1)[0].rstrip()
    if rem.startswith("["):
        if not rem.endswith("]"):
            raise ValueError(f"{filename}:{line_num}: unterminated flow list in 'on:'")
        inner = rem[1:-1].strip()
        if not inner:
            raise ValueError(f"{filename}:{line_num}: empty flow list in 'on:'")
        triggers: set[str] = set()
        for item in inner.split(","):
            tok = item.strip().strip("'\"")
            if not tok:
                raise ValueError(f"{filename}:{line_num}: empty item in 'on:' flow list")
            triggers.add(tok)
        return triggers
    tok = rem.strip("'\"")
    if not tok or any(c.isspace() for c in tok):
        raise ValueError(f"{filename}:{line_num}: invalid inline scalar in 'on:'")
    return {tok}


def _parse_on_block(
    filename: str, lines: list[str], start_idx: int
) -> tuple[set[str], int]:
    """Parse block mapping form of 'on:' starting at start_idx."""
    triggers: set[str] = set()
    idx = start_idx
    max_idx = min(len(lines), start_idx + MAX_LINES)
    for i in range(start_idx, max_idx):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            idx = i + 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent == 1:
            raise ValueError(f"{filename}:{i + 1}: invalid 1-space indentation")
        if indent == 2:
            m = re.match(r"^  ([A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:(.*)$", line)
            if not m:
                raise ValueError(f"{filename}:{i + 1}: invalid trigger key in 'on:'")
            triggers.add(m.group(1).strip("'\""))
        idx = i + 1
    return triggers, idx


def _handle_job_attr(
    line: str, cur_id: str, filename: str, lineno: int
) -> tuple[str | None, bool]:
    """Parse a 4-space job attribute. Returns (name, is_uses)."""
    m = ATTR_RE.match(line)
    if not m:
        return None, False
    key, val = m.group(1), m.group(2)
    if key == "strategy":
        raise ValueError(f"{filename}:{lineno}: job '{cur_id}' uses 'strategy:'")
    if key == "uses":
        return None, True
    if key == "name":
        return parse_job_name(val, filename, lineno), False
    return None, False


def _parse_jobs_block(
    filename: str, lines: list[str], start_idx: int
) -> tuple[list[Job], int]:
    """Parse top-level 'jobs:' block mapping."""
    jobs: list[Job] = []
    seen_ids: set[str] = set()
    cur_id: str | None = None
    cur_line, cur_name, cur_uses = 0, None, False
    idx = start_idx
    max_idx = min(len(lines), start_idx + MAX_LINES)

    for i in range(start_idx, max_idx):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            idx = i + 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            break
        if indent == 2:
            if cur_id is not None:
                jobs.append(Job(filename, cur_line, cur_id, cur_name, cur_uses))
            if stripped.startswith("<<:"):
                raise ValueError(f"{filename}:{i + 1}: merge key '<<:' at job level")
            m = JOB_ID_RE.match(line)
            if not m:
                raise ValueError(f"{filename}:{i + 1}: invalid job identifier")
            cur_id = m.group(1)
            rem = m.group(2).strip()
            if rem and not rem.startswith("#"):
                raise ValueError(f"{filename}:{i + 1}: job must be a block mapping")
            if cur_id in seen_ids:
                raise ValueError(f"{filename}:{i + 1}: duplicate job id '{cur_id}'")
            seen_ids.add(cur_id)
            cur_line, cur_name, cur_uses = i + 1, None, False
        elif indent == 4:
            if cur_id is None:
                raise ValueError(f"{filename}:{i + 1}: job attribute without job")
            name, is_uses = _handle_job_attr(line, cur_id, filename, i + 1)
            if is_uses:
                cur_uses = True
            if name is not None:
                cur_name = name
        elif indent in (1, 3):
            raise ValueError(f"{filename}:{i + 1}: invalid indentation ({indent} spaces)")
        idx = i + 1

    if cur_id is not None:
        jobs.append(Job(filename, cur_line, cur_id, cur_name, cur_uses))
    return jobs, idx


def parse_workflow(filename: str, text: str) -> list[Job]:
    """Parse a workflow file and return jobs if it triggers on pull_request."""
    lines = text.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"{filename}:1: file exceeds maximum line limit of {MAX_LINES}")

    for i, line in enumerate(lines[:MAX_LINES], 1):
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in leading:
            raise ValueError(f"{filename}:{i}: tab character in indentation")
        if i > 1 and line.strip() == "---":
            raise ValueError(f"{filename}:{i}: document separator '---' after first line")

    seen_top_keys: set[str] = set()
    triggers: set[str] = set()
    jobs: list[Job] = []
    next_idx = 0

    for idx, line in enumerate(lines[:MAX_LINES]):
        if idx < next_idx:
            continue
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or (idx == 0 and stripped == "---"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent != 0:
            continue

        m = TOP_KEY_RE.match(line)
        if not m:
            raise ValueError(f"{filename}:{idx + 1}: invalid top-level YAML syntax")
        raw_key, remainder = m.group(1), m.group(2)
        clean_key = raw_key.strip("'\"")
        if clean_key in seen_top_keys:
            raise ValueError(f"{filename}:{idx + 1}: repeated top-level key '{clean_key}'")
        seen_top_keys.add(clean_key)

        if clean_key == "on":
            rem = remainder.strip()
            if rem and not rem.startswith("#"):
                triggers.update(_parse_on_inline(filename, idx + 1, rem))
            else:
                block_triggers, next_idx = _parse_on_block(filename, lines, idx + 1)
                triggers.update(block_triggers)
        elif clean_key == "jobs":
            if "{" in remainder:
                raise ValueError(f"{filename}:{idx + 1}: flow-style 'jobs: {{' is not allowed")
            rem = remainder.strip()
            if rem and not rem.startswith("#"):
                raise ValueError(f"{filename}:{idx + 1}: jobs must be a block mapping")
            jobs, next_idx = _parse_jobs_block(filename, lines, idx + 1)

    if not ("pull_request" in triggers or "pull_request_target" in triggers):
        return []
    return jobs


def parse_ruleset(data: dict[str, Any], filename: str) -> list[str]:
    """Extract required status check contexts from ruleset dictionary."""
    if not isinstance(data, dict):
        raise TypeError(f"{filename}: ruleset root must be a JSON object")
    rules = data.get("rules")
    if not isinstance(rules, list):
        raise TypeError(f"{filename}: 'rules' must be a list")

    matching = [
        r
        for r in rules[:MAX_LINES]
        if isinstance(r, dict) and r.get("type") == "required_status_checks"
    ]
    if len(matching) != 1:
        raise ValueError(
            f"{filename}: expected exactly 1 rule of type 'required_status_checks', found {len(matching)}"
        )

    params = matching[0].get("parameters")
    if not isinstance(params, dict):
        raise TypeError(f"{filename}: missing 'parameters' object in required_status_checks rule")
    checks = params.get("required_status_checks")
    if not isinstance(checks, list):
        raise TypeError(f"{filename}: missing 'required_status_checks' list in rule parameters")

    contexts: list[str] = []
    seen: set[str] = set()
    for item in checks[:MAX_LINES]:
        if not isinstance(item, dict):
            raise TypeError(f"{filename}: required_status_checks entry must be an object")
        ctx = item.get("context")
        if not isinstance(ctx, str) or not ctx.strip():
            raise ValueError(f"{filename}: required context must be a non-empty string")
        if ctx in seen:
            raise ValueError(f"{filename}: duplicate required status check context '{ctx}'")
        seen.add(ctx)
        contexts.append(ctx)
    return contexts


def _find_ruleset_context_line(ruleset_text: str | None, context: str) -> int:
    """Find line number of a context in ruleset JSON text, or 1."""
    if not ruleset_text:
        return 1
    pattern = f'"{context}"'
    for lineno, line in enumerate(ruleset_text.splitlines()[:MAX_LINES], 1):
        if pattern in line and "context" in line:
            return lineno
    for lineno, line in enumerate(ruleset_text.splitlines()[:MAX_LINES], 1):
        if pattern in line:
            return lineno
    return 1


def _check_exemptions(
    exempt: dict[str, str],
    required: list[str],
    jobs: list[Job],
    exempt_file: str,
    exempt_line: int,
) -> list[str]:
    """Validate that EXEMPT entries are valid and used."""
    findings: list[str] = []
    req_set = set(required)
    for ex_ctx in list(exempt.keys())[:MAX_LINES]:
        if ex_ctx in req_set:
            findings.append(
                f"FAIL: {exempt_file}:{exempt_line}: context '{ex_ctx}' is both exempt and required"
            )
        matched = False
        for job in jobs[:MAX_LINES]:
            if job.context == ex_ctx:
                matched = True
                break
            if job.is_uses and ex_ctx.startswith(f"{job.context} / "):
                matched = True
                break
        if not matched:
            findings.append(
                f"FAIL: {exempt_file}:{exempt_line}: EXEMPT entry '{ex_ctx}' matches no pull-request job"
            )
    return findings


def _check_job_contexts(
    jobs: list[Job],
    required: list[str],
    exempt: dict[str, str],
) -> list[str]:
    """Ensure every pull-request job is required or exempt."""
    findings: list[str] = []
    req_set = set(required)
    for job in jobs[:MAX_LINES]:
        ctx = job.context
        if ctx in exempt:
            continue
        if not job.is_uses:
            if ctx not in req_set:
                findings.append(
                    f"FAIL: {job.file}:{job.line}: plain job '{job.job_id}' "
                    f"('{ctx}') is not required and not exempt"
                )
        else:
            prefix = f"{ctx} / "
            has_match = any(r.startswith(prefix) for r in required[:MAX_LINES])
            if not has_match:
                findings.append(
                    f"FAIL: {job.file}:{job.line}: reusable workflow job '{job.job_id}' "
                    f"('{ctx}') has no required check starting with '{prefix}' and is not exempt"
                )
    return findings


def _check_required_contexts(
    required: list[str],
    jobs: list[Job],
    ruleset_file: str,
    ruleset_text: str | None,
) -> list[str]:
    """Ensure every required status check names an existing pull-request job."""
    findings: list[str] = []
    for req_ctx in required[:MAX_LINES]:
        matched = False
        for job in jobs[:MAX_LINES]:
            if not job.is_uses and job.context == req_ctx:
                matched = True
                break
            if job.is_uses and req_ctx.startswith(f"{job.context} / "):
                matched = True
                break
        if not matched:
            lineno = _find_ruleset_context_line(ruleset_text, req_ctx)
            findings.append(
                f"FAIL: {ruleset_file}:{lineno}: required status check '{req_ctx}' "
                "matches no pull-request job"
            )
    return findings


def evaluate_required_checks(
    workflows: dict[str, str],
    ruleset_data: dict[str, Any],
    ruleset_file: str = ".github/rulesets/main.json",
    ruleset_text: str | None = None,
    exempt: dict[str, str] | None = None,
    exempt_file: str = "tools/check_required_checks.py",
    exempt_line: int = 34,
) -> tuple[int, list[str]]:
    """Evaluate workflows and ruleset in-memory. Returns (exit_code, findings/errors)."""
    if exempt is None:
        exempt = EXEMPT
    try:
        required = parse_ruleset(ruleset_data, ruleset_file)
        all_jobs: list[Job] = []
        for fname, text in list(workflows.items())[:MAX_WORKFLOWS]:
            jobs = parse_workflow(fname, text)
            all_jobs.extend(jobs)
    except (ValueError, TypeError) as exc:
        return 2, [str(exc)]

    findings: list[str] = []
    findings.extend(_check_exemptions(exempt, required, all_jobs, exempt_file, exempt_line))
    findings.extend(_check_job_contexts(all_jobs, required, exempt))
    findings.extend(_check_required_contexts(required, all_jobs, ruleset_file, ruleset_text))

    if findings:
        return 1, findings
    return 0, ["PASS: every pull-request job is a required check, and every required check names one."]


def find_exempt_line() -> int:
    """Return line number where EXEMPT is defined in this file."""
    try:
        lines = Path(__file__).read_text(encoding="utf-8").splitlines()
        for idx, line in enumerate(lines[:MAX_LINES], 1):
            if line.startswith("EXEMPT:"):
                return idx
    except (OSError, UnicodeDecodeError):
        pass
    return 1


def scan_repository(root: Path) -> tuple[int, list[str]]:
    """Scan disk workflows and ruleset under repository root."""
    wf_dir = root / ".github" / "workflows"
    ruleset_path = root / ".github" / "rulesets" / "main.json"

    if not wf_dir.is_dir():
        return 2, [f"{wf_dir}: directory not found"]
    if not ruleset_path.is_file():
        return 2, [f"{ruleset_path}: file not found"]

    try:
        ruleset_text = ruleset_path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return 2, [f"{ruleset_path}: cannot read ruleset file: {exc}"]

    try:
        ruleset_data = json.loads(ruleset_text)
    except json.JSONDecodeError as exc:
        return 2, [f"{ruleset_path}:{exc.lineno}: invalid JSON: {exc}"]

    try:
        wf_paths = sorted(
            [p for p in wf_dir.iterdir() if p.is_file() and p.suffix in (".yml", ".yaml")]
        )
    except OSError as exc:
        return 2, [f"{wf_dir}: cannot list directory: {exc}"]

    if len(wf_paths) > MAX_WORKFLOWS:
        return 2, [f"{wf_dir}: too many workflow files ({len(wf_paths)} > {MAX_WORKFLOWS})"]

    workflows: dict[str, str] = {}
    for p in wf_paths[:MAX_WORKFLOWS]:
        rel = str(p.relative_to(root))
        try:
            workflows[rel] = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return 2, [f"{rel}: cannot read workflow file: {exc}"]

    return evaluate_required_checks(
        workflows=workflows,
        ruleset_data=ruleset_data,
        ruleset_file=str(ruleset_path.relative_to(root)),
        ruleset_text=ruleset_text,
        exempt=EXEMPT,
        exempt_file="tools/check_required_checks.py",
        exempt_line=find_exempt_line(),
    )


def _make_ruleset(contexts: list[str]) -> dict[str, Any]:
    return {
        "rules": [
            {
                "type": "required_status_checks",
                "parameters": {
                    "required_status_checks": [{"context": c} for c in contexts]
                },
            }
        ]
    }


SELFTEST_CASES: tuple[tuple[Any, ...], ...] = (
    (
        "all required -> 0",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  build:\n    name: Build\n"},
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "plain job missing -> 1",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  build:\n    name: Build\n"},
        _make_ruleset([]),
        1,
        "is not required and not exempt",
    ),
    (
        "uses: job with no / context -> 1",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset(["OtherCheck"]),
        1,
        "has no required check starting with 'Licence / '",
    ),
    (
        "uses: job with context Licence only (no / ) -> 1",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset(["Licence"]),
        1,
        "has no required check starting with 'Licence / '",
    ),
    (
        "required context naming no job -> 1",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  build:\n    name: Build\n"},
        _make_ruleset(["Build", "GhostCheck"]),
        1,
        "GhostCheck",
    ),
    (
        "job without name -> context is id",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    runs-on: ubuntu\n"},
        _make_ruleset(["test"]),
        0,
        "PASS:",
    ),
    (
        "single- and double-quoted names",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  j1:\n"
                "    name: 'Job One'\n  j2:\n    name: \"Job Two\"\n"
            )
        },
        _make_ruleset(["Job One", "Job Two"]),
        0,
        "PASS:",
    ),
    (
        "name with trailing comment",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  build:\n    name: Build # comment\n"},
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "workflow without pull_request skipped",
        {"release.yml": "name: Release\non:\n  push:\n    tags: ['v*']\njobs:\n  pub:\n    name: Pub\n"},
        _make_ruleset([]),
        0,
        "PASS:",
    ),
    (
        "on: [push, pull_request]",
        {"ci.yml": "name: CI\non: [push, pull_request]\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        0,
        "PASS:",
    ),
    (
        "on: pull_request",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        0,
        "PASS:",
    ),
    (
        "${{ name -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: ${{ matrix.name }}\n"},
        _make_ruleset(["Test"]),
        2,
        "dynamic '${{...}}'",
    ),
    (
        "matrix -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    strategy:\n      matrix: [1]\n"},
        _make_ruleset(["test"]),
        2,
        "strategy:",
    ),
    (
        "tab indent -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n\ttest:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        2,
        "tab character in indentation",
    ),
    (
        "zero required_status_checks rules -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        {"rules": []},
        2,
        "expected exactly 1 rule",
    ),
    (
        "two required_status_checks rules -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        {"rules": [{"type": "required_status_checks"}, {"type": "required_status_checks"}]},
        2,
        "expected exactly 1 rule",
    ),
    (
        "duplicate required context -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        {
            "rules": [
                {
                    "type": "required_status_checks",
                    "parameters": {
                        "required_status_checks": [{"context": "Test"}, {"context": "Test"}]
                    },
                }
            ]
        },
        2,
        "duplicate required status check context",
    ),
    (
        "unused EXEMPT entry -> 1",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        1,
        "EXEMPT entry 'Unused' matches no pull-request job",
        {"Unused": "testing"},
    ),
    (
        "context both exempt and required -> 1",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        1,
        "context 'Test' is both exempt and required",
        {"Test": "testing"},
    ),
    (
        "merge key <<: at job level -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  <<: *anchor\n"},
        _make_ruleset([]),
        2,
        "merge key '<<:'",
    ),
    (
        "flow-style jobs: { -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs: { test: {} }\n"},
        _make_ruleset([]),
        2,
        "flow-style 'jobs: {'",
    ),
    (
        "repeated top-level key -> 2",
        {"ci.yml": "name: CI\non: pull_request\nname: Duplicate\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        2,
        "repeated top-level key 'name'",
    ),
    (
        "document separator --- after line 1 -> 2",
        {"ci.yml": "name: CI\n---\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        2,
        "document separator '---' after first line",
    ),
    (
        "block scalar in name -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: >\n      Test\n"},
        _make_ruleset(["Test"]),
        2,
        "block scalar in job name",
    ),
    (
        "anchor in name -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: &anchor Test\n"},
        _make_ruleset(["Test"]),
        2,
        "anchor/alias/tag in job name",
    ),
    (
        "empty name -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name:\n    runs-on: ubuntu\n"},
        _make_ruleset(["Test"]),
        2,
        "empty job name",
    ),
)


def selftest() -> int:
    """Run in-memory fixture test cases."""
    for case in SELFTEST_CASES[:MAX_LINES]:
        label, workflows, ruleset, exp_exit, exp_sub = (
            case[0],
            case[1],
            case[2],
            case[3],
            case[4],
        )
        exempt_map = case[5] if len(case) > 5 else {}
        code, msgs = evaluate_required_checks(
            workflows=workflows,
            ruleset_data=ruleset,
            exempt=exempt_map,
        )
        combined = " ".join(msgs)
        if code != exp_exit or exp_sub not in combined:
            print(
                f"FAIL: {label}: expected exit {exp_exit} with {exp_sub!r}, "
                f"got exit {code} with {combined!r}",
                file=sys.stderr,
            )
            return 1

    print(f"PASS: {len(SELFTEST_CASES)} selftest cases.")
    return 0


def main() -> int:
    """Parse CLI arguments and run selftest or scan."""
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--selftest", action="store_true", help="run in-memory test suite"
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parent.parent,
        help="repository root to scan",
    )
    args = parser.parse_args()

    if args.selftest:
        return selftest()

    code, msgs = scan_repository(args.root)
    out_target = sys.stdout if code == 0 else sys.stderr
    for msg in msgs:
        print(msg, file=out_target)
    return code


if __name__ == "__main__":
    sys.exit(main())
