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
TRIGGER_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+|'[^']+'|\"[^\"]+\")\s*:(.*)$")
JOB_ID_RE = re.compile(r"^  ([A-Za-z_][A-Za-z0-9_-]*)\s*:(.*)$")
ATTR_RE = re.compile(r"^    ([A-Za-z0-9_-]+)\s*:(.*)$")
TRIGGER_EVENT_RE = re.compile(r"^[a-z_]+$")
PLAIN_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._()/+-]*$")
QUOTED_NAME_RE = re.compile(r"^[ -~]+$")


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


def _strip_quotes(s: str) -> str:
    """Strip one pair of matching outer single or double quotes."""
    if len(s) >= 2 and (
        (s[0] == "'" and s[-1] == "'") or (s[0] == '"' and s[-1] == '"')
    ):
        return s[1:-1]
    return s


def _is_empty_val(val: str) -> bool:
    """Return True if inline value is empty or comment-only."""
    s = val.strip()
    return not s or s.startswith("#")


def _check_block_indent(
    filename: str, lineno: int, indent: int, child_indent: int, block_open: bool | None
) -> None:
    """Validate line indentation within a block."""
    if indent in (1, 3) or indent < child_indent:
        raise ValueError(f"{filename}:{lineno}: invalid indentation ({indent} spaces)")
    if indent > child_indent:
        if block_open is None:
            raise ValueError(
                f"{filename}:{lineno}: invalid indentation ({indent} spaces)"
            )
        if not block_open:
            raise ValueError(
                f"{filename}:{lineno}: continuation line after an inline value"
            )


def _parse_quoted_name(s: str, q: str, filename: str, line_num: int) -> str:
    """Parse single- or double-quoted job name."""
    second = s.find(q, 1)
    if second == -1:
        quote_type = "single-quoted" if q == "'" else "double-quoted"
        raise ValueError(f"{filename}:{line_num}: unterminated {quote_type} name")
    rest = s[second + 1 :].strip()
    if rest and not rest.startswith("#"):
        raise ValueError(f"{filename}:{line_num}: trailing content after quote")
    inner = s[1:second]
    if "\\" in inner or q in inner:
        raise ValueError(f"{filename}:{line_num}: escapes not allowed in quoted name")
    if not inner:
        raise ValueError(f"{filename}:{line_num}: empty job name")
    if not QUOTED_NAME_RE.match(inner):
        raise ValueError(
            f"{filename}:{line_num}: job name outside the allowed character set"
        )
    return inner


def _parse_plain_name(s: str, filename: str, line_num: int) -> str:
    """Parse unquoted plain scalar job name."""
    if " #" in s:
        s = s.split(" #", 1)[0].rstrip()
    if not s:
        raise ValueError(f"{filename}:{line_num}: empty job name")
    if not PLAIN_NAME_RE.match(s):
        raise ValueError(
            f"{filename}:{line_num}: job name outside the allowed character set"
        )
    return s


def parse_job_name(val: str, filename: str, line_num: int) -> str:
    """Parse and validate a job 'name:' attribute value."""
    s = val.strip()
    if not s or s.startswith("#"):
        raise ValueError(f"{filename}:{line_num}: empty job name")
    if "${{" in s:
        raise ValueError(f"{filename}:{line_num}: dynamic '${{{{...}}}}' in job name")
    if s[0] in ("&", "*", "!"):
        raise ValueError(f"{filename}:{line_num}: anchor/alias/tag in job name")
    if s[0] in ("|", ">"):
        raise ValueError(f"{filename}:{line_num}: block scalar in job name")
    if s[0] in ("'", '"'):
        return _parse_quoted_name(s, s[0], filename, line_num)
    return _parse_plain_name(s, filename, line_num)


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
        for item in inner.split(",")[:MAX_LINES]:
            raw = item.strip()
            if not raw:
                raise ValueError(
                    f"{filename}:{line_num}: empty item in 'on:' flow list"
                )
            tok = _strip_quotes(raw)
            if not TRIGGER_EVENT_RE.match(tok):
                raise ValueError(
                    f"{filename}:{line_num}: invalid trigger in 'on:' flow list"
                )
            triggers.add(tok)
        return triggers
    tok = _strip_quotes(rem)
    if not TRIGGER_EVENT_RE.match(tok):
        raise ValueError(f"{filename}:{line_num}: invalid inline scalar in 'on:'")
    return {tok}


def _parse_on_block(
    filename: str, lines: list[str], start_idx: int
) -> tuple[set[str], int]:
    """Parse block mapping form of 'on:' starting at start_idx."""
    triggers: set[str] = set()
    block_open: bool | None = None
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
        _check_block_indent(filename, i + 1, indent, 2, block_open)
        if indent == 2:
            m = TRIGGER_KEY_RE.match(line)
            if not m:
                raise ValueError(f"{filename}:{i + 1}: invalid trigger key in 'on:'")
            key = _strip_quotes(m.group(1))
            if not TRIGGER_EVENT_RE.match(key):
                raise ValueError(f"{filename}:{i + 1}: invalid trigger key in 'on:'")
            triggers.add(key)
            block_open = _is_empty_val(m.group(2))
        idx = i + 1
    return triggers, idx


def _parse_job_header(line: str, filename: str, lineno: int, seen_ids: set[str]) -> str:
    """Parse a 2-space job declaration line. Returns the job identifier."""
    stripped = line.strip()
    if stripped.startswith("<<:"):
        raise ValueError(f"{filename}:{lineno}: merge key '<<:' at job level")
    m = JOB_ID_RE.match(line)
    if not m:
        raise ValueError(f"{filename}:{lineno}: invalid job identifier")
    job_id = m.group(1)
    rem = m.group(2).strip()
    if rem and not rem.startswith("#"):
        raise ValueError(f"{filename}:{lineno}: job must be a block mapping")
    if job_id in seen_ids:
        raise ValueError(f"{filename}:{lineno}: duplicate job id '{job_id}'")
    seen_ids.add(job_id)
    return job_id


def _parse_job_attr_line(
    line: str, cur_id: str, filename: str, lineno: int, seen_attrs: set[str]
) -> tuple[str | None, bool, bool]:
    """Parse a 4-space job attribute line. Returns (name, is_uses, block_open)."""
    m = ATTR_RE.match(line)
    if not m:
        raise ValueError(f"{filename}:{lineno}: invalid job attribute syntax")
    key, val = m.group(1), m.group(2)
    if key in seen_attrs:
        raise ValueError(f"{filename}:{lineno}: duplicate job attribute '{key}'")
    seen_attrs.add(key)
    if key == "strategy":
        raise ValueError(f"{filename}:{lineno}: job '{cur_id}' uses 'strategy:'")
    is_empty = _is_empty_val(val)
    if key == "uses":
        return None, True, is_empty
    if key == "name":
        return parse_job_name(val, filename, lineno), False, is_empty
    return None, False, is_empty


def _flush_job(
    jobs: list[Job],
    filename: str,
    cur_id: str | None,
    cur_line: int,
    cur_name: str | None,
    cur_uses: bool,
) -> None:
    """Append current job to list if present."""
    if cur_id is not None:
        jobs.append(Job(filename, cur_line, cur_id, cur_name, cur_uses))


def _apply_job_attr(
    line: str,
    cur_id: str | None,
    filename: str,
    lineno: int,
    cur_attrs: set[str],
    cur_uses: bool,
    cur_name: str | None,
) -> tuple[bool, str | None, bool]:
    """Parse and apply 4-space job attribute. Returns (cur_uses, cur_name, block_open)."""
    if cur_id is None:
        raise ValueError(f"{filename}:{lineno}: job attribute without job")
    name, is_uses, block_open = _parse_job_attr_line(
        line, cur_id, filename, lineno, cur_attrs
    )
    updated_uses = cur_uses or is_uses
    updated_name = name if name is not None else cur_name
    return updated_uses, updated_name, block_open


def _parse_jobs_block(
    filename: str, lines: list[str], start_idx: int
) -> tuple[list[Job], int]:
    """Parse top-level 'jobs:' block mapping."""
    jobs: list[Job] = []
    seen_ids: set[str] = set()
    cur_id: str | None = None
    cur_line, cur_name, cur_uses = 0, None, False
    cur_attrs: set[str] = set()
    block_open: bool | None = None
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
        if cur_id is None:
            _check_block_indent(filename, i + 1, indent, 2, None)
        elif indent != 2:
            _check_block_indent(filename, i + 1, indent, 4, block_open)
        if indent == 2:
            _flush_job(jobs, filename, cur_id, cur_line, cur_name, cur_uses)
            cur_id = _parse_job_header(line, filename, i + 1, seen_ids)
            cur_line, cur_name, cur_uses = i + 1, None, False
            cur_attrs = set()
            block_open = None
        elif indent == 4:
            cur_uses, cur_name, block_open = _apply_job_attr(
                line, cur_id, filename, i + 1, cur_attrs, cur_uses, cur_name
            )
        idx = i + 1

    _flush_job(jobs, filename, cur_id, cur_line, cur_name, cur_uses)
    return jobs, idx


def _validate_workflow_lines(filename: str, lines: list[str]) -> None:
    """Validate workflow line count, indentation characters, and document markers."""
    if len(lines) > MAX_LINES:
        raise ValueError(
            f"{filename}:1: file exceeds maximum line limit of {MAX_LINES}"
        )
    for i, line in enumerate(lines[:MAX_LINES], 1):
        leading = line[: len(line) - len(line.lstrip(" \t"))]
        if "\t" in leading:
            raise ValueError(f"{filename}:{i}: tab character in indentation")
        if i > 1 and line.strip() == "---":
            raise ValueError(
                f"{filename}:{i}: document separator '---' after first line"
            )


def _parse_on_clause(
    filename: str, idx: int, remainder: str, lines: list[str]
) -> tuple[set[str], int]:
    """Parse 'on:' clause from inline or block mapping format."""
    rem = remainder.strip()
    if rem and not rem.startswith("#"):
        return _parse_on_inline(filename, idx + 1, rem), 0
    return _parse_on_block(filename, lines, idx + 1)


def _parse_jobs_clause(
    filename: str, idx: int, remainder: str, lines: list[str]
) -> tuple[list[Job], int]:
    """Validate and parse 'jobs:' clause."""
    if "{" in remainder:
        raise ValueError(f"{filename}:{idx + 1}: flow-style 'jobs: {{' is not allowed")
    rem = remainder.strip()
    if rem and not rem.startswith("#"):
        raise ValueError(f"{filename}:{idx + 1}: jobs must be a block mapping")
    return _parse_jobs_block(filename, lines, idx + 1)


def parse_workflow(filename: str, text: str) -> list[Job]:
    """Parse a workflow file and return jobs if it triggers on pull_request."""
    lines = text.splitlines()
    _validate_workflow_lines(filename, lines)

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
        if len(line) - len(line.lstrip(" ")) != 0:
            continue

        m = TOP_KEY_RE.match(line)
        if not m:
            raise ValueError(f"{filename}:{idx + 1}: invalid top-level YAML syntax")
        clean_key = m.group(1).strip("'\"")
        if clean_key in seen_top_keys:
            raise ValueError(
                f"{filename}:{idx + 1}: repeated top-level key '{clean_key}'"
            )
        seen_top_keys.add(clean_key)

        if clean_key == "on":
            trigs, next_idx = _parse_on_clause(filename, idx, m.group(2), lines)
            triggers.update(trigs)
        elif clean_key == "jobs":
            jobs, next_idx = _parse_jobs_clause(filename, idx, m.group(2), lines)

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
        raise TypeError(
            f"{filename}: missing 'parameters' object in required_status_checks rule"
        )
    checks = params.get("required_status_checks")
    if not isinstance(checks, list):
        raise TypeError(
            f"{filename}: missing 'required_status_checks' list in rule parameters"
        )

    contexts: list[str] = []
    seen: set[str] = set()
    for item in checks[:MAX_LINES]:
        if not isinstance(item, dict):
            raise TypeError(
                f"{filename}: required_status_checks entry must be an object"
            )
        ctx = item.get("context")
        if not isinstance(ctx, str) or not ctx.strip():
            raise ValueError(f"{filename}: required context must be a non-empty string")
        if ctx in seen:
            raise ValueError(
                f"{filename}: duplicate required status check context '{ctx}'"
            )
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
    exempt_line: int | None = None,
) -> tuple[int, list[str]]:
    """Evaluate workflows and ruleset in-memory. Returns (exit_code, findings/errors)."""
    if exempt is None:
        exempt = EXEMPT
    if exempt_line is None:
        exempt_line = find_exempt_line()
    try:
        required = parse_ruleset(ruleset_data, ruleset_file)
        all_jobs: list[Job] = []
        for fname, text in list(workflows.items())[:MAX_WORKFLOWS]:
            jobs = parse_workflow(fname, text)
            all_jobs.extend(jobs)
    except (ValueError, TypeError) as exc:
        return 2, [str(exc)]

    findings: list[str] = []
    findings.extend(
        _check_exemptions(exempt, required, all_jobs, exempt_file, exempt_line)
    )
    findings.extend(_check_job_contexts(all_jobs, required, exempt))
    findings.extend(
        _check_required_contexts(required, all_jobs, ruleset_file, ruleset_text)
    )

    if findings:
        return 1, findings
    return 0, [
        "PASS: every pull-request job is a required check, and every required check names one."
    ]


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


def _load_ruleset(path: Path) -> tuple[dict[str, Any] | None, str, str | None]:
    """Load and parse ruleset JSON file. Returns (data, raw_text, error)."""
    if not path.is_file():
        return None, "", f"{path}: file not found"
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        return None, "", f"{path}: cannot read ruleset file: {exc}"
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        return None, "", f"{path}:{exc.lineno}: invalid JSON: {exc}"
    if not isinstance(data, dict):
        return None, text, f"{path}: ruleset root must be a JSON object"
    return data, text, None


def _load_workflows(
    wf_dir: Path, root: Path
) -> tuple[dict[str, str] | None, str | None]:
    """Read workflow files from directory. Returns (workflows_dict, error)."""
    if not wf_dir.is_dir():
        return None, f"{wf_dir}: directory not found"
    try:
        wf_paths = sorted(
            [
                p
                for p in wf_dir.iterdir()
                if p.is_file() and p.suffix in (".yml", ".yaml")
            ]
        )
    except OSError as exc:
        return None, f"{wf_dir}: cannot list directory: {exc}"

    if len(wf_paths) > MAX_WORKFLOWS:
        return (
            None,
            f"{wf_dir}: too many workflow files ({len(wf_paths)} > {MAX_WORKFLOWS})",
        )

    workflows: dict[str, str] = {}
    for p in wf_paths[:MAX_WORKFLOWS]:
        rel = str(p.relative_to(root))
        try:
            workflows[rel] = p.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            return None, f"{rel}: cannot read workflow file: {exc}"
    return workflows, None


def scan_repository(root: Path) -> tuple[int, list[str]]:
    """Scan disk workflows and ruleset under repository root."""
    wf_dir = root / ".github" / "workflows"
    ruleset_path = root / ".github" / "rulesets" / "main.json"

    ruleset_data, ruleset_text, err = _load_ruleset(ruleset_path)
    if err is not None:
        return 2, [err]
    if ruleset_data is None:
        return 2, [f"{ruleset_path}: ruleset load error"]

    workflows, wf_err = _load_workflows(wf_dir, root)
    if wf_err is not None:
        return 2, [wf_err]
    if workflows is None:
        return 2, [f"{wf_dir}: workflow load error"]

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
        "uses: job matched through prefix -> 0",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset(["Licence / REUSE lint"]),
        0,
        "PASS:",
    ),
    (
        "uses: job without name -> 0",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset(["licence / REUSE lint"]),
        0,
        "PASS:",
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
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  build:\n    name: Build # comment\n"
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "workflow without pull_request skipped",
        {
            "release.yml": "name: Release\non:\n  push:\n    tags: ['v*']\njobs:\n  pub:\n    name: Pub\n"
        },
        _make_ruleset([]),
        0,
        "PASS:",
    ),
    (
        "on: [push, pull_request]",
        {
            "ci.yml": "name: CI\non: [push, pull_request]\njobs:\n  test:\n    name: Test\n"
        },
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
        "quoted trigger key 'on' block mapping with types -> 0",
        {
            "reuse.yml": (
                "name: REUSE\n'on':\n  pull_request:\n    types: [opened]\n"
                "jobs:\n  licence:\n    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset(["Licence / REUSE lint"]),
        0,
        "PASS:",
    ),
    (
        "pull_request_target trigger -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request_target\njobs:\n  test:\n    name: Test\n"
            )
        },
        _make_ruleset(["Test"]),
        0,
        "PASS:",
    ),
    (
        "block-list on: -> 2",
        {"ci.yml": ("name: CI\non:\n  - push\njobs:\n  test:\n    name: Test\n")},
        _make_ruleset(["Test"]),
        2,
        "invalid trigger key in 'on:'",
    ),
    (
        "quoted attribute key -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    'name': Build\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "invalid job attribute syntax",
    ),
    (
        "attribute line with dash item -> 2",
        {"ci.yml": ("name: CI\non: pull_request\njobs:\n  build:\n    - item\n")},
        _make_ruleset(["Build"]),
        2,
        "invalid job attribute syntax",
    ),
    (
        "3-space line under on: -> 2",
        {
            "ci.yml": (
                "name: CI\non:\n   pull_request:\njobs:\n  test:\n    name: Test\n"
            )
        },
        _make_ruleset(["Test"]),
        2,
        "invalid indentation (3 spaces)",
    ),
    (
        "name twice in one job -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  test:\n    name: First\n    name: Second\n"
            )
        },
        _make_ruleset(["Second"]),
        2,
        "duplicate job attribute 'name'",
    ),
    (
        "${{ name -> 2",
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: ${{ matrix.name }}\n"
        },
        _make_ruleset(["Test"]),
        2,
        "dynamic '${{...}}'",
    ),
    (
        "matrix -> 2",
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    strategy:\n      matrix: [1]\n"
        },
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
        {
            "rules": [
                {"type": "required_status_checks"},
                {"type": "required_status_checks"},
            ]
        },
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
                        "required_status_checks": [
                            {"context": "Test"},
                            {"context": "Test"},
                        ]
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
        "exempt caller context of uses job -> 0",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset([]),
        0,
        "PASS:",
        {"Licence": "exempted caller"},
    ),
    (
        "exempt callee form matches no job context -> 1",
        {
            "reuse.yml": (
                "name: REUSE\non: pull_request\njobs:\n  licence:\n"
                "    name: Licence\n    uses: org/repo/.github/workflows/l.yml@main\n"
            )
        },
        _make_ruleset([]),
        1,
        "EXEMPT entry 'Licence / REUSE lint' matches no pull-request job",
        {"Licence / REUSE lint": "wrong callee form"},
    ),
    (
        "context both exempt and required -> 1",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        _make_ruleset(["Test"]),
        1,
        "tools/check_required_checks.py:",
        {"Test": "testing"},
    ),
    (
        "duplicate job id -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  test:\n    name: First\n  test:\n    name: Second\n"
            )
        },
        _make_ruleset(["First"]),
        2,
        "duplicate job id 'test'",
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
        {
            "ci.yml": "name: CI\non: pull_request\nname: Duplicate\njobs:\n  test:\n    name: Test\n"
        },
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
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: >\n      Test\n"
        },
        _make_ruleset(["Test"]),
        2,
        "block scalar in job name",
    ),
    (
        "anchor in name -> 2",
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: &anchor Test\n"
        },
        _make_ruleset(["Test"]),
        2,
        "anchor/alias/tag in job name",
    ),
    (
        "empty name -> 2",
        {
            "ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name:\n    runs-on: ubuntu\n"
        },
        _make_ruleset(["Test"]),
        2,
        "empty job name",
    ),
    (
        "ruleset root not an object -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        ["not", "an", "object"],
        2,
        "ruleset root must be a JSON object",
    ),
    (
        "indent > 2 before first trigger key -> 2",
        {
            "ci.yml": (
                "name: CI\non:\n    pull_request:\njobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset([]),
        2,
        "invalid indentation (4 spaces)",
    ),
    (
        "indent > 4 before first job attribute -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n      name: Build\n"
            )
        },
        _make_ruleset(["build"]),
        2,
        "invalid indentation (6 spaces)",
    ),
    (
        "indent > 2 before first job header -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n      build:\n        name: Build\n"
            )
        },
        _make_ruleset([]),
        2,
        "invalid indentation (6 spaces)",
    ),
    (
        "flow mapping in on: -> 2",
        {
            "ci.yml": (
                "name: CI\non: {pull_request:}\njobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset([]),
        2,
        "invalid inline scalar in 'on:'",
    ),
    (
        "flow mapping item in on: flow list -> 2",
        {
            "ci.yml": (
                "name: CI\non: [push, {pull_request: {}}]\njobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset([]),
        2,
        "invalid trigger in 'on:' flow list",
    ),
    (
        "name with comment only = empty -> 2",
        {"ci.yml": ("name: CI\non: pull_request\njobs:\n  build:\n    name: #c\n")},
        _make_ruleset(["#c"]),
        2,
        "empty job name",
    ),
    (
        "plain name with colon -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: Build: Test\n"
            )
        },
        _make_ruleset(["Build: Test"]),
        2,
        "job name outside the allowed character set",
    ),
    (
        "flow sequence as name -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: [Build]\n"
            )
        },
        _make_ruleset(["[Build]"]),
        2,
        "job name outside the allowed character set",
    ),
    (
        "nested trigger value at indent 4 -> 0",
        {
            "ci.yml": (
                "name: CI\non:\n  pull_request:\n    branches: [main]\n"
                "jobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "double-quoted on: pull_request -> 0",
        {
            "ci.yml": (
                'name: CI\non: "pull_request"\njobs:\n  build:\n    name: Build\n'
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "single-quoted on: pull_request -> 0",
        {
            "ci.yml": (
                "name: CI\non: 'pull_request'\njobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "job steps at indent 6 after attribute -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n"
                "    name: Build\n    steps:\n      - run: x\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "plain name with parens and dashes -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  check:\n"
                "    name: Public API (cargo-semver-checks)\n"
            )
        },
        _make_ruleset(["Public API (cargo-semver-checks)"]),
        0,
        "PASS:",
    ),
    (
        "plain name Mutation testing (changed code) -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  test:\n"
                "    name: Mutation testing (changed code)\n"
            )
        },
        _make_ruleset(["Mutation testing (changed code)"]),
        0,
        "PASS:",
    ),
    (
        "quoted name with colon -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: 'Build: all'\n"
            )
        },
        _make_ruleset(["Build: all"]),
        0,
        "PASS:",
    ),
    (
        "quoted name with non-ASCII emoji -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: 'Build \U0001f525'\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "job name outside the allowed character set",
    ),
    (
        "quoted name with control character -> 2",
        {
            "ci.yml": (
                'name: CI\non: pull_request\njobs:\n  build:\n    name: "Build \x07"\n'
            )
        },
        _make_ruleset(["Build"]),
        2,
        "job name outside the allowed character set",
    ),
    (
        "ruleset root None -> 2",
        {"ci.yml": "name: CI\non: pull_request\njobs:\n  test:\n    name: Test\n"},
        None,
        2,
        ".github/rulesets/main.json: ruleset root must be a JSON object",
    ),
    (
        "continuation line after name plain scalar -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: Build\n      Test\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "continuation line after an inline value",
    ),
    (
        "continuation line after blank line -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: Build\n\n      Test\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "continuation line after an inline value",
    ),
    (
        "continuation line after single-quoted name -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n    name: 'Build'\n      Test\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "continuation line after an inline value",
    ),
    (
        "continuation line after push inline trigger -> 2",
        {
            "ci.yml": (
                "name: CI\non:\n  push: x\n    pull_request:\njobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "continuation line after an inline value",
    ),
    (
        "continuation line after runs-on attribute -> 2",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n"
                "    name: Build\n    runs-on: ubuntu-latest\n      extra\n"
            )
        },
        _make_ruleset(["Build"]),
        2,
        "continuation line after an inline value",
    ),
    (
        "empty inline env opens nested block -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n"
                "    name: Build\n    env:\n      A: b\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "empty inline steps opens nested block before name -> 0",
        {
            "ci.yml": (
                "name: CI\non: pull_request\njobs:\n  build:\n"
                "    steps:\n      - run: x\n    name: Build\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
    ),
    (
        "comment-only trigger value opens nested block -> 0",
        {
            "ci.yml": (
                "name: CI\non:\n  pull_request: # c\n    branches: [main]\n"
                "jobs:\n  build:\n    name: Build\n"
            )
        },
        _make_ruleset(["Build"]),
        0,
        "PASS:",
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
