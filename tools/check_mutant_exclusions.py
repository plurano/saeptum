#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""Validate category and expiry metadata on cargo-mutants exclusions.

Each entry in exclude_re must be preceded by a structured comment line:
    # category: <A|B|C|D> | entered: YYYY-MM-DD | expires: YYYY-MM-DD

The expiry must equal entered + the category's rectification interval:
    A = interval stated in the entry, B = 3 days, C = 10 days, D = 120 days.

Exits non-zero when any entry is missing metadata, has a wrong expiry
offset, or is past its expiry date.

Run with --selftest to verify the checker itself catches a planted defect.
"""
from __future__ import annotations

import datetime
import re
import sys
from pathlib import Path

CATEGORY_DAYS = {"B": 3, "C": 10, "D": 120}
META_RE = re.compile(
    r"^#\s*category:\s*([A-D])\s*\|\s*entered:\s*(\d{4}-\d{2}-\d{2})"
    r"\s*\|\s*expires:\s*(\d{4}-\d{2}-\d{2})\s*$"
)
ENTRY_RE = re.compile(r"""^\s*['"].*['"],?\s*$""")
PLANTED_MARKER = "# PLANTED-DEFECT: do not remove; selftest expects this to fail"
PLANTED_PATTERN = "PLANTED_DEFECT_MARKER_DO_NOT_MATCH"


def _utc_today() -> datetime.date:
    return datetime.datetime.now(datetime.timezone.utc).date()


def parse_entries(path: Path) -> list[tuple[int, str, str | None, bool]]:
    """Return (line_number, entry_text, preceding_meta_line, is_planted)."""
    lines = path.read_text().splitlines()
    entries: list[tuple[int, str, str | None, bool]] = []
    in_array = False
    last_meta: str | None = None
    is_planted = False
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("exclude_re"):
            in_array = True
            continue
        if not in_array:
            continue
        if stripped == "]":
            break
        if stripped.startswith("#"):
            if PLANTED_MARKER in stripped:
                is_planted = True
            m = META_RE.match(stripped)
            if m:
                last_meta = stripped
            continue
        if ENTRY_RE.match(line):
            entries.append((i, stripped, last_meta, is_planted))
            last_meta = None
            is_planted = False
    return entries


def validate(
    path: Path,
    today: datetime.date | None = None,
    include_planted: bool = False,
) -> list[str]:
    """Return a list of error strings; empty means valid."""
    if today is None:
        today = _utc_today()
    errors: list[str] = []
    for lineno, entry, meta, planted in parse_entries(path):
        if planted and not include_planted:
            continue
        if meta is None:
            errors.append(
                "line %d: missing metadata comment: %s" % (lineno, entry)
            )
            continue
        m = META_RE.match(meta)
        if not m:
            errors.append(
                "line %d: malformed metadata: %s" % (lineno, meta)
            )
            continue
        cat, entered_s, expires_s = m.group(1), m.group(2), m.group(3)
        try:
            entered = datetime.date.fromisoformat(entered_s)
            expires = datetime.date.fromisoformat(expires_s)
        except ValueError as exc:
            errors.append(
                "line %d: invalid date: %s" % (lineno, exc)
            )
            continue
        if cat in CATEGORY_DAYS:
            expected = entered + datetime.timedelta(days=CATEGORY_DAYS[cat])
            if expires != expected:
                errors.append(
                    "line %d: category %s entered %s should expire %s, got %s"
                    % (lineno, cat, entered_s, expected.isoformat(), expires_s)
                )
        if expires < today:
            errors.append(
                "line %d: expired on %s (today %s): %s"
                % (lineno, expires_s, today.isoformat(), entry)
            )
    return errors


def selftest() -> bool:
    """Verify the checker catches the planted defect in mutants.toml."""
    path = Path(__file__).resolve().parent.parent / ".cargo" / "mutants.toml"
    text = path.read_text()
    if PLANTED_MARKER not in text:
        print(
            "FAIL: planted defect marker not found in %s" % path,
            file=sys.stderr,
        )
        return False
    errors = validate(path, today=_utc_today(), include_planted=True)
    planted_errors = [e for e in errors if PLANTED_PATTERN in e]
    if not planted_errors:
        print(
            "FAIL: planted defect was not caught by validator",
            file=sys.stderr,
        )
        return False
    real_errors = validate(path, include_planted=False)
    if real_errors:
        print(
            "FAIL: real exclusions have errors:\n"
            + "\n".join(real_errors),
            file=sys.stderr,
        )
        return False
    print("PASS: planted defect is caught; real exclusions are valid.")
    return True


def main() -> int:
    if "--selftest" in sys.argv:
        return 0 if selftest() else 1
    path = Path(__file__).resolve().parent.parent / ".cargo" / "mutants.toml"
    errors = validate(path, include_planted=False)
    if errors:
        for e in errors:
            print("ERROR: %s" % e, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
