#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""REUSE gate with a planted-defect selftest.

check:    reuse lint over the repository; on failure every finding is printed,
          one per line (reuse lint --lines), never hidden.
selftest: copies the repository's tracked and unignored files into a scratch
          git repository, so .gitignore applies there as it does here. The copy
          passes with a planted gate receipt (.standards-receipt.json, ignored by
          the managed block) and fails with a planted file without licence
          information, whose path the printed findings must name.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 120


def lint(root):
    """(return code, findings text) of reuse lint over root."""
    cmd = ["reuse", "--root", str(root), "lint", "--lines"]
    done = subprocess.run(cmd, cwd=root, capture_output=True, text=True, timeout=TIMEOUT, check=False)
    return done.returncode, (done.stdout + done.stderr).strip()


def listed_files():
    cmd = ["git", "ls-files", "-co", "--exclude-standard", "-z"]
    out = subprocess.run(cmd, cwd=ROOT, capture_output=True, timeout=TIMEOUT, check=True)
    return [p for p in out.stdout.decode().split("\0") if p][:20000]


def copy_tree(dest):
    for rel in listed_files():
        src = ROOT / rel
        if src.is_file():
            (dest / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest / rel)


def scratch_repository(dest):
    """Copy the tree into dest and make it a git repository, so .gitignore holds there."""
    copy_tree(dest)
    subprocess.run(["git", "init", "-q", str(dest)], timeout=TIMEOUT, check=True)


def selftest():
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        scratch_repository(dest)
        (dest / ".standards-receipt.json").write_text("{}\n")
        rc, out = lint(dest)
        if rc != 0:
            print(f"selftest: copy with a gate receipt refused:\n{out}", file=sys.stderr)
            return 1
        (dest / "planted_unlicensed.txt").write_text("no licence information\n")
        rc, out = lint(dest)
        if rc == 0 or "planted_unlicensed.txt" not in out:
            print(f"selftest: planted file without licence passed or was not named:\n{out}", file=sys.stderr)
            return 1
    print("selftest: gate receipt ignored; reuse lint refused the planted file and named it")
    return 0


def main(argv):
    if argv[1:] == ["selftest"]:
        return selftest()
    if argv[1:]:
        print("usage: check_reuse.py [selftest]", file=sys.stderr)
        return 2
    rc, out = lint(ROOT)
    if rc != 0:
        print(out, file=sys.stderr)
    return rc


if __name__ == "__main__":
    sys.exit(main(sys.argv))
