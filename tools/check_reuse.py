#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Lusoris <lusoris@pm.me>
# SPDX-License-Identifier: EUPL-1.2
"""REUSE gate with a planted-defect selftest.

check:    reuse lint over the repository.
selftest: copies the repository's tracked and unignored files into a scratch
          directory, plants one file without licence information, and passes
          only when reuse lint refuses the copy and accepts the unplanted copy.
"""
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIMEOUT = 120


def lint(root):
    cmd = ["reuse", "--root", str(root), "lint", "--quiet"]
    return subprocess.run(cmd, cwd=root, timeout=TIMEOUT, check=False).returncode


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


def selftest():
    with tempfile.TemporaryDirectory() as tmp:
        dest = Path(tmp)
        copy_tree(dest)
        if lint(dest) != 0:
            print("selftest: unplanted copy refused", file=sys.stderr)
            return 1
        (dest / "planted_unlicensed.txt").write_text("no licence information\n")
        if lint(dest) == 0:
            print("selftest: planted file without licence passed", file=sys.stderr)
            return 1
    print("selftest: reuse lint refused the planted file")
    return 0


def main(argv):
    if argv[1:] == ["selftest"]:
        return selftest()
    if argv[1:]:
        print("usage: check_reuse.py [selftest]", file=sys.stderr)
        return 2
    return lint(ROOT)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
