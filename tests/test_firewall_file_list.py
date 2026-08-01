"""The CI firewall's FILE LIST, not its matching.

⚠️ This exists because a real hole survived in the shell path: the file list was
built in YAML as `git ls-files | xargs`, which splits on whitespace, so a tracked
file whose path contained a space was NEVER handed to the scanner — and the scan
reported CLEAN. The Go side had already fixed the same bug (firewall.go:900,
"CRITICAL (arqtos-cli#839 review): this MUST run with -z and split on NUL") and
the fix never crossed over.

⚠️ It survived because the logic lived in YAML, where nothing could test it. The
fix moves the listing INTO the script, so these tests can exist at all. That is
the durable part; the -z flag is just the immediate repair.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
PROBE = "ZZZSYNTHETICPROBE"


def repo_with(tmp_path: Path, filename: str) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    (r / "dl.txt").write_text(PROBE + "\n")
    (r / filename).write_text(f"leak {PROBE} here\n")
    (r / "innocent.md").write_text("nothing to see\n")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r


def scan_all(r: Path) -> subprocess.CompletedProcess:
    """Invoke the script the way CI does — asking it to list tracked files
    ITSELF, which is the whole point of the fix."""
    return subprocess.run([str(SCRIPT), "--denylist=dl.txt", "--all-tracked"],
                          cwd=r, capture_output=True, text=True)


@pytest.mark.parametrize("filename", [
    "plain.md",
    "file with space.md",
    "file\twith\ttab.md",
    "file'with'quote.md",
    'file"with"dquote.md',
    "file\\with\\backslash.md",
])
def test_a_violation_is_found_whatever_the_path_contains(tmp_path, filename):
    """⚠️ The regression. Each of these separators silently dropped the file
    under `git ls-files | xargs`. Fixing only the space would be a partial fix
    that looks complete."""
    r = repo_with(tmp_path, filename)
    p = scan_all(r)
    assert p.returncode == 1, (
        f"a violation in {filename!r} was NOT found — exit {p.returncode}. "
        f"A path the scanner never receives reads as clean, which is the hole.")


def test_a_genuinely_clean_repo_still_passes(tmp_path):
    """So the failures above are not just 'it always fails'."""
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    (r / "dl.txt").write_text(PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    assert scan_all(r).returncode == 0


def test_a_missing_denylist_is_still_exit_2_in_all_tracked_mode(tmp_path):
    """⚠️ The fail-closed property must survive the new mode, not just the old
    one — a scan with nothing to scan against passes everything."""
    r = repo_with(tmp_path, "plain.md")
    p = subprocess.run([str(SCRIPT), "--denylist=nope.txt", "--all-tracked"],
                       cwd=r, capture_output=True, text=True)
    assert p.returncode == 2
