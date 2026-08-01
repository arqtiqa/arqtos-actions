"""The firewall's THREE failure states, at the script AND at the action.

⚠️ Two defects motivate this file, and they are the same shape: a control that
reports success while inert, or a failure state erased before anyone sees it.

  #1076  a rule file with no RULES (zero-byte / all-comment / all-whitespace)
         exits 0 CLEAN. The guard tests that the file EXISTS, not that it has
         content — so a truncated sync or a debugging session that commented
         everything out disarms the scan silently.

  #1077  `xargs` substitutes its own exit status, so on the explicit-files path
         exit 2 arrives as 1. A misconfigured gate becomes indistinguishable
         from a caught leak.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
PROBE = "ZZZSYNTHETICPROBE"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2


def repo(tmp_path: Path, rules: str | None) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    if rules is not None:
        (r / "dl.txt").write_text(rules)
    (r / "leak.md").write_text(f"leak {PROBE} here\n")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return r


def run(r: Path, *args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], cwd=r, input=stdin,
                          capture_output=True)


# --- #1076: a rule file with no rules must be MISCONFIGURED -------------------

@pytest.mark.parametrize("rules,label", [
    ("", "zero-byte"),
    ("# only a comment\n# and another\n", "all-comment"),
    ("   \n\t\n \n", "all-whitespace"),
])
def test_a_rule_file_with_no_rules_is_MISCONFIGURED(tmp_path, rules, label):
    """⚠️ Not clean. A scan with nothing to scan against passes every file, which
    looks exactly like safety. `check-estate-identifiers.py` already refuses to
    run on an empty pattern list for this reason; the firewall must too."""
    r = repo(tmp_path, rules)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"a {label} rule file exited {p.returncode}; a rule file with no rules "
        f"must never report clean")


def test_the_empty_rules_message_is_distinct_from_not_found(tmp_path):
    """⚠️ Otherwise the operator hunts for a missing file that is present."""
    r = repo(tmp_path, "# nothing\n")
    err = run(r, "--denylist=dl.txt", "--all-tracked").stderr.decode()
    assert "no rules" in err or "no patterns" in err
    assert "not found" not in err


def test_a_real_rule_file_still_matches(tmp_path):
    """Control: the new guard must not be satisfied by breaking everything."""
    r = repo(tmp_path, PROBE + "\n")
    assert run(r, "--denylist=dl.txt", "--all-tracked").returncode == MATCHED


def test_a_missing_rule_file_is_still_MISCONFIGURED(tmp_path):
    r = repo(tmp_path, PROBE + "\n")
    assert run(r, "--denylist=nope.txt", "--all-tracked").returncode == MISCONFIGURED


# --- #1077: exit codes must survive the explicit-files path -------------------

@pytest.mark.parametrize("rules,expected,label", [
    (PROBE + "\n", MATCHED, "a match is 1"),
    ("ZZZNOTHINGMATCHESTHIS\n", CLEAN, "no match is 0"),
    (None, MISCONFIGURED, "a missing rule file is 2"),
])
def test_every_exit_code_survives_the_explicit_file_list(tmp_path, rules, expected, label):
    """⚠️ All three, not just 2. A test covering only the misconfigured case
    would pass an implementation that broke the distinction between 0 and 1."""
    r = repo(tmp_path, rules)
    p = run(r, "--denylist=dl.txt", "--files0", stdin=b"leak.md\0")
    assert p.returncode == expected, f"{label}: got {p.returncode}"


def test_the_explicit_list_is_NUL_safe_so_a_space_in_a_path_still_scans(tmp_path):
    """⚠️ The #1075 regression must not return via this path."""
    r = repo(tmp_path, PROBE + "\n")
    (r / "has space.md").write_text(f"leak {PROBE} here\n")
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    p = run(r, "--denylist=dl.txt", "--files0", stdin=b"has space.md\0")
    assert p.returncode == MATCHED
