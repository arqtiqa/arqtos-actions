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


# --- #1069: a pattern beginning with a hyphen must still be APPLIED ----------
#
# ⚠️ Third instance of this file's own shape: an error erased before anyone
# sees it. Without `-e`, grep parses a leading-hyphen pattern as an OPTION,
# exits 2 with "unrecognized option", `2>/dev/null` discards the message, and
# the surrounding `if` reads the failure as "no match" — the rule is silently
# never applied and the scan reports CLEAN.
#
# This was live. The PEM private-key rule begins with five hyphens, so the
# highest-severity class in the secrets tier was unenforced in CI on every
# consuming repo, while the Go scanner matched it locally. CI is the boundary
# guarding the PUBLIC repos, which makes the weaker side the one that counts.
#
# These run on the CI image's GNU grep, which is what the action actually uses
# — the divergence was first seen against BSD grep, and this is what pins the
# behaviour on the engine that matters.

HYPHEN_RULE = "-" * 5 + "BEGIN [A-Z ]*PRIVATE KEY" + "-" * 5


def test_leading_hyphen_pattern_is_applied_not_swallowed(tmp_path: Path) -> None:
    r = repo(tmp_path, HYPHEN_RULE + "\n")
    (r / "leak.md").write_text("-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5 + "\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        "a denylist rule beginning with a hyphen must be APPLIED. Got "
        f"{p.returncode}; without `-e` grep treats it as an option, the error is "
        "discarded, and the scan reports clean.\n"
        f"stderr:\n{p.stderr.decode()}"
    )


def test_leading_hyphen_pattern_still_reports_clean_when_absent(tmp_path: Path) -> None:
    # The mirror case. Without it, a rule that matched EVERYTHING would also
    # satisfy the test above — passing for the wrong reason.
    r = repo(tmp_path, HYPHEN_RULE + "\n")
    (r / "leak.md").write_text("ordinary prose, no credential material\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"expected clean, got {p.returncode}\nstderr:\n{p.stderr.decode()}"
    )


def test_hyphen_rule_does_not_mask_a_normal_rule(tmp_path: Path) -> None:
    # A leading-hyphen rule sits in the same loop as every other rule. If grep
    # aborts on it in a way that terminates the loop, later rules never run —
    # so assert an ordinary rule after it still fires.
    r = repo(tmp_path, HYPHEN_RULE + "\n" + PROBE + "\n")
    (r / "leak.md").write_text(f"leak {PROBE} here\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        "a rule following a leading-hyphen rule must still be evaluated; got "
        f"{p.returncode}\nstderr:\n{p.stderr.decode()}"
    )


# --- #1092: a rule grep cannot COMPILE must be MISCONFIGURED, never clean -----
#
# ⚠️ This is the returning defect, not a new one. arqtiqa/arqtos-cli#831 recorded
# it, then struck it as "gone by construction" when the estate moved to the Go
# in-package verb (an unusable pattern is a ConfigError -> exit 2, with no
# `2>/dev/null` to forget). The estate converged back onto THIS script, and the
# defect came back with the mechanism.
#
# The distinction the old code lost: grep exits 0 on match, 1 on no-match, and
# 2 when it FAILED. `if matches=$(grep ... 2>/dev/null)` collapsed 1 and 2 into
# one branch, so a rule grep refused to compile was read as "no match" — the
# rule silently never applied, and the scan still reported clean.
#
# The `-e` fix above narrowed the TRIGGER (a pattern starting with `-`). These
# tests cover the CLASS.

BAD_RULE = "[unclosed"


def test_uncompilable_rule_is_MISCONFIGURED_not_clean(tmp_path: Path) -> None:
    """⚠️ The core of #1092, and the sharpest test in this file.

    The tree contains a real credential shape. The denylist's only rule is one
    grep cannot compile. Pre-fix this exited 0 — a green gate over a live token,
    which is strictly worse than a red build: the rule turned ITSELF off without
    turning the check red.
    """
    r = repo(tmp_path, BAD_RULE + "\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"an uncompilable rule exited {p.returncode}; a rule that never ran "
        f"cannot be reported as clean — the scan learned nothing about it\n"
        f"stderr:\n{p.stderr.decode()}"
    )


def test_uncompilable_rule_names_itself_and_its_line(tmp_path: Path) -> None:
    """Exit 2 alone sends the operator hunting. The message must say WHICH rule.

    The line number is load-bearing: denylist rules are regexes, several look
    alike, and `dl.txt:2` is the difference between a one-second fix and a
    bisect.
    """
    r = repo(tmp_path, "# a comment\n" + BAD_RULE + "\n")
    err = run(r, "--denylist=dl.txt", "--all-tracked").stderr.decode()
    assert "dl.txt:2" in err, f"the error must locate the rule; got:\n{err}"
    assert BAD_RULE in err, f"the error must quote the rule; got:\n{err}"
    # grep's own diagnostic is the thing `2>/dev/null` used to discard.
    assert "grep:" in err, (
        f"grep's diagnostic must be surfaced, not swallowed; got:\n{err}"
    )


def test_uncompilable_rule_does_not_let_the_scan_pass_on_other_rules(tmp_path: Path) -> None:
    """⚠️ Fail CLOSED, not partially.

    A denylist mixing one bad rule with valid ones must NOT scan the remainder
    and report clean. Partial enforcement reported as success is the same lie in
    a smaller box — the operator reads a green check as "all rules applied".
    """
    r = repo(tmp_path, PROBE + "\n" + BAD_RULE + "\nzzz_other\n")
    (r / "leak.md").write_text("ordinary prose, nothing to match\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"a denylist containing one uncompilable rule exited {p.returncode}; "
        f"it must refuse rather than enforce a subset silently\n"
        f"stderr:\n{p.stderr.decode()}"
    )


def test_a_genuine_no_match_is_still_CLEAN(tmp_path: Path) -> None:
    """⚠️ The control that stops the fix from being 'exit 2 more often'.

    grep's 1 (no match) and 2 (failure) are now different branches. Without this
    test, mapping BOTH to exit 2 would satisfy every assertion above while
    making the gate permanently red — which carries no signal either.
    """
    r = repo(tmp_path, "zzz_never_appears_anywhere\n")
    (r / "leak.md").write_text("ordinary prose\n")
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"a valid rule with no match must be clean, got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}"
    )
