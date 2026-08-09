"""The identity-tier overlay — `ARQTOS_FIREWALL_IDENTITY_OVERLAY` (arqtiqa/arqtos#342).

The firewall has two tiers. CREDENTIAL patterns ship in a committed
`denylist` file. IDENTITY patterns are deliberately committed nowhere — they
are distributed as the org secret `ARQTOS_FIREWALL_IDENTITY_OVERLAY` and
supplied at runtime, because embedding them would compile confidential regex
text into a world-readable release asset regardless of which tier a caller
selected. Before this, the shared action had no way to accept that secret at
all, so every repo using it enforced credential patterns only.

These tests prove five things, each of which cost someone an incident before:

  1. The overlay is genuinely APPLIED, not merely accepted — a synthetic
     overlay-only pattern (absent from the denylist entirely) fails a run
     that would otherwise be clean.
  2. An ABSENT overlay is explicit, never silent — the run still works and
     STATES that it scanned credential-tier only, mirroring the reference Go
     verb's own `tier=work (no overlay)` vs `+overlay` honesty.
  3. An EMPTY overlay (supplied, but resolving to zero usable pattern lines —
     all-comment, all-whitespace, a truncated secret) is a MISCONFIGURATION
     (exit 2), never a pass — distinct from "absent", which is legitimate.
     There is no `--allow-empty` escape hatch (arqtos-skills#85's lesson).
  4. The overlay's own pattern TEXT is never printed in the report, on
     either the match path or the pattern-compile-failure path
     (arqtiqa/arqtos-cli#1009: the same string reaching `arqtos doctor`
     stdout was a defect) — verified directly, not assumed from GitHub
     Actions' log masking, which this script does not depend on.
  5. Every array touched by the new logic is nounset-safe under bash 3.2 (the
     stock `/bin/bash` on macOS and this repo's CI baseline) — an unguarded
     `"${arr[@]}"` on an empty array aborts under `set -u`. This file's
     helper invokes `/bin/bash` explicitly (not just the shebang) for the
     one test that would abort first if that guard were ever dropped.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
IDENTITY_PROBE = "ZZZSYNTHETICIDENTITYPROBE"
CREDENTIAL_PROBE = "ZZZSYNTHETICCREDENTIALPROBE"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2


def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    return r


def add(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(r: Path, *args: str, overlay: str | None = None,
        bash: str | None = None) -> subprocess.CompletedProcess:
    """Invoke the script with FULL control over the overlay env var —
    NEVER inherited ambiently from the pytest process, so these tests are
    deterministic regardless of what happens to be exported in whatever
    shell runs `pytest`.

    `overlay=None` means the env var is UNSET (the "absent" state);
    `overlay=""` or any string means it IS set, to that value (the
    "supplied" state, even when the value is the empty string).
    """
    env: dict[str, str] = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    if overlay is not None:
        env["ARQTOS_FIREWALL_IDENTITY_OVERLAY"] = overlay
    argv = [bash, str(SCRIPT)] if bash else [str(SCRIPT)]
    return subprocess.run([*argv, *args], cwd=r, capture_output=True, env=env)


# --- #1: the overlay is genuinely APPLIED, not merely accepted -------------

def test_an_overlay_only_pattern_fails_a_run_the_denylist_alone_would_pass(tmp_path):
    """⚠️ The core proof. The denylist's own pattern does not appear anywhere
    in the tree — a denylist-only run would be CLEAN. Only the overlay
    pattern is present. If this fails, the overlay was accepted as an input
    but never actually unioned into the scan."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"identity leak: {IDENTITY_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"an overlay-only pattern must fail the run; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_an_overlay_pattern_absent_from_the_tree_still_reports_clean(tmp_path):
    """Mirror case — a real overlay that simply does not match must not make
    the run fail for the wrong reason (control for the test above)."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text("ordinary prose, nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == CLEAN, (
        f"expected clean, got {p.returncode}\nstderr:\n{p.stderr.decode()}")


def test_overlay_and_denylist_patterns_both_fire_independently(tmp_path):
    """Both tiers are live at once — a denylist violation is still caught
    when an overlay is also supplied and does not itself match."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"credential leak: {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED


# --- #2: absent is legitimate, and must be STATED, never silent ------------

def test_no_overlay_still_works_and_states_credential_tier_only(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert "no identity overlay" in err, (
        f"a run with no overlay must say so explicitly; got:\n{err}")
    assert "credential-tier only" in err, f"got:\n{err}"


def test_a_supplied_overlay_states_the_overlay_pattern_count(tmp_path):
    """The honesty statement's mirror half — matching the reference Go
    verb's `tier=work (N patterns) +overlay=... (M patterns)`."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked",
            overlay=IDENTITY_PROBE + "\nZZZSECONDIDENTITYPROBE\n")
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert "+identity overlay (2 pattern(s))" in err, f"got:\n{err}"


def test_a_green_run_with_an_overlay_never_reads_as_credential_tier_only(tmp_path):
    """⚠️ The inverse of the statement above must never ALSO be printed — a
    caller grepping the log for "credential-tier only" as a red flag must
    never get a false negative because both strings were emitted."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == CLEAN
    assert "credential-tier only" not in err, f"got:\n{err}"


# --- #3: EMPTY (supplied, zero patterns) vs ABSENT (unset) -----------------

@pytest.mark.parametrize("overlay,label", [
    ("# only a comment\n", "all-comment"),
    ("   \n\t\n \n", "all-whitespace"),
    ("# a comment\n   \n", "mixed comment and whitespace"),
])
def test_a_supplied_but_zero_pattern_overlay_is_MISCONFIGURED(tmp_path, overlay, label):
    """⚠️ NOT the same state as "absent". A caller who wired the input but
    got nothing usable back (a truncated secret, a bad merge, a debugging
    session that commented everything out) must be refused, never waved
    through as a clean scan — that scan would be checking nothing."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=overlay)
    assert p.returncode == MISCONFIGURED, (
        f"a {label} overlay exited {p.returncode}; a zero-pattern overlay "
        f"must never report clean\nstderr:\n{p.stderr.decode()}")


def test_the_zero_pattern_overlay_message_explains_itself(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    err = run(r, "--denylist=dl.txt", "--all-tracked",
              overlay="# nothing here\n").stderr.decode()
    assert "no rules" in err
    assert "ARQTOS_FIREWALL_IDENTITY_OVERLAY" in err


def test_there_is_no_allow_empty_escape_hatch_for_the_overlay(tmp_path):
    """⚠️ arqtos-skills#85's lesson, ported. A zero-pattern overlay must not
    be recoverable into a pass by ANY flag this script accepts. Uses a
    genuinely non-empty-but-zero-pattern overlay (an all-comment
    placeholder) — the literal empty string is a DIFFERENT, legitimate
    state (see the absent-vs-empty tests below) and would not exercise
    this at all."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    for flag in ("--allow-empty", "--overlay-allow-empty", "--force"):
        p = run(r, "--denylist=dl.txt", flag, "--all-tracked",
                overlay="# placeholder, not filled in yet\n")
        assert p.returncode != CLEAN, (
            f"{flag} must not turn a zero-pattern overlay into a pass")


def test_an_unset_overlay_env_var_is_absent_not_misconfigured(tmp_path):
    """⚠️ The control this whole distinction rests on. "Absent" (the env var
    was never set at all) and "empty-after-filtering" (it was set, but to
    nothing usable) must NOT collapse into the same outcome — the former is
    every existing caller today and must keep working unchanged."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    assert p.returncode == CLEAN, (
        f"an unset overlay must behave exactly like a build with no overlay "
        f"mechanism at all, got {p.returncode}\nstderr:\n{p.stderr.decode()}")


def test_an_overlay_set_to_the_literal_empty_string_is_ALSO_absent(tmp_path):
    """⚠️ A composite action input that is never wired by the caller and one
    explicitly set to `''` are INDISTINGUISHABLE at this action's boundary —
    GitHub Actions composite inputs always resolve to a string, never a true
    "unset" sentinel (an omitted `with:` field just fills in the `default`).
    So the literal empty string is deliberately treated exactly like
    "unset": legitimate, stated, credential-tier-only — never a
    misconfiguration. This is the ONLY coherent rule given that constraint,
    and it is what makes every one of the 15 existing callers (which supply
    no `identity-overlay` input at all, defaulting to `''`) keep working
    unchanged."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay="")
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert "no identity overlay" in err, f"got:\n{err}"


# --- #4: the overlay's pattern TEXT is never printed ------------------------

def test_overlay_pattern_text_is_absent_from_the_match_report_line(tmp_path):
    """⚠️ Verified directly, not assumed from Actions' log masking (this
    script has no idea whether it is even running under Actions). The
    report line naming WHICH pattern fired must be redacted; the matched
    FILE's own content (the operator's own data, not the detector's secret)
    is unaffected and still shown, exactly as the credential tier already
    does."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"identity leak: {IDENTITY_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == MATCHED
    pattern_report_lines = [ln for ln in err.splitlines() if ln.startswith("✗ pattern:")]
    assert pattern_report_lines, f"no pattern: report line found in:\n{err}"
    overlay_report = [ln for ln in pattern_report_lines if "identity overlay" in ln]
    assert overlay_report, f"no identity-overlay pattern: line found in:\n{err}"
    for ln in overlay_report:
        assert IDENTITY_PROBE not in ln, (
            f"the overlay pattern's own text leaked onto its report line: {ln!r}")
        assert "text withheld" in ln, f"expected a withheld-text marker, got: {ln!r}"


def test_overlay_pattern_text_never_appears_anywhere_when_it_fails_to_compile(tmp_path):
    """⚠️ The strongest form of the check. An uncompilable pattern never
    matches any file, so there is no legitimate reason for its text to
    appear ANYWHERE in the combined output — a much cleaner falsifier than
    the match case above, where the operator's own matched content
    legitimately contains a substring of what fired."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    canary = "ZZZCANARYUNCOMPILABLEOVERLAYPATTERNTEXT"
    bad_pattern = "[unclosed" + canary
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=bad_pattern)
    combined = p.stdout.decode() + p.stderr.decode()
    assert p.returncode == MISCONFIGURED, f"stderr:\n{p.stderr.decode()}"
    assert canary not in combined, (
        f"the overlay pattern's text leaked into the output:\n{combined}")


def test_overlay_compile_failure_still_names_arqtos_cli_1009_for_the_operator(tmp_path):
    """The redaction must not degrade into total silence about WHY — the
    operator still needs to know an overlay pattern is broken, just not
    WHAT it is."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    err = run(r, "--denylist=dl.txt", "--all-tracked",
              overlay="[unclosed").stderr.decode()
    assert "identity overlay pattern #1" in err
    assert "arqtos-cli#1009" in err


# --- #5: bash 3.2 nounset safety on the new arrays --------------------------

def test_empty_overlay_array_is_nounset_safe_under_bash_3_2(tmp_path):
    """⚠️ macOS's stock /bin/bash is 3.2.57, which throws "unbound variable"
    on a bare "${arr[@]}" when arr is EMPTY under `set -u`. This is the
    exact class of bug the file's `"${arr[@]+"${arr[@]}"}"` idiom already
    exists to prevent elsewhere; the new overlay_rules array must follow the
    same discipline. Pinned to /bin/bash explicitly rather than relying on
    the shebang, so this stays a real regression guard even on a machine
    whose PATH would otherwise resolve `env bash` to a newer version."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None, bash="/bin/bash")
    assert p.returncode == CLEAN, (
        f"an empty overlay array must not abort the script under bash 3.2's "
        f"nounset; got {p.returncode}\nstderr:\n{p.stderr.decode()}")
    assert "unbound variable" not in p.stderr.decode()


def test_empty_overlay_array_is_nounset_safe_on_a_matched_run_too(tmp_path):
    """The overlay loop runs AFTER the denylist loop regardless of whether
    the denylist already matched — the empty-array guard must hold there
    too, not just on the clean path."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"credential leak: {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None, bash="/bin/bash")
    assert p.returncode == MATCHED
    assert "unbound variable" not in p.stderr.decode()
