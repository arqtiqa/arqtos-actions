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

Round 1 review (same Story) found two more, both fixed here and pinned below:

  6. The overlay pattern was reaching a CHILD PROCESS's own argv via
     `grep -e "$line"`. Argv is a WEAKER channel than the env var this
     script reads the overlay from in the first place — on Linux,
     `/proc/<pid>/cmdline` is world-readable while `/proc/<pid>/environ`
     is owner-only, so the hop made the pattern LESS protected, not more.
     Fixed by feeding the pattern through `-f <(printf '%s\n' "$line")`
     instead — verified here with a `grep` shim that records its own argv,
     so the absence of the pattern text is observed, not assumed.
  7. The overlay was reusing the denylist's `existing_files`, which drops
     (a) the denylist file itself, (b) a byte-identical vendored copy of
     it, and (c) the exemptions file — a rationale specific to a pattern
     list matching its OWN literal text, which does not extend to an
     identity string that can plausibly sit in any of those three files
     (a denylist header, for instance). Fixed by giving the overlay its
     own file list with none of those three skips; pinned in both
     directions below — the overlay must now see all three, and the
     denylist must still skip them.

Round 2 review (same Story) caught a regression the round-1 restructure
introduced, plus a test that did not exercise what it claimed to:

  8. `grep -f <pattern-file> <files...>` with ZERO file operands does not
     skip — it falls back to reading grep's own STDIN. Before round 1,
     `overlay_scan_files` (via `existing_files`) was guaranteed non-empty
     by an early `exit 0` this Story's restructure removed, so the overlay
     loop never had to guard against an empty file list itself. Fixed with
     the same `(( ${#target[@]} == 0 )) && continue` guard the denylist
     loop already uses for its own `scan_targets`. The prior version of
     `test_overlay_scan_files_empty_array_is_nounset_safe` used `--files0`
     with empty stdin, which made `files` itself empty and exited the
     script at the very first "no files" shortcut — never reaching the
     overlay loop at all. Replaced with a construction (`_nonexistent_file_scenario`)
     that keeps `files` non-empty while forcing `overlay_scan_files` empty,
     and two dedicated tests for the two reproduced symptoms (phantom
     `(standard input)` match, and an outright hang).
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


def _nonexistent_file_scenario(tmp_path):
    """Builds the shape round-2 review needed: `files` NON-empty (one
    positional argument naming a path) but `overlay_scan_files` EMPTY
    (that path does not exist anywhere, so the `[[ -f "$f" ]]` filter drops
    it). A plain positional arg is used rather than `--files0`, because
    `--files0` reads ITS file list from the same stdin a buggy overlay loop
    would fall back to — which would consume the very stdin this scenario
    needs free to prove the regression with. `dl.txt` itself is never
    added to `files` at all here (no `--all-tracked`), so it cannot
    accidentally supply a real file to `overlay_scan_files` the way it did
    in an earlier, broken version of this test."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    add(r)
    return r


def test_overlay_scan_files_empty_array_is_nounset_safe(tmp_path):
    """⚠️ `overlay_scan_files` is a NEW array (the overlay's own file list,
    independent of the denylist's `existing_files`) and it can legitimately
    be empty. An overlay WITH real patterns but nothing left to scan them
    against must not abort under bash 3.2's nounset."""
    r = _nonexistent_file_scenario(tmp_path)
    p = run(r, "--denylist=dl.txt", "ghost.md", overlay=IDENTITY_PROBE,
            bash="/bin/bash")
    err = p.stderr.decode()
    assert "unbound variable" not in err, f"got:\n{err}"
    assert p.returncode == CLEAN, f"stderr:\n{err}"


# --- #8: the overlay must not fall back to reading the process's own stdin
#     when its file list is empty (round-2 review; BLOCKING) ----------------
#
# ⚠️ `grep -f <pattern-file> <files...>` with ZERO file operands does not
# skip the scan — it falls back to reading grep's OWN stdin as an implicit
# sole input, exactly as POSIX specifies ("If no file operands are
# specified, the standard input shall be used"). Two reproduced failure
# modes without a guard: a TTY (or any open, not-yet-EOF stdin — a local
# run, the pre-push gate) hangs forever; a piped stdin WITH data gets
# scanned as a phantom "(standard input)" file, inventing a violation out
# of whatever unrelated bytes happened to be on the pipe. Verified by
# mutation before committing the fix: with the guard stripped out of a
# throwaway copy of the script, both symptoms reproduced exactly as
# described (phantom `(standard input)` match / exit 1, and a hang past a
# multi-second timeout); with the guard restored, neither does.

def test_overlay_does_not_invent_a_phantom_violation_from_piped_stdin(tmp_path):
    """The 'pipe stdin with data' half. Stdin carries data that CONTAINS
    the overlay probe — if the guard were missing, grep would read it as
    an implicit input file and report a match at `(standard input):1`."""
    r = _nonexistent_file_scenario(tmp_path)
    stdin_bytes = f"unrelated data mentioning {IDENTITY_PROBE} that must never be scanned\n".encode()
    p = subprocess.run(
        ["/bin/bash", str(SCRIPT), "--denylist=dl.txt", "ghost.md"],
        cwd=r, input=stdin_bytes, capture_output=True, timeout=15,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
             "ARQTOS_FIREWALL_IDENTITY_OVERLAY": IDENTITY_PROBE})
    combined = p.stdout.decode() + p.stderr.decode()
    assert "(standard input)" not in combined, (
        f"the overlay grep fell back to scanning the process's own stdin as "
        f"a phantom file:\n{combined}")
    assert p.returncode == CLEAN, (
        f"expected clean (nothing left for the overlay to scan), got "
        f"{p.returncode}\n{combined}")


def test_overlay_does_not_hang_on_a_blocking_stdin(tmp_path):
    """The TTY half. Stdin is an open pipe with no data and no EOF yet —
    exactly what a real TTY looks like to a blocking reader. Uses `wait()`,
    never `communicate()`: `communicate()` closes the child's stdin as part
    of its own protocol even when given no input, which would silently turn
    this into the OTHER case (immediate EOF) and prove nothing about a hang.
    A short timeout keeps a regression a FAILED test, never an actually
    hung suite."""
    r = _nonexistent_file_scenario(tmp_path)
    proc = subprocess.Popen(
        ["/bin/bash", str(SCRIPT), "--denylist=dl.txt", "ghost.md"],
        cwd=r, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
             "ARQTOS_FIREWALL_IDENTITY_OVERLAY": IDENTITY_PROBE})
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
        pytest.fail(
            "the overlay loop blocked on stdin instead of skipping a rule "
            "with nothing left to scan -- this is the hang a real TTY (or "
            "the pre-push gate) would hit forever, not just for 10s")
    assert proc.returncode == CLEAN, f"expected clean, got {proc.returncode}"


# --- #6: the overlay pattern never reaches a child process's argv ----------

GREP_SHIM = """#!/bin/sh
printf 'ARGV:' >> "$GREP_ARGV_LOG"
for a in "$@"; do printf ' [%s]' "$a" >> "$GREP_ARGV_LOG"; done
printf '\\n' >> "$GREP_ARGV_LOG"
exec /usr/bin/grep "$@"
"""


def test_overlay_pattern_never_reaches_greps_own_argv(tmp_path):
    """⚠️ Round-1 finding. `grep -e "$line"` puts the OVERLAY pattern on a
    CHILD process's command line — on Linux, /proc/<pid>/cmdline is
    world-readable while /proc/<pid>/environ (where this script itself reads
    the overlay from) is owner-only, so that hop makes a confidential
    identity pattern LESS protected than it was one step earlier. Verified
    directly with a `grep` shim that records its own argv to a file — the
    absence of the pattern text is OBSERVED here, not inferred from exit
    codes or report output."""
    shim_dir = tmp_path / "shimbin"
    shim_dir.mkdir()
    grep_shim = shim_dir / "grep"
    grep_shim.write_text(GREP_SHIM)
    grep_shim.chmod(0o755)
    argv_log = tmp_path / "grep_argv.log"

    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"identity leak: {IDENTITY_PROBE} here\n")
    add(r)

    env = {
        "PATH": f"{shim_dir}:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
        "ARQTOS_FIREWALL_IDENTITY_OVERLAY": IDENTITY_PROBE,
        "GREP_ARGV_LOG": str(argv_log),
    }
    p = subprocess.run([str(SCRIPT), "--denylist=dl.txt", "--all-tracked"],
                        cwd=r, capture_output=True, env=env)
    assert p.returncode == MATCHED, f"stderr:\n{p.stderr.decode()}"

    argv_log_text = argv_log.read_text() if argv_log.exists() else ""
    assert argv_log_text, "the grep shim never recorded an invocation"
    assert IDENTITY_PROBE not in argv_log_text, (
        f"the overlay pattern reached a child process's argv:\n{argv_log_text}")
    # Positive control: the CREDENTIAL pattern is still on `-e`'s argv, same
    # as before this round — only the overlay hop changed.
    assert CREDENTIAL_PROBE in argv_log_text, (
        f"the denylist loop's own -e usage should be untouched:\n{argv_log_text}")
    assert " -f " in argv_log_text or "[-f]" in argv_log_text, (
        f"expected the overlay grep call to use -f; got:\n{argv_log_text}")


def test_overlay_leading_hyphen_pattern_still_applies_via_dash_f(tmp_path):
    """A nice side effect of `-f`: a pattern beginning with `-` was never
    grep's problem in the first place when fed via a file rather than argv
    (unlike the denylist's own `-e` loop, which needs `-e` for exactly this
    reason). Confirms the fix didn't accidentally break this class.

    ⚠️ Assembled at runtime, NEVER written as a literal (matches
    `tests/test_firewall_failure_states.py`'s `HYPHEN_RULE` convention) --
    this repo's own denylist carries this exact PEM pattern
    (`.github/scripts/private-content-denylist.txt`), and a literal here
    would trip `arqtos-actions`' own `firewall` CI check against its own
    source, on this very file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    hyphen_pattern = "-" * 5 + "BEGIN [A-Z ]*PRIVATE KEY" + "-" * 5
    (r / "leak.md").write_text("-" * 5 + "BEGIN OPENSSH PRIVATE KEY" + "-" * 5 + "\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=hyphen_pattern)
    assert p.returncode == MATCHED, f"stderr:\n{p.stderr.decode()}"


# --- #7: the three denylist self-skips do NOT apply to the overlay ---------

def test_overlay_scans_the_denylist_file_itself(tmp_path):
    """⚠️ Round-1 finding #2. The denylist skips itself (its own rule text
    self-matches). An identity string sitting in the denylist's own header
    is a real, cited scenario (`denylists/work.txt`'s header) — the overlay
    must still catch it."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(f"# header mentioning {IDENTITY_PROBE}\n{CREDENTIAL_PROBE}\n")
    (r / "other.md").write_text("clean prose\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"the overlay must scan the denylist file itself; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_denylist_still_self_skips_while_overlay_scans_the_same_file(tmp_path):
    """The other direction, in the SAME fixture: the denylist's own
    self-skip must be untouched — its own pattern text must not self-match
    — even though the overlay now scans that exact file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(f"# header mentioning {IDENTITY_PROBE}\n{CREDENTIAL_PROBE}\n")
    (r / "other.md").write_text("clean prose\n")
    add(r)
    # No overlay: the denylist's own rule text must not self-match its own file.
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    assert p.returncode == CLEAN, (
        f"the denylist's self-skip must still hold; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_overlay_scans_a_byte_identical_vendored_denylist_copy(tmp_path):
    """The denylist's vendored-copy skip (arqtos#343) must not extend to the
    overlay either — an identity string in a vendored copy is just as real
    a leak as one in the primary denylist."""
    r = repo(tmp_path)
    dl_text = f"# header mentioning {IDENTITY_PROBE}\n{CREDENTIAL_PROBE}\n"
    (r / "dl.txt").write_text(dl_text)
    (r / "sub").mkdir()
    (r / "sub" / "dl.txt").write_text(dl_text)  # byte-identical vendored copy
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"the overlay must scan a vendored denylist copy too; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_denylist_still_skips_the_vendored_copy_while_overlay_scans_it(tmp_path):
    r = repo(tmp_path)
    dl_text = f"# header mentioning {IDENTITY_PROBE}\n{CREDENTIAL_PROBE}\n"
    (r / "dl.txt").write_text(dl_text)
    (r / "sub").mkdir()
    (r / "sub" / "dl.txt").write_text(dl_text)
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert "skipping vendored denylist" in err, f"got:\n{err}"


def test_overlay_scans_the_firewallignore_file(tmp_path):
    """The exemptions file's skip (its <rule> column is literal denylist-
    pattern text) must not extend to the overlay — an identity string in a
    `.firewallignore` reason field is a real, plausible leak."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / ".firewallignore").write_text(
        f"*.md\t{CREDENTIAL_PROBE}\treason mentioning {IDENTITY_PROBE}\n")
    (r / "other.md").write_text(f"leak {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"the overlay must scan .firewallignore too; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_denylist_exemption_still_applies_while_overlay_scans_firewallignore(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / ".firewallignore").write_text(
        f"*.md\t{CREDENTIAL_PROBE}\treason mentioning {IDENTITY_PROBE}\n")
    (r / "other.md").write_text(f"leak {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, (
        f"the denylist's exemption for other.md must still apply; got "
        f"{p.returncode}\nstderr:\n{err}")
    assert "exempted" in err, f"got:\n{err}"


def test_overlay_violation_survives_even_when_the_denylist_has_nothing_left_to_scan(tmp_path):
    """⚠️ Control-flow regression guard for the round-1 fix. When the only
    files in a run are the denylist and the exemptions file, the DENYLIST
    side's `existing_files` is empty — the script used to `exit 0` right
    there, before the overlay (previously positioned after that shortcut)
    ever ran. The overlay must now still be evaluated and its violation
    must still surface, since it runs on its own file list, ahead of that
    shortcut."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(f"# header mentioning {IDENTITY_PROBE}\n{CREDENTIAL_PROBE}\n")
    (r / ".firewallignore").write_text(f"*.md\t{CREDENTIAL_PROBE}\tsynthetic\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"an overlay violation must not be swallowed just because the "
        f"denylist side has nothing left to scan; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_clean_when_neither_side_has_anything_to_scan_or_match(tmp_path):
    """Control for the test above — the same empty-existing_files shape,
    but with no overlay match either, must still report clean (not
    accidentally always-1 after the control-flow change)."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / ".firewallignore").write_text(f"*.md\t{CREDENTIAL_PROBE}\tsynthetic\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    assert p.returncode == CLEAN, f"stderr:\n{p.stderr.decode()}"
