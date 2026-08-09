"""The firewall's exemptions mechanism — a caller-supplied `.firewallignore`.

⚠️ The Go implementation (`arqtos`'s in-binary firewall verb) has carried a
committed path+rule exemptions file since arqtiqa/arqtos-cli#851. This shell
scanner is what CI actually runs, and until now it read no ignore file at
all: `grep -c 'firewallignore\\|ignore'` over this script returned 0. Any
repo whose fixtures legitimately contain denylist-shaped text (a doc
teaching a credential-ref syntax by example, a detector's own test fixture)
got a PERMANENTLY red gate on entirely legitimate content — and a
permanently-red gate gets disabled rather than obeyed.

These tests exist to prove the mechanism does exactly what it claims, no
more:

  * an exemption suppresses ONLY the (path, rule) pair it names — a file
    exempted for rule A must still FAIL on rule B (arqtos-cli#851's own
    scoping discipline: never rule-only, never path-only)
  * a STALE exemption (a path glob matching no tracked file, or a rule not
    present in the denylist in force) is a configuration error (exit 2),
    never a silent no-op (arqtos-cli#986's precedent: one stale line
    aborted every run at validation and left 21 new fixtures unexamined)
  * an absent exemptions file changes nothing — exit 0/1 paths are
    byte-identical to a build with no exemptions mechanism at all
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
PROBE_A = "ZZZSYNTHETICPROBEALPHA"
PROBE_B = "ZZZSYNTHETICPROBEBETA"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2


def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    return r


def add(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(r: Path, *args: str, stdin: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], cwd=r, input=stdin,
                           capture_output=True)


# --- absent exemptions file: no behaviour change --------------------------

def test_no_firewallignore_present_is_not_an_error_and_a_real_violation_still_fires(tmp_path):
    """⚠️ The common case today. An absent DEFAULT exemptions file must never
    itself be a configuration error — only an explicitly-named missing path is."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        f"a real violation must still fire with no .firewallignore present, got {p.returncode}")


def test_an_explicitly_named_missing_exemptions_path_is_MISCONFIGURED(tmp_path):
    """⚠️ Unlike the default convention path, a path the caller NAMES on purpose
    is a deliberate pointer — naming one that does not exist is a mistake, not
    an optional convention silently ignored."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--exemptions=nope.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"an explicit --exemptions path that does not exist must be a config "
        f"error, got {p.returncode}")


# --- the core mechanism: suppress exactly what is named --------------------

def test_an_exemption_suppresses_its_own_named_violation(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"a fully-exempted violation must report clean, got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_the_default_convention_path_is_honoured_with_no_flag_at_all(tmp_path):
    """The default IS `.firewallignore` at the scan root — no --exemptions
    flag should be required to pick it up."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, f"default .firewallignore not honoured, got {p.returncode}"


def test_an_explicit_exemptions_flag_is_honoured(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / "custom.exempt").write_text(f"leak.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--exemptions=custom.exempt", "--all-tracked")
    assert p.returncode == CLEAN, f"explicit --exemptions path not honoured, got {p.returncode}"


# --- ⚠️ the sharpest test in this file: the gate must still BITE -----------

def test_a_file_exempted_for_rule_A_still_fails_on_rule_B(tmp_path):
    """⚠️ arqtos-cli#851's own non-negotiable: scope is path + SPECIFIC rule,
    never "skip every rule for this path". An exemption that suppressed more
    than its own named rule would blind the gate to a second, genuinely
    different violation landing in the same already-exempted file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n" + PROBE_B + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\nleak {PROBE_B} here\n")
    (r / ".firewallignore").write_text(f"leak.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        f"rule B was not exempted and must still fire; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")
    err = p.stderr.decode()
    assert PROBE_B in err, "the surviving violation must name the still-live rule"
    assert f"pattern: {PROBE_A}" not in err, "the exempted rule must not also be reported"


def test_an_exemption_does_not_suppress_the_same_rule_in_an_unrelated_file(tmp_path):
    """⚠️ The mirror non-negotiable: scope is path + rule, never "skip this
    rule everywhere". Exempting one file must not blind the gate to the same
    secret shape landing in a completely different file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "fixture.md").write_text(f"leak {PROBE_A} here\n")
    (r / "real-leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"fixture.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        f"the unrelated file's violation must still fire; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")
    assert "real-leak.md" in p.stderr.decode()


def test_two_rules_on_the_same_file_need_two_entries(tmp_path):
    """A fixture needing two rules exempted gets TWO entries — one entry
    naming only rule A leaves rule B live in the very same file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n" + PROBE_B + "\n")
    (r / "fixture.md").write_text(f"leak {PROBE_A} here\nleak {PROBE_B} here\n")
    (r / ".firewallignore").write_text(
        f"fixture.md\t{PROBE_A}\treason one\n"
        f"fixture.md\t{PROBE_B}\treason two\n"
    )
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"both entries together must fully exempt the fixture, got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


# --- ⚠️ fail closed on a stale entry (arqtos-cli#986's precedent) ----------

def test_a_path_glob_matching_no_tracked_file_is_MISCONFIGURED(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"nosuchfile.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"a path glob matching no tracked file must be a config error, not a "
        f"silent no-op; got {p.returncode}")
    assert ".firewallignore:1" in p.stderr.decode()


def test_a_rule_absent_from_the_active_denylist_is_MISCONFIGURED(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md\tZZZNEVERINDENYLIST\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"a rule not present in the active denylist must be a config error, "
        f"not a silent no-op; got {p.returncode}")


def test_a_stale_entry_aborts_BEFORE_scanning_not_just_at_the_end(tmp_path):
    """⚠️ arqtos-cli#986's precedent: validation runs BEFORE the scan, so a
    stale entry must not let a genuine, unrelated violation slip through
    reported as clean — the whole run must refuse, examining nothing."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n" + PROBE_B + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_B} here\n")  # a REAL, unexempted violation
    (r / ".firewallignore").write_text(f"nosuchfile.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED, (
        f"a stale exemption must abort at validation, not fall through to a "
        f"partial scan; got {p.returncode}")
    assert "pattern:" not in p.stderr.decode(), (
        "validation must run before scanning -- no rule should have been "
        "applied yet")


# --- malformed exemption lines: every field is MANDATORY -------------------

def test_a_line_with_only_one_field_is_MISCONFIGURED(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text("onefieldonly\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED
    assert "expected three fields" in p.stderr.decode()


def test_a_line_missing_the_reason_field_is_MISCONFIGURED(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md\t{PROBE_A}\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED
    assert "reason" in p.stderr.decode()


def test_a_single_space_between_fields_is_not_a_valid_separator(tmp_path):
    """⚠️ The format is a TAB or 2+ spaces, deliberately — a single space is
    ordinary prose punctuation, not a field boundary. A single-space-joined
    line must therefore read as ONE field, not three."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md {PROBE_A} reason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED
    assert "expected three fields" in p.stderr.decode()


def test_two_spaces_between_fields_is_a_valid_separator(tmp_path):
    """The control for the test above: 2+ spaces DOES count."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md  {PROBE_A}  reason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN


def test_a_reason_with_internal_double_spaces_is_not_mis_split(tmp_path):
    """⚠️ Only the FIRST TWO separators split fields. A reason that itself
    contains a double-space run must stay in ONE reason field, not spill
    into a spurious fourth."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(
        f"leak.md\t{PROBE_A}\tsynthetic fixture -- see  the golden corpus for details\n"
    )
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"a double-space inside the reason field must not break parsing, got "
        f"{p.returncode}\nstderr:\n{p.stderr.decode()}")


@pytest.mark.parametrize("rules", [
    "leak.md\t\treason\n",       # empty rule
    "\tPROBE\treason\n",          # empty glob (leading tab makes glob empty)
])
def test_an_empty_mandatory_field_is_MISCONFIGURED(tmp_path, rules):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(rules)
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED


def test_a_zero_byte_reason_after_trailing_whitespace_is_MISCONFIGURED(tmp_path):
    """A reason field that trims down to empty (trailing spaces only) must
    not silently pass as present."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"leak.md   {PROBE_A}   \n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == MISCONFIGURED
    assert "reason" in p.stderr.decode()


# --- comments and blank lines are ignored, same convention as the denylist -

def test_comments_and_blank_lines_in_the_exemptions_file_are_ignored(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "leak.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(
        "# a header comment\n"
        "\n"
        "   \n"
        f"leak.md\t{PROBE_A}\tsynthetic fixture, not a real leak\n"
        "# a trailing comment\n"
    )
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, f"comments/blank lines broke parsing, got {p.returncode}"


# --- self-skip: the exemptions file must not trip its own listed rules -----

def test_the_exemptions_file_does_not_self_match_its_own_rule_text(tmp_path):
    """⚠️ An exemption's <rule> column is literal denylist-pattern text. Without
    a self-skip, `.firewallignore` would report a false violation against
    itself on every run that used a broad, self-matching pattern."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "clean.md").write_text("nothing to see here\n")
    (r / ".firewallignore").write_text(
        f"clean.md\t{PROBE_A}\tthis reason mentions {PROBE_A} by name\n"
    )
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"the exemptions file must skip itself from scanning, got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


# --- arqtos-cli#998 parity: a scoped scan must not report an out-of-scope --
# --- exemption as stale ----------------------------------------------------

def test_an_exemption_outside_a_scoped_file_list_is_not_falsely_stale(tmp_path):
    """A caller scanning only an explicit subset of files (a PR diff, say)
    must not have every exemption OUTSIDE that subset reported as stale --
    the glob is checked against the full tracked tree before being called
    stale, exactly like the reference Go implementation's own widening fix."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "exempted.md").write_text(f"leak {PROBE_A} here\n")
    (r / "other.md").write_text("nothing here\n")
    (r / ".firewallignore").write_text(f"exempted.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--files0", stdin=b"other.md\0")
    assert p.returncode == CLEAN, (
        f"an out-of-scope exemption must not be reported stale, got "
        f"{p.returncode}\nstderr:\n{p.stderr.decode()}")


def test_a_genuinely_stale_glob_still_fails_even_on_a_scoped_scan(tmp_path):
    """The control for the widening test above: a glob that matches NOTHING
    anywhere (not even the full tracked tree) must still be caught."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "other.md").write_text("nothing here\n")
    (r / ".firewallignore").write_text(f"genuinely-nowhere.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--files0", stdin=b"other.md\0")
    assert p.returncode == MISCONFIGURED, (
        f"a genuinely stale glob must still fail on a scoped scan, got "
        f"{p.returncode}")


# --- glob matching: '*' must not cross a path separator --------------------

def test_a_star_glob_matches_within_one_path_segment(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "fixtures").mkdir()
    (r / "fixtures" / "tokens.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"fixtures/*.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    assert p.returncode == CLEAN, f"a same-segment '*' glob should match, got {p.returncode}"


def test_a_star_glob_does_not_cross_a_path_separator(tmp_path):
    """⚠️ filepath.Match-style: '*' matches any sequence of non-'/' characters.
    A glob written for one directory level must not silently exempt a nested
    subdirectory too -- that would be a wider suppression than the entry's
    author reviewed."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(PROBE_A + "\n")
    (r / "fixtures" / "nested").mkdir(parents=True)
    (r / "fixtures" / "nested" / "tokens.md").write_text(f"leak {PROBE_A} here\n")
    (r / ".firewallignore").write_text(f"fixtures/*.md\t{PROBE_A}\treason\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked")
    # The glob fixtures/*.md matches no tracked file (only the nested one
    # exists) -> stale exemption -> MISCONFIGURED, not a silent pass-through.
    assert p.returncode == MISCONFIGURED, (
        f"'*' crossing '/' would silently widen this exemption's reach; "
        f"got {p.returncode}")
