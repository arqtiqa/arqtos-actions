"""The denylist falsifier — a STANDING proof that a committed denylist bites.

⚠️ arqtiqa/arqtos#361. `arqtiqa/arqtos-cli#831` requires every repository's
denylist to be covered by a falsifier test. For all but a handful of repos
that requirement was discharged by a ONE-TIME, NARRATED, MANUAL DRY-RUN on the
day the gate was enabled — evidence the list bit once, on one day, against one
tree. Nothing re-runs it, and every way a denylist decays leaves the gate
GREEN:

  * a rule edited into a form that still COMPILES but matches nothing
    (`arqtos-cli#1092` was this one level down: the shared script reported
    CLEAN when `grep` REJECTED a pattern)
  * a rule deleted during an unrelated edit
  * a rule widened until it matches ordinary content

These tests are the falsifier's own falsifier. Each one is a specific way the
mechanism could report coverage it does not have, written so that a mechanism
which merely *runs* cannot pass them:

  * NEUTERING one rule into a compiling-but-non-matching form must turn it RED
    — and the test asserts the mutation ACTUALLY APPLIED and ACTUALLY CHANGED
    BEHAVIOUR first, because a mutation that compiles and changes nothing
    reads exactly like coverage.
  * DELETING a rule must turn it RED. This is the direction a "count the
    violations" design is blind to: deleting a rule shrinks the rule set, so
    "every rule fires" stays trivially true over the smaller set. The orphaned
    probe is what turns it red.
  * ADDING a rule with no probe behind it must turn it RED.
  * A BENIGN LOOKALIKE must not fire — the mirror failure, a rule widened
    until it matches everything, satisfies every other assertion perfectly.
  * The caller's own `.firewallignore` must NOT suppress the probes. The
    corpus is exempted for the caller's real gate (it is a file full of
    denylist-shaped strings by construction); if that suppression reached the
    falsifier, the falsifier would assert nothing while staying green.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FALSIFIER = ROOT / ".github/actions/firewall-falsifier/check-denylist-liveness.sh"
SCANNER = ROOT / ".github/actions/firewall/check-private-content.sh"

LIVE, DEAD, MISCONFIGURED = 0, 1, 2

# Synthetic rules and the synthetic strings that fire them. Nothing here is a
# real credential shape on purpose: these tests are about the MECHANISM, and a
# test fixture that carried real secret-shaped text would need exemptions of
# its own to survive this repository's own gate.
RULE_A = "ZZZSYNTHETICPROBEALPHA[0-9]{4}"
HIT_A = "ZZZSYNTHETICPROBEALPHA1234"
RULE_B = "ZZZSYNTHETICPROBEBETA-[a-z]{3}"
HIT_B = "ZZZSYNTHETICPROBEBETA-xyz"
# ⚠️ Begins with hyphens, mirroring the real PEM-header rule. `grep` parses a
# leading-hyphen pattern as an OPTION unless `-e` is used — the live defect
# arqtos-cli#1069 filed, where the highest-severity rule was silently never
# applied in CI. A falsifier that could not carry such a probe would be blind
# to exactly the class of rule that failure hit.
RULE_C = "-----ZZZSYNTHETIC [A-Z ]*PROBE GAMMA-----"
HIT_C = "-----ZZZSYNTHETIC WHOLLY FAKE PROBE GAMMA-----"
BENIGN = "an ordinary sentence with no probe shape in it at all"


def corpus(matches: list[str], lookalikes: list[str]) -> str:
    return (
        "# synthetic falsifier corpus\n"
        "[must-match]\n"
        + "".join(m + "\n" for m in matches)
        + "\n[must-not-match]\n"
        + "".join(m + "\n" for m in lookalikes)
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    (r / "dl.txt").write_text(f"# a denylist\n{RULE_A}\n{RULE_B}\n{RULE_C}\n")
    (r / ".firewall-probes").write_text(corpus([HIT_A, HIT_B, HIT_C], [BENIGN]))
    return r


def run(r: Path, *args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    argv = [str(FALSIFIER), "--denylist=dl.txt", f"--scanner={SCANNER}", *args]
    return subprocess.run(argv, cwd=r, capture_output=True, text=True, env=env)


# --- the mechanism, working ------------------------------------------------

def test_a_corpus_covering_every_rule_reports_the_denylist_LIVE(repo):
    p = run(repo)
    assert p.returncode == LIVE, f"expected LIVE, got {p.returncode}\n{p.stderr}"
    assert "all 3 rule(s) proven live" in p.stderr


def test_the_run_STATES_that_probes_are_scanned_with_exemptions_disabled(repo):
    """⚠️ Never silent. The corpus is exempted for the caller's REAL gate; a
    reader of this log must be able to tell that the falsifier did not inherit
    that suppression, without reading the source to find out."""
    p = run(repo)
    assert p.returncode == LIVE
    assert "exemptions DISABLED" in p.stderr


# --- RED when a rule is NEUTERED -------------------------------------------

def test_a_rule_NEUTERED_into_a_compiling_but_non_matching_form_is_RED(repo):
    """⚠️ THE CENTRAL TEST. This is arqtos-cli#1092's failure mode: a rule that
    still compiles, so nothing errors, and matches nothing, so the gate stays
    green over content it was meant to catch.

    The mutation is verified THREE ways before its effect is asserted, because
    a mutation that did not apply, or applied and changed nothing, reads
    exactly like coverage:

      1. the denylist file's bytes actually changed
      2. the mutated rule still COMPILES (grep accepts it) — otherwise this
         would be testing the already-covered "grep rejected the pattern"
         path (exit 2), not the silent one
      3. the mutated rule no longer matches the probe, while the ORIGINAL
         did — the behaviour change is real, not assumed
    """
    dl = repo / "dl.txt"
    before = dl.read_text()
    probe_file = repo / "probe.txt"
    probe_file.write_text(HIT_A + "\n")

    # (3a) the ORIGINAL rule matches the probe.
    assert subprocess.run(["grep", "-qE", "-e", RULE_A, str(probe_file)]).returncode == 0, (
        "the unmutated rule must match its probe, or this test proves nothing")

    # A digit-count bump: still a valid ERE, still obviously a rule, matches
    # nothing this corpus (or any realistic content) contains.
    neutered = RULE_A.replace("[0-9]{4}", "[0-9]{40}")
    dl.write_text(before.replace(RULE_A, neutered))

    # (1) the mutation applied.
    assert dl.read_text() != before, "the mutation did not apply"
    assert neutered in dl.read_text()
    # (2) it still compiles — this is the SILENT failure mode, not the loud one.
    compiles = subprocess.run(["grep", "-qE", "-e", neutered, str(probe_file)])
    assert compiles.returncode in (0, 1), (
        f"the mutated rule must still COMPILE (grep exit 0 or 1), got {compiles.returncode}; "
        "a rule grep rejects is the already-covered exit-2 path, not this one")
    # (3b) and it no longer matches.
    assert compiles.returncode == 1, "the mutated rule still matches — the mutation changed nothing"

    p = run(repo)
    assert p.returncode == DEAD, (
        f"a neutered rule must be RED, got {p.returncode}\n{p.stderr}")
    assert "not exercised by any probe" in p.stderr

    # restore, and prove the RED was caused by the mutation and nothing else
    dl.write_text(before)
    assert run(repo).returncode == LIVE, "restoring the rule must restore GREEN"


def test_the_neutered_rule_is_named_by_HANDLE_and_line_number_not_by_its_text(repo):
    """A CI log is a wider audience than a repository, and several callers of
    this action are public. `sha256:` + 12 hex locates the rule exactly and
    quotes nothing — and it is the same vocabulary `.firewallignore` uses
    (arqtiqa/arqtos#365), so the handle can be pasted straight into one."""
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text().replace(RULE_A, RULE_A.replace("[0-9]{4}", "[0-9]{40}")))
    p = run(repo)
    assert p.returncode == DEAD
    assert "rule sha256:" in p.stderr
    assert "dl.txt:2" in p.stderr, f"the rule's line number must be reported\n{p.stderr}"


# --- RED when a rule is DELETED --------------------------------------------

def test_a_DELETED_rule_is_RED_via_its_orphaned_probe(repo):
    """⚠️ THE DIRECTION A VIOLATION-COUNT DESIGN IS BLIND TO.

    Asserting `violations == rule_count` cannot see a deletion: remove a rule
    and BOTH sides drop by one, so the equality still holds and the build stays
    green. What remains is a probe that fires nothing, and that is what has to
    be checked."""
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text().replace(RULE_B + "\n", ""))
    assert RULE_B not in dl.read_text(), "the deletion did not apply"

    p = run(repo)
    assert p.returncode == DEAD, f"a deleted rule must be RED, got {p.returncode}\n{p.stderr}"
    assert "fired NO rule" in p.stderr
    assert ".firewall-probes:4" in p.stderr, f"the orphaned probe's line must be named\n{p.stderr}"


# --- RED when a rule is ADDED with no probe --------------------------------

def test_a_rule_ADDED_with_no_probe_behind_it_is_RED(repo):
    """Nobody ever demonstrated the new rule bites. It may be a typo that
    matches nothing, and it would ship as coverage."""
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text() + "ZZZSYNTHETICPROBEDELTA[0-9]{2}\n")
    p = run(repo)
    assert p.returncode == DEAD, f"an unprobed rule must be RED, got {p.returncode}\n{p.stderr}"
    assert "not exercised by any probe" in p.stderr


# --- RED on a FALSE POSITIVE -----------------------------------------------

def test_a_benign_lookalike_that_FIRES_is_RED(repo):
    """The mirror failure: a rule widened until it matches ordinary content
    satisfies every coverage assertion perfectly. The lookalike is the
    requirement, so widening a rule must break the build rather than the
    lookalike being deleted to make it pass."""
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text().replace(RULE_A, "ordinary"))
    (repo / ".firewall-probes").write_text(
        corpus(["an ordinary hit", HIT_B, HIT_C], [BENIGN]))
    p = run(repo)
    assert p.returncode == DEAD, f"a firing lookalike must be RED, got {p.returncode}\n{p.stderr}"
    assert "lookalike FIRED" in p.stderr
    assert "fired: sha256:" in p.stderr


def test_a_clean_run_reports_the_lookalikes_it_actually_proved_inert(repo):
    (repo / ".firewall-probes").write_text(
        corpus([HIT_A, HIT_B, HIT_C], [BENIGN, "another perfectly ordinary line"]))
    p = run(repo)
    assert p.returncode == LIVE
    assert "2 lookalike(s) proven inert" in p.stderr


# --- the caller's exemptions must not reach the falsifier -------------------

def test_the_callers_own_firewallignore_does_NOT_suppress_the_probes(repo):
    """⚠️ THE SELF-MATCH TRAP, CLOSED.

    The corpus is a file full of denylist-shaped strings, so the caller's REAL
    gate fires on it and the caller commits `.firewallignore` entries to
    exempt it — explicitly, per rule, with reasons. If that suppression leaked
    into the falsifier, every probe would be suppressed and the falsifier
    would prove nothing while reporting success. The script passes an EMPTY
    exemptions file rather than no exemptions file for exactly this reason:
    the scanner then takes its explicit-path branch and never falls back to
    whatever `.firewallignore` sits in the CWD."""
    (repo / ".firewallignore").write_text(
        f"*  {RULE_A}  a blanket exemption that must not reach the falsifier\n"
        f"*  {RULE_B}  ditto\n"
        f"*  {RULE_C}  ditto\n"
    )
    p = run(repo)
    assert p.returncode == LIVE, (
        f"probes must still fire despite a blanket .firewallignore, got {p.returncode}\n{p.stderr}")

    # and the same file must not be able to HIDE a dead rule either
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text().replace(RULE_A, RULE_A.replace("[0-9]{4}", "[0-9]{40}")))
    p = run(repo)
    assert p.returncode == DEAD, (
        f"a blanket .firewallignore must not mask a dead rule, got {p.returncode}\n{p.stderr}")


def test_an_ambient_identity_overlay_cannot_pollute_the_fired_rule_set(repo):
    """Overlay liveness is arqtiqa/arqtos#344's job and an overlay pattern is a
    SECRET, so no committed corpus can probe one. An overlay left in the
    environment would union extra patterns into every scan here, fire on
    probes, and make the fired-rule set nondeterministic — so all three
    overlay variables are stripped from each invocation rather than merely
    left unset."""
    import os

    env = dict(os.environ)
    env["ARQTOS_FIREWALL_IDENTITY_OVERLAY"] = "ZZZSYNTHETIC"
    env["ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY"] = "true"
    p = run(repo, env=env)
    assert p.returncode == LIVE, (
        f"an ambient overlay must not change the verdict, got {p.returncode}\n{p.stderr}")
    assert "identity overlay" not in p.stderr.replace("no identity overlay", "")


# --- misconfiguration is never a pass --------------------------------------

def test_a_MISSING_corpus_is_MISCONFIGURED_not_nothing_to_check(repo):
    """"No falsifier ran" is precisely the state this Story exists to end, and
    a skipped check renders green exactly like a passing one."""
    (repo / ".firewall-probes").unlink()
    p = run(repo)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "probe corpus not found" in p.stderr


def test_a_MISSING_denylist_is_MISCONFIGURED(repo):
    (repo / "dl.txt").unlink()
    p = run(repo)
    assert p.returncode == MISCONFIGURED


def test_an_EMPTY_must_match_section_is_MISCONFIGURED_not_a_pass(repo):
    (repo / ".firewall-probes").write_text(corpus([], [BENIGN]))
    p = run(repo)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "no [must-match] probes" in p.stderr


def test_an_EMPTY_must_not_match_section_is_MISCONFIGURED_not_a_pass(repo):
    """Without a lookalike, a rule widened until it matches everything passes
    every other assertion here."""
    (repo / ".firewall-probes").write_text(corpus([HIT_A, HIT_B, HIT_C], []))
    p = run(repo)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "no [must-not-match] lookalikes" in p.stderr


def test_a_TYPOD_section_header_is_MISCONFIGURED_not_a_silently_empty_section(repo):
    """A typo'd header would otherwise drop every probe beneath it — a corpus
    that proves nothing while looking complete."""
    (repo / ".firewall-probes").write_text(
        "[must-match]\n" + HIT_A + "\n[must-not-mach]\n" + BENIGN + "\n")
    p = run(repo)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "unknown section header" in p.stderr


def test_a_probe_BEFORE_any_section_header_is_MISCONFIGURED(repo):
    (repo / ".firewall-probes").write_text(
        HIT_A + "\n[must-match]\n" + HIT_B + "\n[must-not-match]\n" + BENIGN + "\n")
    p = run(repo)
    assert p.returncode == MISCONFIGURED
    assert "before the first section header" in p.stderr


def test_an_empty_denylist_is_MISCONFIGURED(repo):
    (repo / "dl.txt").write_text("# all comments, no rules\n")
    p = run(repo)
    assert p.returncode == MISCONFIGURED
    assert "contains no rules" in p.stderr


def test_a_rule_grep_REJECTS_is_MISCONFIGURED_not_a_dead_rule(repo):
    """⚠️ arqtos-cli#1092's own lesson, applied one layer up. grep has THREE
    outcomes and an uncompilable pattern is not "did not match" — the scanner
    exits 2 for it, and this must pass that through rather than reporting the
    rule merely dead (which an author would fix by editing the corpus)."""
    dl = repo / "dl.txt"
    dl.write_text(dl.read_text() + "[unclosed\n")
    p = run(repo)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "configuration error" in p.stderr


# --- the invocation contract itself ----------------------------------------

def test_a_SPACE_separated_flag_is_REFUSED_not_silently_ignored(repo):
    """⚠️ The sibling scanner treats an unrecognised bare argument as a FILE to
    scan, which is how `--denylist <path>` degrades there into scanning a file
    literally named `--denylist` and exiting having examined nothing. This
    script has no positional operands, so anything unrecognised is a mistake."""
    p = subprocess.run(
        [str(FALSIFIER), "--denylist", "dl.txt", f"--scanner={SCANNER}"],
        cwd=repo, capture_output=True, text=True)
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{p.stderr}"
    assert "unrecognised argument" in p.stderr


def test_no_denylist_at_all_is_MISCONFIGURED(repo):
    p = subprocess.run(
        [str(FALSIFIER), f"--scanner={SCANNER}"],
        cwd=repo, capture_output=True, text=True)
    assert p.returncode == MISCONFIGURED
    assert "no denylist supplied" in p.stderr


def test_help_prints_the_module_doc_without_truncating_it(repo):
    p = subprocess.run([str(FALSIFIER), "--help"], capture_output=True, text=True)
    assert p.returncode == 0
    assert "WHY THIS EXISTS" in p.stdout
    assert "REPORTS NAME RULES BY HANDLE" in p.stdout, (
        "the help text stopped short of the end of the module doc")


# --- this repository's own corpus ------------------------------------------

def test_THIS_repositorys_own_denylist_is_proven_live_by_its_own_corpus():
    """⚠️ Dogfood. arqtos-actions ships the gate AND is subject to it; its own
    pin sat two mechanisms behind its own `main` once (arqtiqa/arqtos#346),
    which is how #348 shipped a mechanism that made the action unloadable for
    every consumer. The repository that ships a falsifier must be the first
    repository the falsifier runs against."""
    p = subprocess.run(
        [str(FALSIFIER),
         "--denylist=.github/scripts/private-content-denylist.txt",
         f"--scanner={SCANNER}"],
        cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == LIVE, (
        f"this repo's own denylist is not proven live: {p.returncode}\n{p.stderr}")
