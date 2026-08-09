"""Exempting an IDENTITY-OVERLAY rule — rule handles (arqtiqa/arqtos#365).

Before this, the exemptions validator resolved a `.firewallignore` entry's
`<rule>` field against the on-disk denylist ONLY, and the identity-overlay
matches ran in a separate loop with no exemption filtering at all. The two
consequences compounded into a gate that could not be adopted:

    wire `identity-overlay:` alone            -> exit 1 on every run
    wire it AND a `.firewallignore` entry     -> exit 2 on every run, worse
                                                 ("rule does not match any
                                                  active denylist pattern")

So any repository with even ONE legitimate identity match — which, given
what the overlay is for, is most repositories worth wiring it on — had no
path to a green gate. That is the permanently-red gate arqtiqa/arqtos#341
was filed about, one tier up.

⚠️ THE DESIGN PROBLEM: `.firewallignore` IS COMMITTED, THE RULE IS A SECRET.

An overlay pattern arrives in the `ARQTOS_FIREWALL_IDENTITY_OVERLAY` secret
and is confidential identity regex (arqtiqa/arqtos-cli#1009 filed exactly
that text reaching a log as a defect). So the exemption has to name a rule
it must never quote. The mechanism is a RULE HANDLE: `sha256:` plus the
first 12 lowercase hex digits of the SHA-256 of the pattern's exact text.

The rejected alternative was a positional index (`overlay:3`), and it is
rejected for one reason: it fails OPEN. Reorder or insert a rule in the
secret and every exemption silently re-points at a DIFFERENT rule,
suppressing something nobody reviewed, with nothing anywhere able to detect
it — strictly worse than no exemption mechanism at all, because it reads as
a reviewed decision. A digest cannot re-point. The two properties are pinned
directly below, not argued:

  * REORDER the overlay -> every handle still names its own rule
    (test_reordering_the_overlay_leaves_every_handle_on_its_own_rule)
  * EDIT a rule -> the handle resolves to nothing, the exemption is HELD
    INERT, the edited rule scans that path again, and the run goes RED
    (test_editing_an_exempted_overlay_rule_makes_the_run_red_again)

⚠️ AND THE REPORT ITSELF WAS A DISCLOSURE. A violation printed grep's own
`file:line:CONTENT`. For an identity rule the matched CONTENT *is* the
confidential string, so a run that caught an identity leak republished it
into the CI log — world-readable on a public repository. #365 withholds the
content as well as the pattern, and prints the rule's handle instead, which
is also what an author needs in order to write the exemption.
"""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
IDENTITY_PROBE = "ZZZSYNTHETICIDENTITYPROBE"
IDENTITY_PROBE_TWO = "ZZZSYNTHETICIDENTITYPROBETWO"
CREDENTIAL_PROBE = "ZZZSYNTHETICCREDENTIALPROBE"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2


def handle(pattern: str) -> str:
    """The handle the script must derive for `pattern`.

    Computed here INDEPENDENTLY of the script (Python's own hashlib, not by
    invoking the script and reading back what it printed), so this also pins
    the digest's definition: the SHA-256 of the pattern's exact bytes with NO
    trailing newline, truncated to 12 lowercase hex digits. The reference Go
    implementation computes the same value the same way, which is what lets
    ONE committed exemptions file serve both engines.
    """
    return "sha256:" + hashlib.sha256(pattern.encode()).hexdigest()[:12]


def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    return r


def add(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(r: Path, *args: str, overlay: str | None = None) -> subprocess.CompletedProcess:
    """Invoke the script with FULL control over the overlay env var — never
    inherited ambiently from the pytest process, so these tests are
    deterministic regardless of what is exported in whatever shell runs
    `pytest`. `overlay=None` means UNSET (absent); any string means SET.
    """
    env: dict[str, str] = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    if overlay is not None:
        env["ARQTOS_FIREWALL_IDENTITY_OVERLAY"] = overlay
    return subprocess.run([str(SCRIPT), *args], cwd=r, capture_output=True, env=env)


# --- AC-1: an entry naming an overlay rule VALIDATES rather than exiting 2 ---

def test_an_exemption_naming_an_overlay_rule_by_handle_validates(tmp_path):
    """⚠️ THE DEFECT, DIRECTLY. Pre-#365 this exact input exited 2 with
    "rule does not match any active denylist pattern" — the overlay tier's
    rules were simply not part of the set `<rule>` resolved against."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\tinternal governance note, not a publication path\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode != MISCONFIGURED, (
        f"an exemption naming an overlay rule by handle must VALIDATE, not exit 2\n{err}")
    assert "does not match any active denylist pattern" not in err, f"got:\n{err}"


def test_an_exemption_naming_an_overlay_rule_verbatim_also_validates(tmp_path):
    """Go parity on the VALIDATOR. The reference implementation unions tier +
    overlay and compares `<rule>` against every active Pattern.Source
    verbatim, so the shell must resolve the verbatim form too — otherwise one
    committed exemptions file cannot serve both engines.

    ⚠️ AND THE VERBATIM FORM IS NOT MERELY UNSAFE FOR AN OVERLAY RULE — IT IS
    UNUSABLE. `.firewallignore` is itself scanned by the overlay (arqtos#342
    round 1: the denylist's three self-skips deliberately do NOT extend to the
    identity tier, because an identity string can legitimately sit in any of
    those files). So an entry quoting an overlay pattern turns the exemptions
    file into an overlay hit of its own, on line 1, and the run fails no
    matter how many other paths it exempted. Pinned here in exactly that
    shape: the entry RESOLVES (no exit 2 — the defect this Story closes), and
    then the file it is written in fires. This is why the handle is not a
    convenience over the verbatim form; it is the only form that can work at
    all for an overlay rule.
    """
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{IDENTITY_PROBE}\tverbatim form, for Go parity\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode != MISCONFIGURED, (
        f"the verbatim form must RESOLVE against the overlay -- Go accepts it, "
        f"so the shell must too\n{err}")
    assert "does not match any active denylist pattern" not in err, f"got:\n{err}"
    # notes.md WAS exempted -- the entry works. What fires is the exemptions
    # file itself, now carrying the identity string it had to quote.
    assert p.returncode == MATCHED, f"got {p.returncode}\n{err}"
    assert ".firewallignore:1" in err, (
        f"the surviving hit must be the exemptions file's own quoted text\n{err}")
    assert "notes.md" not in err, (
        f"the exemption itself must still have applied to the path it named\n{err}")


# --- AC-2: exempted does not fail; NON-exempted still does ------------------

def test_an_exempted_overlay_match_does_not_fail_the_run(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\tinternal governance note, not a publication path\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"an exempted overlay match must not fail the run\n{err}"
    assert "exempted 1 file/rule pair(s)" in err, (
        f"suppression must be DISCLOSED, never silent\n{err}")


def test_a_non_exempted_overlay_match_still_fails_the_run(tmp_path):
    """⚠️ The half that makes the half above worth having. The exemption
    mechanism must not become an off switch for the tier."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"an overlay match with no exemption must still fail\n{p.stderr.decode()}")


# --- AC-3 ⚠️: an exemption is scoped to ONE path and ONE rule ---------------

def test_exempting_an_overlay_rule_for_one_path_leaves_it_live_elsewhere(tmp_path):
    """⚠️ THE SHARPEST TEST IN THIS FILE. If exempting a rule for one path
    disabled that rule globally, the exemption would be a rule-level off
    switch wearing a path's clothes — and the file that looks reviewed would
    be blinding the gate everywhere else. Same scoping discipline
    arqtos-cli#851 fixed for the denylist tier, now on the overlay tier."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "exempted.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / "elsewhere.md").write_text(f"a DIFFERENT file naming {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"exempted.md\t{handle(IDENTITY_PROBE)}\tonly this one path is reviewed\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == MATCHED, (
        f"the SAME overlay rule must still fire on a path the exemption does "
        f"not name; got {p.returncode}\n{err}")
    assert "elsewhere.md" in err, f"the surviving violation must name the other path\n{err}"
    assert "exempted.md" not in err, (
        f"the exempted path must not appear in the violation report\n{err}")


def test_exempting_one_overlay_rule_leaves_another_live_on_the_same_path(tmp_path):
    """The other axis of the same discipline: never "skip every rule for this
    path". A file exempted for rule A still fails on rule B."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"{IDENTITY_PROBE} and also {IDENTITY_PROBE_TWO}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\tonly rule A is reviewed for this path\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked",
            overlay=f"{IDENTITY_PROBE}\n{IDENTITY_PROBE_TWO}\n")
    err = p.stderr.decode()
    assert p.returncode == MATCHED, (
        f"the un-exempted second overlay rule must still fire on the same "
        f"file; got {p.returncode}\n{err}")
    assert handle(IDENTITY_PROBE_TWO) in err, (
        f"the violation must name the rule that actually fired\n{err}")
    assert handle(IDENTITY_PROBE) not in err, (
        f"the exempted rule must not be reported\n{err}")


def test_a_denylist_exemption_does_not_suppress_an_overlay_hit_on_the_same_path(tmp_path):
    """Cross-tier scoping: an entry naming a DENYLIST rule must not carry
    over to the identity tier just because both matched the same file."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"{CREDENTIAL_PROBE} and {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{CREDENTIAL_PROBE}\tcredential-shaped fixture, reviewed\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert p.returncode == MATCHED, (
        f"the overlay hit must survive a denylist-scoped exemption\n{p.stderr.decode()}")


# --- ⚠️ the handle's whole justification: reorder-stable, edit-visible ------

def test_reordering_the_overlay_leaves_every_handle_on_its_own_rule(tmp_path):
    """⚠️ THE REASON THIS IS A DIGEST AND NOT A POSITION (`overlay:3`).

    The same `.firewallignore` is run against two overlays that differ ONLY
    in the order of their two rules. A positional handle would silently
    re-point at the other rule between these two runs — exempting a rule
    nobody reviewed while still reading as a reviewed decision, with nothing
    anywhere able to notice. A digest is derived from the rule's own text,
    so order is not part of its identity and neither run moves.
    """
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"only rule A applies here: {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\treviewed: rule A on this path only\n")
    add(r)

    forward = run(r, "--denylist=dl.txt", "--all-tracked",
                  overlay=f"{IDENTITY_PROBE}\n{IDENTITY_PROBE_TWO}\n")
    reversed_ = run(r, "--denylist=dl.txt", "--all-tracked",
                    overlay=f"{IDENTITY_PROBE_TWO}\n{IDENTITY_PROBE}\n")

    assert forward.returncode == CLEAN, f"stderr:\n{forward.stderr.decode()}"
    assert reversed_.returncode == CLEAN, (
        f"reordering the overlay changed the verdict -- the handle re-pointed, "
        f"which is the positional-index failure mode this design exists to "
        f"avoid\nstderr:\n{reversed_.stderr.decode()}")


def test_editing_an_exempted_overlay_rule_makes_the_run_red_again(tmp_path):
    """⚠️ FAIL CLOSED, PROVEN. Edit the rule the exemption named — here by
    broadening it — and the digest moves, so the handle resolves to nothing
    and the exemption is HELD INERT. The edited rule then scans the path it
    used to be exempted from, still matches, and the run turns RED. The
    suppression can only ever be LOST by an edit, never transferred to a
    rule nobody reviewed."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\treviewed against the rule as it was\n")
    add(r)

    before = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    assert before.returncode == CLEAN, (
        f"precondition: the exemption must apply before the edit\n{before.stderr.decode()}")

    # Same rule, edited (a suffix-optional broadening). Its text changed, so
    # its digest changed, so the committed handle no longer names it.
    after = run(r, "--denylist=dl.txt", "--all-tracked",
                overlay=IDENTITY_PROBE + "(PROBE)?")
    err = after.stderr.decode()
    assert after.returncode == MATCHED, (
        f"editing the exempted rule must make the run RED again, not silently "
        f"keep the exemption alive; got {after.returncode}\n{err}")
    assert "held INERT" in err, (
        f"an inert exemption must be DISCLOSED, never silently dropped\n{err}")


def test_an_unresolvable_handle_is_inert_rather_than_a_configuration_error(tmp_path):
    """⚠️ The fork-pull-request / Dependabot case, and why an unresolvable
    HANDLE is inert while an unresolvable VERBATIM rule is still exit 2.

    GitHub withholds org secrets from a fork PR and from Dependabot, so an
    overlay-wired repository runs those WITHOUT the overlay — with the same
    committed `.firewallignore`. Exit 2 there would make every external
    contribution red on exactly the repositories whose purpose is external
    contribution: the arqtos-skills#85 failure mode that arqtiqa/arqtos#344
    already accommodates for this same withheld secret. Nothing is
    under-scanned, because the tier the entry names did not run at all."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\treviewed; resolves only when the overlay is present\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, (
        f"a committed overlay exemption must not turn a credential-tier-only "
        f"run into a configuration error; got {p.returncode}\n{err}")
    assert "held INERT" in err, f"the inert entry must be disclosed\n{err}"
    assert "no identity overlay" in err, f"got:\n{err}"


def test_a_verbatim_rule_matching_no_active_pattern_is_still_exit_2(tmp_path):
    """The unchanged half of the fail-closed contract. Verbatim text names a
    rule set that is entirely present in this run, so a miss really is
    staleness — arqtos-cli#851's rule, and its message, untouched."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text("ordinary prose\n")
    (r / ".firewallignore").write_text(
        "notes.md\tZZZRULETHATNEVEREXISTED\tstale on purpose\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{err}"
    assert "does not match any active denylist pattern" in err, f"got:\n{err}"


def test_a_stale_path_glob_on_a_handle_entry_is_still_exit_2(tmp_path):
    """Inert applies to the RULE axis only. A path glob matching no tracked
    file is checkable without the overlay and stays a configuration error,
    handle or not."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"gone.md\t{handle(IDENTITY_PROBE)}\tpath deleted long ago\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    err = p.stderr.decode()
    assert p.returncode == MISCONFIGURED, f"got {p.returncode}\n{err}"
    assert "matches no tracked file" in err, f"got:\n{err}"


# --- ⚠️ arqtos#344's fail-closed contract must not weaken -------------------

def test_an_absent_overlay_is_still_exit_2_when_it_is_REQUIRED(tmp_path):
    """arqtiqa/arqtos#344's contract, re-pinned from this Story's side: an
    overlay exemption sitting in the repo must not talk a REQUIRED-but-absent
    overlay into a pass."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\treviewed\n")
    add(r)
    p = subprocess.run(
        [str(SCRIPT), "--denylist=dl.txt", "--all-tracked"], cwd=r, capture_output=True,
        env={"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin",
             "ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY": "true"})
    assert p.returncode == MISCONFIGURED, (
        f"require-identity-overlay must still refuse an absent overlay; got "
        f"{p.returncode}\n{p.stderr.decode()}")


def test_an_empty_overlay_is_still_exit_2_with_an_overlay_exemption_committed(tmp_path):
    """A supplied-but-zero-pattern overlay reports every file clean, which is
    strictly worse than no overlay at all. Committing an overlay exemption
    must not turn that into a pass either."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    (r / ".firewallignore").write_text(
        f"notes.md\t{handle(IDENTITY_PROBE)}\treviewed\n")
    add(r)
    # ⚠️ The literal empty string means ABSENT, not "supplied but empty" —
    # the distinction arqtiqa/arqtos#342's honesty statement is built on — so
    # only the genuinely-supplied-but-rule-less shapes belong here.
    for value in ("# nothing here\n", "   \n\t\n"):
        p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=value)
        assert p.returncode == MISCONFIGURED, (
            f"a supplied-but-rule-less overlay must stay exit 2 with an overlay "
            f"exemption present; got {p.returncode}\n{p.stderr.decode()}")


# --- ⚠️ the report is not itself a disclosure ------------------------------

def test_the_matched_line_content_is_withheld_from_an_overlay_violation(tmp_path):
    """⚠️ THE CI-LOG DISCLOSURE, CLOSED. The report used to print grep's own
    `file:line:CONTENT`; for an identity rule the matched content IS the
    confidential string, so catching an identity leak republished it into a
    log that is world-readable on a public repository. Path and line number
    are enough to act on and disclose nothing."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"line one\ninternal note about {IDENTITY_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE)
    combined = p.stdout.decode() + p.stderr.decode()
    assert p.returncode == MATCHED, f"stderr:\n{p.stderr.decode()}"
    assert IDENTITY_PROBE not in combined, (
        f"the matched identity string reached the report:\n{combined}")
    assert "notes.md:2" in combined, (
        f"the report must still locate the hit precisely (path and line)\n{combined}")


def test_the_denylist_tier_still_shows_its_matched_content(tmp_path):
    """⚠️ Deliberately NOT widened. A denylist pattern and its match are
    committed, public content — showing the line is what makes a credential
    finding actionable, and withholding it there would be a usability loss
    with no confidentiality gain."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"leak {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == MATCHED, f"stderr:\n{err}"
    assert f"leak.md:1:leak {CREDENTIAL_PROBE} here" in err, (
        f"the credential tier's own file:line:content report must be unchanged\n{err}")


def test_the_violation_report_names_the_handle_so_an_author_never_computes_one(tmp_path):
    """Ergonomics, and the reason a digest is usable at all: the author is
    told the exact handle to paste, in the exact three-field shape, by the
    run that failed."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "notes.md").write_text(f"internal note about {IDENTITY_PROBE}\n")
    add(r)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE).stderr.decode()
    assert handle(IDENTITY_PROBE) in err, (
        f"the report must name the rule's handle\n{err}")
    assert "<path-glob>" in err and "<reason>" in err, (
        f"the report must show the exemption line's shape\n{err}")


# --- additive: a caller with no overlay is untouched ------------------------

def test_a_denylist_only_run_with_a_verbatim_exemption_is_unchanged(tmp_path):
    """⚠️ 14 of this action's 15 callers wire no overlay at all and quote
    rule text verbatim. Nothing about their runs may move."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"leak {CREDENTIAL_PROBE} here\n")
    (r / ".firewallignore").write_text(
        f"leak.md\t{CREDENTIAL_PROBE}\tsynthetic fixture, not a real leak\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"got {p.returncode}\n{err}"
    assert "held INERT" not in err, (
        f"a verbatim-only exemptions file must produce no handle machinery "
        f"output at all\n{err}")


def test_help_documents_the_rule_handle(tmp_path):
    """The help text and the README are the action's surface; a mechanism an
    author cannot discover is a mechanism nobody uses."""
    out = subprocess.run([str(SCRIPT), "--help"], capture_output=True,
                         env={"PATH": "/usr/bin:/bin"}).stdout.decode()
    assert "sha256:" in out, f"--help does not document the rule handle:\n{out}"
    assert "EXEMPTING AN IDENTITY-OVERLAY RULE" in out, (
        f"--help truncates before the section that explains it:\n{out}")
