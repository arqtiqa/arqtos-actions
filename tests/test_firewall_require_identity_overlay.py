"""`require-identity-overlay` -- an opt-in that lets a caller INSIST on
identity-tier coverage rather than accepting `#342`'s best-effort default
(arqtiqa/arqtos#344).

⚠️ THE CENTRAL DIFFICULTY THIS FILE PINS. The repositories that most need
required coverage are exactly the ones with external collaborators, where
GitHub withholds the `ARQTOS_FIREWALL_IDENTITY_OVERLAY` secret from a fork
pull request -- and, separately, from a Dependabot-triggered run. A flat
"required means red when absent" would turn every external contribution red
on exactly the repos whose purpose is external contribution, training
reviewers to read red as noise (`arqtos-skills#85`). The fix follows the
precedent `arqtos-skills`' `estate-identifiers` job already established:
skip (never fail) on Dependabot / a fork, and let the merge-time
`push: branches: [main]` run -- which executes with the real secret -- be
the backstop that actually verifies coverage once the change lands.

These tests exercise the SCRIPT directly, exactly as
`test_firewall_identity_overlay.py` does for `#342` -- the two new env vars
this feature reads (`ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY` and
`ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD`) are set directly here, bypassing
`action.yml`'s `github.*`-context expression that would normally compute the
second one. That expression cannot be exercised by pytest at all (there is
no GitHub Actions runtime here) -- it is proven separately by a live
Actions run resolving `uses:` at this branch's SHA (see the Story's
report), which is also the only way to catch a template-validation failure
like `arqtiqa/arqtos#348`'s, a class YAML linting does not catch either.

The matrix, each state proven both to occur AND to say what it is:

  1. require=false (the default: unset, and explicitly 'false') -- BYTE-
     IDENTICAL to `#342`'s existing behaviour, overlay present or absent.
     This is the AC that keeps all 15 existing callers unaffected.
  2. require=true, overlay present & valid -- unchanged: still scans with
     it, still says `+identity overlay (N pattern(s))`.
  3. require=true, overlay present but resolves to zero patterns -- exit 2,
     the SAME message `#342` already produces (this AC was already true
     before this Story; pinned here as a regression guard, not a new
     behaviour).
  4. require=true, overlay absent, context says the secret could exist
     (`ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD` unset/false) -- MISCONFIGURED
     (exit 2). This is the case the Story exists for: never wired.
  5. require=true, overlay absent, context says the secret is legitimately
     withheld (fork PR / Dependabot) -- NOT red. Reports identity coverage
     as required-but-unverified, in text that shares no substring with
     either the plain "no overlay" disclosure (#342, still used when
     require=false) or the "+overlay" disclosure -- so a log reader, or a
     grep, can always tell the three apart. Credential-tier scanning still
     runs and can still fail on ITS OWN merits (a real denylist violation
     still reddens the run) -- outcome 5 only means the OVERLAY tier didn't
     run, not that scanning stopped.
  6. Nounset safety: the new code touches no new arrays (two plain scalar
     flags, both defaulted via `${VAR:-}`), so there is nothing new to
     guard against bash 3.2's `set -u` -- verified directly under
     `/bin/bash` for both new exit paths anyway, because this file has hit
     this exact class of regression twice before.

Round-1 review (same Story) found two more, both fixed here and pinned below:

  7. `require-identity-overlay` is a CALLER-supplied input (unlike
     `ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD`, which action.yml computes
     and always renders a literal 'true'/'false'), so a typo is a real
     hazard: 'TRUE', 'yes', '1' all used to silently no-op the requirement
     -- exactly the silent-degradation class this Story exists to close,
     reappearing in its own argument parser. Now refused (exit 2) rather
     than quietly treated as 'false'.
  8. `action.yml`'s fork/Dependabot predicate used
     `github.event.pull_request.head.repo.fork`, which means "the head repo
     is a fork OF ANYTHING" -- not "the head repo differs from this run's
     OWN repo". A consuming repository that is itself a fork would have
     gotten the withheld-exemption on every same-repo pull request, where
     the secret is in fact available. Fixed to compare
     `head.repo.full_name != github.repository` instead. This lives in
     `action.yml`, so it cannot be pytest-exercised directly (same
     limitation as point 5's context expression above) -- verified by a
     live Actions run instead (see the Story's report).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
IDENTITY_PROBE = "ZZZSYNTHETICIDENTITYPROBE"
CREDENTIAL_PROBE = "ZZZSYNTHETICCREDENTIALPROBE"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2

# The exact three disclosure strings this file pins as MUTUALLY EXCLUSIVE.
NO_OVERLAY_TEXT = "no identity overlay -- credential-tier only"
PLUS_OVERLAY_TEXT = "+identity overlay ("
REQUIRED_UNVERIFIED_TEXT = "REQUIRED but UNVERIFIED"


def repo(tmp_path: Path, name: str = "r") -> Path:
    r = tmp_path / name
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    return r


def add(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(r: Path, *args: str, overlay: str | None = None,
        require: str | None = None, may_be_withheld: str | None = None,
        bash: str | None = None) -> subprocess.CompletedProcess:
    """Mirrors `test_firewall_identity_overlay.py`'s `run()` helper --
    every new env var defaults to UNSET, never ambiently inherited, so a
    test that does not mention one of these flags exercises exactly the
    same environment as the pre-#344 script."""
    env: dict[str, str] = {"PATH": "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"}
    if overlay is not None:
        env["ARQTOS_FIREWALL_IDENTITY_OVERLAY"] = overlay
    if require is not None:
        env["ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY"] = require
    if may_be_withheld is not None:
        env["ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD"] = may_be_withheld
    argv = [bash, str(SCRIPT)] if bash else [str(SCRIPT)]
    return subprocess.run([*argv, *args], cwd=r, capture_output=True, env=env)


def clean_repo(tmp_path: Path, name: str = "r") -> Path:
    r = repo(tmp_path, name)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "innocent.md").write_text("nothing to see\n")
    add(r)
    return r


# --- #1: require=false (the default) is byte-identical to pre-#344 --------

@pytest.mark.parametrize("require_value", [None, "false"])
def test_require_false_or_unset_overlay_absent_is_unchanged(tmp_path, require_value):
    """⚠️ THE AC THIS STORY MUST NOT BREAK. All 15 existing callers never set
    `require-identity-overlay` -- action.yml's default resolves to the
    literal string 'false' for them, but a caller could also omit it
    entirely when invoking the script directly (as a test, or a future
    non-Actions consumer). Both must produce the EXACT pre-#344 message."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None, require=require_value)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert NO_OVERLAY_TEXT in err, f"got:\n{err}"
    assert REQUIRED_UNVERIFIED_TEXT not in err, f"got:\n{err}"


@pytest.mark.parametrize("require_value", [None, "false"])
def test_require_false_or_unset_overlay_present_is_unchanged(tmp_path, require_value):
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE, require=require_value)
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert PLUS_OVERLAY_TEXT in err, f"got:\n{err}"


def test_require_false_never_misconfigures_on_a_missing_overlay_even_in_a_normal_context(tmp_path):
    """Control for #4/#5 below -- PASSES both with and without this Story's
    code, because the pre-#344 script never looks at either new env var, so
    require=false is a no-op on both sides of the change by construction.
    Kept as a control: with require=false, an absent overlay in a perfectly
    ordinary (non-fork, non-Dependabot) context must still be the
    legitimate default -- never exit 2."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="false", may_be_withheld="false")
    assert p.returncode == CLEAN, f"stderr:\n{p.stderr.decode()}"


# --- #2: require=true, overlay present & valid -- unchanged ---------------
#
# ⚠️ Both tests below PASS both with and without this Story's code: the
# pre-#344 script already scans normally whenever the overlay resolves to
# real patterns, regardless of any `require`/context env var it has never
# heard of. Kept as controls pinning the "required + satisfied is
# unchanged" half of the AC, not as RED-without-code proofs.

def test_require_true_with_a_valid_overlay_scans_normally(tmp_path):
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"identity leak: {IDENTITY_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE, require="true")
    err = p.stderr.decode()
    assert p.returncode == MATCHED, f"stderr:\n{err}"
    assert PLUS_OVERLAY_TEXT in err, f"got:\n{err}"


def test_require_true_with_a_valid_overlay_and_a_clean_tree_passes(tmp_path):
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=IDENTITY_PROBE, require="true")
    err = p.stderr.decode()
    assert p.returncode == CLEAN, f"stderr:\n{err}"
    assert PLUS_OVERLAY_TEXT in err, f"got:\n{err}"


# --- #3: require=true, overlay present but zero-pattern -- unchanged from #342

def test_require_true_with_a_zero_pattern_overlay_is_still_MISCONFIGURED(tmp_path):
    """Control -- PASSES both with and without this Story's code, since
    `#342` already exits 2 for a zero-pattern overlay before this Story's
    logic is ever reached. Consistent with `#342`: an overlay that IS
    supplied but resolves to zero usable pattern lines is a
    misconfiguration regardless of `require-identity-overlay`. Pinned here
    as a regression guard specific to this Story's new code paths, which
    sit right next to this check and could easily have shadowed it.

    ⚠️ arqtiqa/arqtos#344 round-1 review, MINOR: a return-code-only assertion
    cannot tell `#342`'s zero-pattern exit 2 apart from THIS Story's own
    required-and-absent exit 2 -- both are the literal integer 2. Deleting
    `#342`'s guard entirely still leaves this test green, because the new
    require block below it produces the same code for a different reason
    (an overlay resolving to zero rules, at this point in the script, means
    the overlay was PRESENT-but-empty, which the require block never
    special-cases -- it only branches on absence). Asserting on `#342`'s
    own message text is what actually proves ITS guard fired, not a
    same-numbered coincidence from this Story's."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked",
            overlay="# only a comment\n", require="true")
    err = p.stderr.decode()
    assert p.returncode == MISCONFIGURED, f"stderr:\n{err}"
    assert "was supplied but contains no rules" in err, (
        f"expected #342's own zero-pattern message, got:\n{err}")


# --- #4: require=true, overlay absent, secret COULD exist -- MISCONFIGURED

def test_require_true_overlay_absent_ordinary_context_is_MISCONFIGURED(tmp_path):
    """⚠️ THE CASE THIS STORY EXISTS FOR. Required, nothing supplied, and
    nothing about this run says the secret is expected to be missing --
    never wired, a rotated/renamed secret, or visibility that never
    covered this repo. Must go red."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="false")
    err = p.stderr.decode()
    assert p.returncode == MISCONFIGURED, f"expected exit 2, got {p.returncode}\nstderr:\n{err}"
    assert "require-identity-overlay" in err, f"got:\n{err}"


def test_require_true_overlay_absent_context_flag_unset_is_ALSO_MISCONFIGURED(tmp_path):
    """The context flag defaults to absent, same as the overlay itself --
    an unset ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD must behave exactly
    like 'false' (the ordinary case), never like 'true' (which would
    silently exempt every run from ever being checked)."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld=None)
    assert p.returncode == MISCONFIGURED, f"stderr:\n{p.stderr.decode()}"


def test_require_true_overlay_absent_ordinary_context_message_names_the_input(tmp_path):
    r = clean_repo(tmp_path)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="true", may_be_withheld="false").stderr.decode()
    assert "never wired" in err, f"got:\n{err}"
    assert "ARQTOS_FIREWALL_IDENTITY_OVERLAY" in err, f"got:\n{err}"


# --- #5: require=true, overlay absent, secret legitimately withheld -------

def test_require_true_overlay_absent_fork_or_dependabot_context_does_not_go_red(tmp_path):
    """⚠️ THE OTHER HALF OF THE CENTRAL DIFFICULTY. A fork PR or a Dependabot
    run cannot supply the secret -- GitHub withholds it -- and this must
    NOT be indistinguishable from a caught leak or a real misconfiguration.

    By itself this assertion PASSES both with and without this Story's
    code (the pre-#344 script also returns CLEAN for an absent overlay --
    it just cannot yet say WHY, which is what the paired
    "is_distinguishable_from_..." tests below pin instead). Kept as the
    direct statement of the "must not go red" AC; the RED-without-code
    proof for this state lives in the tests that check WHAT it reports,
    not merely that it exits 0."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="true")
    err = p.stderr.decode()
    assert p.returncode == CLEAN, (
        f"a required-but-unavailable overlay in a fork/Dependabot context "
        f"must not fail the run; got {p.returncode}\nstderr:\n{err}")


def test_required_unverified_state_is_distinguishable_from_a_clean_overlay_run(tmp_path):
    r = clean_repo(tmp_path)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="true", may_be_withheld="true").stderr.decode()
    assert REQUIRED_UNVERIFIED_TEXT in err, f"got:\n{err}"
    assert PLUS_OVERLAY_TEXT not in err, (
        f"the required-but-unverified state must not read as a run that HAD "
        f"the overlay:\n{err}")


def test_required_unverified_state_is_distinguishable_from_the_plain_no_overlay_disclosure(tmp_path):
    """⚠️ THE AC THAT MOST NEEDS PINNING. Both states share the same root
    cause (the overlay is absent) but mean DIFFERENT things: the plain
    disclosure is `#342`'s ordinary default (require=false, nobody asked
    for coverage); this one is "coverage was demanded and could not be
    verified". A reader must never confuse the two."""
    r = clean_repo(tmp_path)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="true", may_be_withheld="true").stderr.decode()
    assert REQUIRED_UNVERIFIED_TEXT in err, f"got:\n{err}"
    assert NO_OVERLAY_TEXT not in err, (
        f"the required-but-unverified state must not print the exact same "
        f"phrase the unrequired default uses:\n{err}")


def test_the_three_disclosure_strings_never_collide_across_all_three_states(tmp_path):
    """The strongest form of #5's distinguishability requirement: collect
    all three disclosure lines from three separate runs and assert each
    one's signature phrase is ABSENT from the other two's full output,
    both directions, all three pairs."""
    r_default = clean_repo(tmp_path, "default")
    err_default = run(r_default, "--denylist=dl.txt", "--all-tracked",
                       overlay=None, require="false").stderr.decode()

    r_overlay = clean_repo(tmp_path, "overlay")
    err_overlay = run(r_overlay, "--denylist=dl.txt", "--all-tracked",
                       overlay=IDENTITY_PROBE, require="true").stderr.decode()

    r_unverified = clean_repo(tmp_path, "unverified")
    err_unverified = run(r_unverified, "--denylist=dl.txt", "--all-tracked",
                          overlay=None, require="true", may_be_withheld="true").stderr.decode()

    states = {
        "default (no overlay)": (err_default, NO_OVERLAY_TEXT),
        "+overlay": (err_overlay, PLUS_OVERLAY_TEXT),
        "required, unverified": (err_unverified, REQUIRED_UNVERIFIED_TEXT),
    }
    for name, (_, signature) in states.items():
        for other_name, (other_output, _) in states.items():
            if name == other_name:
                continue
            assert signature not in other_output, (
                f"{name}'s signature phrase {signature!r} leaked into "
                f"{other_name}'s output:\n{other_output}")


def test_required_unverified_state_emits_a_workflow_warning_annotation(tmp_path):
    """The visual half of distinguishability in the GitHub Actions UI: a
    `::warning::` command renders as a distinct annotation on an otherwise
    GREEN run, unlike the plain default (no annotation) or a real failure
    (red). Verified as literal text here since there is no GitHub Actions
    runner in this test environment to render it."""
    r = clean_repo(tmp_path)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="true", may_be_withheld="true").stderr.decode()
    out = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="true", may_be_withheld="true").stdout.decode()
    combined = err + out
    assert "::warning::" in combined, f"got stdout+stderr:\n{combined}"


def test_required_unverified_state_still_lets_a_real_violation_fail(tmp_path):
    """⚠️ Outcome 5 means the OVERLAY tier did not run -- it must not also
    disable the credential tier. A real denylist violation in the same run
    must still fail, for its own, unrelated reason.

    PASSES both with and without this Story's code (the pre-#344 script's
    denylist scan is entirely untouched by either new env var), so this is
    a control against a specific plausible implementation mistake --
    routing the required-but-unverified state through an early `exit 0` --
    rather than a RED-without-code proof."""
    r = repo(tmp_path)
    (r / "dl.txt").write_text(CREDENTIAL_PROBE + "\n")
    (r / "leak.md").write_text(f"credential leak: {CREDENTIAL_PROBE} here\n")
    add(r)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="true")
    assert p.returncode == MATCHED, f"stderr:\n{p.stderr.decode()}"


# --- #6: bash 3.2 nounset safety on the new code paths ---------------------

def test_require_true_misconfigured_path_is_nounset_safe_under_bash_3_2(tmp_path):
    """⚠️ macOS's stock /bin/bash is 3.2.57 (`set -u` throws "unbound
    variable" on an unguarded reference). This Story's two new flags are
    plain scalars defaulted via `${VAR:-}`, so no new array is introduced
    -- but this exact file has hit this class of regression twice before,
    so the new exit paths are checked directly under bash 3.2 anyway."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="false", bash="/bin/bash")
    assert p.returncode == MISCONFIGURED
    assert "unbound variable" not in p.stderr.decode()


def test_require_true_unverified_path_is_nounset_safe_under_bash_3_2(tmp_path):
    """Control -- PASSES both with and without this Story's code (no new
    code, no new opportunity for an unbound-variable regression). Kept
    alongside the misconfigured-path test above so both new exit paths are
    checked under bash 3.2, not just the one that happens to be RED."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="true", bash="/bin/bash")
    assert p.returncode == CLEAN
    assert "unbound variable" not in p.stderr.decode()


def test_require_false_path_with_both_new_env_vars_unset_is_nounset_safe_under_bash_3_2(tmp_path):
    """The plainest control: neither new env var set at all (every one of
    the 15 existing callers, run under bash 3.2)."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", bash="/bin/bash")
    assert p.returncode == CLEAN


# --- #7: strict value parsing (round-1 review, SHOULD-FIX) -----------------
#
# ⚠️ `require-identity-overlay` is a CALLER-supplied input -- unlike
# `ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD`, which action.yml computes and
# always renders a literal 'true'/'false', a human can and does typo a YAML
# value. Before this fix, anything other than the exact string 'true' was
# silently treated as 'false' -- so a caller who wrote 'TRUE', 'yes', or `1`
# believing they had required identity coverage instead got an ordinary,
# unrequired, credential-tier-only run with no indication anything was
# wrong. That is the exact silent-degradation class this whole Story exists
# to close, reappearing in its own argument parser.

@pytest.mark.parametrize("bad_value", ["TRUE", "True", "yes", "1", "on", " true", "true "])
def test_an_unrecognized_require_value_is_MISCONFIGURED(tmp_path, bad_value):
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None, require=bad_value)
    err = p.stderr.decode()
    assert p.returncode == MISCONFIGURED, (
        f"require-identity-overlay={bad_value!r} must be refused, never "
        f"silently treated as 'false'; got {p.returncode}\nstderr:\n{err}")


def test_an_unrecognized_require_value_names_the_bad_value_and_the_input(tmp_path):
    r = clean_repo(tmp_path)
    err = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
              require="TRUE").stderr.decode()
    assert "require-identity-overlay" in err, f"got:\n{err}"
    assert "'true' or 'false'" in err, f"got:\n{err}"
    assert "TRUE" in err, f"the bad value itself should be echoed back:\n{err}"


def test_require_true_lowercase_still_arms_the_requirement(tmp_path):
    """Control: the fix must refuse GARBAGE, not narrow what already worked.
    The exact string 'true' must keep arming the requirement exactly as
    before -- this is the same scenario as
    `test_require_true_overlay_absent_ordinary_context_is_MISCONFIGURED`,
    repeated here as a direct sibling of the new parametrized refusal test
    so the pass/refuse boundary is visible in one place."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None,
            require="true", may_be_withheld="false")
    assert p.returncode == MISCONFIGURED
    assert "require-identity-overlay" in p.stderr.decode()


def test_require_false_lowercase_still_a_no_op(tmp_path):
    """Control: the exact string 'false' (action.yml's own default value)
    must keep behaving as a no-op, not be swept up by the new refusal."""
    r = clean_repo(tmp_path)
    p = run(r, "--denylist=dl.txt", "--all-tracked", overlay=None, require="false")
    assert p.returncode == CLEAN, f"stderr:\n{p.stderr.decode()}"
    assert "unbound variable" not in p.stderr.decode()
