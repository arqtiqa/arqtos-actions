"""Tests for the ci-baseline gate.

⚠️ THE POINT OF THESE TESTS IS THAT THE GATE FAILS WHEN IT SHOULD.

A checker is trivially easy to write so that it passes everything, and such a
checker is worse than none — it certifies the drift it was meant to catch. So
almost every test here asserts a NON-ZERO exit on deliberately-broken input, and
the clean cases exist to prove the broken ones are not passing by accident.

Assertions are POSITIVE about the satisfied path wherever possible. A negative
substring guard that does not match the real message can never fire: that exact
mistake let a mutation survive seven tests elsewhere in this estate, because the
guard read "no closing reference" while the message said "no closing ISSUE
reference".
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

GATE = Path(__file__).resolve().parents[1] / ".github/actions/ci-baseline/check_ci_baseline.py"

spec = importlib.util.spec_from_file_location("gate", GATE)
gate = importlib.util.module_from_spec(spec)
sys.modules["gate"] = gate
spec.loader.exec_module(gate)

OK, VIOLATION, MISCONFIGURED = 0, 1, 2

MANIFEST = """
version: 1
actions:
  actions/checkout:
    pin: v7
    why: test
  astral-sh/setup-uv:
    pin: v9.0.0
    exact: true
    why: test
  arqtiqa/arqtos-actions:
    pin: v1
    why: test
    per_action_overrides:
      firewall:
        pin_style: commit-sha
        why: test
single_consumer_exempt:
  - action: some/single-consumer-action
    consumer: only-one
exceptions_file: .github/ci-baseline-exceptions.yml
"""

SHA = "a" * 40


def build(tmp_path: Path, workflow: str, *, manifest: str = MANIFEST,
          exceptions: str | None = None, precommit: str | None = None) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/workflows/ci.yml").write_text(workflow)
    if exceptions is not None:
        (root / ".github/ci-baseline-exceptions.yml").write_text(exceptions)
    if precommit is not None:
        (root / ".pre-commit-config.yaml").write_text(precommit)
    mpath = tmp_path / "ci-baseline.yml"
    mpath.write_text(manifest)
    return root, mpath


def run(root: Path, mpath: Path) -> int:
    return gate.run(["--manifest", str(mpath), "--root", str(root)])


WF_CLEAN = """
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
"""


# --- the clean baseline, so every failure below is meaningful -----------------

def test_a_conforming_repo_passes(tmp_path, capsys):
    assert run(*build(tmp_path, WF_CLEAN)) == OK
    # positive assertion: it says what it checked, not merely nothing
    assert "at the declared baseline" in capsys.readouterr().err


# --- ⚠️ fail-closed: the property that stops a vacuous pass -------------------

def test_missing_manifest_is_MISCONFIGURED_not_clean(tmp_path, capsys):
    root, _ = build(tmp_path, WF_CLEAN)
    rc = gate.run(["--manifest", str(tmp_path / "nope.yml"), "--root", str(root)])
    assert rc == MISCONFIGURED, "a missing baseline must never report clean"
    assert "refusing to report clean" in capsys.readouterr().err


def test_unparseable_manifest_is_MISCONFIGURED(tmp_path):
    assert run(*build(tmp_path, WF_CLEAN, manifest="actions: [oops\n  bad: yaml")) == MISCONFIGURED


def test_manifest_with_no_actions_is_MISCONFIGURED(tmp_path, capsys):
    assert run(*build(tmp_path, WF_CLEAN, manifest="version: 1\nactions: {}\n")) == MISCONFIGURED
    # ⚠️ an empty baseline would accept EVERY pin — the vacuous-pass shape
    assert "accept every pin" in capsys.readouterr().err


def test_manifest_entry_without_a_pin_is_MISCONFIGURED(tmp_path):
    bad = "version: 1\nactions:\n  actions/checkout:\n    why: no pin here\n"
    assert run(*build(tmp_path, WF_CLEAN, manifest=bad)) == MISCONFIGURED


# --- forbidden interpreters ---------------------------------------------------

@pytest.mark.parametrize("snippet,label", [
    ("      - uses: actions/setup-python@v7\n", "actions/setup-python"),
    ("      - run: python3 -m pip install pyyaml\n", "pip install"),
    ("      - run: pip install pyyaml\n", "pip install"),
    ("      - run: python3 tools/thing.py\n", "bare python3"),
])
def test_forbidden_interpreter_shapes_FAIL(tmp_path, capsys, snippet, label):
    wf = "jobs:\n  a:\n    steps:\n" + snippet
    assert run(*build(tmp_path, wf)) == VIOLATION
    assert label in capsys.readouterr().err


def test_uv_run_locked_is_NOT_flagged(tmp_path):
    """The prescribed form must pass, or the gate pushes people off it."""
    wf = "jobs:\n  a:\n    steps:\n      - run: uv run --locked pytest\n"
    assert run(*build(tmp_path, wf)) == OK


def test_the_word_python3_in_a_COMMENT_is_not_a_violation(tmp_path):
    """⚠️ A gate that fires on documentation gets disabled. Narrowness is a feature."""
    wf = "jobs:\n  a:\n    steps:\n      # we deliberately avoid python3 here\n      - run: uv run --locked pytest\n"
    assert run(*build(tmp_path, wf)) == OK


def test_a_forbidden_shape_in_the_PRE_COMMIT_config_also_fails(tmp_path):
    pc = "repos:\n  - repo: local\n    hooks:\n      - entry: python3 tools/x.py\n"
    assert run(*build(tmp_path, WF_CLEAN, precommit=pc)) == VIOLATION


# --- off-baseline pins --------------------------------------------------------

def test_off_baseline_pin_FAILS_and_names_the_expected_version(tmp_path, capsys):
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n"
    assert run(*build(tmp_path, wf)) == VIOLATION
    err = capsys.readouterr().err
    assert "expected @v7" in err                    # names the fix
    assert "ci-baseline.yml" in err                 # names where the baseline lives


def test_an_ungoverned_action_is_ignored(tmp_path):
    wf = "jobs:\n  a:\n    steps:\n      - uses: some/other-action@v3\n"
    assert run(*build(tmp_path, wf)) == OK


def test_a_single_consumer_exempt_action_is_ignored(tmp_path):
    """Its absence from the pins is a statement, not an omission."""
    wf = "jobs:\n  a:\n    steps:\n      - uses: some/single-consumer-action@v99\n"
    assert run(*build(tmp_path, wf)) == OK


# --- ⚠️ the override, narrow in BOTH directions -------------------------------

def test_firewall_MUST_be_sha_pinned_so_a_tag_FAILS(tmp_path, capsys):
    wf = f"jobs:\n  a:\n    steps:\n      - uses: arqtiqa/arqtos-actions/.github/actions/firewall@v1\n"
    assert run(*build(tmp_path, wf)) == VIOLATION
    assert "must be pinned to a commit SHA" in capsys.readouterr().err


def test_firewall_with_a_sha_PASSES(tmp_path):
    wf = f"jobs:\n  a:\n    steps:\n      - uses: arqtiqa/arqtos-actions/.github/actions/firewall@{SHA}\n"
    assert run(*build(tmp_path, wf)) == OK


def test_a_NON_firewall_action_pinned_by_sha_FAILS(tmp_path, capsys):
    """⚠️ The permissive direction is a violation too. An exception that only
    ever widens is how a baseline decays into a suggestion."""
    wf = f"jobs:\n  a:\n    steps:\n      - uses: actions/checkout@{SHA}\n"
    assert run(*build(tmp_path, wf)) == VIOLATION
    assert "must use the baseline pin, not a commit SHA" in capsys.readouterr().err


# --- internal inconsistency ---------------------------------------------------

def test_two_versions_of_one_action_in_one_repo_FAILS(tmp_path, capsys):
    root, mpath = build(tmp_path, WF_CLEAN)
    (root / ".github/workflows/other.yml").write_text(
        "jobs:\n  b:\n    steps:\n      - uses: actions/checkout@v4\n")
    assert run(root, mpath) == VIOLATION
    assert "two versions" in capsys.readouterr().err


# --- exceptions ---------------------------------------------------------------

FUTURE, PAST = "2099-01-01", "2000-01-01"


def test_a_valid_exception_lets_an_off_baseline_pin_PASS(tmp_path):
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
    ex = f"exceptions:\n  - action: actions/checkout\n    pin: v5\n    why: a reason\n    expires: {FUTURE}\n"
    assert run(*build(tmp_path, wf, exceptions=ex)) == OK


def test_an_EXPIRED_exception_stops_working(tmp_path, capsys):
    """⚠️ An expired exception that keeps working is not an expiry date."""
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
    ex = f"exceptions:\n  - action: actions/checkout\n    pin: v5\n    why: a reason\n    expires: {PAST}\n"
    assert run(*build(tmp_path, wf, exceptions=ex)) == VIOLATION
    assert "EXPIRED" in capsys.readouterr().err


def test_an_exception_with_NO_expires_is_rejected(tmp_path, capsys):
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
    ex = "exceptions:\n  - action: actions/checkout\n    pin: v5\n    why: a reason\n"
    assert run(*build(tmp_path, wf, exceptions=ex)) == VIOLATION
    assert "incomplete" in capsys.readouterr().err


def test_an_exception_with_no_reason_is_rejected(tmp_path):
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v5\n"
    ex = f"exceptions:\n  - action: actions/checkout\n    pin: v5\n    expires: {FUTURE}\n"
    assert run(*build(tmp_path, wf, exceptions=ex)) == VIOLATION


def test_an_exception_cannot_be_a_blanket_skip(tmp_path):
    """It licenses ONE pin, not the action generally."""
    wf = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@v3\n"
    ex = f"exceptions:\n  - action: actions/checkout\n    pin: v5\n    why: r\n    expires: {FUTURE}\n"
    assert run(*build(tmp_path, wf, exceptions=ex)) == VIOLATION


# --- ⚠️ direct_reference: forbidden, and the wrapper exemption ----------------

MANIFEST_NODIRECT = MANIFEST.replace(
    "  astral-sh/setup-uv:\n    pin: v9.0.0\n    exact: true\n    why: test\n",
    "  astral-sh/setup-uv:\n    pin: v9.0.0\n    exact: true\n    direct_reference: forbidden\n    why: test\n")


def test_a_workflow_referencing_a_forbidden_action_FAILS_even_at_the_right_pin(tmp_path, capsys):
    """⚠️ The version is CORRECT and it still fails. That is the whole point:
    the pin lives in one wrapper, and a consumer holding its own reference
    re-creates the duplication a single source exists to remove."""
    wf = "jobs:\n  a:\n    steps:\n      - uses: astral-sh/setup-uv@v9.0.0\n"
    assert run(*build(tmp_path, wf, manifest=MANIFEST_NODIRECT)) == VIOLATION
    assert "may not be referenced directly" in capsys.readouterr().err


def test_an_ACTION_DEFINITION_may_hold_the_forbidden_reference(tmp_path):
    """The wrapper is the one place the literal belongs, so scanning must not
    make the wrapper flag itself."""
    root, mpath = build(tmp_path, WF_CLEAN, manifest=MANIFEST_NODIRECT)
    d = root / ".github/actions/python-toolchain"
    d.mkdir(parents=True)
    (d / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: astral-sh/setup-uv@v9.0.0\n")
    assert run(root, mpath) == OK


def test_an_ACTION_DEFINITION_is_still_checked_for_off_baseline_pins(tmp_path, capsys):
    """⚠️ Exempting the wrapper from ONE rule must not exempt it from all of
    them — in the repo that hosts the shared actions, the definitions are where
    most pins live."""
    root, mpath = build(tmp_path, WF_CLEAN)
    d = root / ".github/actions/thing"
    d.mkdir(parents=True)
    (d / "action.yml").write_text(
        "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n")
    assert run(root, mpath) == VIOLATION
    assert "expected @v7" in capsys.readouterr().err


# --- ⚠️ doubled CI: pull_request + an unfiltered push run every PR commit twice

WF_DOUBLED = """
on:
  push:
  pull_request:
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
"""

WF_SCOPED = """
on:
  pull_request:
  push:
    branches: [main]
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
"""

WF_PUSH_ONLY = """
on:
  push:
    tags: ['v*']
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
"""

WF_DISPATCH_AND_SCHEDULE = """
on:
  workflow_dispatch:
  schedule:
    - cron: '0 3 * * *'
jobs:
  a:
    steps:
      - uses: actions/checkout@v7
"""


def test_unfiltered_push_with_pull_request_is_a_VIOLATION(tmp_path, capsys):
    assert run(*build(tmp_path, WF_DOUBLED)) == VIOLATION
    # positive: the message must name the FIX, not merely report that a rule fired
    assert "branches: [main]" in capsys.readouterr().err


def test_scoped_push_with_pull_request_passes(tmp_path):
    assert run(*build(tmp_path, WF_SCOPED)) == OK


def test_push_only_workflow_passes(tmp_path):
    assert run(*build(tmp_path, WF_PUSH_ONLY)) == OK


def test_workflow_dispatch_and_schedule_pass(tmp_path):
    assert run(*build(tmp_path, WF_DISPATCH_AND_SCHEDULE)) == OK
