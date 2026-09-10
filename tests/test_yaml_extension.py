"""The YAML extension gate — a check that must FAIL, not merely pass.

⚠️ arqtiqa/arqtos-core#206. Five of the six repositories this gate is for had
no CI harness at all, so there was no existing check to invoke and this one
ships an implementation — the opposite of `go-fmt`, and the README says why.

That makes these tests the only thing standing between the estate and a shared
gate that reports green over an unconverted tree. Each one is a specific way the
mechanism could claim coverage it does not have:

  * a STRAY `.yml` must turn it RED. The obvious direction, and the only one a
    "does it run" test would catch.
  * an EMPTY exemption list must REFUSE, not pass. A list emptied during an edit
    leaves every file conformant by definition, and a gate that passes over it
    reads exactly like one that checked.
  * an entry NAMING NO TOOL must REFUSE. That is the difference between an
    exemption and a preference, and it cannot be enforced by review alone.
  * a root with NO YAML must REFUSE. A misconfigured `root` otherwise reads as
    conformance — the failure mode that makes a green gate worse than none.
  * a NAME-keyed entry must not spare a directory, and a DIR-keyed entry must
    spare any name under it. The two shapes exist because GitHub reads
    `dependabot.yml` by name and issue forms by directory; collapsing them
    either misses a template added tomorrow or spares `bug.yml` anywhere.
"""

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".github" / "actions" / "yaml-extension" / "check-yaml-extension.sh"
SHIPPED = ROOT / ".github" / "actions" / "yaml-extension" / "exemptions.txt"

PASS, FAIL, REFUSE = 0, 1, 2


def run(root: Path, exemptions: Path | None = None) -> subprocess.CompletedProcess:
    argv = [str(SCRIPT), f"--root={root}"]
    argv.append(f"--exemptions={exemptions if exemptions else SHIPPED}")
    return subprocess.run(argv, capture_output=True, text=True)


def tree(base: Path, *paths: str) -> Path:
    for p in paths:
        f = base / p
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text("name: fixture\n")
    return base


def test_a_conformant_tree_PASSES_and_says_what_it_counted(tmp_path):
    r = tree(tmp_path, ".github/workflows/ci.yaml", "config.yaml")
    got = run(r)
    assert got.returncode == PASS, got.stderr
    # A count, not a bare "ok": a pass that names no number cannot be told from
    # a pass over an empty set.
    assert "2 YAML file(s)" in got.stdout, got.stdout


def test_a_STRAY_yml_is_RED_and_is_named(tmp_path):
    r = tree(tmp_path, ".github/workflows/ci.yaml", "sneaky.yml")
    got = run(r)
    assert got.returncode == FAIL, f"a stray .yml passed: {got.stdout}"
    assert "sneaky.yml" in got.stderr, got.stderr


def test_an_EMPTY_exemption_list_REFUSES_rather_than_passing(tmp_path):
    empty = tmp_path / "empty.txt"
    empty.write_text("# every line a comment, no rules at all\n")
    r = tree(tmp_path / "repo", "ci.yaml")
    got = run(r, exemptions=empty)
    assert got.returncode == REFUSE, (
        f"an emptied list passed, so switching the gate off is invisible: {got.stdout}"
    )
    assert "emptied" in got.stderr, got.stderr


def test_an_entry_NAMING_NO_TOOL_refuses(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("name:whatever.yml\n")
    r = tree(tmp_path / "repo", "ci.yaml")
    got = run(r, exemptions=bad)
    assert got.returncode == REFUSE, got.stdout
    assert "names no tool" in got.stderr, got.stderr


def test_an_entry_with_an_empty_reason_refuses(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("name:whatever.yml|   \n")
    r = tree(tmp_path / "repo", "ci.yaml")
    got = run(r, exemptions=bad)
    assert got.returncode == REFUSE, got.stdout


def test_an_entry_of_NEITHER_KIND_refuses(tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("whatever.yml|some tool reads it\n")
    r = tree(tmp_path / "repo", "ci.yaml")
    got = run(r, exemptions=bad)
    assert got.returncode == REFUSE, got.stdout
    assert "neither name: nor dir:" in got.stderr, got.stderr


def test_a_root_with_NO_YAML_refuses_rather_than_passing(tmp_path):
    (tmp_path / "README.md").write_text("nothing yaml here\n")
    got = run(tmp_path)
    assert got.returncode == REFUSE, (
        f"a tree with no YAML passed, so a misconfigured root reads as clean: {got.stdout}"
    )
    assert "silence means nothing" in got.stderr, got.stderr


def test_a_missing_root_refuses(tmp_path):
    got = run(tmp_path / "absent")
    assert got.returncode == REFUSE, got.stdout


def test_an_unreadable_exemption_list_refuses(tmp_path):
    r = tree(tmp_path / "repo", "ci.yaml")
    got = run(r, exemptions=tmp_path / "absent.txt")
    assert got.returncode == REFUSE, got.stdout


def test_the_SHIPPED_list_spares_dependabot_by_name(tmp_path):
    r = tree(tmp_path, ".github/dependabot.yml", "ci.yaml")
    got = run(r)
    assert got.returncode == PASS, got.stderr
    assert "1 declared exemption" in got.stdout, got.stdout


def test_the_SHIPPED_list_spares_ANY_issue_form_name(tmp_path):
    # The shape that matters: a template nobody has added yet must be spared
    # too, which a name-keyed entry could not do.
    r = tree(
        tmp_path,
        ".github/ISSUE_TEMPLATE/bug.yml",
        ".github/ISSUE_TEMPLATE/config.yml",
        ".github/ISSUE_TEMPLATE/invented-tomorrow.yml",
        "ci.yaml",
    )
    got = run(r)
    assert got.returncode == PASS, got.stderr
    assert "3 declared exemption" in got.stdout, got.stdout


def test_a_DIR_entry_does_not_spare_the_same_name_elsewhere(tmp_path):
    # The mirror failure: an exemption widened until it matches everywhere
    # satisfies every other assertion in this file.
    r = tree(tmp_path, "docs/bug.yml", "ci.yaml")
    got = run(r)
    assert got.returncode == FAIL, (
        f"docs/bug.yml was spared, so the issue-form exemption matches by name: {got.stdout}"
    )
    assert "docs/bug.yml" in got.stderr, got.stderr


def test_a_NAME_entry_matches_EXACTLY_not_as_a_substring(tmp_path):
    # The mirror of the dir-entry test, and it survived a mutation before it
    # existed: relaxing name matching to a substring spared a file that merely
    # CONTAINS an exempt name, and every other assertion here stayed green.
    r = tree(tmp_path, "not-dependabot.yml", "ci.yaml")
    got = run(r)
    assert got.returncode == FAIL, (
        f"not-dependabot.yml was spared, so an exempt name matches as a substring: {got.stdout}"
    )
    assert "not-dependabot.yml" in got.stderr, got.stderr


def test_action_yml_is_NOT_spared(tmp_path):
    # #206 ruled action.yml is renamed, not exempted, because GitHub documents
    # both spellings. If it ever appears in the shipped list, this fails.
    r = tree(tmp_path, ".github/actions/x/action.yml", "ci.yaml")
    got = run(r)
    assert got.returncode == FAIL, (
        f"action.yml was spared, which contradicts the #206 ruling: {got.stdout}"
    )


def test_an_unrecognised_argument_refuses(tmp_path):
    got = subprocess.run(
        [str(SCRIPT), "--wat=1"], capture_output=True, text=True
    )
    assert got.returncode == REFUSE, got.stdout


def test_the_action_is_action_yaml_which_is_the_ruling_it_proves(tmp_path):
    # If this file were renamed to action.yml, the gate would still pass while
    # the estate's own ruling had been quietly reversed in the one place that
    # demonstrates it is safe.
    d = ROOT / ".github" / "actions" / "yaml-extension"
    assert (d / "action.yaml").is_file(), "the action must be action.yaml"
    assert not (d / "action.yml").exists(), "action.yml would reverse the #206 ruling in place"
