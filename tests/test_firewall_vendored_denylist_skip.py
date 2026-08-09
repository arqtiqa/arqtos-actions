"""The firewall's vendored-denylist skip — arqtiqa/arqtos#343.

⚠️ The scanner used to skip any tracked file sharing the denylist's BASENAME,
on the theory that it must be a vendored copy of the denylist elsewhere in
the tree. That is a name coincidence, not evidence: an unrelated file merely
named the same as the denylist was silently dropped from the file list
BEFORE exemptions are even resolved — so the one mechanism this estate has
for recording "this file legitimately contains denylist-shaped text, and
here is why" never got a chance to fire. Silent-clean is the exact state the
whole firewall exists to prevent.

Proven live: arqtos-cli's own `internal/firewall/testdata/golden/work.txt`
— a golden-corpus fixture, not a denylist copy — shares a basename with
`internal/firewall/denylists/work.txt` and was skipped outright, unreviewed
and unrecorded.

The fix requires corroboration beyond the name: a same-basename file is only
treated as a vendored copy (and skipped) when its CONTENT is byte-identical
to the denylist's. An unrelated file that merely shares a name no longer
gets a free pass, and the skip is still STATED on stderr when it does fire.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / ".github/actions/firewall/check-private-content.sh"
PROBE = "ZZZSYNTHETICPROBE"
CLEAN, MATCHED, MISCONFIGURED = 0, 1, 2


def repo(tmp_path: Path) -> Path:
    r = tmp_path / "r"
    r.mkdir()
    subprocess.run(["git", "init", "-qb", "main"], cwd=r, check=True)
    return r


def add(r: Path) -> None:
    subprocess.run(["git", "add", "-A"], cwd=r, check=True,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run(r: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run([str(SCRIPT), *args], cwd=r, capture_output=True)


# --- ⚠️ THE regression, reproduced directly -------------------------------

def test_an_unrelated_file_sharing_the_denylists_basename_is_scanned_not_skipped(tmp_path):
    """`denylists/work.txt` and `golden/work.txt` share a basename by pure
    coincidence — different directories, unrelated content — and the OLD
    code skipped the golden file outright on the name alone, before
    exemptions could ever be consulted."""
    r = repo(tmp_path)
    (r / "denylists").mkdir()
    (r / "denylists" / "work.txt").write_text(PROBE + "\n")
    (r / "golden").mkdir()
    (r / "golden" / "work.txt").write_text(f"unrelated content mentioning {PROBE} too\n")
    add(r)
    p = run(r, "--denylist=denylists/work.txt", "--all-tracked")
    assert p.returncode == MATCHED, (
        f"an unrelated file sharing the denylist's basename must be SCANNED, "
        f"not silently skipped on name alone; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")
    assert "golden/work.txt" in p.stderr.decode(), (
        "the surviving violation must name the file that was wrongly "
        "skipped before")


def test_the_unrelated_same_basename_file_is_never_reported_as_skipped(tmp_path):
    """The mirror of the test above: not only must the file be scanned, the
    scanner must not even CLAIM to have skipped it — a same-name-only file
    is not a vendored copy and gets no special mention at all."""
    r = repo(tmp_path)
    (r / "denylists").mkdir()
    (r / "denylists" / "work.txt").write_text(PROBE + "\n")
    (r / "golden").mkdir()
    (r / "golden" / "work.txt").write_text(f"unrelated content mentioning {PROBE} too\n")
    add(r)
    p = run(r, "--denylist=denylists/work.txt", "--all-tracked")
    assert "skipping vendored denylist" not in p.stderr.decode()


# --- ⚠️ the case condition 2 was protecting must still work ---------------

def test_a_byte_identical_vendored_copy_is_still_skipped(tmp_path):
    """The real case condition 2 exists for: a genuine vendored copy of the
    denylist, byte-for-byte identical content, living at a different path.
    Its own patterns trivially self-match their own literal text, so
    scanning it would fire a false positive on every commit that touches
    the denylist. Content corroboration must still recognise and skip it."""
    r = repo(tmp_path)
    (r / "denylists").mkdir()
    denylist_text = PROBE + "\n"
    (r / "denylists" / "work.txt").write_text(denylist_text)
    (r / "vendor").mkdir()
    (r / "vendor" / "work.txt").write_text(denylist_text)  # byte-identical copy
    add(r)
    p = run(r, "--denylist=denylists/work.txt", "--all-tracked")
    assert p.returncode == CLEAN, (
        f"a byte-identical vendored copy must still be skipped, not scanned "
        f"into a false positive; got {p.returncode}\n"
        f"stderr:\n{p.stderr.decode()}")


def test_the_vendored_copy_skip_is_stated_on_stderr(tmp_path):
    """⚠️ A silent exclusion is the defect; a loud one is a decision. The
    skip must name the file and the reason, not just disappear quietly."""
    r = repo(tmp_path)
    (r / "denylists").mkdir()
    denylist_text = PROBE + "\n"
    (r / "denylists" / "work.txt").write_text(denylist_text)
    (r / "vendor").mkdir()
    (r / "vendor" / "work.txt").write_text(denylist_text)
    add(r)
    err = run(r, "--denylist=denylists/work.txt", "--all-tracked").stderr.decode()
    assert "vendor/work.txt" in err, f"the skip must name the file; got:\n{err}"
    assert "skipping vendored denylist" in err, (
        f"the skip must state its reason; got:\n{err}")
