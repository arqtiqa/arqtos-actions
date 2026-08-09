#!/usr/bin/env python3
"""check_ci_baseline.py — enforce the declared CI baseline in a consumer repo.

Realizes REQ-ARQ-J-09. Reads ci-baseline.yml (the manifest) and rejects, in the
consumer's workflows and pre-commit config:

  1. a bare interpreter or unpinned installer  (`python3`, `pip install`,
     `actions/setup-python`)
  2. a governed action pinned off the manifest
  3. two versions of the same action inside one repository
  4. a workflow declaring `pull_request` alongside an unfiltered `push`, which
     runs — and bills — every PR-branch commit twice

⚠️ FOUR DESIGN RULES, EACH FROM A DEFECT RATHER THAN A PREFERENCE.

FAIL CLOSED. If the manifest is missing or unparseable this exits 2. A checker
with nothing to check against reports every subject clean, which looks like a
pass and is worse than not running — the same reasoning that makes a missing
firewall denylist an exit-2, and that makes `check-estate-identifiers` refuse to
run on an empty pattern list.

NAME THE FIX, NOT JUST THE VIOLATION. Every failure states the expected value
and where the baseline is declared, in the summary/affected/reason/fix shape
`check-release-discipline` uses. A gate whose output does not say what to do
trains people to bypass it.

THE OVERRIDE IS NARROW IN BOTH DIRECTIONS. The firewall action must be pinned to
a commit SHA and NOT to `@v1`; every other action must use its manifest pin and
NOT a SHA. An exception that only ever widens is how a baseline decays into a
suggestion — so violating it in the permissive direction is a violation too.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

import yaml

EXIT_OK, EXIT_VIOLATION, EXIT_MISCONFIGURED = 0, 1, 2

# `uses: owner/repo[/path]@ref`, capturing the action identity and the ref.
USES_RE = re.compile(r"^\s*-?\s*uses:\s*([A-Za-z0-9][A-Za-z0-9._/-]*?)@([A-Za-z0-9._-]+)", re.M)
# A 40-char lowercase hex string is a commit SHA; anything else is a tag/branch.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# Bare-interpreter and unpinned-installer shapes. Deliberately narrow: matching
# the WORD `python3` anywhere would hit prose in comments, and a gate that fires
# on documentation gets disabled.
FORBIDDEN = [
    (re.compile(r"^\s*-?\s*uses:\s*actions/setup-python@", re.M), "actions/setup-python"),
    (re.compile(r"(?<![\w/-])python3?\s+-m\s+pip\s+install", re.M), "pip install"),
    (re.compile(r"(?<![\w/-])pip3?\s+install", re.M), "pip install"),
    (re.compile(r"(?<![\w/.-])python3(?:\s|$)", re.M), "bare python3"),
]


@dataclass
class Finding:
    summary: str
    affected: str
    reason: str
    fix: str


@dataclass
class Manifest:
    pins: dict[str, str] = field(default_factory=dict)
    exact: set[str] = field(default_factory=set)
    sha_pinned: set[str] = field(default_factory=set)   # full action paths
    exempt: set[str] = field(default_factory=set)
    no_direct_ref: set[str] = field(default_factory=set)
    path: str = ""


def _workflow_on_block(text: str) -> object | None:
    """Return a workflow's `on:` value, in whatever shape it was written
    (string / list / dict), or `None` if there is no `on:` block at all.

    ⚠️ YAML 1.1 boolean resolution turns the bare key `on` into the boolean
    `True` — the classic GitHub Actions authoring gotcha — so PyYAML parses
    `on:\\n  push:` into `{True: {'push': None}}`, not `{'on': ...}`. Both
    spellings are checked; a workflow that is not even valid YAML, or whose
    top level is not a mapping, is treated the same as "no `on:` block" —
    this rule only ever adds a finding, it never turns a parse wobble into a
    crash.
    """
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(doc, dict):
        return None
    if True in doc:
        return doc[True]
    return doc.get("on")


def _trigger_names(on_block: object) -> set[str]:
    """The trigger keywords declared, regardless of which of the three legal
    `on:` shapes (bare string, list, or mapping) the author used."""
    if isinstance(on_block, str):
        return {on_block}
    if isinstance(on_block, list):
        return {str(x) for x in on_block}
    if isinstance(on_block, dict):
        return set(on_block.keys())
    return set()


def _strip_comments(text: str) -> str:
    """Blank out comments, preserving offsets so line numbers stay truthful.

    ⚠️ Length-preserving on purpose: the caller computes a line number from the
    match offset, so deleting characters would silently misreport WHERE a
    violation is — and a gate that points at the wrong line is only slightly
    better than one that says nothing.

    Handles a whole-line comment and a trailing one. A `#` inside a quoted
    string is treated as a comment, which can only ever cause a MISSED match,
    never a false one; a forbidden interpreter is not invoked from inside a
    string literal.
    """
    out = []
    for line in text.split("\n"):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            out.append(" " * len(line))
            continue
        idx = line.find(" #")
        if idx != -1:
            out.append(line[:idx] + " " * (len(line) - idx))
            continue
        out.append(line)
    return "\n".join(out)


def emit(f: Finding) -> None:
    sys.stderr.write(f"✗ ci-baseline: {f.summary}\n")
    sys.stderr.write(f"  affected: {f.affected}\n")
    sys.stderr.write(f"  reason:   {f.reason}\n")
    sys.stderr.write(f"  fix:      {f.fix}\n\n")


def die_misconfigured(reason: str, fix: str) -> int:
    """⚠️ The fail-closed path. Never returns a clean verdict."""
    emit(Finding(
        summary="cannot run — refusing to report clean",
        affected="the baseline manifest",
        reason=reason,
        fix=fix,
    ))
    return EXIT_MISCONFIGURED


def load_manifest(path: Path) -> Manifest | int:
    if not path.is_file():
        return die_misconfigured(
            f"manifest not found at {path}",
            "point --manifest at ci-baseline.yml. A scan with no baseline would "
            "pass every workflow, which is why this is an error and not a warning.",
        )
    try:
        raw = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        return die_misconfigured(f"manifest at {path} is not valid YAML: {e}",
                                 "fix the manifest; a partially-read baseline is not a baseline.")
    if not isinstance(raw, dict) or not isinstance(raw.get("actions"), dict) or not raw["actions"]:
        return die_misconfigured(
            f"manifest at {path} declares no actions",
            "an empty baseline would accept every pin. If that is genuinely "
            "intended, delete the gate rather than emptying its input.",
        )

    m = Manifest(path=str(path))
    for name, spec in raw["actions"].items():
        if not isinstance(spec, dict) or "pin" not in spec:
            return die_misconfigured(f"manifest entry {name!r} has no `pin`",
                                     "every governed action needs a pin, or the gate cannot judge it.")
        m.pins[name] = str(spec["pin"])
        if spec.get("exact"):
            m.exact.add(name)
        if spec.get("direct_reference") == "forbidden":
            m.no_direct_ref.add(name)
        for sub, ov in (spec.get("per_action_overrides") or {}).items():
            if ov.get("pin_style") == "commit-sha":
                m.sha_pinned.add(f"{name}/.github/actions/{sub}")
    for e in raw.get("single_consumer_exempt") or []:
        if isinstance(e, dict) and e.get("action"):
            m.exempt.add(e["action"])
    return m


def load_exceptions(root: Path, manifest_raw: dict) -> tuple[dict[str, str], list[Finding]]:
    """Consumer-recorded deviations. ⚠️ `expires` is REQUIRED and enforced —
    an exception with no date is a permanent carve-out wearing the costume of a
    temporary one, and an expired one must stop working or it is not a date."""
    rel = manifest_raw.get("exceptions_file", ".github/ci-baseline-exceptions.yml")
    p = root / rel
    if not p.is_file():
        return {}, []
    try:
        data = yaml.safe_load(p.read_text()) or {}
    except yaml.YAMLError as e:
        return {}, [Finding("exceptions file is not valid YAML", str(p), str(e),
                            "fix or remove it; an unreadable exceptions file is not an exception.")]
    out: dict[str, str] = {}
    problems: list[Finding] = []
    for ex in data.get("exceptions") or []:
        act, pin, why, exp = ex.get("action"), ex.get("pin"), ex.get("why"), ex.get("expires")
        if not (act and pin and why and exp):
            problems.append(Finding(
                "exception is incomplete", f"{p}: {act or '<no action>'}",
                "an exception needs action, pin, why and expires",
                "add the missing fields. `why` and `expires` are what make it a decision rather than a hole."))
            continue
        try:
            when = date.fromisoformat(str(exp))
        except ValueError:
            problems.append(Finding("exception has an unreadable `expires`", f"{p}: {act}",
                                    f"{exp!r} is not an ISO date",
                                    "use YYYY-MM-DD."))
            continue
        if when < date.today():
            problems.append(Finding(
                "exception has EXPIRED", f"{p}: {act}",
                f"expired {when.isoformat()}",
                "renew it with a fresh reason, or bring the pin to baseline. ⚠️ An expired "
                "exception that keeps working is not an expiry date."))
            continue
        out[act] = str(pin)
    return out, problems


def scan_repo(root: Path, m: Manifest, exceptions: dict[str, str]) -> list[Finding]:
    findings: list[Finding] = []
    # ⚠️ Composite action DEFINITIONS are scanned too. They contain `uses:`
    # lines and are as much a part of CI as a workflow — in the repository that
    # hosts the shared actions they are where most pins actually live, so
    # scanning only workflows would leave the pins unguarded in the one repo
    # that owns them.
    #
    # The pair is (path, is_consumer_surface). A WORKFLOW consumes actions; an
    # action DEFINITION may legitimately be the wrapper that owns a pin. That
    # distinction is what lets `direct_reference: forbidden` be enforced without
    # the wrapper flagging itself.
    targets: list[tuple[Path, bool]] = []
    for pat in (".github/workflows/*.yml", ".github/workflows/*.yaml"):
        targets += [(f, True) for f in sorted(root.glob(pat))]
    pre = root / ".pre-commit-config.yaml"
    if pre.is_file():
        targets.append((pre, True))
    for pat in (".github/actions/*/action.yml", ".github/actions/*/action.yaml"):
        targets += [(f, False) for f in sorted(root.glob(pat))]

    seen: dict[str, dict[str, list[str]]] = {}

    for f, is_consumer in targets:
        rel = f.relative_to(root).as_posix()
        text = f.read_text()

        # ⚠️ Comments are stripped BEFORE matching the forbidden shapes, and the
        # blanking preserves line numbers so a report still points at the right
        # line. Without this the gate fires on prose — including on a comment
        # that says "we deliberately avoid python3 here", which is the exact
        # false positive that gets a gate switched off rather than obeyed.
        for rx, label in FORBIDDEN:
            for mt in rx.finditer(_strip_comments(text)):
                line = text[: mt.start()].count("\n") + 1
                findings.append(Finding(
                    f"{label} is not allowed",
                    f"{rel}:{line}",
                    f"{label} bypasses the locked toolchain. A bare interpreter is not a "
                    f"version — it is whatever is first on that runner's PATH — and an "
                    f"unpinned installer resolves whatever is newest at run time.",
                    "use the python-toolchain action and invoke commands as "
                    "`uv run --locked <cmd>`.",
                ))

        # ⚠️ Doubled CI: `pull_request` plus a `push` with no `branches:` or
        # `branches-ignore:` filter fires BOTH events for every commit on a PR
        # branch, so every job in this workflow runs — and bills — twice. Only
        # a genuine workflow declares `on:`, so this is scoped to the
        # `.github/workflows/` surface; an action definition's `runs:` block
        # never has one, and would just read as "no `on:` block" anyway.
        if rel.startswith(".github/workflows/"):
            on_block = _workflow_on_block(text)
            triggers = _trigger_names(on_block)
            if "pull_request" in triggers and "push" in triggers:
                push_spec = on_block.get("push") if isinstance(on_block, dict) else None
                # ⚠️ The question is not "does push: carry a filter key" but
                # "can this push: fire on an ordinary branch commit". A
                # `branches:`/`branches-ignore:` filter answers that directly.
                # A `tags:`/`tags-ignore:` filter answers it too, but only
                # when there is NO branch filter alongside it: a tag push is
                # not a branch commit, so tags-only can never double against
                # `pull_request` — but `paths:`-only (or no filter at all)
                # still fires on every matching branch commit, so that stays
                # a violation.
                has_branch_filter = isinstance(push_spec, dict) and (
                    "branches" in push_spec or "branches-ignore" in push_spec
                )
                has_tag_filter = isinstance(push_spec, dict) and (
                    "tags" in push_spec or "tags-ignore" in push_spec
                )
                filtered = has_branch_filter or has_tag_filter
                if not filtered:
                    findings.append(Finding(
                        "pull_request and an unfiltered push: double every PR-branch commit",
                        rel,
                        "on: declares both `pull_request` and `push` with no `branches:` "
                        "or `branches-ignore:` filter, so every push to a PR branch fires "
                        "both events and this workflow's jobs run — and bill — twice.",
                        f"scope the push trigger, e.g. add `branches: [main]` under "
                        f"{rel}'s `push:` key so it only fires outside a PR, or drop the "
                        f"`push:` trigger entirely if `pull_request` coverage is enough.",
                    ))

        for mt in USES_RE.finditer(text):
            action, ref = mt.group(1), mt.group(2)
            line = text[: mt.start()].count("\n") + 1
            where = f"{rel}:{line}"

            if action in m.sha_pinned:
                if not SHA_RE.match(ref):
                    findings.append(Finding(
                        "this action must be pinned to a commit SHA, not a tag",
                        where,
                        f"{action}@{ref} — it is a security GATE, and a compromised gate "
                        f"does not break the build, it returns a green check on a repo "
                        f"whose scan is no longer running.",
                        f"pin a 40-char SHA and annotate it, e.g. `{action}@<sha>  # {ref}`. "
                        f"Declared in {m.path}.",
                    ))
                continue

            base = action.split("/.github/")[0] if "/.github/" in action else action
            key = base if base in m.pins else action
            if key not in m.pins or key in m.exempt:
                continue

            # ⚠️ Referencing this action directly is forbidden even though the
            # version would be CORRECT. Matching the pin is not the point: the
            # pin lives in exactly one wrapper, and a consumer holding its own
            # reference re-creates the duplication the single source removed.
            # Enforced on consumer surfaces only — the wrapper is an action
            # definition, and it is the one place the literal belongs.
            if is_consumer and key in m.no_direct_ref:
                findings.append(Finding(
                    "this action may not be referenced directly",
                    where,
                    f"{action}@{ref} — the pin lives in exactly one wrapper, and a "
                    f"direct reference re-creates the drift surface a single source "
                    f"exists to remove, even at the correct version.",
                    f"use the wrapper action instead. Declared in {m.path} as "
                    f"`direct_reference: forbidden`.",
                ))
                continue

            if SHA_RE.match(ref):
                findings.append(Finding(
                    "this action must use the baseline pin, not a commit SHA",
                    where,
                    f"{action}@{ref[:12]}… — only the firewall is SHA-pinned. A SHA here "
                    f"reintroduces one bump per consumer, which is the cost a single "
                    f"declared source exists to remove.",
                    f"use `{key}@{m.pins[key]}`. Declared in {m.path}.",
                ))
                continue

            want = exceptions.get(key, m.pins[key])
            if ref != want:
                src = "a recorded exception" if key in exceptions else m.path
                findings.append(Finding(
                    "action pinned off the baseline",
                    where,
                    f"{action}@{ref}, expected @{want}",
                    f"change it to `{key}@{want}` (declared in {src}), or record an "
                    f"exception in the exceptions file with a reason and an `expires` date.",
                ))
            seen.setdefault(key, {}).setdefault(ref, []).append(where)

    for action, refs in seen.items():
        if len(refs) > 1:
            spots = "; ".join(f"{r} at {', '.join(v)}" for r, v in sorted(refs.items()))
            findings.append(Finding(
                "one action pinned at two versions inside this repository",
                action,
                f"{spots} — so there is no single 'current version' even locally, and two "
                f"workflows here do not run the same CI.",
                f"unify on `{m.pins[action]}` from {m.path}.",
            ))
    return findings


def run(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Enforce the declared CI baseline (REQ-ARQ-J-09).")
    ap.add_argument("--manifest", required=True, help="path to ci-baseline.yml")
    ap.add_argument("--root", default=".", help="repository root to scan")
    a = ap.parse_args(argv)

    root = Path(a.root).resolve()
    mpath = Path(a.manifest)
    m = load_manifest(mpath)
    if isinstance(m, int):
        return m

    raw = yaml.safe_load(mpath.read_text())
    exceptions, ex_problems = load_exceptions(root, raw)
    findings = ex_problems + scan_repo(root, m, exceptions)

    if not findings:
        nw = len(list(root.glob(".github/workflows/*.yml")))
        na = len(list(root.glob(".github/actions/*/action.yml")))
        sys.stderr.write(
            f"✓ ci-baseline: {nw} workflow(s) + {na} action definition(s) at the "
            f"declared baseline ({len(m.pins)} governed action(s), manifest {m.path}).\n")
        return EXIT_OK

    for f in findings:
        emit(f)
    sys.stderr.write(f"✗ ci-baseline: {len(findings)} violation(s).\n")
    return EXIT_VIOLATION


if __name__ == "__main__":  # pragma: no cover
    sys.exit(run(sys.argv[1:]))
