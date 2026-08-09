# `firewall-falsifier` — the standing proof that a denylist still bites

The [`firewall`](../firewall) action scans a caller's tracked files against a
caller-supplied denylist. **A green firewall is not evidence that the denylist
still matches anything.**

This action is what makes it evidence.

## The gap it closes

`arqtiqa/arqtos-cli#831` requires every repository's denylist to be *covered by
a falsifier test*. For most repositories that requirement was discharged by a
**one-time, narrated, manual dry-run** performed on the day the gate was
switched on — evidence the list bit *once*, on one day, against one tree.
Nothing re-runs it.

A denylist decays silently, and **every decay mode leaves the gate green**:

| decay | what CI shows |
| --- | --- |
| a rule edited into a form that still **compiles** but matches nothing | green |
| a rule **deleted** during an unrelated edit | green |
| a rule **added** that never matched anything in the first place | green |
| a rule **widened** until it matches ordinary content | green |

`arqtos-cli#1092` was the first of those, one level down: the shared script
reported CLEAN when `grep` *rejected* a pattern. A green firewall over a dead
denylist is worse than no firewall, because it is trusted.

## Usage

```yaml
- uses: actions/checkout@v7

- name: Scan tracked files against the denylist
  uses: arqtiqa/arqtos-actions/.github/actions/firewall@<sha>
  with:
    denylist: .github/scripts/private-content-denylist.txt

- name: Prove every denylist rule still bites
  uses: arqtiqa/arqtos-actions/.github/actions/firewall-falsifier@<sha>
  with:
    denylist: .github/scripts/private-content-denylist.txt
```

| input | required | default | notes |
| --- | --- | --- | --- |
| `denylist` | yes | — | **the same path the gate scans.** Proving a different list alive is the most convincing possible form of no coverage. |
| `probes` | no | `.firewall-probes` | the caller's synthetic probe corpus |

⚠️ **Pin both actions to the same SHA.** The falsifier drives the scanner from
its own sibling directory, so a consumer that pinned them apart would prove one
scanner build alive while a *different* build guarded the repository. Both are
`pin_style: commit-sha` in `ci-baseline.yml`, for the same reason: a
compromised falsifier does not break the build, it reports every rule alive.

## The corpus (`.firewall-probes`)

```
# free-form comments and blank lines are skipped
[must-match]
<one synthetic probe per line — each must fire at least one rule>

[must-not-match]
<one benign lookalike per line — none may fire anything>
```

Both sections are **mandatory** and both must be **non-empty**. A probe is the
**whole line**; there are no fields to split, so a probe cannot begin with `#`
or `[`. Describe each one in the comment above it.

⚠️ **Probes are synthetic.** A probe is shaped *like* what a rule catches and
is never an instance of it — never a real credential, never a real identity
value, never a real host. The corpus is committed, and several repositories
carrying one are public.

### ⚠️ GitHub push protection scans this file too — expect to meet it

A corpus is a file of credential-shaped strings, so **third-party secret
scanners flag it**, and GitHub's push protection will *refuse the push* that
adds it. Detectors whose shape carries a checksum (the GitHub token prefixes,
AWS access key ids) reject an obviously-fake body on their own. Detectors that
are **prefix-plus-length alone** — Linear API keys, for one — do not, and will
block.

The fix is to make the probe *embedded* rather than token-initial: prefix it
with something like `ZZZSYNTHETIC`. Every rule in this estate's denylists that
matches such a prefix is **unanchored**, so an embedded occurrence is still a
genuine match for it, while the detector's own leading boundary no longer
holds.

⚠️ **Never resolve it with the "allow this secret" link in the push
rejection.** That whitelists the string estate-wide and teaches reviewers that
push protection is something you click past — the same *"a permanently red gate
gets disabled rather than obeyed"* failure the exemptions mechanism exists to
avoid, on a control this estate does not own.

⚠️ **The corpus ships with the caller, never with this action** — the same
split the `firewall` action makes for the denylist itself. A probe corpus is
*derived* data (a string engineered to match a rule describes that rule), and
the central assertion here is that the corpus exercises **every** rule of
*this* caller's list. Callers' lists legitimately differ, so one shared corpus
would be wrong for every caller but one.

## What is asserted

| # | assertion | catches |
| --- | --- | --- |
| A | every active rule fires on at least one `[must-match]` probe | a rule neutered into a compiling-but-non-matching form; a rule added with no probe behind it |
| B | every `[must-match]` probe fires at least one rule | a rule **deleted** |
| C | no `[must-not-match]` lookalike fires anything | a rule **widened** until it matches ordinary content |

⚠️ **A and B are both needed, and neither alone closes the door.** A design
that asserts `violations == rule_count` is blind to deletion: remove a rule and
*both sides drop by one*, so the equality still holds and the build stays
green. The orphaned probe is what turns it red — which is assertion B.

## Exit codes

| code | meaning |
| --- | --- |
| 0 | every rule proven live, every lookalike proven inert |
| 1 | a liveness assertion failed — the denylist no longer bites as claimed |
| 2 | misconfiguration: no corpus, no denylist, an empty section, a typo'd header, or a rule `grep` cannot compile |

Same three-state contract as the scanner, and for the same reason: *"the
falsifier did not run"* must never be indistinguishable from *"the falsifier
passed"*. A missing corpus is exit 2, not "nothing to check" — **"no falsifier
ran" is precisely the state this exists to end**, and a skipped check renders
green exactly like a passing one.

## ⚠️ The corpus fires the real gate on itself, and that is handled in the open

The corpus is a file full of denylist-shaped strings, so the caller's *real*
firewall matches it. That is not a wart; it is the file working.

It is handled by **one committed `.firewallignore` entry per rule**, each
naming the corpus path and that one rule, each with its mandatory reason:

```
.firewall-probes	<rule text verbatim>	synthetic falsifier probe for this rule — must match, by construction
```

⚠️ **It is deliberately *not* solved by excluding the corpus from the scan
inside the tooling.** A silent exclusion is the defect class
`arqtiqa/arqtos#343` was filed for — a file dropped from the scan before
`.firewallignore` ever got a chance to record a decision about it. Entries in
`.firewallignore` are visible in the diff, scoped to one path and one rule
each, and **fail closed**: edit or delete a rule and its entry matches no
active pattern, which is exit 2.

That gives a deleted rule **two** independent red paths — the falsifier's
orphaned probe, and the gate's own stale exemption.

⚠️ **The falsifier itself scans its probes with exemptions OUT of force**, and
says so on every run. It must: otherwise the corpus's own suppression would
suppress the falsifier too, and it would assert nothing while staying green.

## Two things this action deliberately does not do

- **It does not implement matching.** It drives the real
  `check-private-content.sh` from its own sibling directory, so it proves the
  scanner build the caller's gate actually runs. A falsifier with its own
  engine proves only that its engine agrees with itself.
- **It does not cover the identity overlay.** Overlay liveness is
  `arqtiqa/arqtos#344`'s job (`require-identity-overlay`), and an overlay
  pattern is a *secret* — no committed corpus could probe one without
  publishing it. The three overlay environment variables are actively
  stripped from every scanner invocation, so an ambient overlay cannot pollute
  the fired-rule set.

## Residual, stated

Because probes are scanned with exemptions disabled, this action **cannot see
an exemption that widened** until it swallows real content. That failure mode
is held by the exemptions mechanism's own fail-closed validation
(`arqtiqa/arqtos#341`, `#365`: a glob matching no tracked file, or a verbatim
rule matching no active pattern, is exit 2) and by review of a security file.

⚠️ Do **not** close it by teaching this action a second glob engine. The
reference one lives in the scanner, and a second implementation of matching
semantics is the drift `arqtos-cli#828` was filed about.

## Reports name rules by handle, never by pattern text

A rule handle is `sha256:` + the first 12 lowercase hex digits of the SHA-256
of the pattern's exact text — the same vocabulary `.firewallignore` uses
(`arqtiqa/arqtos#365`), so a handle printed here pastes straight into an
exemption. Handle plus `<denylist>:<lineno>` locates a rule exactly while
quoting nothing: a CI log is a wider audience than a repository.
