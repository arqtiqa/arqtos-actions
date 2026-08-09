# `firewall`

Scans tracked files against a **caller-supplied** denylist. Fails when any pattern matches.

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/firewall@<40-char-sha>  # v1
  with:
    denylist: .github/scripts/private-content-denylist.txt
    # optional -- see "Exemptions" below; omit to use the default
    # .firewallignore convention path if the repo has one
    exemptions: .firewallignore
```

## ⚠️ Pin this action to a commit SHA — it is the one that does not use `@v1`

Every other action here takes the moving `@v1` tag. This one does not, and the reason is **how it fails**, not consistency:

| action | if compromised or mis-retagged |
|---|---|
| `python-toolchain` | the build **breaks loudly** — the toolchain is missing, tests do not run |
| `resolve-canary` | breaks loudly, and is trivial by construction |
| **`firewall`** | ⚠️ **can report CLEAN** — the scan simply finds nothing |

A compromised firewall action does not announce itself. It puts a **green check** on a repository whose private-content gate is no longer running. That is the silent-failure mode this action's own exit-code contract exists to prevent — the same shape as a missing denylist reading as clean — arriving one level up.

So the cost a moving tag exists to avoid, one bump per consumer per change, is paid **once**, for the one action where nobody would notice the failure.

Annotate the pin with the tag (`# v1`) so a human can still read which release it is.

## ⚠️ It ships no denylist, and that is the design

**A denylist is a list of the things it protects.** A copy committed here — a public repository — would publish exactly what it exists to guard. So the logic is shared and the **data is not**.

That asymmetry is not tidiness, it is required. One repository's list legitimately differs from another's: a repo readable by people outside the organisation must not carry maintainer-identity patterns, while an internal-only repo should. **Centralising the data would force the union, and the union is the disclosure.**

So: **share the logic, keep every denylist scoped to the audience of the repo it lives in.** New *secret-shape* patterns (a token format for some service) belong everywhere. Identity-shape patterns belong only where the audience already knows them.

## ⚠️ A missing denylist is a misconfiguration, never "clean"

| exit | meaning |
|---|---|
| `0` | clean |
| `1` | a pattern matched (`file:line` on stderr) |
| **`2`** | **misconfiguration — a missing denylist, among others** |

The third state is the one that matters and the one most easily lost in a refactor: `0` and `1` are what anyone thinks to test, and `2` only fires when something is already wrong. **A scan with nothing to scan against reports every file clean**, which is worse than not running at all, because it looks like a pass.

⚠️ **Do not add a default denylist to make this convenient.** The inconvenience *is* the guarantee.

The check is duplicated deliberately — in this action *and* in the script — because GitHub does **not** enforce `required: true` for composite-action inputs. The declaration is documentation, not a guarantee, so an empty input would otherwise fall through to the script's own path resolution and fail naming a path the caller never chose.

## Inputs

| input | required | notes |
|---|---|---|
| `denylist` | **yes** | no default, no bundled fallback; absent or unreadable → `2` |
| `files` | no | space/newline-separated; defaults to `git ls-files` |
| `exemptions` | no | path+rule exemptions file; empty defaults to `.firewallignore` at the repo root if present — see "Exemptions" below, including how a rule handle exempts an identity-overlay hit without quoting it |
| `identity-overlay` | no | identity-tier pattern **text** (not a path) for the org secret `ARQTOS_FIREWALL_IDENTITY_OVERLAY` (`#342`) — see "The identity-tier overlay" below |
| `require-identity-overlay` | no | `'true'` to make identity coverage a requirement rather than best-effort (`#344`) — see "Requiring identity coverage" below |

## The identity-tier overlay

The firewall has two tiers. **Credential** patterns ship in the caller's committed `denylist`. **Identity** patterns — a login, a hostname scheme, a customer name — are deliberately committed nowhere, because embedding them would compile confidential regex text into a world-readable release asset regardless of which tier a caller selected. They are distributed instead as the org secret `ARQTOS_FIREWALL_IDENTITY_OVERLAY` and supplied at runtime:

```yaml
    identity-overlay: ${{ secrets.ARQTOS_FIREWALL_IDENTITY_OVERLAY }}
```

Absent (unset, or the secret unavailable — a Dependabot-triggered run, which GitHub never grants org secrets to) is a legitimate, **stated**, credential-tier-only run; it never fails just because the overlay is missing. A value that **is** supplied but resolves to zero usable pattern lines (all-comment, all-whitespace, a truncated secret) is a configuration error (`2`), never a pass — the same rule the denylist's own empty-file guard follows. The overlay's own pattern text is never printed in the report, on any path; neither is a matched line's **content**, which for an identity rule *is* the confidential string (`arqtiqa/arqtos#365`) — an overlay hit reports its rule's handle and `path:line`, nothing else.

A legitimate identity match is exempted the same way any other match is, by a committed `.firewallignore` entry — see "Exempting an identity-overlay rule" below. Without that, wiring this input on a repository with even one legitimate match produced a permanently red gate, which is why the estate sat at one adopting repository.

## Requiring identity coverage

`identity-overlay` alone cannot tell a caller "unwired" apart from "wired to an empty secret, a rotated secret, or a secret this repository's visibility never covered" — all of them just look like the ordinary credential-tier-only default, indefinitely. `require-identity-overlay: 'true'` closes that gap **for the repositories where the secret can actually be present**:

```yaml
on:
  pull_request:
  push:
    branches: [main]   # ⚠️ the backstop below depends on this trigger existing

jobs:
  firewall:
    steps:
      - uses: arqtiqa/arqtos-actions/.github/actions/firewall@<40-char-sha>  # v1
        with:
          denylist: .github/scripts/private-content-denylist.txt
          identity-overlay: ${{ secrets.ARQTOS_FIREWALL_IDENTITY_OVERLAY }}
          require-identity-overlay: 'true'
```

⚠️ **Only the literal strings `'true'` and `'false'` are accepted.** This is a security opt-in, so a typo (`'TRUE'`, `'yes'`, `'1'`) is refused (`2`) rather than silently treated as `'false'` — the same silent-degradation class this input exists to close would otherwise reappear in its own argument parser.

⚠️ **The repositories that most need this are exactly the repositories where GitHub withholds the secret** — a pull request whose head repository differs from this one, or a Dependabot-triggered run (its own separate secret store). Setting `require-identity-overlay: 'true'` does **not** turn those runs red: the action detects that context itself from ambient `github.*` facts (never something a caller's `with:` block supplies) and reports that identity coverage could not be verified **this run** — credential-tier only, stated distinctly from both a clean run that had the overlay and a genuine failure. What **does** fail (`2`) is the case this input exists to catch: the same repository, in a context where the secret is expected to be available, running without it.

⚠️ **A repository adopting this input still needs the `push: branches: [main]` trigger shown above.** It is the merge-time backstop the fork/Dependabot exemption depends on: the run that lands on `main` once such a PR merges executes with the real secret and is what actually verifies coverage for that change — the same pattern `arqtos-skills`' `estate-identifiers` job already uses (skip on Dependabot, recover via the push-triggered run). Setting `require-identity-overlay: 'true'` states the intent; it does not by itself supply that backstop run. Without the trigger, an external contribution's identity coverage is stated as unverified and then never actually checked by anything, ever.

## Exemptions

A denylist rule sometimes legitimately fires on content that is **deliberately** shaped like a violation — a doc teaching a credential-reference syntax by example, or a fixture whose entire purpose is a concrete secret-shaped string a detector test asserts against. Without an escape hatch, a repo with any such fixture gets a **permanently red** gate on material that is entirely legitimate, and a permanently-red gate gets disabled rather than obeyed.

`exemptions` names a committed file of one exemption per line, three **mandatory** whitespace-separated fields:

```
<path-glob>  <rule>  <reason>
```

A tab or 2+ spaces separates the fields (a single space is ordinary prose punctuation, not a boundary). `<path-glob>` is matched `*`/`?`-never-crosses-`/` style against a scanned file's path; `<rule>` names one active pattern — either a denylist line's exact text copied verbatim, or a **rule handle** (see below); `<reason>` is a mandatory one-line justification — never optional, since that is what stops this file from growing into a blanket suppression nobody has to justify. Blank lines and full-line `#` comments are skipped, same convention as the denylist itself.

⚠️ **Scoped as narrowly as the mechanism allows: path + one specific rule, never "skip this rule everywhere" and never "skip every rule for this path."** A fixture needing two rules exempted gets two entries. An exemption suppresses only its own named (path, rule) pair — a file exempted for one rule still fails on any other rule that also matches it, and a rule exempted for one path still fires on every other path.

⚠️ **Fail closed on a stale entry.** A path glob matching no tracked file, or a **verbatim** rule matching no active pattern, is a **configuration error (exit 2)**, never a silent no-op — validated before any scanning happens, exactly like the denylist's own empty-file guard above. A stale exemption left in place after its target is renamed, deleted, or its pattern is tightened would otherwise rot into a permanent, invisible blind spot.

### Exempting an identity-overlay rule — rule handles

An identity-overlay match can be exempted too (`arqtiqa/arqtos#365`), but it cannot be exempted by quoting the rule: `.firewallignore` is **committed** and an overlay pattern is a **secret**, so the entry has to name a rule it must never write down. It names it by **handle** instead — `sha256:` plus the first 12 lowercase hex digits of the SHA-256 of the pattern's exact text:

```
.arqtos/memory/*.md  sha256:a645c356c63b  internal governance note, never on a publication path
```

**You never compute a handle by hand.** A failing run prints the handle of whichever overlay rule fired, together with the exemption line's shape, and prints the hit as `path:line` only — never the pattern and never the matched line's content, both of which are the confidential text the identity tier exists to keep out of a log.

⚠️ **A handle, not a position.** A positional reference (`overlay:3`) fails **open**: insert or reorder a rule in the secret and every exemption silently re-points at a *different* rule, suppressing something nobody reviewed while still reading as a reviewed decision. A digest cannot re-point — it resolves to the exact same pattern text or to nothing:

| what changes | what happens |
|---|---|
| the overlay is **reordered** | nothing moves; order is not part of a rule's identity |
| a rule is **edited** | its digest moves, the handle resolves to nothing, the exemption is **held inert** (disclosed on stderr) — so the edited rule scans that path again and the run goes **red** if it still matches |
| the overlay is **absent** (fork PR, Dependabot, or never wired) | the handle resolves to nothing and is held inert — the tier did not run, so nothing is under-scanned, and an external contribution does not go red on a committed exemption it cannot resolve |

An unresolvable handle is therefore held inert while an unresolvable **verbatim** rule is still exit 2: verbatim text names a rule set that is wholly present in the run, so a miss there really is staleness. Losing a suppression restores protection; it never removes any.

⚠️ **Do not quote an overlay pattern verbatim.** It resolves — the reference Go implementation compares `<rule>` against every active pattern's source text, so the shell must too — but it is unusable: the identity tier scans `.firewallignore` itself, so the entry turns the exemptions file into an overlay hit on its own line and the run fails anyway. For a **denylist** rule the verbatim text remains the recommended form; it is committed and public, so there is nothing to withhold.

Absent is fine: with no `exemptions` input and no `.firewallignore` present, behaviour is unchanged from a build with no exemptions mechanism at all. An **explicitly-named** `exemptions` path that does not exist, though, is a configuration error — naming one on purpose is a deliberate pointer, not an optional convention.

This is the same format and the same fail-closed validation the reference Go implementation of this policy already uses (see "There is a second implementation of this policy" below), so one committed exemptions file serves both engines.

## Why the script is vendored inside this action

A composite action can only run files that ship with it. Placing the script beside `action.yml` makes the action self-contained and located relative to `github.action_path`, so it works regardless of the caller's working directory.

⚠️ **This is the third home this script has had, and the reason matters**: a workflow cannot check out another **private** repository with the default `GITHUB_TOKEN`, which is why consumers previously vendored their own copies. Hosting it in a public repository is what makes a shared copy reachable at all.

## ⚠️ There is a second implementation of this policy

The same rules are implemented in Go inside the `arqtos` binary, for local and pre-push use — a CI runner has no binary, and pre-push must not depend on CI, so both are needed. They are **not** currently checked against each other; that gap is tracked separately. If you change matching behaviour here, assume the other side does not follow.
