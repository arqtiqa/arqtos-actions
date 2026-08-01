# arqtos-actions

Shared GitHub Actions for `arqtiqa` repositories. One declared source, referenced — never copied.

## Why this repository is public

Not a preference — a constraint, measured. A **private** repository's composite action **cannot be resolved by a public consumer**, even with `access_level: organization` set on the host:

| consumer | visibility | result |
|---|---|---|
| private | private host | ✅ resolves |
| public | private host | ❌ `Unable to resolve action '<host>', not found` |

Three arqtiqa repositories are public, so a private host would have forced them to keep local copies — which is the duplication this repository exists to end.

> The access policy lives on the **host**, and querying it on a public repository returns `422 — Access policy only applies to internal and private repositories`. So this is not visible by reading settings; it has to be run.

## ⚠️ What may never be committed here

Everything in this repository is world-readable. That makes the boundary sharp:

| | |
|---|---|
| ✅ **logic** | composite actions, scripts, the steps a check performs |
| ❌ **patterns** | a denylist, an allowlist, any list of the things a check protects — **a denylist is a list of what it guards**, so publishing it defeats it |
| ❌ **defaults that bundle patterns** | an action must not ship a fallback denylist. Make the input **required**, so a missing one is a *misconfiguration*, never a silent fall-back |
| ❌ **credentials, tokens, environment dumps** | including in examples and test fixtures |
| ❌ **anything identifying a person, machine or customer** | a real name, a personal address, a host-naming scheme, a customer name |

Patterns are supplied at run time from a secret — the same split used elsewhere in the estate: **the mechanism is public, the data is not.**

⚠️ **The reviewable question for any change here is not "does it work" but "what does it now reveal".**

## Consuming an action

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/<name>@v1
```

Pin the **moving major tag** `@v1` — not `@main`, and not an exact SHA.

- `@main` puts every commit live in every consumer with no review in any of them.
- an exact SHA reintroduces one bump per consumer, which is the cost a single source exists to remove.
- `@v1` moves on a **deliberate act**, which makes that act the reviewable moment.

⚠️ **These tags are action-resolution pointers, not a release channel.** No changelogs, no artifacts, no release notes. A retag reaches every consumer at once — treat it as a review, not a chore.

## The baseline manifest

[`ci-baseline.yml`](ci-baseline.yml) declares the version of every action used by two or more consumers. The gate reads it and fails a pull request pinning a governed action off it.

⚠️ It carries **no organisation specifics** — no repository names, no work-item references, no internal metrics. Version pins are not sensitive; **which of your repositories lags is.** Estate-specific detail (which repos a pin moves, what to re-verify per consumer) lives on the private side and is derived by scanning rather than stored, so there is no list to go stale.

⚠️ An action is governed **only when two or more repositories need it.** A single-consumer action stays local and is ignored by the gate — its absence from the manifest is a statement, not an omission. Do not add one "for completeness": a name in that file reads as governed, and the gate would start enforcing a version on the one repository entitled to choose it.

## Actions

| action | purpose |
|---|---|
| [`resolve-canary`](.github/actions/resolve-canary) | proves cross-repository action resolution still works — see its README |

## What this repository is not

It holds **no arqtos source**, no work items, and is on no project board. Work that changes an action here is tracked in the estate's work repository.
