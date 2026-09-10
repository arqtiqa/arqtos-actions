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
| ❌ **an action's own patterns** | no action under `.github/actions/` may carry, bundle or default a denylist — **a shared denylist is the union of every caller's list**, and the union is the disclosure |
| ❌ **defaults that bundle patterns** | make the input **required**, so a missing one is a *misconfiguration*, never a silent fall-back |
| ❌ **credentials, tokens, environment dumps** | including in examples and test fixtures |
| ❌ **anything identifying a person, machine or customer** | a real name, a personal address, a host-naming scheme, a customer name — **in any file, including a denylist** |
| ✅ **this repo's own caller list** | `.github/scripts/private-content-denylist.txt` — generic credential *shapes* and private-network ranges, scoped to this repo's audience, read only by this repo's own `firewall` workflow |
| ✅ **this repo's own probe corpus** | `.firewall-probes` — one **synthetic** string per rule, shaped *like* what the rule catches and never an instance of it. It is exempted per-rule in `.firewallignore`, visibly, because the gate matches it by construction — that is the file working. ⚠️ A "probe" that was a real secret would be a leak filed as a test |

An action's data is public; a caller's data is the caller's. **The mechanism is shared, the patterns are not.**

⚠️ **The last two rows look contradictory and are not — the distinction is load-bearing, and this is the only repository where it can be got wrong,** because the action and one of its callers live here together.

- **A generic credential *shape*** — `ghp_` followed by 36 base62 characters — is published by the vendor that issues it. It describes a *format*, tells a reader nothing about this estate, and is why the equivalent patterns are compiled into a world-readable release binary (arqtos-cli#839).
- **An identity pattern** — a login, a hostname scheme, a customer name — *is* a description of the thing it guards. Committing one here publishes it. #839 removed exactly these from the embedded tiers and moved them to a run-time overlay, and that ruling binds this repository too.

So: this repo scanning **itself** against generic shapes is correct and was the gap (arqtos-sdk-go#38 — the repo hosting the firewall was not running it). The shared **action** shipping those same shapes as a default would still be wrong, for a different reason: it would make a caller's missing denylist look like a clean scan.

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

[`ci-baseline.yaml`](ci-baseline.yaml) declares the version of every action used by two or more consumers. The gate reads it and fails a pull request pinning a governed action off it.

⚠️ It carries **no organisation specifics** — no repository names, no work-item references, no internal metrics. Version pins are not sensitive; **which of your repositories lags is.** Estate-specific detail (which repos a pin moves, what to re-verify per consumer) lives on the private side and is derived by scanning rather than stored, so there is no list to go stale.

⚠️ An action is governed **only when two or more repositories need it.** A single-consumer action stays local and is ignored by the gate — its absence from the manifest is a statement, not an omission. Do not add one "for completeness": a name in that file reads as governed, and the gate would start enforcing a version on the one repository entitled to choose it.

## Actions

| action | purpose |
|---|---|
| [`firewall`](.github/actions/firewall) | scans tracked files against a **caller-supplied** denylist — ships none, by design |
| [`firewall-falsifier`](.github/actions/firewall-falsifier) | proves every rule in that denylist still **bites** — a green gate is not evidence the list still matches anything; ships no corpus, by design |
| [`go-fmt`](.github/actions/go-fmt) | invokes the caller's `make fmt-check` — **does not run gofmt**, by design; see its README |
| [`python-toolchain`](.github/actions/python-toolchain) | sets up `uv` at the governed version — the only place that pin lives |
| [`resolve-canary`](.github/actions/resolve-canary) | proves cross-repository action resolution still works — see its README |

## What this repository is not

It holds **no arqtos source**, no work items, and is on no project board. Work that changes an action here is tracked in the estate's work repository.
