# `firewall`

Scans tracked files against a **caller-supplied** denylist. Fails when any pattern matches.

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/firewall@v1
  with:
    denylist: .github/scripts/private-content-denylist.txt
```

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

## Why the script is vendored inside this action

A composite action can only run files that ship with it. Placing the script beside `action.yml` makes the action self-contained and located relative to `github.action_path`, so it works regardless of the caller's working directory.

⚠️ **This is the third home this script has had, and the reason matters**: a workflow cannot check out another **private** repository with the default `GITHUB_TOKEN`, which is why consumers previously vendored their own copies. Hosting it in a public repository is what makes a shared copy reachable at all.

## ⚠️ There is a second implementation of this policy

The same rules are implemented in Go inside the `arqtos` binary, for local and pre-push use — a CI runner has no binary, and pre-push must not depend on CI, so both are needed. They are **not** currently checked against each other; that gap is tracked separately. If you change matching behaviour here, assume the other side does not follow.
