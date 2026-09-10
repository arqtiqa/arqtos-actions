# YAML extension gate

Asserts that arqtos-authored YAML in the calling repository is spelled `.yaml`,
against **one** estate-wide exemption list.

```yaml
- uses: actions/checkout@v7
- uses: arqtiqa/arqtos-actions/.github/actions/yaml-extension@v1
```

That is the whole adoption cost. There is no harness to install, no Makefile
target to add, and no per-repository exemption file — which is the point.

## Why this one ships an implementation

The `go-fmt` action in this repository deliberately does **not** implement its
check: it invokes the caller's `make fmt-check`, because four repositories had
four disagreeing spellings of one check and a fifth would have agreed with
nobody.

This case is the opposite shape. Measured at `arqtiqa/arqtos-core#206`: of the
six repositories this gate is for, **one had a check and five had no CI harness
of any kind** — no directory to add a gate to, no Makefile target to invoke.

There is nothing to invoke in five of the six. Asking each to grow a harness is
how the estate would end up with six implementations rather than one — the
divergence `go-fmt` warns about, arrived at from the other direction.

## The exemptions, and the two shapes they take

| entry | shape | why |
|---|---|---|
| `name:dependabot.yml` | one exact filename | GitHub reads only `.github/dependabot.yml` |
| `dir:.github/ISSUE_TEMPLATE/` | any name under a directory | GitHub reads **any** name there |

⚠️ **The two shapes are not interchangeable.** A name-keyed issue-form entry
would either miss a template somebody adds tomorrow, or spare a `bug.yml`
anywhere in the tree. `arqtos-core`'s own gate is name-only, which is one of the
recorded differences below.

⚠️ **`action.yml` is not exempt.** GitHub documents both spellings, so "the tool
dictates" does not apply. `#206` ruled these are renamed — and this action's own
`action.yaml` is the proof that works.

## Three states, and the middle one matters

| exit | meaning |
|---|---|
| 0 | every YAML is `.yaml`, or declared |
| 1 | a stray `.yml` exists — the list is printed |
| 2 | **REFUSED to judge**: unreadable or empty exemption list, an entry naming no tool, an entry that is neither `name:` nor `dir:`, or a root containing no YAML at all |

A root with no YAML is refused rather than passed, because a check that looked
at nothing has said nothing, and a misconfigured `root` otherwise reads as
conformance.

## What is still owed

The one repository that already had a check keeps it, and the divergence is
real rather than an oversight:

- this action runs only in CI; that repository's gate also runs locally, so a
  developer sees it before pushing;
- it carries its own selftest, which this one replaces with `pytest`;
- its exemption entries are name-only, so it cannot express the directory shape
  the issue forms need.

Two enforcement points, one policy. **The policy is what must not drift**, and
reconciling the two lists is recorded as owed at `arqtiqa/arqtos-core#206`
rather than claimed as done here.
