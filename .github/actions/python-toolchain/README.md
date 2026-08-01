# `python-toolchain`

Sets up `uv` at the governed version, cached. **The only place that version lives.**

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/python-toolchain@v1
- run: uv run --locked pytest
```

## Why an action rather than a documented pin

Before this existed, `astral-sh/setup-uv@v9.0.0` appeared **11 times across two repositories** — every occurrence a place the version could drift, and a place a bot has to bump.

⚠️ **Do not reference `astral-sh/setup-uv` directly.** Use this action. The manifest treats a direct reference as a violation, and that rule is what makes this a *single* source rather than a second one: a composite action cannot read the manifest to discover its own pin, so the literal has to live somewhere — and the guarantee is that it lives here **and nowhere else**.

⚠️ The pin is **exact**, not a moving major, because `setup-uv` publishes no moving major tag: `v9` and `v8` both 404. `@v9` would simply fail to resolve.

## `--locked`, not `--frozen`

The action prints this on every run, because it was got wrong in practice before it was measured:

| invocation | behaviour on a stale lock |
|---|---|
| `uv run` | **silently re-locks** — rewrites the lockfile as a side effect of a test run |
| `uv run --frozen` | uses the lock verbatim but **never validates it** — an un-locked dependency is ignored and the run **passes** |
| `uv run --locked` | **errors**, naming the stale lock |

`--frozen` is a weaker check wearing the name of a stronger one. Only `--locked` turns a stale lock into a failure instead of a silent divergence.

⚠️ **This action does not run your commands for you**, deliberately. Wrapping `uv run` would put the flag inside the action, where nobody chooses it — and the flag *is* the decision.

## Inputs

| input | default | notes |
|---|---|---|
| `enable-cache` | `true` | every known consumer wants it; a cold cache is waste on a per-PR gate |
| `python-version-file` | `''` | empty lets `uv` do its own discovery. ⚠️ Set it only where a repo genuinely differs — naming it when the default already finds it re-creates the duplication this action removes |
