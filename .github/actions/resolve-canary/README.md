# `resolve-canary`

A deliberately trivial composite action. It succeeds if it ran at all.

## Why it exists

Cross-repository action resolution is a **configuration** property — host visibility plus the org access policy — and it fails **before any step runs**:

```
##[error]Unable to resolve action `<owner>/<repo>`, not found
```

That failure cannot be reproduced by a test inside this repository, because resolution is what a *consumer* does. Referencing this action from a consumer is the cheapest assertion that it still works.

It has no inputs and no logic, so a failure means **resolution**, not the action. That is the whole design: an action with no failure mode of its own is a clean signal.

## Use

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/resolve-canary@v1
```

## When to reach for it

- adding a **public** consumer — the case that fails against a private host
- after any change to the host's visibility or org action-access policy
- diagnosing `Unable to resolve action` before suspecting your own workflow

⚠️ A passing canary proves **resolution**, nothing more. It says nothing about whether the action you actually wanted behaves correctly.
