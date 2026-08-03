# `go-fmt` — the Go formatting gate

Invokes the **caller's** `make fmt-check`. It does not run `gofmt`.

## The convention it enforces

Every arqtiqa Go repository exposes the same two targets with the same behaviour:

| target | does |
|---|---|
| `make fmt` | **WRITES** — matches `go fmt` / `gofmt`, which write |
| `make fmt-check` | **CHECKS** — fails on unformatted files; what `lint` and CI depend on |
| `make lint` | depends on **`fmt-check`**, never on `fmt` |

```yaml
- uses: arqtiqa/arqtos-actions/.github/actions/go-fmt@v1
```

## ⚠️ Why it invokes rather than implements

The problem was never a missing check. It was **four implementations of one check that disagreed** —
one repo where `make fmt` was a check that failed, one where it rewrote your working tree, one with no
Makefile at all whose check lived inline in its workflow, and a fourth spelling inside a local composite
action.

> **A fifth implementation here would have agreed with nobody** and left the other four in place.

So the **Makefile target is the single definition** and this action is the single **invocation**. That is
also what lets a developer run locally exactly what CI runs — which an inline `gofmt -l` in a workflow
never permits.

## What it adds over `run: make fmt-check`

**The adoption check.** A repo that has not adopted the convention otherwise fails with
`make: *** No rule to make target 'fmt-check'`, which reads as a broken workflow rather than as an
unadopted standard. This action separates three states:

| state | message |
|---|---|
| no `Makefile` | the repo has not adopted the convention, with the targets to add |
| `Makefile`, no target | partially adopted or renamed — **lists the targets that do exist** |
| target present | runs it |

## ⚠️ The gofmt trap has two halves — the caller must handle both

This action cannot enforce the check's *body* from outside. A caller's `fmt-check` must handle:

1. **`gofmt -l` exits 0 while listing files.** The exit code gates nothing — the **emptiness** of the
   output is the check.
2. **`gofmt` exits non-zero when it cannot PARSE a file**, and that is *not* "formatting is fine".

> **Collapsing the two makes an unparseable tree report CLEAN.** Handling only the first is the common
> mistake, and it produces a gate that looks correct and cannot fail on a real class of breakage.

A reference body that handles both:

```make
fmt:
	gofmt -w .

fmt-check:
	@out=$$(gofmt -l . 2>/tmp/gofmt.err); status=$$?; \
	if [ $$status -ne 0 ]; then \
	  echo "gofmt could not parse the tree (exit $$status) — this is NOT a passing format check"; \
	  cat /tmp/gofmt.err >&2; exit 1; \
	fi; \
	if [ -n "$$out" ]; then \
	  echo "not gofmt-clean — run 'make fmt':"; echo "$$out"; exit 1; \
	fi; \
	echo "gofmt: clean"

lint: fmt-check vet
```

## Inputs

| input | default | notes |
|---|---|---|
| `make-target` | `fmt-check` | override only with a documented reason — needing to is itself a drift signal |
| `working-directory` | `.` | directory containing the `Makefile` |

## Verifying a caller

A formatting gate that cannot fail is worse than none. Prove yours discriminates:

```
clean tree        -> exit 0, "gofmt: clean"
dirty tree        -> exit non-zero, lists the files
unparseable tree  -> exit non-zero, "could not parse the tree"
```
