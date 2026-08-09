#!/usr/bin/env bash
# check-private-content — gate that fails when staged / changed files
# match a denylist pattern. The private-content firewall.
#
# Usage:
#   check-private-content.sh <file> [<file>...]
#   check-private-content.sh                          # nothing to check; exits 0
#   check-private-content.sh --denylist=<path> ...     # override denylist location
#   check-private-content.sh --exemptions=<path> ...   # override exemptions file
#   ARQTOS_FIREWALL_IDENTITY_OVERLAY="$(pattern lines)" check-private-content.sh ...
#                                                       # union in the identity tier
#   ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY=true check-private-content.sh ...
#                                                       # insist on identity coverage
#                                                       # (arqtiqa/arqtos#344)
#
# Exits 0 if no matches, 1 if any pattern fires, 2 on configuration error
# (missing denylist, etc). A DENYLIST hit reports file:line:content on
# stderr; an IDENTITY-OVERLAY hit reports the rule's handle and file:line
# only -- neither the pattern nor the matched line's content, both of which
# are confidential identity text (arqtiqa/arqtos#365).
#
# ARQTOS_FIREWALL_IDENTITY_OVERLAY (optional environment variable, never a
# CLI flag or a committed path -- see the module doc further down for the
# full "why") unions an identity-tier pattern list into the scan. Absent
# (unset or empty) is a legitimate, stated, credential-tier-only run. Set
# but resolving to zero usable pattern lines is a configuration error
# (exit 2). The overlay's own pattern text is never printed.
#
# ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY (optional, arqtiqa/arqtos#344) --
# set to the literal string "true" to turn an absent overlay from a stated
# default into a misconfiguration (exit 2), EXCEPT in a run where GitHub is
# known to withhold the secret (a fork pull request, or Dependabot), where it
# instead reports identity coverage as required-but-unverified rather than
# failing. See the module doc further down ("require-identity-overlay") for
# the full "why", and this action's action.yml for how the fork/Dependabot
# context is derived (ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD) -- never a
# caller-supplied input, so a caller cannot set its way out of the
# requirement. Only the exact strings "true" and "false" (or unset/empty,
# treated as "false") are accepted -- this is a security opt-in, so any
# other value (a typo like "TRUE", "yes", "1") is a configuration error
# (exit 2) rather than a silent no-op.
#
# --exemptions=<path> (optional) names a committed path+rule escape hatch
# (arqtiqa/arqtos-cli#851) for content that is DELIBERATELY supposed to look
# like a violation -- docs teaching a credential-ref syntax by example, or a
# fixture whose entire purpose is a concrete secret-shaped string a detector
# test asserts against. Defaults to .firewallignore in the current directory;
# a missing DEFAULT is fine (no exemptions committed yet), but an
# explicitly-named path that does not exist is a configuration error (exit
# 2) -- naming one on purpose is a deliberate pointer, not an optional
# convention.
#
# Format: one exemption per line, three MANDATORY fields separated by a tab
# or 2+ spaces -- `<path-glob>  <rule>  <reason>`. <path-glob> is matched
# (`*`/`?` never cross a `/`, .gitignore-style) against a scanned file's
# path as it appears in the scan's own file list; <rule> names ONE active
# pattern, either as a denylist line's exact text (copy it verbatim) or as
# a RULE HANDLE (`sha256:` + the first 12 hex digits of the pattern text's
# SHA-256 -- see "EXEMPTING AN IDENTITY-OVERLAY RULE" below); <reason> is a
# mandatory one-line justification. Blank lines and full-line `#` comments
# are skipped, same convention as the denylist file. Scoped as narrowly as
# the mechanism allows: one rule per entry, never "skip this rule
# everywhere" -- a file needing two rules exempted gets two entries.
#
# FAIL CLOSED: a path glob matching no tracked file, or a VERBATIM rule
# matching no active pattern, is a configuration error (exit 2), never a
# silent no-op -- a stale exemption must never rot into an invisible blind
# spot. This mirrors the reference Go implementation's exemptions mechanism
# exactly (same format, same fail-closed validation), so one committed
# exemptions file serves both engines.
#
# EXEMPTING AN IDENTITY-OVERLAY RULE (arqtiqa/arqtos#365).
#
# ⚠️ THE PROBLEM THE HANDLE SOLVES. `.firewallignore` is COMMITTED; an
# overlay pattern is a SECRET (see the identity-overlay section below), and
# its text is confidential identity regex -- arqtiqa/arqtos-cli#1009 filed
# exactly that text reaching a log as a defect. So an exemption for an
# overlay rule has to name a rule it must never quote. Before #365 it could
# not name one at all: <rule> resolved only against the on-disk denylist, so
# any entry for an overlay rule exited 2 ("rule does not match any active
# denylist pattern") and the overlay was unadoptable on any repo with even
# one legitimate match.
#
# A rule handle is `sha256:` followed by the first 12 lowercase hex digits
# of the SHA-256 of the pattern's exact text. It discloses nothing (a digest
# is not the preimage), and the violation report PRINTS the handle of
# whichever overlay rule fired, so an author never has to compute one.
#
# ⚠️ WHY A DIGEST AND NOT A POSITION (`overlay:3`). A positional index fails
# OPEN: insert or reorder a rule in the secret and every exemption silently
# re-points at a DIFFERENT rule, suppressing something nobody reviewed,
# with nothing anywhere to detect it. A digest cannot re-point: it resolves
# to the exact same pattern text or to nothing at all.
#
#   * REORDERED overlay -> every handle still resolves to its own rule.
#     Order is not part of the identity, so nothing moves.
#   * EDITED rule -> its digest changes, the handle resolves to no active
#     pattern, and the exemption is HELD INERT (disclosed on stderr, never
#     silently dropped): the edited rule scans that path again, so if it
#     still matches, the run turns RED and the change is visible. The
#     suppression can only ever be LOST by an edit, never transferred.
#   * ABSENT overlay (a fork pull request, Dependabot, or a caller that
#     never wired the secret) -> the handle resolves to nothing and is held
#     inert, so a committed overlay exemption does not turn those runs into
#     configuration errors. Nothing is under-scanned: the overlay tier did
#     not run at all in that context. This is deliberately the SAME
#     accommodation arqtiqa/arqtos#344 makes for the same withheld secret.
#
# An inert handle is therefore the fail-closed direction (protection is
# restored, not removed) -- which is why an unresolvable HANDLE is inert
# while an unresolvable VERBATIM rule is still exit 2: verbatim text names a
# rule set that is fully present in this run, so a miss there really is
# staleness.
#
# ⚠️ THE VERBATIM FORM IS NOT MERELY UNSAFE FOR AN OVERLAY RULE -- IT IS
# UNUSABLE. It still RESOLVES (it must: the reference Go implementation
# compares <rule> against every active pattern's source text, and one
# committed file has to serve both engines), but the identity tier scans
# `.firewallignore` itself -- the denylist's three self-skips deliberately do
# not extend to it -- so an entry that quotes an overlay pattern turns the
# exemptions file into an overlay hit of its own, on the entry's own line.
# The run then fails regardless of what that entry exempted elsewhere. The
# handle is therefore not a nicety over quoting the text; it is the only form
# that can work at all for an overlay rule.
#
# A handle also works for an ordinary denylist rule, but prefer the verbatim
# text there: a committed pattern is public, so there is nothing to withhold
# and the text reads better in review.
#
# IDENTITY-TIER OVERLAY (arqtiqa/arqtos#342). Read from the environment
# variable ARQTOS_FIREWALL_IDENTITY_OVERLAY -- the SAME org secret
# (`arqtiqa`, visibility private) arqtos-skills' estate-identifiers job and
# the Go verb's --extra-denylist both consume, so one secret serves every
# consumer. This is deliberately NOT a --overlay=<path> flag: unlike the
# denylist, identity patterns are never committed anywhere (embedding them
# would compile confidential regex text into a world-readable release
# asset), so there is no file for a path to name. Format is identical to
# the denylist's: one pattern per line, blank lines and full-line `#`
# comments skipped.
#
# ⚠️ EMPTY MEANS ABSENT; NON-EMPTY-BUT-ZERO-PATTERNS MEANS MISCONFIGURED.
# A caller that never wires the overlay gets an empty environment variable
# -- that is a legitimate, common, credential-tier-only run, and is STATED
# as such below, never silently upgraded or downgraded. A caller that DOES
# wire it (`identity-overlay: ${{ secrets.ARQTOS_FIREWALL_IDENTITY_OVERLAY }}`)
# but whose value strips down to zero usable pattern lines -- an
# all-comment placeholder, a truncated secret, a bad merge -- gets exit 2,
# never a pass: a zero-pattern overlay reports every file clean, which is
# strictly worse than no overlay at all. There is no --allow-empty escape
# hatch for this, on purpose (arqtos-skills#85 paid for that lesson once).
#
# ⚠️ THE OVERLAY'S PATTERN TEXT IS NEVER PRINTED, even on a match or a
# compile failure. An overlay pattern IS confidential identity regex text
# (arqtiqa/arqtos-cli#1009: the same string reaching `arqtos doctor` stdout
# was a defect); GitHub Actions masks registered secrets in logs, but this
# script does not rely on that alone -- it withholds the text itself, at
# the source, so the same guarantee holds outside Actions too (a local
# invocation, a test, a future consumer).
set -euo pipefail

DEFAULT_DENYLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/private-content-denylist.txt"
denylist="$DEFAULT_DENYLIST"
exemptions=".firewallignore"
exemptions_explicit=0

files=()
all_tracked=0
files0=0
for arg in "$@"; do
  case "$arg" in
    --denylist=*)
      denylist="${arg#--denylist=}"
      ;;
    --exemptions=*)
      exemptions="${arg#--exemptions=}"
      exemptions_explicit=1
      ;;
    --all-tracked)
      all_tracked=1
      ;;
    --files0)
      # ⚠️ Read a NUL-delimited file list from stdin. This exists so the caller
      # never needs `xargs`: xargs SUBSTITUTES ITS OWN EXIT STATUS, mapping the
      # script's 2 (misconfigured) onto 1 (matched) — GNU to 123, BSD to 1 —
      # so a gate that did not run properly became indistinguishable from a
      # caught leak. The three-state contract only survives if this process is
      # the one whose status the caller sees.
      files0=1
      ;;
    --help|-h)
      # ⚠️ Delimited by the first line of code, not by a hard-coded line
      # number. The previous form (`sed -n '2,78p'`) silently truncated the
      # module doc mid-sentence the moment the doc grew, and every future
      # edit to it would have had to remember to re-count.
      sed -n '2,$p' "${BASH_SOURCE[0]}" | sed -n '/^set -euo pipefail/q;p' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    --)
      ;;
    *)
      files+=("$arg")
      ;;
  esac
done

# ⚠️ Fail fast on an EXPLICITLY-named exemptions path that does not exist,
# regardless of how many files this run will end up scanning. Unlike the
# DEFAULT `.firewallignore` convention (whose absence just means "no
# exemptions committed yet" -- a legitimate, common state, checked once the
# scan set is known below), a path the caller names on purpose via
# --exemptions is a deliberate pointer: naming one that does not exist is a
# configuration mistake, not silently ignored.
if (( exemptions_explicit )) && [[ ! -f "$exemptions" ]]; then
  echo "✗ check-private-content: --exemptions $exemptions: no such file" >&2
  exit 2
fi

# ⚠️ THE FILE LIST IS BUILT HERE, NOT BY THE CALLER, AND IT IS NUL-DELIMITED.
#
# This mode exists because the listing used to live in the workflow as
#     git ls-files | xargs check-private-content.sh
# and that is broken: `git ls-files` without -z emits newline-separated paths and
# `xargs` splits on whitespace, so ANY tracked file whose path contained a space,
# tab, quote or backslash was never passed to the scanner — and the scan reported
# CLEAN. A path the scanner never receives cannot match anything.
#
# The Go implementation already carried this exact fix
# (internal/firewall/firewall.go:900, "CRITICAL (arqtos-cli#839 review): this
# MUST run with `-z` and split on NUL") and it never crossed to the shell.
#
# ⚠️ It survived because the logic lived in YAML, where nothing could test it.
# Moving it into the script is the durable half of the fix; -z is only the
# immediate repair.
if (( all_tracked )); then
  while IFS= read -r -d '' f; do
    files+=("$f")
  done < <(git ls-files -z)
fi

if (( files0 )); then
  while IFS= read -r -d '' f; do
    [[ -n "$f" ]] && files+=("$f")
  done
fi

if [[ ! -f "$denylist" ]]; then
  echo "✗ check-private-content: denylist not found at $denylist" >&2
  exit 2
fi

# ⚠️ EXISTING IS NOT ENOUGH — IT MUST CONTAIN RULES.
#
# The guard above tested only that the file is present. A file that is present
# but empty of patterns (zero-byte, all-comment, all-whitespace) made every scan
# report CLEAN: nothing to compare against means nothing matches, and the result
# is indistinguishable from safety. A truncated sync, a bad merge, or a debugging
# session that commented every line out disarms the scan silently.
#
# This is the same rule `check-estate-identifiers` already enforces for its own
# pattern list — "a run with no patterns reports every scan clean and must never
# be usable as a gate" — applied where it was missing.
rule_count=$(grep -cvE '^[[:space:]]*(#|$)' "$denylist" || true)
if [[ "${rule_count:-0}" -eq 0 ]]; then
  echo "✗ check-private-content: $denylist exists but contains no rules." >&2
  echo "  A scan with nothing to scan against passes every file, so this is a" >&2
  echo "  misconfiguration (exit 2), not a clean result." >&2
  exit 2
fi

# ---------------------------------------------------------------------------
# Identity-tier overlay (arqtiqa/arqtos#342) -- see the module doc above for
# the full "why". Parsed and validated HERE, alongside the denylist's own
# rule-count guard above and before the "no files" shortcuts below, because
# a misconfigured overlay is a configuration error regardless of how many
# files this particular run happens to touch.
# ---------------------------------------------------------------------------
overlay_raw="${ARQTOS_FIREWALL_IDENTITY_OVERLAY:-}"
overlay_rules=()
if [[ -n "$overlay_raw" ]]; then
  while IFS= read -r ov_line; do
    # ⚠️ `(#|$)`, not `-z ||  #` — an all-WHITESPACE line (no `#`) must also
    # count as blank, same as the denylist's own rule-count guard above
    # (`grep -cvE '^[[:space:]]*(#|$)'`). Using the narrower `-z` test here
    # would let a whitespace-only overlay line slip through AS a pattern
    # (a literal-space regex), masking the exact all-whitespace-secret
    # misconfiguration this guard exists to catch.
    [[ "$ov_line" =~ ^[[:space:]]*(#|$) ]] && continue
    overlay_rules+=("$ov_line")
  done <<<"$overlay_raw"

  # ⚠️ NON-EMPTY input that resolves to ZERO usable patterns is the
  # misconfiguration this guard exists for (see module doc) -- NOT the
  # same as an absent overlay, handled by the honesty statement below.
  if [[ "${#overlay_rules[@]}" -eq 0 ]]; then
    echo "✗ check-private-content: \$ARQTOS_FIREWALL_IDENTITY_OVERLAY was supplied but contains no rules." >&2
    echo "  A zero-pattern overlay reports every file clean, which is strictly worse" >&2
    echo "  than no identity coverage at all -- this is a misconfiguration (exit 2)," >&2
    echo "  never a pass. There is no --allow-empty escape hatch for this." >&2
    exit 2
  fi
fi

# ---------------------------------------------------------------------------
# require-identity-overlay (arqtiqa/arqtos#344) -- an opt-in that lets a
# caller INSIST on identity coverage rather than silently accepting its
# absence. Default is off (ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY unset or
# any value other than the literal string "true"): every one of this action's
# existing callers never sets this, so this whole block is a no-op for all of
# them -- unreached, because the guard below only fires when BOTH this is
# true AND overlay_rules is still empty at this point (which, given the block
# above, means the overlay was ABSENT -- unset or the literal empty string --
# never "present but empty", which already exited 2 above regardless of this
# input).
#
# ⚠️ THE CENTRAL DIFFICULTY (see this Story's brief in full): the repositories
# that most need required coverage are exactly the ones with external
# collaborators, where GitHub withholds Actions secrets from a fork pull
# request -- and from a Dependabot-triggered run, which has its own separate
# secret store. A flat "required means red-when-absent" would turn every
# external contribution red on exactly the repos whose purpose is external
# contribution, training reviewers to read red as noise -- the
# arqtos-skills#85 failure mode, one level up.
#
# The fix follows the precedent named in the brief: arqtos-skills'
# estate-identifiers job skips on Dependabot instead of failing, and recovers
# coverage through an unconditional `push: branches: [main]` run that
# executes with the real secret the moment a fork PR merges. Applied here as
# THREE distinguishable outcomes rather than two:
#
#   1. required, overlay present & valid        -> unchanged: scans with it.
#   2. required, overlay absent, secret COULD
#      exist in this context (not a fork PR,
#      not Dependabot)                          -> MISCONFIGURED (exit 2).
#      This is the case the Story exists for: never wired, a secret renamed
#      or rotated out from under the workflow, or repository visibility that
#      never covered this repo.
#   3. required, overlay absent, secret is
#      LEGITIMATELY withheld (fork PR / Dependabot) -> NOT red. Reports that
#      identity coverage could not be verified THIS run, distinctly from both
#      a clean +overlay run and a failure -- see the three-way disclosure
#      below. The merge-time `push: branches: [main]` run is the backstop
#      that actually verifies coverage once the change lands on main, running
#      with the real secret; this action cannot supply that trigger itself,
#      which is why the input's own description tells a caller to wire it.
#
# ⚠️ WHICH CONTEXT THE SECRET COULD EXIST IN IS NOT A CALLER-SUPPLIED INPUT,
# ON PURPOSE. It is derived entirely from ambient `github.*` context in
# action.yml (the actor, and whether a pull request's head repository
# DIFFERS FROM this run's own repository -- NOT merely "is a fork of
# something", which round-1 review found would wrongly exempt every
# same-repo PR on a consuming repository that is itself a fork of some
# upstream) and handed down as ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD -- a
# caller cannot set this via `with:` to talk its way out of the
# requirement, because a fork PR's own workflow definition is never the one
# that runs (GitHub always runs the BASE branch's workflow file for a
# `pull_request` trigger), and `github.actor` is set by the platform, not
# the caller's YAML.
#
# ⚠️ arqtiqa/arqtos#344 round-1 review, SHOULD-FIX: require_overlay_raw is a
# CALLER-SUPPLIED input (unlike overlay_may_be_withheld_raw below, which
# action.yml computes and always renders a literal 'true'/'false'), so a
# typo here is a real hazard -- 'TRUE', 'yes', '1' would all silently
# no-op a caller's security opt-in, turning an intended requirement into an
# unnoticed credential-tier-only run. That is exactly the silent-degradation
# class this Story exists to close, so it is refused (exit 2), never
# quietly treated as 'false' -- the same "fail closed on an unrecognised
# value" discipline the rest of this file already applies to a denylist
# rule grep cannot compile.
require_overlay_raw="${ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY:-}"
require_overlay=0
case "$require_overlay_raw" in
  "" | "false")
    ;;
  "true")
    require_overlay=1
    ;;
  *)
    echo "✗ check-private-content: require-identity-overlay must be the literal string 'true' or 'false' (got '$require_overlay_raw')." >&2
    echo "  This input is a security opt-in -- silently treating an unrecognised value" >&2
    echo "  as 'false' would let a typo turn a caller's intended requirement into an" >&2
    echo "  unnoticed credential-tier-only run. Use exactly 'true' or 'false'." >&2
    exit 2
    ;;
esac

# overlay_may_be_withheld_raw is NOT caller-supplied (action.yml computes it
# from ambient github.* context and always renders a literal 'true' or
# 'false' -- see action.yml's own comment on ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD
# for why it can never be anything else), so there is no equivalent typo
# surface here to fail closed on; the strict equality check below already
# matches require_overlay_raw's own strictness -- only the exact string
# 'true' counts as true.
overlay_may_be_withheld_raw="${ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD:-}"
overlay_may_be_withheld=0
if [[ "$overlay_may_be_withheld_raw" == "true" ]]; then
  overlay_may_be_withheld=1
fi

# This run's identity tier, for the three-way disclosure just below. Left at
# 0 on every path except outcome 3 above.
overlay_required_unverified=0

if (( require_overlay )) && [[ "${#overlay_rules[@]}" -eq 0 ]]; then
  if (( overlay_may_be_withheld )); then
    overlay_required_unverified=1
  else
    echo "✗ check-private-content: require-identity-overlay is set, but no identity overlay was supplied and this run is not one where GitHub is known to withhold the secret (not a fork pull request, not a Dependabot-triggered run)." >&2
    echo "  This is the case require-identity-overlay exists to catch: the secret was" >&2
    echo "  never wired, renamed, rotated, or its repository visibility never covered" >&2
    echo "  this repository." >&2
    echo "  Wire the identity-overlay input from the org secret" >&2
    echo "  ARQTOS_FIREWALL_IDENTITY_OVERLAY (see this action's own input" >&2
    echo "  description for the exact syntax), or remove require-identity-overlay if" >&2
    echo "  credential-tier-only coverage is intentional for this repository." >&2
    exit 2
  fi
fi

# ⚠️ STATED, NEVER SILENT (arqtiqa/arqtos#342, extended by #344). A green run
# must never imply coverage it did not have. Printed unconditionally, before
# any scanning and regardless of outcome, mirroring the reference Go verb's
# own "tier=work (N patterns, no overlay)" vs "tier=work (N patterns)
# +overlay=…" report line -- this is that same honesty, in the shell
# scanner, now in three mutually exclusive forms so a reader (or a log
# grep) can always tell which of the three actually happened:
#
#   +identity overlay (M pattern(s))       -- tier ran, found nothing extra.
#   REQUIRED but UNVERIFIED this run       -- tier did NOT run; required, but
#                                              the secret is legitimately
#                                              withheld in this context.
#   no identity overlay -- credential-tier only -- tier did not run; not
#                                              required, so this is simply
#                                              the default, unchanged since
#                                              #342.
#
# None of the three strings is a substring of either of the other two --
# verified directly in tests/test_firewall_require_identity_overlay.py --
# so a caller grepping logs for one state can never get a false positive
# from another.
if [[ "${#overlay_rules[@]}" -gt 0 ]]; then
  echo "info: check-private-content: denylist ($rule_count pattern(s)) +identity overlay (${#overlay_rules[@]} pattern(s))" >&2
elif (( overlay_required_unverified )); then
  # ⚠️ Also emitted as a `::warning::` workflow command (arqtiqa/arqtos#344) --
  # GitHub Actions renders this as a distinct annotation on an otherwise
  # GREEN run, which is the visual half of "distinguishable from both a
  # clean full run and a failure": a plain credential-tier-only run (no
  # `require-identity-overlay`) carries no annotation at all, and a genuine
  # failure is red, not a green run with a warning icon.
  echo "::warning::check-private-content: identity coverage is REQUIRED but could not be verified this run -- the overlay secret is unavailable in a context where GitHub is expected to withhold it (fork pull request or Dependabot). Scanned credential-tier only. The push-to-main run after merge, which runs with the real secret, is the backstop that verifies coverage for this change."
  echo "info: check-private-content: denylist ($rule_count pattern(s)), identity coverage REQUIRED but UNVERIFIED this run (overlay secret unavailable in this context) -- credential-tier only" >&2
else
  echo "info: check-private-content: denylist ($rule_count pattern(s)), no identity overlay -- credential-tier only" >&2
fi

# No files to check — common in CI when the diff is doc-only or empty.
if (( ${#files[@]} == 0 )); then
  exit 0
fi

# ---------------------------------------------------------------------------
# Identity-tier overlay scan (arqtiqa/arqtos#342). Runs HERE, over its OWN
# file list, BEFORE the denylist-specific filtering below — deliberately,
# per round-1 review:
#
# ⚠️ THE DENYLIST'S THREE SELF-SKIPS DO NOT APPLY TO THE OVERLAY.
#
# `existing_files` below drops (a) the denylist file itself, (b) a
# byte-identical vendored copy of it, and (c) the exemptions file, because a
# DENYLIST's own rule text self-matches its own patterns — the literal
# regex source sits right there in the file being scanned. That rationale
# is specific to a pattern list scanning ITSELF; an identity STRING is
# different content, and it can plausibly appear in any of those three
# files without being the overlay's own source text — `denylists/work.txt`'s
# own header, cited in this Story's own brief, is exactly that case. Reusing
# `existing_files` for the overlay would silently create three permanent
# blind spots with no analogous justification, so the overlay scans its own
# list instead: `overlay_scan_files`, built straight from `files` with only
# the "exists as a regular file" filter, none of the three skips.
#
# This also means the overlay must run even when `existing_files` (below)
# ends up EMPTY — e.g. a run whose only files are the denylist and the
# exemptions file — so it runs ahead of that filtering, and the violations
# tally it contributes to survives regardless of what the denylist side
# goes on to find.
# ---------------------------------------------------------------------------
overlay_scan_files=()
for f in "${files[@]+"${files[@]}"}"; do
  [[ -f "$f" ]] && overlay_scan_files+=("$f")
done

# The DENYLIST side's file list. Built HERE, ahead of the overlay scan
# below, because exemptions are resolved between the two (arqtiqa/arqtos#365)
# and their staleness check reads this list. Nothing in it depends on the
# overlay, so moving it earlier is a reordering only -- the overlay still
# scans its own, unfiltered list.
#
# Filter to existing regular files (handle deletes + non-regular paths).
# Skip the denylist file itself — its patterns naturally match themselves
# (the literal text inside the regexes), which would create a recursive
# false positive every commit that touched the denylist. We skip on TWO
# conditions:
#   1. realpath match — same physical file as the configured denylist.
#      Unconditional: this IS the denylist, so it always self-matches.
#   2. basename match CORROBORATED BY CONTENT — a vendored copy elsewhere in
#      the tree has a different realpath but the same shape, so it would
#      still trip the self-match.
#
# ⚠️ arqtiqa/arqtos#343: condition 2 used to fire on the basename ALONE, which
# excludes any unrelated tracked file that merely happens to share the
# denylist's filename — proven live by arqtos-cli's own
# `internal/firewall/testdata/golden/work.txt`, a golden-corpus fixture with
# no relation to `internal/firewall/denylists/work.txt` beyond the name,
# dropped from the scan entirely and unreviewed. Worse, this skip happens
# HERE, while the file list is built, before exemptions are resolved below —
# so `.firewallignore` (arqtos#341) never gets a chance to record a reviewed
# decision about it either. A same-basename file is now ALSO required to be
# byte-identical to the denylist's own content before it is treated as a
# vendored copy: that is what "vendored" actually means (a copy), and it is
# corroboration a name coincidence cannot supply. An unrelated file that
# merely shares a name is scanned like any other file, and only a genuine
# content-identical copy is skipped — loudly, on stderr, naming the file.
#
# The exemptions file is skipped by realpath only — there is no "vendored
# copy" precedent for it the way there is for the denylist: its own <rule>
# column is literal denylist-pattern text, so without this it would
# self-match the very rule it names.
denylist_real=$(cd "$(dirname "$denylist")" && pwd -P)/$(basename "$denylist")
denylist_base=$(basename "$denylist")
exemptions_real=""
if [[ -f "$exemptions" ]]; then
  exemptions_real=$(cd "$(dirname "$exemptions")" && pwd -P)/$(basename "$exemptions")
fi
existing_files=()
for f in "${files[@]+"${files[@]}"}"; do
  [[ ! -f "$f" ]] && continue
  f_real=$(cd "$(dirname "$f")" && pwd -P)/$(basename "$f")
  if [[ "$f_real" == "$denylist_real" ]]; then
    continue
  fi
  if [[ "$(basename "$f")" == "$denylist_base" ]] && cmp -s -- "$f" "$denylist"; then
    echo "info: skipping vendored denylist $f (same name AND byte-identical content to $denylist)" >&2
    continue
  fi
  if [[ -n "$exemptions_real" && "$f_real" == "$exemptions_real" ]]; then
    continue
  fi
  existing_files+=("$f")
done

# ---------------------------------------------------------------------------
# RULE HANDLES (arqtiqa/arqtos#365) -- how an exemption names an identity-
# overlay rule without quoting it. See the module doc's "EXEMPTING AN
# IDENTITY-OVERLAY RULE" section for the full "why", including why a digest
# and not a position.
#
# A handle is `sha256:` + the first 12 lowercase hex digits of the SHA-256 of
# a pattern's exact text. 12 hex digits is 48 bits, which for the handful of
# patterns any one run carries is collision-free in practice, and it is short
# enough to paste into a `.firewallignore` column by hand.
#
# ⚠️ The digest tool is resolved LAZILY and only when something actually needs
# a handle -- an overlay run with no exemptions and no violations never
# computes one, so this adds no new dependency to the common path.
# ---------------------------------------------------------------------------
digest_tool=""
ensure_digest_tool() {
  if [[ -n "$digest_tool" ]]; then
    return 0
  fi
  if command -v sha256sum >/dev/null 2>&1; then
    digest_tool="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    # macOS ships no sha256sum but always ships shasum (perl); GitHub's
    # ubuntu runners ship both. One of the two is present on every platform
    # this gate runs on.
    digest_tool="shasum -a 256"
  else
    echo "✗ check-private-content: cannot compute rule handles -- neither sha256sum nor shasum is on PATH." >&2
    echo "  A rule handle (sha256:<12 hex>) is how an exemption names an identity-overlay" >&2
    echo "  rule without quoting its confidential text, and how a violation report names" >&2
    echo "  WHICH overlay rule fired (arqtiqa/arqtos#365). Neither is possible without a" >&2
    echo "  digest tool, so this is a configuration error (exit 2), never a pass." >&2
    exit 2
  fi
  return 0
}

# rule_digest TEXT -- the 12-hex body of TEXT's handle. Digests the pattern
# text with NO trailing newline, so the value is identical whichever tool
# resolved above happens to be in use, and identical to the reference Go
# implementation's own RuleHandle.
rule_digest() {
  printf '%s' "$1" | $digest_tool | cut -c1-12
}

# is_rule_handle FIELD -- true when a `.firewallignore` <rule> field is a
# handle rather than verbatim pattern text. The shape is exact (`sha256:`
# plus exactly 12 lowercase hex digits) so a denylist rule can never be
# mistaken for one, and a mistyped handle is treated as verbatim text and
# fails closed as an unknown rule rather than resolving to something else.
is_rule_handle() {
  [[ "$1" =~ ^sha256:[0-9a-f]{12}$ ]]
}

# overlay_handles[i] is the handle of overlay_rules[i], filled in on first
# use. Never computed when the overlay is absent.
overlay_handles=()
overlay_handles_ready=0
ensure_overlay_handles() {
  if (( overlay_handles_ready )); then
    return 0
  fi
  overlay_handles_ready=1
  if (( ${#overlay_rules[@]} == 0 )); then
    return 0
  fi
  ensure_digest_tool
  local i
  for i in "${!overlay_rules[@]}"; do
    overlay_handles[i]="sha256:$(rule_digest "${overlay_rules[$i]}")"
  done
  return 0
}

# exemption_names_rule IDX RULE_TEXT RULE_HANDLE -- does exemption IDX name
# this rule, either verbatim or by handle? RULE_HANDLE may be empty (no
# handle computed for this rule), in which case only the verbatim form can
# match -- never the empty string, which would match every entry.
exemption_names_rule() {
  local idx="$1" rule_text="$2" rule_handle="$3"
  if [[ "${exempt_rules[$idx]}" == "$rule_text" ]]; then
    return 0
  fi
  if [[ -n "$rule_handle" && "${exempt_rules[$idx]}" == "$rule_handle" ]]; then
    return 0
  fi
  return 1
}

# Is there anything at all for exemptions to apply TO this run? Before #365
# this was simply "the denylist side has at least one file", because the
# denylist side was the only side exemptions could reach. The overlay side
# scans its own list (see above), so a run whose only files are the denylist
# and the exemptions file has an empty `existing_files` but a non-empty
# overlay corpus -- and an overlay exemption has to resolve there too.
#
# ⚠️ Deliberately still FALSE when no overlay is in force, so every caller
# that does not wire one (14 of this action's 15 consumers today) reaches
# exemption parsing on exactly the runs it did before.
exemptions_in_scope=0
if (( ${#existing_files[@]} > 0 )); then
  exemptions_in_scope=1
elif (( ${#overlay_rules[@]} > 0 )) && (( ${#overlay_scan_files[@]} > 0 )); then
  exemptions_in_scope=1
fi

# ---------------------------------------------------------------------------
# Exemptions (arqtiqa/arqtos-cli#851 format and rationale; #986's
# fail-closed-before-scan ordering; #998's stale-glob widening). Parsed and
# VALIDATED here, before ANY scanning happens below — exactly like the
# denylist's own rule-count guard above.
#
# ⚠️ arqtiqa/arqtos#365 MOVED THIS ABOVE THE OVERLAY SCAN. It used to sit
# inside the denylist-only block further down, which is precisely why an
# overlay match could not be exempted: by the time exemptions existed at
# all, the overlay loop had already run and recorded its violation, and the
# <rule> validator resolved only against the on-disk denylist. Both halves
# are fixed here — exemptions are parsed before either scan, and <rule>
# resolves against the denylist UNION the overlay.
#
# Reached only when `exemptions_in_scope` (computed above) says there is
# something for exemptions to apply to. For a caller with no overlay that
# predicate is exactly the pre-#365 "`existing_files` is non-empty" test, so
# every such caller reaches this on exactly the runs it did before.
# ---------------------------------------------------------------------------

# glob_to_ere GLOB — translate a filepath.Match-style glob (`*`/`?` never
# cross `/`, `[...]` a character class) into a POSIX ERE anchored with
# ^...$ by the caller. Mirrors the reference Go implementation's matching
# semantics: over-matching here would be the "blinding" failure the whole
# exemptions mechanism exists to prevent (a `*` that crossed `/` could
# exempt a genuine violation in an unintended sibling path).
glob_to_ere() {
  local glob="$1" out="" c i len j br
  len=${#glob}
  i=0
  while (( i < len )); do
    c="${glob:i:1}"
    case "$c" in
      '*') out+='[^/]*' ;;
      '?') out+='[^/]' ;;
      '[')
        j=$((i + 1))
        br="["
        if [[ "${glob:j:1}" == "^" ]]; then br+="^"; j=$((j + 1)); fi
        if [[ "${glob:j:1}" == "]" ]]; then br+="]"; j=$((j + 1)); fi
        while (( j < len )) && [[ "${glob:j:1}" != "]" ]]; do
          br+="${glob:j:1}"
          j=$((j + 1))
        done
        br+="]"
        out+="$br"
        i=$j
        ;;
      '.'|'\'|'^'|'$'|'+'|'{'|'}'|'|'|'('|')')
        out+="\\$c"
        ;;
      *)
        out+="$c"
        ;;
    esac
    i=$((i + 1))
  done
  printf '%s' "$out"
}

exempt_linenos=()
exempt_globs=()
exempt_rules=()
exempt_reasons=()
exempt_eres=()
# Set below when at least one entry addresses its rule by handle; read again
# by the denylist scan loop, which only digests its own rules when it must.
any_handle_exemptions=0
# Entries whose handle resolved to no active pattern (see the handle block
# above). Disclosed at the end of the run, never silently dropped.
exempt_inert=0

if (( exemptions_in_scope )) && [[ -f "$exemptions" ]]; then
  # One awk pass parses the whole file into `OK<US>line<US>glob<US>rule<US>reason`
  # or `ERR<US>line<US>message` records (US = ASCII unit separator, 0x1F,
  # chosen because it cannot appear in ordinary exemption text -- and,
  # empirically, unlike \001, bash 3.x's `read` field-splits on it reliably).
  # This reproduces the reference Go parser's exact two-split contract: only
  # the FIRST TWO occurrences of a tab or 2+ spaces are treated as field
  # separators, so a reason containing its own double-space run is never
  # mis-split into a spurious fourth field.
  while IFS=$'\037' read -r rectype recline f1 f2 f3; do
    if [[ "$rectype" == "ERR" ]]; then
      echo "✗ check-private-content: $exemptions:$recline: $f1" >&2
      exit 2
    fi
    exempt_linenos+=("$recline")
    exempt_globs+=("$f1")
    exempt_rules+=("$f2")
    exempt_reasons+=("$f3")
  done < <(awk '
    {
      line = $0
      trimmed = line
      sub(/^[ \t]+/, "", trimmed)
      if (trimmed == "" || substr(trimmed, 1, 1) == "#") next

      if (!match(line, /\t|  +/)) {
        printf "ERR\037%d\037expected three fields (<path-glob>  <rule>  <reason>, separated by a tab or 2+ spaces) -- found one field\n", NR
        next
      }
      glob = substr(line, 1, RSTART - 1)
      rest = substr(line, RSTART + RLENGTH)
      gsub(/^[ \t]+/, "", glob); gsub(/[ \t]+$/, "", glob)

      if (!match(rest, /\t|  +/)) {
        printf "ERR\037%d\037missing the mandatory reason field -- an exemption with no reason is never allowed\n", NR
        next
      }
      rule = substr(rest, 1, RSTART - 1)
      reason = substr(rest, RSTART + RLENGTH)
      gsub(/^[ \t]+/, "", rule); gsub(/[ \t]+$/, "", rule)
      gsub(/^[ \t]+/, "", reason); gsub(/[ \t]+$/, "", reason)

      if (glob == "") { printf "ERR\037%d\037empty path glob\n", NR; next }
      if (rule == "") { printf "ERR\037%d\037empty rule\n", NR; next }
      if (reason == "") { printf "ERR\037%d\037empty reason -- a mandatory reason is what stops this file from growing into a blanket suppression\n", NR; next }

      printf "OK\037%d\037%s\037%s\037%s\n", NR, glob, rule, reason
    }
  ' "$exemptions")

  # Precompute each glob's ERE once, up front — the hot loop below runs one
  # regex TEST per (file, exemption) pair, and re-deriving the ERE inside
  # that loop would repeat the same string-building work per file for no
  # reason.
  for idx in "${!exempt_globs[@]}"; do
    exempt_eres[idx]=$(glob_to_ere "${exempt_globs[$idx]}")
  done

  if (( ${#exempt_globs[@]} > 0 )); then
    # The denylist's own active rule set, as RAW lines (untrimmed, identical
    # text to what the scan loop below passes to `grep -e`) — an exemption's
    # <rule> field must equal one of these byte-for-byte, same as the
    # reference Go implementation comparing against Pattern.Source verbatim.
    denylist_rules=()
    while IFS= read -r dl_line; do
      [[ -z "$dl_line" || "$dl_line" =~ ^[[:space:]]*# ]] && continue
      denylist_rules+=("$dl_line")
    done < "$denylist"

    # ⚠️ Handles are computed ONLY when some entry actually uses one, so a
    # `.firewallignore` that quotes rule text verbatim (every one of them
    # before arqtiqa/arqtos#365) spawns no digest process at all and stays
    # byte-identical in behaviour.
    for er in "${exempt_rules[@]+"${exempt_rules[@]}"}"; do
      if is_rule_handle "$er"; then
        any_handle_exemptions=1
        break
      fi
    done
    active_handles=()
    if (( any_handle_exemptions )); then
      ensure_digest_tool
      ensure_overlay_handles
      for oh in "${overlay_handles[@]+"${overlay_handles[@]}"}"; do
        active_handles+=("$oh")
      done
      # A committed denylist rule can be addressed by handle too. That is
      # not the recommended form for one (its text is public, so quoting it
      # reads better in review), but the reference Go implementation
      # resolves a handle against the whole ACTIVE pattern set, and one
      # committed exemptions file has to serve both engines.
      for dl in "${denylist_rules[@]+"${denylist_rules[@]}"}"; do
        active_handles+=("sha256:$(rule_digest "$dl")")
      done
    fi

    # denylist_rules is expected non-empty here (the rule-count guard near the
    # top of the script already refused an all-comment/all-blank denylist),
    # but every array below is expanded via the nounset-safe idiom anyway --
    # this file's whole point is not trusting "should never be empty" for an
    # externally-supplied file's content.

    # arqtos-cli#998 parity: a glob that matches nothing in THIS run's file
    # list is re-checked against the full tracked tree before being called
    # stale — otherwise a caller scanning a narrow explicit file list (a PR
    # diff, say) would report every exemption outside that diff as stale,
    # which is a false positive, not a real staleness signal. Resolved
    # lazily, at most once, so the common "--all-tracked, everything
    # matches already" case never shells out to git at all.
    widened_computed=0
    widened_files=()

    for idx in "${!exempt_globs[@]}"; do
      ere="${exempt_eres[$idx]}"
      ln="${exempt_linenos[$idx]}"
      g="${exempt_globs[$idx]}"
      r="${exempt_rules[$idx]}"

      matched=0
      for f in "${existing_files[@]+"${existing_files[@]}"}"; do
        if [[ "$f" =~ ^${ere}$ ]]; then
          matched=1
          break
        fi
      done
      if (( ! matched )) && (( ! widened_computed )); then
        widened_computed=1
        while IFS= read -r -d '' wf; do
          widened_files+=("$wf")
        done < <(git ls-files -z 2>/dev/null || true)
      fi
      if (( ! matched )); then
        # ⚠️ Nounset-safe expansion (matches the `exemptions_arg` guard in
        # action.yml) -- REQUIRED, not decorative: bash 3.2 (macOS's stock
        # `/bin/bash`, and this sandbox's default) throws "unbound variable"
        # on a plain "${arr[@]}" when arr is EMPTY under `set -u`. widened_files
        # is legitimately empty outside a git work tree (or one with no
        # tracked files) -- exactly the shape a `--files0` / local / pre-push
        # invocation can hit, and exactly the crash a reviewer reproduced here.
        for f in "${widened_files[@]+"${widened_files[@]}"}"; do
          if [[ "$f" =~ ^${ere}$ ]]; then
            matched=1
            break
          fi
        done
      fi
      if (( ! matched )); then
        echo "✗ check-private-content: $exemptions:$ln: path glob '$g' matches no tracked file -- a stale exemption is a configuration error, not a silent no-op; fix or remove this entry" >&2
        exit 2
      fi

      # ⚠️ <rule> resolves against the ACTIVE rule set -- the denylist UNION
      # the identity overlay (arqtiqa/arqtos#365), not the denylist alone.
      # Resolving against the denylist alone IS the defect: an exemption
      # naming an overlay rule exited 2 right here, so a repo with even one
      # legitimate identity match could neither wire the overlay (exit 1
      # forever) nor exempt it (exit 2 forever).
      rule_known=0
      if is_rule_handle "$r"; then
        for h in "${active_handles[@]+"${active_handles[@]}"}"; do
          if [[ "$h" == "$r" ]]; then
            rule_known=1
            break
          fi
        done
        if (( ! rule_known )); then
          # ⚠️ HELD INERT, NOT exit 2 -- and that is the fail-CLOSED
          # direction, not a softening. A handle resolves to one exact
          # pattern text or to nothing at all; it can never silently
          # re-point at a DIFFERENT rule the way a positional index would.
          # So there are only two ways to reach here:
          #   (a) the overlay is ABSENT in this context -- a fork pull
          #       request, a Dependabot run, or a caller that never wired
          #       the secret. The identity tier did not run at all, so
          #       nothing is under-scanned, and refusing the run instead
          #       would make every fork PR on an overlay-wired repo a
          #       configuration error: the permanently-red gate
          #       arqtiqa/arqtos#341 was filed about and #344 already
          #       accommodates for this same withheld secret.
          #   (b) the rule was EDITED, so its digest moved. Dropping the
          #       suppression makes the edited rule scan that path again --
          #       if it still matches, the run turns RED and the change is
          #       visible. The exemption can only ever be LOST by an edit,
          #       never transferred to something nobody reviewed.
          # Disclosed at the end of the run either way; never silent.
          exempt_inert=$((exempt_inert + 1))
          continue
        fi
      else
        for dl in "${denylist_rules[@]+"${denylist_rules[@]}"}"; do
          if [[ "$dl" == "$r" ]]; then
            rule_known=1
            break
          fi
        done
        if (( ! rule_known )); then
          for ov in "${overlay_rules[@]+"${overlay_rules[@]}"}"; do
            if [[ "$ov" == "$r" ]]; then
              rule_known=1
              break
            fi
          done
        fi
        if (( ! rule_known )); then
          # VERBATIM text, unlike a handle, names a rule set that is fully
          # present in this run, so a miss here really is staleness. Message
          # and exit code unchanged from pre-#365.
          echo "✗ check-private-content: $exemptions:$ln: rule does not match any active denylist pattern -- a stale exemption is a configuration error, not a silent no-op; fix or remove this entry" >&2
          echo "    rule: $r" >&2
          exit 2
        fi
      fi
    done
  fi
fi

# grep's diagnostics go here so they can be SURFACED rather than discarded.
# Shared by this loop and the denylist loop further down.
grep_stderr=$(mktemp)
trap 'rm -f "$grep_stderr"' EXIT

violations=0
exempted_pairs=0

overlay_lineno=0
for line in "${overlay_rules[@]+"${overlay_rules[@]}"}"; do
  overlay_lineno=$((overlay_lineno + 1))

  # ⚠️ BLOCKING (arqtos#342 round-2 review): same guard the denylist loop
  # below applies to its own `scan_targets`, and for the same reason --
  # `grep -f <pattern-file> <files...>` with ZERO file operands does not
  # skip the scan, it falls back to reading grep's OWN STDIN as an implicit
  # single input. Before this restructure, `overlay_scan_files` reused
  # `existing_files`, which the removed `exit 0` guaranteed was non-empty by
  # the time either loop ran. That guarantee is gone now that the overlay
  # runs ahead of and independently from that filtering, so this loop needs
  # its own check. Two reproduced failure modes without it: a TTY stdin (a
  # local run, or the pre-push gate) hangs forever waiting for input that
  # never comes; a piped stdin WITH data gets scanned as a phantom
  # "(standard input)" file, inventing a violation out of whatever
  # unrelated bytes happened to be on the pipe.
  if (( ${#overlay_scan_files[@]} == 0 )); then
    continue
  fi

  # ---- exemptions, on the overlay side (arqtiqa/arqtos#365) ----------------
  #
  # The same input-filtering the denylist loop below already does, applied to
  # the tier that could not be exempted at all before this Story: drop, from
  # THIS rule's scan, every file exempted for THIS rule -- named verbatim, or
  # by the rule's handle. Never a rule exempted everywhere, never a path
  # exempted from every rule: exempting one overlay rule for one path leaves
  # that same rule live on every other path, and leaves every other rule live
  # on that path.
  overlay_targets=("${overlay_scan_files[@]+"${overlay_scan_files[@]}"}")
  if (( ${#exempt_globs[@]} > 0 )); then
    # Same lazy discipline as the denylist loop below: an exemptions file
    # that addresses every rule verbatim needs no handle to match against,
    # so no digest is computed for it.
    ov_handle=""
    if (( any_handle_exemptions )); then
      ensure_overlay_handles
      ov_handle="${overlay_handles[$((overlay_lineno - 1))]}"
    fi
    rule_is_exempted=0
    for idx in "${!exempt_globs[@]}"; do
      if exemption_names_rule "$idx" "$line" "$ov_handle"; then
        rule_is_exempted=1
        break
      fi
    done
    if (( rule_is_exempted )); then
      overlay_targets=()
      for f in "${overlay_scan_files[@]+"${overlay_scan_files[@]}"}"; do
        skip=0
        for idx in "${!exempt_globs[@]}"; do
          if exemption_names_rule "$idx" "$line" "$ov_handle" && [[ "$f" =~ ^${exempt_eres[$idx]}$ ]]; then
            skip=1
            exempted_pairs=$((exempted_pairs + 1))
            break
          fi
        done
        if (( ! skip )); then
          overlay_targets+=("$f")
        fi
      done
    fi
  fi

  # Same zero-operand guard as above, re-checked because the filtering just
  # above can empty the list even when overlay_scan_files was not: `grep -f`
  # with no file operands reads THIS PROCESS's stdin instead of skipping.
  if (( ${#overlay_targets[@]} == 0 )); then
    continue
  fi

  : >"$grep_stderr"
  # ⚠️ `-f <(printf '%s\n' "$line")`, NEVER `-e "$line"` (arqtos#342 round-1
  # review). `-e` puts the pattern on GREP'S OWN ARGV, and argv is a
  # DIFFERENT, LESS-PROTECTED channel than the env var this script was
  # otherwise careful to read the overlay from: on Linux, /proc/<pid>/cmdline
  # is world-readable while /proc/<pid>/environ is owner-only, so handing an
  # env-sourced secret to a child process via -e makes it LESS protected
  # after the hop than before it — the exact confidential-identity-regex
  # leak this Story exists to close, one process later. A process-substituted
  # file descriptor keeps the pattern text off every process's argv. `-f`
  # reads one pattern per line, same as `-e` reads one pattern per
  # invocation — behaviourally identical for a single pattern (see the test
  # suite's byte-for-byte match/exit-code proof). The denylist loop further
  # down is left on `-e` deliberately: those patterns are committed and
  # public, so this hop protects nothing there.
  matches=$(grep -nIHE -f <(printf '%s\n' "$line") "${overlay_targets[@]+"${overlay_targets[@]}"}" 2>"$grep_stderr") \
    && grep_status=0 || grep_status=$?

  if (( grep_status >= 2 )); then
    echo "✗ check-private-content: grep could not apply identity overlay pattern #$overlay_lineno (exit $grep_status)." >&2
    if [[ -s "$grep_stderr" ]]; then
      sed 's/^/    grep: /' "$grep_stderr" >&2
    fi
    echo "" >&2
    echo "  The pattern's own text is withheld here on purpose (arqtiqa/arqtos-cli#1009)" >&2
    echo "  -- fix it at its source, the ARQTOS_FIREWALL_IDENTITY_OVERLAY secret. An" >&2
    echo "  identity pattern that never ran cannot be reported as clean." >&2
    exit 2
  fi

  if (( grep_status == 0 )) && [[ -n "$matches" ]]; then
    # ⚠️ THE MATCHED LINE'S CONTENT IS WITHHELD TOO (arqtiqa/arqtos#365), not
    # only the pattern's. This used to print grep's own `file:line:CONTENT`,
    # and for an IDENTITY rule the matched content IS the confidential string
    # -- so a run that caught an identity leak published that leak into the CI
    # log, which on a public repository is world-readable. That defeats the
    # tier: a detector whose finding is itself the disclosure. `$matches` is
    # therefore computed (it is what tells us a rule fired) but never printed;
    # the report is re-derived per file as path + line number only.
    #
    # ⚠️ Per-file re-derivation rather than splitting grep's combined output:
    # a path may itself contain a colon, so `file:line:content` cannot be
    # split back into its fields reliably -- the same reason the denylist loop
    # filters grep's INPUT instead of parsing its output. Paid only on a
    # violation, so the clean path costs exactly what it did before.
    ensure_overlay_handles
    ov_handle="${overlay_handles[$((overlay_lineno - 1))]}"
    echo "✗ pattern: [identity overlay rule $ov_handle -- text withheld, arqtiqa/arqtos-cli#1009]" >&2
    for f in "${overlay_targets[@]+"${overlay_targets[@]}"}"; do
      ov_hit_lines=$(grep -nIE -f <(printf '%s\n' "$line") -- "$f" | cut -d: -f1) || ov_hit_lines=""
      if [[ -z "$ov_hit_lines" ]]; then
        continue
      fi
      while IFS= read -r ov_hit_line; do
        [[ -n "$ov_hit_line" ]] && echo "    $f:$ov_hit_line" >&2
      done <<<"$ov_hit_lines"
    done
    echo "    (matched line content withheld: an identity match IS the confidential" >&2
    echo "     string, arqtiqa/arqtos#365 -- open the file at the line above to see it)" >&2
    echo "    To record a reviewed exception, add a line to $exemptions:" >&2
    echo "      <path-glob>  $ov_handle  <reason>" >&2
    violations=$((violations + 1))
  fi
done


# ⚠️ NOT an early `exit 0` on empty `existing_files` (arqtos#342 round 1):
# the overlay loop above may already have recorded violations even when the
# denylist side has nothing left to scan (e.g. this run's only files were
# the denylist and the exemptions file, both excluded above). Exiting here
# would silently drop those. The denylist-specific work below is skipped
# when there is nothing for IT to scan, but the shared violations tally at
# the bottom of the script is always reached.
if (( ${#existing_files[@]} > 0 )); then


# grep_stderr/trap, $violations and $exempted_pairs are already declared
# above (shared with the overlay loop, which must run even when there is
# nothing here for the denylist side to scan) -- only this loop's own
# counter is local to it.
rule_lineno=0
while IFS= read -r line; do
  rule_lineno=$((rule_lineno + 1))
  # Skip blank lines and full-line comments (no inline comments per the format).
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

  # arqtos-cli#851 parity: drop, from THIS rule's scan, every file exempted
  # for this EXACT rule text — never a rule exempted everywhere, never a
  # path exempted from every rule. Filtering the grep INPUT this way is
  # observationally identical to filtering its MATCHES afterward (same
  # files end up flagged or not), and sidesteps re-parsing grep's own
  # `file:line:content` output, which cannot be split back into "which
  # file" reliably once a path itself might contain a colon.
  scan_targets=("${existing_files[@]+"${existing_files[@]}"}")
  if (( ${#exempt_globs[@]} > 0 )); then
    # A denylist rule's own handle, computed only when some exemption in this
    # repo actually addresses a rule by handle (arqtiqa/arqtos#365) -- so a
    # verbatim-only `.firewallignore`, which is every one of them today,
    # spawns no digest process here at all.
    dl_handle=""
    if (( any_handle_exemptions )); then
      dl_handle="sha256:$(rule_digest "$line")"
    fi
    rule_is_exempted=0
    for idx in "${!exempt_globs[@]}"; do
      if exemption_names_rule "$idx" "$line" "$dl_handle"; then
        rule_is_exempted=1
        break
      fi
    done
    if (( rule_is_exempted )); then
      scan_targets=()
      for f in "${existing_files[@]+"${existing_files[@]}"}"; do
        skip=0
        for idx in "${!exempt_globs[@]}"; do
          if exemption_names_rule "$idx" "$line" "$dl_handle" && [[ "$f" =~ ^${exempt_eres[$idx]}$ ]]; then
            skip=1
            exempted_pairs=$((exempted_pairs + 1))
            break
          fi
        done
        if (( ! skip )); then
          scan_targets+=("$f")
        fi
      done
    fi
  fi

  if (( ${#scan_targets[@]} == 0 )); then
    continue
  fi

  # `grep -I` skips binaries; `-E` extended regex; `-n` line numbers; `-H` filename.
  #
  # ⚠️ `-e` IS LOAD-BEARING — DO NOT REMOVE IT (arqtos-cli#1069).
  #
  # Without it, any pattern BEGINNING WITH A HYPHEN is parsed by grep as an
  # OPTION, not a pattern. grep then exits 2 with "unrecognized option", the
  # `2>/dev/null` swallows the message, and the `if` reads the non-zero status
  # as "no match" — so the rule is silently NEVER APPLIED and the file reports
  # CLEAN.
  #
  # This was live: the PEM private-key rule (`-----BEGIN ... PRIVATE KEY-----`)
  # begins with five hyphens, so the highest-severity class in the secrets tier
  # was unenforced in CI on every repo using this action, while the Go scanner
  # matched it locally. CI is the boundary guarding the PUBLIC repos, so the
  # weaker side was the one that mattered.
  #
  # Found by the cross-implementation parity test (arqtos-cli#1069) on its
  # first run — nothing else could have found it, because both sides of the
  # pre-existing parity test were Go.
  # ⚠️ GREP HAS THREE OUTCOMES AND THIS MUST DISTINGUISH ALL THREE (arqtos-cli#1092).
  #
  #   0 = matched          -> a violation
  #   1 = no match         -> this rule is clean
  #   2 = grep FAILED      -> the rule never ran; the scan learned NOTHING about it
  #
  # The old form was `if matches=$(grep ... 2>/dev/null); then`, which collapsed
  # 1 and 2 into the same branch: a pattern grep could not compile was read as
  # "no match", the rule was silently skipped, and the scan still reported CLEAN.
  # Verified live — a denylist whose only rule was `[unclosed` passed a tree
  # containing a real `ghp_` token with exit 0.
  #
  # That is the disarm-and-stay-green failure mode the whole firewall exists to
  # prevent, and it is worse than a broken build: a rule that stops compiling
  # turns itself off without turning the check red.
  #
  # ⚠️ `2>/dev/null` IS GONE ON PURPOSE. Do not restore it "to keep the output
  # quiet" — discarding the diagnostic is half of how this defect hid. The
  # message is captured, and printed on the path that acts on it.
  #
  # Fail CLOSED on 2. An unusable pattern, an unreadable file, or any other grep
  # failure is a MISCONFIGURATION (exit 2), never a clean result — same rule the
  # rule-count guard above applies to an empty denylist.
  : >"$grep_stderr"
  matches=$(grep -nIHE -e "$line" "${scan_targets[@]+"${scan_targets[@]}"}" 2>"$grep_stderr") \
    && grep_status=0 || grep_status=$?

  if (( grep_status >= 2 )); then
    echo "✗ check-private-content: grep could not apply a denylist rule (exit $grep_status)." >&2
    echo "  $denylist:$rule_lineno" >&2
    echo "    $line" >&2
    if [[ -s "$grep_stderr" ]]; then
      sed 's/^/    grep: /' "$grep_stderr" >&2
    fi
    echo "" >&2
    echo "  This rule was NOT applied, so the scan cannot report clean: an unenforced" >&2
    echo "  rule is indistinguishable from an absent one. Fix the pattern (or the" >&2
    echo "  unreadable path) — exit 2 is misconfiguration, not a caught leak." >&2
    exit 2
  fi

  if (( grep_status == 0 )) && [[ -n "$matches" ]]; then
    echo "✗ pattern: $line" >&2
    printf '%s\n' "$matches" | sed 's/^/    /' >&2
    violations=$((violations + 1))
  fi
done < "$denylist"

fi # (( ${#existing_files[@]} > 0 )) -- the denylist-specific block opened above

# Disclosure, not silence: suppressing a match must never be indistinguishable
# from "nothing was there to find" (same discipline as the reference Go
# implementation's ExemptedFiles count). Printed only when the count is
# nonzero — with zero exemptions applied, output stays byte-identical to a
# build with no exemptions mechanism at all.
if (( exempted_pairs > 0 )); then
  echo "info: check-private-content: $exemptions exempted $exempted_pairs file/rule pair(s)" >&2
fi

# ⚠️ An INERT exemption is disclosed too (arqtiqa/arqtos#365), for the same
# reason a suppressed match is: "this entry did nothing" must never be
# indistinguishable from "this entry applied". A handle resolving to no
# active pattern is the two-case state documented in the module doc -- the
# overlay is absent in this context, or the rule it named was edited -- and
# in BOTH the rule was scanned rather than suppressed, so this line reports
# less coverage lost, never more. Printed only when nonzero, so a run with
# no inert entries stays byte-identical to pre-#365 output.
if (( exempt_inert > 0 )); then
  echo "info: check-private-content: $exemptions: $exempt_inert exemption(s) name a rule handle that matches no active pattern -- held INERT, so the rule they name was scanned, not suppressed (the identity overlay is absent in this run, or the rule's text was edited)" >&2
fi

if (( violations > 0 )); then
  echo "" >&2
  # ⚠️ Tier-neutral wording (arqtiqa/arqtos#342) -- $violations now counts
  # BOTH denylist and identity-overlay hits, so a message hard-coding
  # "denylist" would misreport a run an overlay pattern alone failed.
  echo "✗ check-private-content: $violations pattern(s) matched." >&2
  echo "  Denylist source: $denylist (identity-overlay patterns come from" >&2
  echo "  \$ARQTOS_FIREWALL_IDENTITY_OVERLAY, never a file)" >&2
  echo "  If a match is a true leak: remove it from the file — a placeholder in the committed" >&2
  echo "  copy, the real value supplied at runtime from the environment or a secret reference." >&2
  echo "  If a match is a false positive: refine the pattern (more specific) rather than removing it." >&2
  exit 1
fi
exit 0
