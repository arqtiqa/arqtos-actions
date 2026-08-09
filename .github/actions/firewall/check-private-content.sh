#!/usr/bin/env bash
# check-private-content — gate that fails when staged / changed files
# match a denylist pattern. The private-content firewall.
#
# Usage:
#   check-private-content.sh <file> [<file>...]
#   check-private-content.sh                          # nothing to check; exits 0
#   check-private-content.sh --denylist=<path> ...     # override denylist location
#   check-private-content.sh --exemptions=<path> ...   # override exemptions file
#
# Exits 0 if no matches, 1 if any pattern fires (with file:line:pattern
# context on stderr), 2 on configuration error (missing denylist, etc).
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
# path as it appears in the scan's own file list; <rule> must equal a
# denylist line's exact text (copy it verbatim); <reason> is a mandatory
# one-line justification. Blank lines and full-line `#` comments are
# skipped, same convention as the denylist file. Scoped as narrowly as the
# mechanism allows: one rule per entry, never "skip this rule everywhere" --
# a file needing two rules exempted gets two entries.
#
# FAIL CLOSED: a path glob matching no tracked file, or a rule matching no
# active denylist pattern, is a configuration error (exit 2), never a
# silent no-op -- a stale exemption must never rot into an invisible blind
# spot. This mirrors the reference Go implementation's exemptions mechanism
# exactly (same format, same fail-closed validation), so one committed
# exemptions file serves both engines.

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
      sed -n '2,39p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
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

# No files to check — common in CI when the diff is doc-only or empty.
if (( ${#files[@]} == 0 )); then
  exit 0
fi

# Filter to existing regular files (handle deletes + non-regular paths).
# Skip the denylist file itself — its patterns naturally match themselves
# (the literal text inside the regexes), which would create a recursive
# false positive every commit that touched the denylist. We skip on TWO
# conditions:
#   1. realpath match — same physical file as the configured denylist
#   2. basename match — a vendored copy elsewhere in the tree has a
#      different realpath but the same shape, so it would still trip the
#      self-match.
#
# The exemptions file is skipped the same way (realpath only — there is no
# "vendored copy" precedent for it the way there is for the denylist): its
# own <rule> column is literal denylist-pattern text, so without this it
# would self-match the very rule it names.
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
  if [[ "$(basename "$f")" == "$denylist_base" ]]; then
    echo "info: skipping vendored denylist $f" >&2
    continue
  fi
  if [[ -n "$exemptions_real" && "$f_real" == "$exemptions_real" ]]; then
    continue
  fi
  existing_files+=("$f")
done
if (( ${#existing_files[@]} == 0 )); then
  exit 0
fi

# ---------------------------------------------------------------------------
# Exemptions (arqtiqa/arqtos-cli#851 format and rationale; #986's
# fail-closed-before-scan ordering; #998's stale-glob widening). Parsed and
# VALIDATED here, before any scanning happens below — exactly like the
# denylist's own rule-count guard above. Reached only once we know there is
# at least one real file to scan (the "nothing to check" shortcuts above
# already exited 0), which covers every real invocation of this gate
# (`--all-tracked` in CI always has files) and keeps that pre-existing
# zero-files exit code untouched by this feature.
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

if [[ -f "$exemptions" ]]; then
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

      rule_known=0
      for dl in "${denylist_rules[@]+"${denylist_rules[@]}"}"; do
        if [[ "$dl" == "$r" ]]; then
          rule_known=1
          break
        fi
      done
      if (( ! rule_known )); then
        echo "✗ check-private-content: $exemptions:$ln: rule does not match any active denylist pattern -- a stale exemption is a configuration error, not a silent no-op; fix or remove this entry" >&2
        echo "    rule: $r" >&2
        exit 2
      fi
    done
  fi
fi

# grep's diagnostics go here so they can be SURFACED rather than discarded.
# See the exit-status handling below for why this file has to exist.
grep_stderr=$(mktemp)
trap 'rm -f "$grep_stderr"' EXIT

violations=0
exempted_pairs=0
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
    rule_is_exempted=0
    for r in "${exempt_rules[@]+"${exempt_rules[@]}"}"; do
      if [[ "$r" == "$line" ]]; then
        rule_is_exempted=1
        break
      fi
    done
    if (( rule_is_exempted )); then
      scan_targets=()
      for f in "${existing_files[@]+"${existing_files[@]}"}"; do
        skip=0
        for idx in "${!exempt_globs[@]}"; do
          if [[ "${exempt_rules[$idx]}" == "$line" ]] && [[ "$f" =~ ^${exempt_eres[$idx]}$ ]]; then
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

# Disclosure, not silence: suppressing a match must never be indistinguishable
# from "nothing was there to find" (same discipline as the reference Go
# implementation's ExemptedFiles count). Printed only when the count is
# nonzero — with zero exemptions applied, output stays byte-identical to a
# build with no exemptions mechanism at all.
if (( exempted_pairs > 0 )); then
  echo "info: check-private-content: $exemptions exempted $exempted_pairs file/rule pair(s)" >&2
fi

if (( violations > 0 )); then
  echo "" >&2
  echo "✗ check-private-content: $violations denylist pattern(s) matched." >&2
  echo "  Source: $denylist" >&2
  echo "  If a match is a true leak: remove it from the file — a placeholder in the committed" >&2
  echo "  copy, the real value supplied at runtime from the environment or a secret reference." >&2
  echo "  If a match is a false positive: refine the pattern (more specific) rather than removing it." >&2
  exit 1
fi
exit 0
