#!/usr/bin/env bash
# check-private-content — gate that fails when staged / changed files
# match a denylist pattern. The private-content firewall.
#
# Usage:
#   check-private-content.sh <file> [<file>...]
#   check-private-content.sh                       # nothing to check; exits 0
#   check-private-content.sh --denylist=<path> ... # override denylist location
#
# Exits 0 if no matches, 1 if any pattern fires (with file:line:pattern
# context on stderr), 2 on configuration error (missing denylist, etc).

set -euo pipefail

DEFAULT_DENYLIST="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/private-content-denylist.txt"
denylist="$DEFAULT_DENYLIST"

files=()
all_tracked=0
files0=0
for arg in "$@"; do
  case "$arg" in
    --denylist=*)
      denylist="${arg#--denylist=}"
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
      sed -n '2,12p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    --)
      ;;
    *)
      files+=("$arg")
      ;;
  esac
done

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
# immediate repair. Anything a caller cannot test, a caller cannot trust.
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
denylist_real=$(cd "$(dirname "$denylist")" && pwd -P)/$(basename "$denylist")
denylist_base=$(basename "$denylist")
existing_files=()
for f in "${files[@]}"; do
  [[ ! -f "$f" ]] && continue
  f_real=$(cd "$(dirname "$f")" && pwd -P)/$(basename "$f")
  if [[ "$f_real" == "$denylist_real" ]]; then
    continue
  fi
  if [[ "$(basename "$f")" == "$denylist_base" ]]; then
    echo "info: skipping vendored denylist $f" >&2
    continue
  fi
  existing_files+=("$f")
done
if (( ${#existing_files[@]} == 0 )); then
  exit 0
fi

violations=0
while IFS= read -r line; do
  # Skip blank lines and full-line comments (no inline comments per the format).
  [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue

  # `grep -I` skips binaries; `-E` extended regex; `-n` line numbers; `-H` filename.
  if matches=$(grep -nIHE "$line" "${existing_files[@]}" 2>/dev/null); then
    if [[ -n "$matches" ]]; then
      echo "✗ pattern: $line" >&2
      printf '%s\n' "$matches" | sed 's/^/    /' >&2
      violations=$((violations + 1))
    fi
  fi
done < "$denylist"

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
