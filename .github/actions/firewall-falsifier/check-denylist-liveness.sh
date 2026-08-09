#!/usr/bin/env bash
# check-denylist-liveness — the STANDING FALSIFIER for a committed denylist.
#
# Usage:
#   check-denylist-liveness.sh --denylist=<path> [--probes=<path>]
#                              [--scanner=<path>]
#
# Exits 0 when every active rule in <denylist> is proven to still bite and no
# benign lookalike fires, 1 when that is not true, and 2 on a configuration
# error. Same three-state contract as the scanner it drives, and for the same
# reason: "the falsifier did not run" must never be indistinguishable from
# "the falsifier passed".
#
# ---------------------------------------------------------------------------
# ⚠️ WHY THIS EXISTS (arqtiqa/arqtos#361)
# ---------------------------------------------------------------------------
#
# `arqtiqa/arqtos-cli#831` requires every repository's denylist to be covered
# by a falsifier test. For all but a handful of repositories that requirement
# was satisfied by a ONE-TIME, NARRATED, MANUAL DRY-RUN performed on the day
# the gate was switched on. That is evidence the list bit ONCE, on one day,
# against one tree. It is not a test, and nothing re-runs it.
#
# A denylist decays SILENTLY, and every one of its decay modes leaves the gate
# GREEN — which reads as coverage:
#
#   * a rule edited into a form that still COMPILES but matches nothing.
#     `arqtos-cli#1092` was exactly this, one level down: the shared script
#     reported CLEAN when `grep` REJECTED a pattern.
#   * a rule deleted during an unrelated edit — the scan simply has one fewer
#     thing to say, and says it just as greenly.
#   * a rule the repository never had, because a list was copied from a
#     narrower tier when the gate was enabled.
#
# A green firewall over a dead denylist is WORSE than no gate at all, because
# it is trusted. This script is the thing that notices.
#
# ---------------------------------------------------------------------------
# ⚠️ THE CORPUS IS DATA AND STAYS WITH THE CALLER — same split as the denylist
# ---------------------------------------------------------------------------
#
# The sibling `firewall` action ships NO denylist, on purpose: a denylist is a
# list of the things it protects, so centralising it into this public
# repository would force the union of every caller's list, and the union is
# the disclosure. THE LOGIC IS SHARED, THE DATA IS NOT.
#
# A probe corpus is DERIVED from a denylist — a string engineered to match a
# rule describes that rule — so it inherits the same rule exactly. This action
# therefore ships no corpus either, and could not usefully ship one: the
# central assertion below is that the corpus exercises EVERY rule of THIS
# caller's list, and callers' lists legitimately differ. A shared corpus would
# be wrong for every caller but one.
#
# ---------------------------------------------------------------------------
# THE PROBE CORPUS FORMAT (`.firewall-probes` by convention)
# ---------------------------------------------------------------------------
#
#   # free-form comments and blank lines are skipped, same convention as the
#   # denylist and `.firewallignore`
#   [must-match]
#   <one synthetic probe per line>
#   ...
#   [must-not-match]
#   <one benign lookalike per line>
#   ...
#
# A probe is the WHOLE LINE — there are no fields to split, deliberately: a
# probe for a rule matching a PEM header or a private-network address contains
# spaces and punctuation, and any field-splitting convention would eventually
# mangle one. The cost is that a probe cannot begin with `#` or `[`; no rule
# in this estate needs one that does, and the parser says so rather than
# silently reinterpreting the line.
#
# ⚠️ PROBES ARE SYNTHETIC AND MUST STAY SYNTHETIC. A probe is a string shaped
# LIKE the thing a rule catches — never an instance of it. Never a real
# credential, never a real identity value, never a real host. Several
# repositories carrying this corpus are public, and a corpus is committed:
# a "probe" that was a real secret would be a leak filed as a test.
#
# ---------------------------------------------------------------------------
# WHAT IS ASSERTED, AND WHY BOTH DIRECTIONS ARE NEEDED
# ---------------------------------------------------------------------------
#
#   A. EVERY ACTIVE RULE FIRES on at least one `[must-match]` probe.
#      Catches: a rule neutered into a compiling-but-non-matching form; a rule
#      added to the list with no probe behind it (so nobody ever demonstrated
#      it bites); a list copied from a tier whose rule never worked here.
#
#   B. EVERY `[must-match]` PROBE FIRES at least one rule.
#      Catches: a rule DELETED. A is blind to deletion on its own — deleting a
#      rule shrinks the active set, so "every active rule fires" stays
#      trivially true over the smaller set. The orphaned probe is what
#      remains, and it is what turns the build red.
#
#   C. NO `[must-not-match]` LOOKALIKE FIRES anything.
#      Catches a rule widened until it matches ordinary content. Without C a
#      corpus could be satisfied by a rule that matches EVERYTHING, which is
#      the mirror image of one that matches nothing and just as useless.
#
# A and B are the two closing directions of the same door, and neither alone
# closes it. This is the same fail-closed-in-both-directions discipline
# `.firewallignore` already applies to itself (a stale exemption is exit 2,
# never a silent no-op).
#
# ---------------------------------------------------------------------------
# ⚠️ PROBES ARE SCANNED WITH EXEMPTIONS DISABLED — STATED, NEVER SILENT
# ---------------------------------------------------------------------------
#
# The corpus is a file full of denylist-shaped strings, so the REAL gate fires
# on the corpus itself. That self-match is handled where it belongs and
# visibly: the caller commits one `.firewallignore` entry per rule, scoped to
# the corpus path, each with its mandatory reason — reviewed, fail-closed
# (a stale entry is exit 2), and legible in the diff. It is deliberately NOT
# solved by excluding the corpus from the scan inside this tooling: a silent
# exclusion is the defect class arqtiqa/arqtos#343 was filed for, where a
# same-basename file was dropped from the scan before `.firewallignore` ever
# got a chance to record a decision about it.
#
# This script must therefore scan its probes with those exemptions OUT of
# force — otherwise the corpus's own suppression would suppress the falsifier
# too, and every probe would report "no rule fired" (a red build for the
# wrong reason) or, worse, a future refactor would "fix" that by trusting the
# exemption and asserting nothing. It passes an EMPTY exemptions file rather
# than no exemptions file, so the scanner takes its explicit-path branch and
# never falls back to whatever `.firewallignore` happens to sit in the CWD.
# The choice is printed on every run.
#
# ⚠️ RESIDUAL, STATED HONESTLY: because probes are scanned with exemptions
# disabled, this script cannot see an exemption that WIDENED until it swallows
# real content. That failure mode is held by the exemptions mechanism's own
# fail-closed validation (arqtiqa/arqtos#341, #365: a glob matching no tracked
# file, or a verbatim rule matching no active pattern, is exit 2) plus review
# of a security file. Do not "close" it here by teaching this script a second
# glob engine — the reference one lives in the scanner, and a second
# implementation of matching semantics is the drift arqtos-cli#828 was filed
# about.
#
# ---------------------------------------------------------------------------
# ⚠️ THE IDENTITY OVERLAY IS OUT OF SCOPE AND IS ACTIVELY CLEARED
# ---------------------------------------------------------------------------
#
# Overlay liveness is arqtiqa/arqtos#344's job (`require-identity-overlay`),
# and an overlay pattern is a SECRET — a committed corpus could not contain a
# probe for one without publishing it. So the three overlay environment
# variables are explicitly stripped from every scanner invocation below rather
# than merely left unset: an ambient overlay in the caller's environment would
# union extra patterns into the scan, fire on probes, and pollute the fired-
# rule set this script reasons over. Committed rules only, deterministically.
#
# ---------------------------------------------------------------------------
# ⚠️ REPORTS NAME RULES BY HANDLE AND LINE NUMBER, NOT BY PATTERN TEXT
# ---------------------------------------------------------------------------
#
# A rule handle is `sha256:` + the first 12 lowercase hex digits of the
# SHA-256 of the pattern's exact text — the same handle vocabulary
# `.firewallignore` uses (arqtiqa/arqtos#365), so a handle printed here can be
# pasted straight into an exemption. Naming a rule by handle plus
# `<denylist>:<lineno>` locates it exactly while quoting nothing: a CI log is
# a wider audience than a repository, and several callers of this action are
# public.
set -euo pipefail

denylist=""
probes=".firewall-probes"
scanner="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/../firewall/check-private-content.sh"

# ⚠️ UNKNOWN ARGUMENTS ARE REFUSED, NOT IGNORED. The sibling scanner treats an
# unrecognised bare argument as a FILE to scan, which is how a space-separated
# `--denylist <path>` silently degrades there into "scan a file literally named
# --denylist". This script has no positional operands at all, so anything it
# does not recognise is a mistake, and a gate's harness must fail loudly on one
# rather than run a differently-configured check than the author asked for.
for arg in "$@"; do
  case "$arg" in
    --denylist=*)
      denylist="${arg#--denylist=}"
      ;;
    --probes=*)
      probes="${arg#--probes=}"
      ;;
    --scanner=*)
      scanner="${arg#--scanner=}"
      ;;
    --help|-h)
      # Delimited by the first line of code, never a hard-coded line number —
      # the sibling scanner's `--help` was truncated mid-sentence by exactly
      # that mistake once already.
      sed -n '2,$p' "${BASH_SOURCE[0]}" | sed -n '/^set -euo pipefail/q;p' | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "✗ check-denylist-liveness: unrecognised argument '$arg'." >&2
      echo "  This script takes no positional operands. Flags are --denylist=<path>," >&2
      echo "  --probes=<path>, --scanner=<path> -- with an EQUALS SIGN. A" >&2
      echo "  space-separated form is a different, silently-wrong invocation, so it is" >&2
      echo "  refused (exit 2) rather than guessed at." >&2
      exit 2
      ;;
  esac
done

if [[ -z "$denylist" ]]; then
  echo "✗ check-denylist-liveness: no denylist supplied (--denylist=<path>)." >&2
  echo "  There is no default and no bundled fallback, for the same reason the" >&2
  echo "  firewall action ships none: the data belongs to the caller." >&2
  exit 2
fi
if [[ ! -f "$denylist" ]]; then
  echo "✗ check-denylist-liveness: denylist not found at $denylist" >&2
  exit 2
fi
if [[ ! -f "$probes" ]]; then
  echo "✗ check-denylist-liveness: probe corpus not found at $probes" >&2
  echo "  A denylist with no corpus has no standing falsifier -- which is the state" >&2
  echo "  arqtiqa/arqtos#361 exists to end, so it is a configuration error (exit 2)," >&2
  echo "  never a pass. See this action's README for the corpus format." >&2
  exit 2
fi
if [[ ! -x "$scanner" ]]; then
  echo "✗ check-denylist-liveness: scanner not found or not executable at $scanner" >&2
  echo "  The falsifier drives the REAL scanner rather than reimplementing matching:" >&2
  echo "  a falsifier with its own matching engine proves only that its own engine" >&2
  echo "  agrees with itself." >&2
  exit 2
fi

# --- rule handles ----------------------------------------------------------
#
# Same construction as the scanner's own `rule_digest` (arqtiqa/arqtos#365) --
# `sha256:` + the first 12 lowercase hex digits of the pattern text's SHA-256,
# digested with NO trailing newline. Duplicated here rather than shared
# because the scanner is an executable, not a library: this is 10 lines of
# FORMAT parity, not a second copy of the matching logic (which is exactly
# what this script refuses to grow -- see the module doc).
digest_tool=""
if command -v sha256sum >/dev/null 2>&1; then
  digest_tool="sha256sum"
elif command -v shasum >/dev/null 2>&1; then
  digest_tool="shasum -a 256"
else
  echo "✗ check-denylist-liveness: neither sha256sum nor shasum is on PATH." >&2
  echo "  Rule handles are how this report names a rule without quoting it." >&2
  exit 2
fi

rule_handle() {
  printf 'sha256:%s' "$(printf '%s' "$1" | $digest_tool | cut -c1-12)"
}

# --- the caller's active rule set ------------------------------------------
#
# ⚠️ Read with `|| [[ -n "$line" ]]`, so a final rule on an UNTERMINATED last
# line is seen here. The scanner's own rule loop is a plain `read` and would
# drop it -- meaning such a rule is never applied to anything while the
# scanner's `grep -cvE` rule COUNT still includes it. Seeing it here turns
# that pre-existing silent hole into a legible red build ("not exercised by
# any probe") instead of leaving it invisible on both sides.
rule_texts=()
rule_lines=()
dl_lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
  dl_lineno=$((dl_lineno + 1))
  [[ "$line" =~ ^[[:space:]]*(#|$) ]] && continue
  rule_texts+=("$line")
  rule_lines+=("$dl_lineno")
done < "$denylist"

if (( ${#rule_texts[@]} == 0 )); then
  echo "✗ check-denylist-liveness: $denylist contains no rules." >&2
  echo "  A scan with nothing to scan against passes every file, so there is nothing" >&2
  echo "  here a falsifier could prove alive. This is the same misconfiguration the" >&2
  echo "  scanner itself refuses (exit 2), caught one layer earlier." >&2
  exit 2
fi

# --- the probe corpus ------------------------------------------------------
must_match=()
must_match_lines=()
must_not_match=()
must_not_match_lines=()
section=""
p_lineno=0
while IFS= read -r line || [[ -n "$line" ]]; do
  p_lineno=$((p_lineno + 1))
  trimmed="${line#"${line%%[![:space:]]*}"}"
  [[ -z "$trimmed" ]] && continue
  [[ "${trimmed:0:1}" == "#" ]] && continue
  if [[ "${trimmed:0:1}" == "[" ]]; then
    case "$trimmed" in
      "[must-match]")
        section="match"
        ;;
      "[must-not-match]")
        section="nomatch"
        ;;
      *)
        echo "✗ check-denylist-liveness: $probes:$p_lineno: unknown section header '$trimmed'." >&2
        echo "  The only sections are [must-match] and [must-not-match]. A typo'd header" >&2
        echo "  would otherwise silently drop every probe beneath it, which is a corpus" >&2
        echo "  that proves nothing while looking complete." >&2
        exit 2
        ;;
    esac
    continue
  fi
  if [[ -z "$section" ]]; then
    echo "✗ check-denylist-liveness: $probes:$p_lineno: probe before the first section header." >&2
    echo "  Every probe must sit under [must-match] or [must-not-match] -- a probe whose" >&2
    echo "  expected verdict is unstated cannot falsify anything." >&2
    exit 2
  fi
  if [[ "$section" == "match" ]]; then
    must_match+=("$line")
    must_match_lines+=("$p_lineno")
  else
    must_not_match+=("$line")
    must_not_match_lines+=("$p_lineno")
  fi
done < "$probes"

# ⚠️ BOTH SECTIONS ARE MANDATORY AND BOTH MUST BE NON-EMPTY.
#
# An empty [must-match] is the "green over a dead list" state this whole
# mechanism exists to end, wearing the falsifier's own clothes. An empty
# [must-not-match] is subtler and just as bad: without a benign lookalike,
# a rule widened until it matches ordinary prose satisfies every other
# assertion here perfectly. Neither is a degraded pass; both are exit 2.
if (( ${#must_match[@]} == 0 )); then
  echo "✗ check-denylist-liveness: $probes has no [must-match] probes." >&2
  echo "  A corpus that asserts nothing reports every denylist alive, which is the" >&2
  echo "  silent-green state this falsifier exists to end (exit 2, never a pass)." >&2
  exit 2
fi
if (( ${#must_not_match[@]} == 0 )); then
  echo "✗ check-denylist-liveness: $probes has no [must-not-match] lookalikes." >&2
  echo "  A rule widened until it matches ordinary content passes every other check" >&2
  echo "  here. Pinning the ABSENCE of false positives is half the falsifier, so an" >&2
  echo "  empty section is a configuration error (exit 2)." >&2
  exit 2
fi

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
: >"$tmpdir/no-exemptions"

echo "info: check-denylist-liveness: $denylist (${#rule_texts[@]} rule(s)) vs $probes (${#must_match[@]} probe(s), ${#must_not_match[@]} lookalike(s))" >&2
echo "info: check-denylist-liveness: probes are scanned with exemptions DISABLED and no identity overlay -- the corpus is exempted for the caller's own gate by committed .firewallignore entries (see $probes), which is deliberately not the same thing as excluding it from this check" >&2

# PROBE_STATUS / PROBE_FIRED are set by run_probe, read by its callers.
PROBE_STATUS=0
PROBE_FIRED=""
run_probe() {
  printf '%s\n' "$1" >"$tmpdir/probe.txt"
  local out
  set +e
  out=$(
    env -u ARQTOS_FIREWALL_IDENTITY_OVERLAY \
        -u ARQTOS_FIREWALL_REQUIRE_IDENTITY_OVERLAY \
        -u ARQTOS_FIREWALL_OVERLAY_MAY_BE_WITHHELD \
        "$scanner" \
          "--denylist=$denylist" \
          "--exemptions=$tmpdir/no-exemptions" \
          "$tmpdir/probe.txt" 2>&1 >/dev/null
  )
  PROBE_STATUS=$?
  set -e
  # The scanner reports a denylist hit as `✗ pattern: <rule text>` on stderr.
  # Rule text is extracted here to build the fired set, and is never printed.
  PROBE_FIRED=$(printf '%s\n' "$out" | sed -n 's/^✗ pattern: //p')
  if (( PROBE_STATUS >= 2 )); then
    echo "✗ check-denylist-liveness: the scanner reported a configuration error (exit $PROBE_STATUS) while running a probe." >&2
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    echo "  A falsifier cannot report a denylist alive on a run where the scanner never" >&2
    echo "  applied it -- this is misconfiguration, not a result." >&2
    exit 2
  fi
}

fired_all=()
failures=0

# --- assertion B: every probe fires something ------------------------------
idx=0
while (( idx < ${#must_match[@]} )); do
  run_probe "${must_match[$idx]}"
  if (( PROBE_STATUS != 1 )) || [[ -z "$PROBE_FIRED" ]]; then
    echo "✗ check-denylist-liveness: $probes:${must_match_lines[$idx]}: this [must-match] probe fired NO rule." >&2
    echo "    The rule it was written for is gone or no longer matches it. Restore the" >&2
    echo "    rule in $denylist, or -- if the rule was retired on purpose -- retire this" >&2
    echo "    probe in the same commit, so the corpus and the list stay in step." >&2
    failures=$((failures + 1))
  else
    while IFS= read -r f; do
      [[ -n "$f" ]] && fired_all+=("$f")
    done <<<"$PROBE_FIRED"
  fi
  idx=$((idx + 1))
done

# --- assertion C: no lookalike fires anything ------------------------------
idx=0
while (( idx < ${#must_not_match[@]} )); do
  run_probe "${must_not_match[$idx]}"
  if (( PROBE_STATUS != 0 )); then
    echo "✗ check-denylist-liveness: $probes:${must_not_match_lines[$idx]}: this [must-not-match] lookalike FIRED." >&2
    while IFS= read -r f; do
      [[ -z "$f" ]] && continue
      j=0
      while (( j < ${#rule_texts[@]} )); do
        if [[ "${rule_texts[$j]}" == "$f" ]]; then
          echo "    fired: $(rule_handle "$f")  ($denylist:${rule_lines[$j]})" >&2
        fi
        j=$((j + 1))
      done
    done <<<"$PROBE_FIRED"
    echo "    A rule has widened until it matches ordinary content. Narrow the rule" >&2
    echo "    rather than deleting the lookalike -- the lookalike is the requirement." >&2
    failures=$((failures + 1))
  fi
  idx=$((idx + 1))
done

# --- assertion A: every active rule fired ----------------------------------
idx=0
while (( idx < ${#rule_texts[@]} )); do
  rule="${rule_texts[$idx]}"
  covered=0
  j=0
  while (( j < ${#fired_all[@]} )); do
    if [[ "${fired_all[$j]}" == "$rule" ]]; then
      covered=1
      break
    fi
    j=$((j + 1))
  done
  if (( ! covered )); then
    echo "✗ check-denylist-liveness: rule $(rule_handle "$rule") ($denylist:${rule_lines[$idx]}) is not exercised by any probe." >&2
    echo "    Either the rule was edited into a form that still compiles but no longer" >&2
    echo "    matches what it is meant to match, or it was added without a probe behind" >&2
    echo "    it. Add a [must-match] line to $probes that this rule fires on, and watch" >&2
    echo "    it go red before it goes green." >&2
    if (( idx == ${#rule_texts[@]} - 1 )); then
      echo "    (this is the LAST rule in the file: if $denylist does not end in a" >&2
      echo "     newline, the scanner never applies it at all -- check that first)" >&2
    fi
    failures=$((failures + 1))
  fi
  idx=$((idx + 1))
done

if (( failures > 0 )); then
  echo "" >&2
  echo "✗ check-denylist-liveness: $failures liveness assertion(s) failed." >&2
  echo "  A denylist that no longer bites still produces a GREEN firewall, which is" >&2
  echo "  worse than no firewall because it is trusted. That is what this is." >&2
  exit 1
fi

echo "info: check-denylist-liveness: all ${#rule_texts[@]} rule(s) proven live; ${#must_not_match[@]} lookalike(s) proven inert" >&2
exit 0
