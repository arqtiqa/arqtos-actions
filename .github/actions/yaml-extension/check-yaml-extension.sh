#!/usr/bin/env bash
# check-yaml-extension — arqtos-authored YAML is .yaml, and the exceptions are
# declared rather than assumed.
#
# Usage:
#   check-yaml-extension.sh [--exemptions=<path>] [--root=<path>]
#
# Exits 0 when every arqtos-authored YAML file under <root> is spelled .yaml or
# is covered by a declared exemption, 1 when it is not, and 2 on a configuration
# error. Three states, for the reason every gate in this estate has three: "the
# check did not run" must never be indistinguishable from "the check passed".
#
# ---------------------------------------------------------------------------
# ⚠️ WHY THIS SHIPS AN IMPLEMENTATION, WHERE go-fmt DELIBERATELY DOES NOT
# ---------------------------------------------------------------------------
#
# The go-fmt action here invokes the CALLER's Makefile target and says so
# loudly: four repositories had four disagreeing spellings of one check, and a
# fifth implementation would have "agreed with nobody".
#
# This is the opposite shape, measured at arqtiqa/arqtos-core#206: of the six
# repositories this gate is for, ONE had a check and five had no CI harness of
# any kind. There is nothing to invoke in five of the six, so asking each to
# grow a harness is how the estate gets six implementations instead of one —
# the divergence go-fmt warns about, reached from the other direction.
#
# ⚠️ THE ONE THAT HAD A CHECK KEEPS IT, and the divergence is real: this action
# runs only in CI, and that gate also runs locally so a developer sees it before
# pushing. Two enforcement points, one policy. The policy is exemptions.txt, and
# reconciling the two lists is recorded as owed at #206.
set -uo pipefail

exemptions=""
root="."
for arg in "$@"; do
	case "$arg" in
	--exemptions=*) exemptions="${arg#*=}" ;;
	--root=*) root="${arg#*=}" ;;
	*)
		echo "REFUSING: unrecognised argument $arg" >&2
		exit 2
		;;
	esac
done
[ -n "$exemptions" ] || exemptions="$(dirname "$0")/exemptions.txt"

[ -d "$root" ] || {
	echo "REFUSING: --root=$root is not a directory, so this check has nothing to read." >&2
	exit 2
}
[ -r "$exemptions" ] || {
	echo "REFUSING: $exemptions is unreadable. The exemption list is committed, never inferred." >&2
	exit 2
}

# ⚠️ VALIDATE THE LIST BEFORE TRUSTING IT. An entry naming no tool is a
# preference wearing a rule's clothes, and an empty list is a check quietly
# switched off while still reporting green.
names=()
dirs=()
entries=0
while IFS= read -r line; do
	case "$line" in '' | '#'*) continue ;; esac
	kv="${line%%|*}"
	reason="${line#*|}"
	if [ "$kv" = "$line" ] || [ -z "${reason//[[:space:]]/}" ]; then
		echo "REFUSING: the exemption \"$line\" names no tool." >&2
		echo "          An exemption without one is a preference wearing a rule's clothes." >&2
		exit 2
	fi
	value="${kv#*:}"
	if [ -z "$value" ]; then
		echo "REFUSING: the exemption \"$line\" has an empty value." >&2
		exit 2
	fi
	case "$kv" in
	name:*) names+=("$value") ;;
	dir:*) dirs+=("$value") ;;
	*)
		echo "REFUSING: the exemption \"$line\" is neither name: nor dir:." >&2
		echo "          The kind says what the tool actually reads, so it cannot be omitted." >&2
		exit 2
		;;
	esac
	entries=$((entries + 1))
done <"$exemptions"

if [ "$entries" -eq 0 ]; then
	echo "REFUSING: $exemptions declares no exemptions, so it has been emptied rather than satisfied." >&2
	exit 2
fi

exempt() { # path
	local path="$1" base n d
	base="${path##*/}"
	for n in ${names[@]+"${names[@]}"}; do
		[ "$base" = "$n" ] && return 0
	done
	for d in ${dirs[@]+"${dirs[@]}"}; do
		case "$path" in "$d"*) return 0 ;; esac
	done
	return 1
}

# BOTH spellings, so the census covers the whole surface rather than the half
# that is already wrong.
# ⚠️ A while-read loop, not mapfile: mapfile is bash 4, macOS ships bash 3.2,
# and this script is meant to be runnable by a developer as well as by CI. The
# bash-4 form worked on the ubuntu runner and broke on the machine it was
# written on, which is the wrong way round for a check anybody trusts.
# ⚠️ COUNTED AS IT READS, into a plain integer. The first draft asked
# ${#all[@]:-0}, which bash 3.2 tolerated and bash 5 rejects as a bad
# substitution — so the census guard below errored on the runner and the check
# PASSED over an empty tree. Two shells, two different ways to get this wrong,
# so neither array length nor a default expansion is asked for at all.
all=()
total=0
while IFS= read -r found; do
	all[$total]="$found"
	total=$((total + 1))
done < <(cd "$root" && /usr/bin/find . \( -name '*.yml' -o -name '*.yaml' \) \
	-not -path './.git/*' -type f | sed 's|^\./||' | LC_ALL=C sort)

# ⚠️ A CENSUS, NOT A SEARCH. A tree with no YAML is one this check has said
# nothing about, and reporting that as a pass is how a misconfigured root reads
# as conformance.
if [ "$total" -eq 0 ]; then
	echo "REFUSING: no YAML file found under $root, so this check's silence means nothing." >&2
	exit 2
fi

stray=()
spared=0
for path in ${all[@]+"${all[@]}"}; do
	case "$path" in *.yml) ;; *) continue ;; esac
	if exempt "$path"; then
		spared=$((spared + 1))
		continue
	fi
	stray+=("$path")
done

if [ "${#stray[@]}" -ne 0 ]; then
	echo "FAILING: arqtos-authored YAML is .yaml. These are still .yml:" >&2
	printf '  %s\n' "${stray[@]}" >&2
	echo "" >&2
	echo "Rename each, AND every reference to it, in the same commit. If a tool" >&2
	echo "dictates the spelling, add it to the shared exemption list with the tool" >&2
	echo "named - there is no per-repository override, on purpose." >&2
	exit 1
fi

echo "yamlext: $total YAML file(s) under $root, all .yaml except $spared declared exemption(s), against $entries rule(s)"
