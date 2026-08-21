#!/usr/bin/env bash
#
# Repository hygiene checks. Run in CI, and locally with:
#
#     .github/scripts/tree-hygiene.sh
#
#   1. no tracked file is covered by an ignore rule
#   2. no relative link or "see <file>" reference points at a path that would
#     not be published -- dangling references rot silently and mislead readers.
#      Vendored code is exempt: its comments point into the upstream project's
#      own documentation tree, which is not vendored along with the sources.
#   3. no machine-local details: private-range addresses, ssh targets, absolute
#      home paths
#
# Checks 2 and 3 look at everything git would publish, which is the tracked
# files plus the untracked ones no ignore rule covers. Scanning only what is
# already committed would clear a file at every moment except the one that
# matters, the commit that first adds it.
#
# Add a trailing  # hygiene-ok  to a line to allow a deliberate occurrence, and
# list generated or external paths in allowed-paths.txt.
#
# This script necessarily contains the patterns it searches for, so it excludes
# its own directory from the content checks.
#
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

SELF_DIR='.github/scripts'
ALLOW_FILE="$SELF_DIR/allowed-paths.txt"
VENDOR_DIR='third_party'

status=0
fail() { printf '\033[1;31mFAIL\033[0m  %s\n' "$*" >&2; status=1; }
pass() { printf '\033[1;32mok\033[0m    %s\n' "$*"; }
detail() { printf '        %s\n' "$*" >&2; }

mapfile -t PUBLISHED < <(git ls-files --cached --others --exclude-standard)
if [ "${#PUBLISHED[@]}" -eq 0 ]; then
    echo "nothing to publish yet -- nothing to check"
    exit 0
fi

declare -A IS_PUBLISHED=()
for f in "${PUBLISHED[@]}"; do IS_PUBLISHED["$f"]=1; done

declare -A ALLOWED=()
if [ -f "$ALLOW_FILE" ]; then
    while IFS= read -r line; do
        line="${line%%#*}"; line="${line// /}"
        [ -n "$line" ] && ALLOWED["$line"]=1
    done < "$ALLOW_FILE"
fi

is_text() {
    # crude but dependency-free: treat anything with a NUL byte as binary
    ! grep -qI . "$1" 2>/dev/null && return 1
    return 0
}

scannable() {
    local f=$1
    case "$f" in "$SELF_DIR"/*) return 1 ;; esac
    [ -f "$f" ] || return 1
    is_text "$f"
}

# ------------------------------------------------------------------ check 1
# A tracked file that an ignore rule also covers means someone forced it in.
ignored=$(git ls-files -z | xargs -0 -r git check-ignore --no-index 2>/dev/null || true)
if [ -n "$ignored" ]; then
    fail "tracked files are covered by ignore rules -- were these force-added?"
    while IFS= read -r f; do detail "$f"; done <<< "$ignored"
else
    pass "no tracked file is covered by an ignore rule"
fi

# ------------------------------------------------------------------ check 2
# Relative references must resolve to something git tracks.
dangling=0
resolve_and_check() {
    local src=$1 ref=$2 base resolved

    ref="${ref%%#*}"                        # drop anchor
    [ -z "$ref" ] && return
    case "$ref" in
        *://*|mailto:*|'#'*|'$'*|'~'*) return ;;   # external / templated
        /*|[A-Za-z]:*) return ;;                   # absolute -- check 3's job
        *' '*) return ;;
    esac
    [ -n "${ALLOWED[$ref]:-}" ] && return

    base=$(dirname "$src")
    resolved=$(realpath -m --relative-to=. "$base/$ref" 2>/dev/null) || return
    [ -n "${ALLOWED[$resolved]:-}" ] && return
    [ -n "${IS_PUBLISHED[$resolved]:-}" ] && return

    # a reference to a directory that holds published files is fine
    for t in "${PUBLISHED[@]}"; do
        case "$t" in "$resolved"/*) return ;; esac
    done

    fail "$src references a path that would not be published: $ref"
    dangling=1
}

for f in "${PUBLISHED[@]}"; do
    scannable "$f" || continue
    # Upstream sources describe their own tree, not this one. Listing every
    # such reference in allowed-paths.txt would mean editing that file after
    # every dependency bump, for references we have no say over anyway.
    case "$f" in "$VENDOR_DIR"/*) continue ;; esac

    # markdown links:  [text](path)
    while IFS= read -r ref; do
        [ -n "$ref" ] && resolve_and_check "$f" "$ref"
    done < <(grep -oE '\]\([^)]+\)' "$f" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//')

    # prose and comments:  see foo/bar.md
    while IFS= read -r ref; do
        [ -n "$ref" ] && resolve_and_check "$f" "$ref"
    done < <(grep -oiE '\bsee +[A-Za-z0-9_./-]+\.(md|txt|rst)\b' "$f" 2>/dev/null \
             | awk '{print $2}')
done
[ "$dangling" -eq 0 ] && pass "all relative references resolve to published paths"

# ------------------------------------------------------------------ check 3
# Machine-local details.
LOCAL_PATTERNS=(
    '\b192\.168\.[0-9]{1,3}\.[0-9]{1,3}\b'
    '\b10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\b'
    '\b172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}\b'
    '\b[a-z_][a-z0-9_-]*@([0-9]{1,3}\.){3}[0-9]{1,3}\b'
    '[A-Za-z]:\\+Users\\+'
    '/home/[a-z]'
    '/mnt/[a-z]/'
    '/Users/[A-Za-z]'
)
# One alternation, so a line matching several patterns is reported once.
LOCAL_RE=$(IFS='|'; printf '%s' "${LOCAL_PATTERNS[*]}")

leaked=0
for f in "${PUBLISHED[@]}"; do
    scannable "$f" || continue
    hits=$(grep -nE -- "$LOCAL_RE" "$f" 2>/dev/null | grep -v 'hygiene-ok' || true)
    if [ -n "$hits" ]; then
        fail "$f contains machine-local details:"
        while IFS= read -r h; do detail "$h"; done <<< "$hits"
        leaked=1
    fi
done
[ "$leaked" -eq 0 ] && pass "no machine-local details in the files git would publish"

exit "$status"
