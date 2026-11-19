#!/usr/bin/env bash
# Checks the parity ledger against the Go reference.
#
# Every Go test must be accounted for exactly once: named in a comment
# of the conformance suite or of a unit test under src/, which marks it
# ported, or listed in the "Not ported" tables of tests/PARITY.md with
# the reason. A name that
# matches no Go test is a stale reference and fails the check too.
#
# Usage: tests/check-parity.sh <path to the Go source tree>
set -euo pipefail

go_source="${1:?usage: check-parity.sh <path to the Go source tree>}"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

grep -rhoE '^func Test[A-Za-z0-9_]+' --include='*_test.go' "$go_source" |
    sed 's/^func //' | sort -u >"$work/go"

# Comment lines only, so a Rust identifier can never count as a port.
grep -rhE '^\s*//' "$here/conformance" "$here/../src" --include='*.rs' |
    grep -oE '\bTest[A-Z][A-Za-z0-9_]+' | sort -u >"$work/ported"

sed -n '/^## Not ported/,$p' "$here/PARITY.md" |
    grep -oE '`Test[A-Z][A-Za-z0-9_]+`' | tr -d '`' | sort -u >"$work/deferred"

status=0

report() {
    local title="$1" file="$2"

    if [[ -s "$file" ]]; then
        printf '%s\n' "$title"
        sed 's/^/  /' "$file"
        status=1
    fi
}

sort -u "$work/ported" "$work/deferred" >"$work/accounted"

comm -23 "$work/go" "$work/accounted" >"$work/missing"
comm -13 "$work/go" "$work/accounted" >"$work/stale"
comm -12 "$work/ported" "$work/deferred" >"$work/both"

report "Go tests neither ported nor listed in PARITY.md:" "$work/missing"
report "Names that match no Go test:" "$work/stale"
report "Go tests marked both ported and not ported:" "$work/both"

printf 'Go tests: %d, ported: %d, not ported: %d\n' \
    "$(wc -l <"$work/go")" "$(wc -l <"$work/ported")" "$(wc -l <"$work/deferred")"

exit "$status"
