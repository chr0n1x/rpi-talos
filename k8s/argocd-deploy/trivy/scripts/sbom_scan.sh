#!/bin/sh
# Scans the images listed in state/plan.tsv into CycloneDX JSON.
# Runs under busybox sh inside the trivy image, so no bash features here.
set -u

DIR="${SBOM_DIR:-/data}"
PLAN="$DIR/state/plan.tsv"

if [ ! -s "$PLAN" ]; then
    echo "no plan at $PLAN" >&2
    exit 0
fi

# A previous scan counts only when it left a complete JSON document, so a run
# killed mid-write gets redone instead of being skipped forever.
scanned() {
    [ -s "$1" ] && case "$(tail -c 32 "$1" 2>/dev/null | tr -d '[:space:]')" in
        *'}') return 0 ;;
    esac
    return 1
}

fails=0

# plan.tsv columns: SBOM path, image reference, reference pinned to its digest.
while read -r out ref target; do
    [ -n "$out" ] || continue
    path="$DIR/$out"
    if scanned "$path"; then
        echo "SKIP $target"
        continue
    fi
    # Fixed tmp name: Forbid guarantees one writer, so a leftover from a
    # killed run is overwritten by the next scan instead of never reaped.
    tmp="$path.tmp"
    mkdir -p "$(dirname "$path")"
    # Only the rename is visible to readers, so no one sees a partial SBOM.
    if trivy image --format cyclonedx --output "$tmp" --parallel 2 "$target"; then
        mv -f "$tmp" "$path"
        echo "OK $target"
    else
        echo "FAILED $target"
        rm -f "$tmp"
        fails=$((fails + 1))
    fi
done < "$PLAN"

# Modulo-256 exit would turn 256 failures into a silent success.
[ "$fails" -eq 0 ] || exit 1
