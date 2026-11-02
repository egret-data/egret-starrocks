#!/usr/bin/env bash
# Build the AuditLoader plugin at AUDITLOADER_COMMIT with patches/auditloader/ into out/auditloader.zip.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../UPSTREAM
source "$ROOT/UPSTREAM"
SRC=${AUDITLOADER_SRC:-$ROOT/work/auditloader}
OUT=$ROOT/out

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$(dirname "$SRC")"
    git init -q "$SRC"
fi
git -C "$SRC" fetch -q --depth 1 "$AUDITLOADER_URL" "$AUDITLOADER_COMMIT"
git -C "$SRC" checkout -q -f --detach FETCH_HEAD
actual=$(git -C "$SRC" rev-parse HEAD)
if [ "$actual" != "$AUDITLOADER_COMMIT" ]; then
    echo "AuditLoader is at $actual, expected $AUDITLOADER_COMMIT" >&2
    exit 1
fi
git -C "$SRC" clean -qfdx
for p in "$ROOT"/patches/auditloader/*.patch; do
    echo "applying auditloader/$(basename "$p")"
    git -C "$SRC" apply --index "$p"
done

(cd "$SRC" && mvn -B package -DskipTests)

mkdir -p "$OUT"
command cp -f "$SRC/target/auditloader.zip" "$OUT/auditloader.zip"
echo "auditloader $AUDITLOADER_COMMIT + $(cd "$ROOT/patches/auditloader" && ls ./*.patch | tr '\n' ' ')" >> "$OUT/EGRET-PATCHES.txt"
echo "auditloader: $AUDITLOADER_COMMIT + $(ls "$ROOT"/patches/auditloader/*.patch | wc -l | tr -d ' ') patch(es) -> out/auditloader.zip"
