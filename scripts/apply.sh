#!/usr/bin/env bash
# Fetch the upstream tag into work/starrocks and apply patches/*.patch on a clean tree.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../UPSTREAM
source "$ROOT/UPSTREAM"
SRC=${SRC:-$ROOT/work/starrocks}
# A local clone that has the tag works too (offline, faster): UPSTREAM_URL=/path/to/starrocks
UPSTREAM_URL=${UPSTREAM_URL:-https://github.com/StarRocks/starrocks.git}

if [ ! -d "$SRC/.git" ]; then
    mkdir -p "$(dirname "$SRC")"
    git init -q "$SRC"
fi
git -C "$SRC" fetch -q --depth 1 "$UPSTREAM_URL" "refs/tags/$UPSTREAM_TAG:refs/tags/$UPSTREAM_TAG"
actual=$(git -C "$SRC" rev-parse "$UPSTREAM_TAG^{commit}")
if [ "$actual" != "$UPSTREAM_COMMIT" ]; then
    echo "tag $UPSTREAM_TAG is $actual, expected $UPSTREAM_COMMIT (tag moved?)" >&2
    exit 1
fi
git -C "$SRC" checkout -q -f --detach "$UPSTREAM_COMMIT"
git -C "$SRC" clean -q -fdx -e 'fe/**/target/'
for p in "$ROOT"/patches/*.patch; do
    echo "applying $(basename "$p")"
    git -C "$SRC" apply --index --whitespace=nowarn "$p"
done
echo "patched tree ready: $SRC"
