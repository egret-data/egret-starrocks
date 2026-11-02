#!/usr/bin/env bash
# Build the FE image (for Kubernetes / the operator) and the allin1 image (for compose and the e2e).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../UPSTREAM
source "$ROOT/UPSTREAM"
REGISTRY=${REGISTRY:-ghcr.io/egret-data}
TAG="$UPSTREAM_TAG-egret.$EGRET_PATCH_LEVEL"

for kind in fe allin1; do
    docker build -f "$ROOT/docker/$kind.Dockerfile" \
        --build-arg UPSTREAM_TAG="$UPSTREAM_TAG" --build-arg JAR_SUFFIX="$JAR_SUFFIX" \
        -t "$REGISTRY/egret-starrocks-$kind:$TAG" "$ROOT"
    echo "built $REGISTRY/egret-starrocks-$kind:$TAG"
done
