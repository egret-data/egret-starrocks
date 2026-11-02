#!/usr/bin/env bash
# Build the patched FE modules and collect the jars that replace the official ones in out/.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
# shellcheck source=../UPSTREAM
source "$ROOT/UPSTREAM"
SRC=${SRC:-$ROOT/work/starrocks}
OUT=$ROOT/out
PYTHON=${PYTHON:-python3}

# Only fe-core and fe-spi carry patches; every other jar in the image stays the official one built
# from the same tag. If a patch ever touches another module, add it here.
MODULES=(fe-spi fe-core)

(cd "$SRC/fe" && mvn -B package -pl fe-core -am -DskipTests -Dcheckstyle.skip=true -Djacoco.skip=true \
    -Dpython="$PYTHON")

mkdir -p "$OUT"
rm -f "$OUT"/*.jar
for m in "${MODULES[@]}"; do
    jar=$(find "$SRC/fe/$m/target" -maxdepth 1 -name "$m*.jar" \
        ! -name '*-tests.jar' ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1)
    if [ -z "$jar" ]; then
        echo "no jar built for $m" >&2
        exit 1
    fi
    command cp -f "$jar" "$OUT/$m-$JAR_SUFFIX.jar"
    echo "$m: $jar -> out/$m-$JAR_SUFFIX.jar"
done
(cd "$ROOT/patches" && ls ./*.patch) > "$OUT/EGRET-PATCHES.txt"
echo "upstream $UPSTREAM_TAG ($UPSTREAM_COMMIT), egret patch level $EGRET_PATCH_LEVEL" >> "$OUT/EGRET-PATCHES.txt"
