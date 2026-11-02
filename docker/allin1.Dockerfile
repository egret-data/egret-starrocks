# The official StarRocks allin1 image with the patched fe-core and fe-spi jars (compose, e2e).
ARG UPSTREAM_TAG
FROM starrocks/allin1-ubuntu:${UPSTREAM_TAG}
ARG JAR_SUFFIX
COPY out/fe-core-${JAR_SUFFIX}.jar /data/deploy/starrocks/fe/lib/fe-core-${JAR_SUFFIX}.jar
COPY out/fe-spi-${JAR_SUFFIX}.jar /data/deploy/starrocks/fe/lib/fe-spi-${JAR_SUFFIX}.jar
COPY out/EGRET-PATCHES.txt /data/deploy/starrocks/fe/EGRET-PATCHES.txt
# Exactly one fe-core and one fe-spi jar must end up on the classpath: a JAR_SUFFIX that does not
# match the official file names would add a second copy instead of replacing it.
RUN test "$(ls /data/deploy/starrocks/fe/lib/fe-core-*.jar | wc -l)" -eq 1 && test "$(ls /data/deploy/starrocks/fe/lib/fe-spi-*.jar | wc -l)" -eq 1
LABEL org.opencontainers.image.source="https://github.com/egret-data/egret-starrocks" \
      org.opencontainers.image.description="StarRocks allin1 with egret security patches (not an official StarRocks image)" \
      org.opencontainers.image.licenses="Apache-2.0"
