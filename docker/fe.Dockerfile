# The official StarRocks FE image with the patched fe-core and fe-spi jars.
ARG UPSTREAM_TAG
FROM starrocks/fe-ubuntu:${UPSTREAM_TAG}
ARG JAR_SUFFIX
COPY out/fe-core-${JAR_SUFFIX}.jar /opt/starrocks/fe/lib/fe-core-${JAR_SUFFIX}.jar
COPY out/fe-spi-${JAR_SUFFIX}.jar /opt/starrocks/fe/lib/fe-spi-${JAR_SUFFIX}.jar
COPY out/EGRET-PATCHES.txt /opt/starrocks/fe/EGRET-PATCHES.txt
# Exactly one fe-core and one fe-spi jar must end up on the classpath: a JAR_SUFFIX that does not
# match the official file names would add a second copy instead of replacing it.
RUN test "$(ls /opt/starrocks/fe/lib/fe-core-*.jar | wc -l)" -eq 1 && test "$(ls /opt/starrocks/fe/lib/fe-spi-*.jar | wc -l)" -eq 1
LABEL org.opencontainers.image.source="https://github.com/egret-data/egret-starrocks" \
      org.opencontainers.image.description="StarRocks FE with egret security patches (not an official StarRocks image)" \
      org.opencontainers.image.licenses="Apache-2.0"
