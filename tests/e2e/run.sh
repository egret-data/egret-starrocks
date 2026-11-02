#!/usr/bin/env bash
# Run the security checks against a StarRocks allin1 image with access_control = ranger.
#
#   tests/e2e/run.sh <allin1-image>
#
# Starts, on a private docker network: RustFS (S3), an Iceberg REST catalog, the StarRocks image
# and, on the host, a fake Ranger Admin serving policies.py's policies. KEEP=1 leaves it all running.
set -euo pipefail
IMAGE=${1:?usage: run.sh <allin1-image>}
HERE=$(cd "$(dirname "$0")" && pwd)
SR_PORT=${SR_PORT:-19130}
SR_HTTP_PORT=${SR_HTTP_PORT:-19131}
# Arrow Flight SQL: the FE returns the BE's own address (127.0.0.1:<port>) for fetching results, so both
# ports are published on the same number.
FE_FLIGHT_PORT=19408
BE_FLIGHT_PORT=19419
S3_PORT=${S3_PORT:-19100}
RANGER_PORT=18777
NAME=egs-e2e
WORK=$(mktemp -d)
NET=$NAME-net
REST_IMAGE=apache/iceberg-rest-fixture:1.10.1
S3_IMAGE=rustfs/rustfs:1.0.1
FE_CONF=/data/deploy/starrocks/fe/conf
BE_CONF=/data/deploy/starrocks/be/conf
RANGER_PID=

cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then
        echo "KEEP=1: containers $NAME-* and fake Ranger (pid $RANGER_PID) left running; work dir $WORK"
        return
    fi
    [ -n "$RANGER_PID" ] && kill "$RANGER_PID" 2>/dev/null || true
    docker rm -f "$NAME-sr" "$NAME-rest" "$NAME-s3" >/dev/null 2>&1 || true
    docker network rm "$NET" >/dev/null 2>&1 || true
    rm -rf "$WORK"
}
trap cleanup EXIT

if [ ! -x "$HERE/.venv/bin/python" ]; then
    python3 -m venv "$HERE/.venv"
    "$HERE/.venv/bin/pip" -q install -r "$HERE/requirements.txt"
fi
PY=$HERE/.venv/bin/python

"$PY" -I "$HERE/policies.py" "$HERE/servicedef-starrocks.json" "$HERE/servicedef-tag.json" "$WORK/policies.json" \
    "$WORK/tags.json"
"$PY" -I "$HERE/fakeranger.py" "$WORK/policies.json" "$WORK/tags.json" "$RANGER_PORT" 2> "$WORK/ranger.log" &
RANGER_PID=$!

docker rm -f "$NAME-sr" "$NAME-rest" "$NAME-s3" >/dev/null 2>&1 || true
docker network rm "$NET" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

docker run -d --name "$NAME-s3" --network "$NET" --network-alias s3 -p "$S3_PORT:9000" \
    -e RUSTFS_ACCESS_KEY=e2e -e RUSTFS_SECRET_KEY=e2esecret "$S3_IMAGE" >/dev/null
docker run -d --name "$NAME-rest" --network "$NET" --network-alias iceberg-rest \
    -e CATALOG_WAREHOUSE=s3://warehouse/ -e CATALOG_IO__IMPL=org.apache.iceberg.aws.s3.S3FileIO \
    -e CATALOG_S3_ENDPOINT=http://s3:9000 -e CATALOG_S3_PATH__STYLE__ACCESS=true \
    -e AWS_ACCESS_KEY_ID=e2e -e AWS_SECRET_ACCESS_KEY=e2esecret -e AWS_REGION=us-east-1 \
    "$REST_IMAGE" >/dev/null

docker run --rm --entrypoint cat "$IMAGE" "$FE_CONF/fe.conf" > "$WORK/fe.conf"
printf '\naccess_control = ranger\narrow_flight_port = %s\n' "$FE_FLIGHT_PORT" >> "$WORK/fe.conf"
# Arrow needs java.nio opened; the official fe.conf does not, so Flight SQL fails without it.
sed -i.bak 's#^JAVA_OPTS="#JAVA_OPTS="--add-opens=java.base/java.nio=ALL-UNNAMED #' "$WORK/fe.conf"
docker run --rm --entrypoint cat "$IMAGE" "$BE_CONF/be.conf" > "$WORK/be.conf"
printf '\narrow_flight_port = %s\n' "$BE_FLIGHT_PORT" >> "$WORK/be.conf"
docker run -d --name "$NAME-sr" --network "$NET" -p "$SR_PORT:9030" -p "$SR_HTTP_PORT:8030" \
    -p "$FE_FLIGHT_PORT:$FE_FLIGHT_PORT" -p "$BE_FLIGHT_PORT:$BE_FLIGHT_PORT" \
    --add-host host.docker.internal:host-gateway \
    -v "$WORK/fe.conf:$FE_CONF/fe.conf" -v "$WORK/be.conf:$BE_CONF/be.conf" \
    -v "$HERE/ranger-starrocks-security.xml:$FE_CONF/ranger-starrocks-security.xml:ro" \
    -v "$HERE/ranger-starrocks-audit.xml:$FE_CONF/ranger-starrocks-audit.xml:ro" \
    "$IMAGE" >/dev/null

root() { docker exec -i "$NAME-sr" mysql -h127.0.0.1 -P9030 -uroot "$@"; }

echo "waiting for StarRocks ($IMAGE)"
for _ in $(seq 1 90); do
    if root -e 'SHOW BACKENDS\G' 2>/dev/null | grep -q 'Alive: true'; then break; fi
    if docker ps -a --filter "name=$NAME-sr" --format '{{.Status}}' | grep -q Exited; then
        docker logs "$NAME-sr" 2>&1 | tail -20
        exit 1
    fi
    sleep 5
done
root -N -e 'SELECT current_version()'

"$PY" -I - "$S3_PORT" <<'EOF'
import sys, boto3
s3 = boto3.client("s3", endpoint_url=f"http://127.0.0.1:{sys.argv[1]}", aws_access_key_id="e2e",
                  aws_secret_access_key="e2esecret", region_name="us-east-1")
s3.create_bucket(Bucket="warehouse")
EOF

root <<'EOF'
CREATE DATABASE demo;
CREATE TABLE demo.customers (id BIGINT, phone VARCHAR(64), grade VARCHAR(16))
    DUPLICATE KEY(id) DISTRIBUTED BY HASH(id) BUCKETS 1 PROPERTIES ('replication_num' = '1');
INSERT INTO demo.customers VALUES (1, '010-1111-2222', 'A'), (2, '010-3333-4444', 'A'), (3, '010-5555-6666', 'B');
CREATE EXTERNAL CATALOG ice PROPERTIES (
    "type" = "iceberg", "iceberg.catalog.type" = "rest", "iceberg.catalog.uri" = "http://iceberg-rest:8181",
    "aws.s3.endpoint" = "http://s3:9000", "aws.s3.enable_path_style_access" = "true",
    "aws.s3.access_key" = "e2e", "aws.s3.secret_key" = "e2esecret", "aws.s3.region" = "us-east-1");
CREATE DATABASE ice.sales;
CREATE TABLE ice.sales.orders (id BIGINT, region STRING, email STRING);
INSERT INTO ice.sales.orders VALUES (1, 'us', 'a@x.io'), (2, 'eu', 'b@x.io'), (3, 'us', 'c@x.io'), (4, 'eu', 'd@x.io');
CREATE USER alice IDENTIFIED BY 'alicepw';
CREATE USER bob IDENTIFIED BY 'bobpw';
CREATE USER eve IDENTIFIED BY 'evepw';
CREATE USER svc IDENTIFIED BY 'svcpw';
CREATE USER mallory IDENTIFIED BY 'mallorypw';
CREATE USER tina IDENTIFIED BY 'tinapw';
EOF

# The AuditLoader plugin, when the image ships it (egret's images do, the official ones do not): the
# table egret creates on every engine, a loader user with INSERT on it only, a 5 second batch.
if docker exec "$NAME-sr" test -f /opt/egret/auditloader.zip; then
    root < "$HERE/audit-table.sql"
    root -e "CREATE USER egret_audit IDENTIFIED BY 'auditpw'"
    root -e 'INSTALL PLUGIN FROM "/opt/egret/auditloader.zip" PROPERTIES ("user" = "egret_audit", "password" = "auditpw", "max_batch_interval_sec" = "5", "frontend_host_port" = "127.0.0.1:8030")'
    root -e 'SHOW PLUGINS\G' | grep -E 'Name: AuditLoader|Status' | head -4
    # StarRocks hands audit events only to the audit plugins it knew at its last refresh, once a minute
    # (AuditEventProcessor.UPDATE_PLUGIN_INTERVAL_MS): wait until a probe statement reaches the table.
    echo "waiting for the AuditLoader to receive events"
    for _ in $(seq 1 60); do
        root -N -e "SELECT 'egret-audit-probe'" >/dev/null
        n=$(root -N -e "SELECT count(*) FROM starrocks_audit_db__.starrocks_audit_tbl__ WHERE stmt LIKE '%egret-audit-probe%' AND \`user\` = 'root' AND stmt NOT LIKE '%starrocks_audit_tbl__%'")
        if [ "$n" != 0 ]; then
            echo "AuditLoader is loading"
            break
        fi
        sleep 2
    done
else
    echo "this image ships no AuditLoader: the audit checks will fail"
fi

echo "waiting for the Ranger plugin to load the policies"
for _ in $(seq 1 30); do
    grep -q 'lastKnownVersion=1' "$WORK/ranger.log" 2>/dev/null && break
    sleep 2
done
grep -q 'lastKnownVersion=1' "$WORK/ranger.log" || { echo "plugin never loaded policy version 1" >&2; exit 1; }
# A service whose definition carries a TagEnricher makes the plugin fetch the tags on its own poll.
echo "waiting for the Ranger plugin to download the tags"
for _ in $(seq 1 30); do
    grep -q '/tags/' "$WORK/ranger.log" 2>/dev/null && break
    sleep 2
done
if grep -q '/tags/' "$WORK/ranger.log"; then
    echo "tag downloads: $(grep -c '/tags/' "$WORK/ranger.log") ($(grep '/tags/' "$WORK/ranger.log" | head -1))"
else
    echo "the plugin never requested the tags"
fi

status=0
echo "checks start $(date -u +%T)"
"$PY" -I "$HERE/checks.py" "$SR_PORT" "$SR_HTTP_PORT" "$FE_FLIGHT_PORT" || status=1
echo "audit checks start $(date -u +%T)"
if ! "$PY" -I "$HERE/audit_checks.py" "$SR_PORT"; then
    status=1
    echo "--- fe.log, AuditLoader and stream load lines"
    docker exec "$NAME-sr" sh -c 'grep -i -E "audit|stream.?load|plugin" /data/deploy/starrocks/fe/log/fe.log /data/deploy/starrocks/fe/log/fe.warn.log | tail -60' || true
    echo "--- be.INFO, stream load lines"
    docker exec "$NAME-sr" sh -c 'grep -i -E "stream.?load|starrocks_audit" /data/deploy/starrocks/be/log/be.INFO | tail -30' || true
    root -e "SELECT \`timestamp\`, queryType, \`user\`, state, command, querySource, left(stmt, 90) FROM starrocks_audit_db__.starrocks_audit_tbl__ ORDER BY \`timestamp\`" || true
    echo "--- fe.audit.log tail"
    docker exec "$NAME-sr" sh -c 'tail -5 /data/deploy/starrocks/fe/log/fe.audit.log | cut -c1-200; wc -l /data/deploy/starrocks/fe/log/fe.audit.log' || true
    root -e 'SHOW PLUGINS\G' || true
fi
exit $status
