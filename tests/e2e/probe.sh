#!/usr/bin/env bash
# Probe the paths nobody has measured against a StarRocks allin1 image with access_control = ranger.
#
#   tests/e2e/probe.sh <allin1-image>
#
# Unlike run.sh this is not a gate: every check prints a verdict (ENFORCED, LEAK, BLIND, N/A, SKIP, ERROR,
# see probe_lib.py). The run fails only on BLIND (a check that cannot see) or ERROR (a check that broke).
#
#   PROBE_SKIP=<names>  comma list of probes to leave out: hive jdbc paimon stream-load routine-load
#                       in-namespace (an unknown name stops the run with exit 2)
#   BE_HTTP_AUTH=1      mitigation variant: enable_http_auth = true in be.conf
#   KEEP=1              leave the containers, the canary and the fake Ranger running, as run.sh does
#
# It and run.sh must not run at the same time: both use the fake Ranger port 18777 that
# ranger-starrocks-security.xml names.
set -euo pipefail
IMAGE=${1:?usage: probe.sh <allin1-image>}
HERE=$(cd "$(dirname "$0")" && pwd)
SR_PORT=19230
SR_HTTP_PORT=19231
BE_HTTP_PORT=19240
FE_FLIGHT_PORT=19508
BE_FLIGHT_PORT=19519
S3_PORT=19200
RANGER_PORT=18777
CANARY_PORT=18778
NAME=egs-probe
WORK=$(mktemp -d)
NET=$NAME-net
REST_IMAGE=apache/iceberg-rest-fixture:1.10.1
S3_IMAGE=rustfs/rustfs:1.0.1
# Optional services, pinned by tag and digest (docker buildx imagetools inspect, 2026-11-12).
PG_IMAGE=postgres:17.6@sha256:00bc86618629af00d2937fdc5a5d63db3ff8450acf52f0636ec813c7f4902929
HIVE_IMAGE=apache/hive:4.0.1@sha256:5194161ef50b80875f937dff04936df047cbe894e9727ab8f0606349345b1bd3
KAFKA_IMAGE=apache/kafka:3.9.1@sha256:4ceccc577f03f51f6af8dbfda55194d0d892f4fa7913ffbded567ce3895622ed
# Used by a later task: the in-namespace container.
PYTHON_IMAGE=python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b
FE_CONF=/data/deploy/starrocks/fe/conf
BE_CONF=/data/deploy/starrocks/be/conf
RANGER_PID=
CANARY_PID=

# shellcheck source=stack.sh
. "$HERE/stack.sh"
STACK_CONTAINERS+=("$NAME-pg" "$NAME-hms" "$NAME-kafka")

probe_cleanup() {
    if [ "${KEEP:-0}" != 1 ] && [ -n "$CANARY_PID" ]; then
        kill "$CANARY_PID" 2>/dev/null || true
    fi
    stack_cleanup
    [ "${KEEP:-0}" = 1 ] && echo "KEEP=1: canary pid ${CANARY_PID:-none} on port $CANARY_PORT"
    return 0
}
trap probe_cleanup EXIT

stack_venv
PY=$HERE/.venv/bin/python

# PROBE_SKIP, validated before anything starts (exit 2 on an unknown name).
export PROBE_SKIP=${PROBE_SKIP:-}
SKIPPED=" $("$PY" -I -c 'import os, sys
sys.path.insert(0, sys.argv[1])
import probe_lib
print(" ".join(sorted(p.value for p in probe_lib.skipped_probes(os.environ["PROBE_SKIP"]))))' "$HERE" || exit 2) "
skipped() { case "$SKIPPED" in *" $1 "*) return 0 ;; esac; return 1; }
for p in $SKIPPED; do echo "SKIP requested: $p (PROBE_SKIP)"; done

# Probe users: loader gets its policies from policies.py --probe; nat gets a native GRANT (probe 3).
POLICY_ARGS=(--probe)
SR_RUN_ARGS=(-p "$BE_HTTP_PORT:8040")

# One id per run, set before any seed: the seeds and the checks name their markers with it.
RUN_ID=$(date +%s)

mkdir -p "$WORK/canary-files"
CANARY_LOG=$WORK/canary.log
: > "$CANARY_LOG"
"$PY" -I "$HERE/canary.py" "$WORK/canary-files" "$CANARY_PORT" "$CANARY_LOG" &
CANARY_PID=$!
# The canary must be live, or every egress check would read "no hit" as enforced: a hard failure, not a skip.
# The checks' sight controls prove it again from inside the StarRocks container.
CANARY_LIVE=canary-live-$RUN_ID
for _ in $(seq 1 20); do
    curl -s -o /dev/null "http://127.0.0.1:$CANARY_PORT/$CANARY_LIVE" 2>/dev/null && break
    sleep 0.5
done
if ! grep -q "^/$CANARY_LIVE " "$CANARY_LOG"; then
    echo "the canary on port $CANARY_PORT never logged /$CANARY_LIVE" >&2
    exit 1
fi
echo "canary live on port $CANARY_PORT"

stack_fake_ranger
stack_network
stack_rustfs
stack_iceberg_rest

start_postgres() {
    docker run -d --name "$NAME-pg" --network "$NET" --network-alias pg \
        -e POSTGRES_PASSWORD=pgsecret -e POSTGRES_DB=sales "$PG_IMAGE" >/dev/null
    for _ in $(seq 1 30); do
        # Over TCP: the image's init server listens on the socket only, and restarts before it is ready.
        docker exec "$NAME-pg" pg_isready -h 127.0.0.1 -U postgres -d sales >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "Postgres never became ready" >&2
    return 1
}

# The stock image cannot create an s3:// location ("Failed to create external path s3://..."): hive-conf/ adds
# the S3A settings for RustFS, and HADOOP_OPTIONAL_TOOLS puts the hadoop-aws jars the image already ships on the
# classpath, so no image is built.
start_hive_metastore() {
    docker run -d --name "$NAME-hms" --network "$NET" --network-alias hive-metastore \
        -e SERVICE_NAME=metastore -e DB_DRIVER=derby -e HADOOP_OPTIONAL_TOOLS=hadoop-aws \
        -e HIVE_CUSTOM_CONF_DIR=/opt/egret-probe/hive-conf -v "$HERE/hive-conf:/opt/egret-probe/hive-conf:ro" \
        "$HIVE_IMAGE" >/dev/null
}

# The metastore initialises its Derby schema before it listens: wait for its thrift port (the image has bash,
# no nc or curl). Called by seed_hive, so the schema init overlaps the StarRocks start-up.
wait_hive_metastore() {
    for _ in $(seq 1 60); do
        docker exec "$NAME-hms" bash -c 'exec 3<>/dev/tcp/127.0.0.1/9083' 2>/dev/null && return 0
        if docker ps -a --filter "name=$NAME-hms" --format '{{.Status}}' | grep -q Exited; then break; fi
        sleep 2
    done
    docker logs "$NAME-hms" 2>&1 | tail -20
    echo "the Hive Metastore never listened on 9083" >&2
    return 1
}

# Kafka in KRaft mode with a PLAINTEXT listener (9092) and a SASL_PLAINTEXT one (9093, PLAIN, user probe).
start_kafka() {
    docker run -d --name "$NAME-kafka" --network "$NET" --network-alias kafka \
        -e KAFKA_NODE_ID=1 -e KAFKA_PROCESS_ROLES=broker,controller \
        -e KAFKA_LISTENERS=PLAINTEXT://:9092,SASL_PLAINTEXT://:9093,CONTROLLER://:9094 \
        -e KAFKA_ADVERTISED_LISTENERS=PLAINTEXT://kafka:9092,SASL_PLAINTEXT://kafka:9093 \
        -e KAFKA_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT,SASL_PLAINTEXT:SASL_PLAINTEXT \
        -e KAFKA_CONTROLLER_QUORUM_VOTERS=1@localhost:9094 -e KAFKA_CONTROLLER_LISTENER_NAMES=CONTROLLER \
        -e KAFKA_INTER_BROKER_LISTENER_NAME=PLAINTEXT -e KAFKA_SASL_ENABLED_MECHANISMS=PLAIN \
        -e 'KAFKA_LISTENER_NAME_SASL__PLAINTEXT_PLAIN_SASL_JAAS_CONFIG=org.apache.kafka.common.security.plain.PlainLoginModule required user_probe="probepw";' \
        -e KAFKA_OFFSETS_TOPIC_REPLICATION_FACTOR=1 -e KAFKA_TRANSACTION_STATE_LOG_REPLICATION_FACTOR=1 \
        -e KAFKA_TRANSACTION_STATE_LOG_MIN_ISR=1 "$KAFKA_IMAGE" >/dev/null
}

# A service starts only when a probe that needs it is not skipped. A missing service is an ERROR, not a skip.
if ! skipped jdbc; then start_postgres; fi
if ! skipped hive; then start_hive_metastore; fi
if ! skipped routine-load; then start_kafka; fi

stack_conf
# The metastore's first S3A call (class loading) outlasts the FE's 10 s metastore timeout: the FE retries, the
# retry fails on the duplicate and rolls the first call's directory back. Not mutable at run time, so fe.conf.
if ! skipped hive; then
    printf 'hive_meta_store_timeout_s = 60\n' >> "$WORK/fe.conf"
fi
# The mitigation variants edit the conf the container is about to read.
if [ "${BE_HTTP_AUTH:-0}" = 1 ]; then
    printf 'enable_http_auth = true\n' >> "$WORK/be.conf"
fi
stack_starrocks
stack_wait_starrocks
stack_bucket
stack_seed
for u in loader nat; do
    root -e "CREATE USER $u IDENTIFIED BY '${u}pw'"
done
stack_auditloader
stack_wait_policies
stack_wait_tags

# The PostgreSQL JDBC driver, from Maven Central, pinned by version and sha256 (its sha1 matches the .sha1
# Maven Central publishes). The canary serves it: the FE and the BE fetch driver_url themselves.
PG_DRIVER=postgresql-42.7.8.jar
PG_DRIVER_URL=https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.8/$PG_DRIVER
PG_DRIVER_SHA256=2a32a9dcbc42d67a50ad3a0de5efd102c8d2be46720045f2cbd6689f160ab7c7

# Postgres holds sales.orders (a schema is a database of a StarRocks JDBC catalog), the rows of ORDERS_ALL in
# checks.py. The catalog is created as root, with the keys egret's renderer writes, on one line: C15 finds the
# statement in the audit trail by its text.
seed_jdbc() {
    curl -sfL -o "$WORK/canary-files/$PG_DRIVER" "$PG_DRIVER_URL"
    echo "$PG_DRIVER_SHA256  $WORK/canary-files/$PG_DRIVER" | shasum -a 256 -c - >/dev/null \
        || { echo "$PG_DRIVER: sha256 mismatch" >&2; exit 1; }
    docker exec -i "$NAME-pg" psql -q -U postgres -d sales -v ON_ERROR_STOP=1 <<'SQL'
CREATE SCHEMA sales;
CREATE TABLE sales.orders (id BIGINT, region TEXT, email TEXT);
INSERT INTO sales.orders VALUES (1, 'us', 'a@x.io'), (2, 'eu', 'b@x.io'), (3, 'us', 'c@x.io'), (4, 'eu', 'd@x.io');
SQL
    root -e "CREATE EXTERNAL CATALOG jdbc PROPERTIES (\"type\" = \"jdbc\", \"user\" = \"postgres\", \"password\" = \"pgsecret\", \"jdbc_uri\" = \"jdbc:postgresql://pg:5432/sales\", \"driver_url\" = \"http://host.docker.internal:$CANARY_PORT/files/$PG_DRIVER\", \"driver_class\" = \"org.postgresql.Driver\")"
    root -N -e 'SELECT count(*) FROM jdbc.sales.orders' | grep -qx 4 || { echo "jdbc.sales.orders: not 4 rows" >&2; exit 1; }
    echo "seeded jdbc.sales.orders"
}

# The Hive catalog holds the RustFS keys; the table is created and filled through it, as root, partitioned by
# region (StarRocks puts partition columns last: id, email, region). Its CREATE is one line, as jdbc's.
seed_hive() {
    wait_hive_metastore
    root -e "CREATE EXTERNAL CATALOG hive PROPERTIES (\"type\" = \"hive\", \"hive.metastore.uris\" = \"thrift://hive-metastore:9083\", \"aws.s3.endpoint\" = \"http://s3:9000\", \"aws.s3.enable_path_style_access\" = \"true\", \"aws.s3.access_key\" = \"e2e\", \"aws.s3.secret_key\" = \"e2esecret\", \"aws.s3.region\" = \"us-east-1\")"
    root <<'SQL'
CREATE DATABASE hive.sales PROPERTIES ("location" = "s3://warehouse/hive/sales");
CREATE TABLE hive.sales.orders (id BIGINT, email STRING, region STRING) PARTITION BY (region);
INSERT INTO hive.sales.orders VALUES (1, 'a@x.io', 'us'), (2, 'b@x.io', 'eu'), (3, 'c@x.io', 'us'), (4, 'd@x.io', 'eu');
SQL
    root -N -e 'SELECT count(*) FROM hive.sales.orders' | grep -qx 4 || { echo "hive.sales.orders: not 4 rows" >&2; exit 1; }
    echo "seeded hive.sales.orders"
}

# StarRocks 4.1.7 cannot create a Paimon table, so pypaimon (requirements-paimon.txt) writes sales.orders into the
# filesystem warehouse on RustFS from the host: the rows of ORDERS_ALL in one commit, (id, region, email)
# partitioned by region. The catalog then reads it with the RustFS keys; its CREATE is one line, as jdbc's.
seed_paimon() {
    "$PY" -I - "$S3_PORT" <<'EOF'
import sys
import pyarrow as pa
from pypaimon import CatalogFactory, Schema
catalog = CatalogFactory.create({
    "warehouse": "s3://warehouse/paimon/", "s3.endpoint": f"http://127.0.0.1:{sys.argv[1]}",
    "s3.access-key": "e2e", "s3.secret-key": "e2esecret", "s3.region": "us-east-1", "s3.path-style-access": "true"})
catalog.create_database("sales", False)
schema = pa.schema([("id", pa.int64()), ("region", pa.string()), ("email", pa.string())])
catalog.create_table("sales.orders", Schema.from_pyarrow_schema(schema, partition_keys=["region"]), False)
builder = catalog.get_table("sales.orders").new_batch_write_builder()
write, commit = builder.new_write(), builder.new_commit()
write.write_arrow(pa.Table.from_pylist([
    {"id": 1, "region": "us", "email": "a@x.io"}, {"id": 2, "region": "eu", "email": "b@x.io"},
    {"id": 3, "region": "us", "email": "c@x.io"}, {"id": 4, "region": "eu", "email": "d@x.io"}], schema=schema))
commit.commit(write.prepare_commit())
write.close()
commit.close()
EOF
    root -e "CREATE EXTERNAL CATALOG paimon PROPERTIES (\"type\" = \"paimon\", \"paimon.catalog.type\" = \"filesystem\", \"paimon.catalog.warehouse\" = \"s3://warehouse/paimon/\", \"aws.s3.endpoint\" = \"http://s3:9000\", \"aws.s3.enable_path_style_access\" = \"true\", \"aws.s3.access_key\" = \"e2e\", \"aws.s3.secret_key\" = \"e2esecret\", \"aws.s3.region\" = \"us-east-1\")"
    root -N -e 'SELECT count(*) FROM paimon.sales.orders' | grep -qx 4 || { echo "paimon.sales.orders: not 4 rows" >&2; exit 1; }
    echo "seeded paimon.sales.orders"
}

# Each probe's seed: later tasks fill these in (loads: task 5).
seed_catalogs() {
    if ! skipped jdbc; then seed_jdbc; fi
    if ! skipped hive; then seed_hive; fi
    if ! skipped paimon; then seed_paimon; fi
}
seed_loads() { :; }
seed_in_namespace() { :; }
seed_catalogs
seed_loads
seed_in_namespace

# The probe files, in order catalogs, loads, in-namespace. A group whose probes are all in PROBE_SKIP is
# not run; a missing file of a group that is run is an ERROR line (the summary counts it) and fails the run.
status=0
: > "$WORK/probe.out"

# in-namespace runs INSIDE a throwaway container on the probe network, with no credentials: Task 6 extends
# the arguments after <run_id> (the FE and BE ports, the canary) and its own checks.
inns_phase() {
    docker run --rm --network "$NET" -v "$HERE:/e2e:ro" "$PYTHON_IMAGE" \
        python -I /e2e/inns_checks.py "$NAME-sr" "$RUN_ID"
}

# run_group <file> <runner: host|inns> <probe names of the group...>
# A host probe file gets: <mysql port> <http port> <flight port> <be http port> <canary log> <run_id>.
run_group() {
    local file=$1 runner=$2 first="" p
    shift 2
    for p in "$@"; do
        if ! skipped "$p"; then first=$p; break; fi
    done
    [ -n "$first" ] || return 0
    if [ ! -f "$HERE/$file" ]; then
        echo "ERROR  [probe:$first]  $file probe file missing" | tee -a "$WORK/probe.out"
        status=1
        return 0
    fi
    echo "$file start $(date -u +%T)"
    if [ "$runner" = inns ]; then
        inns_phase 2>&1 | tee -a "$WORK/probe.out" || status=1
    else
        AUDITLOADER_LOADING=${AUDITLOADER_LOADING:-0} "$PY" -I "$HERE/$file" "$SR_PORT" "$SR_HTTP_PORT" "$FE_FLIGHT_PORT" "$BE_HTTP_PORT" "$CANARY_LOG" "$RUN_ID" 2>&1 \
            | tee -a "$WORK/probe.out" || status=1
    fi
}
run_group probe_catalogs.py host hive jdbc paimon
run_group probe_loads.py host stream-load routine-load
run_group inns_checks.py inns in-namespace

echo
echo "combined verdicts"
for v in ENFORCED LEAK BLIND N/A SKIP ERROR; do
    printf '%s %s  ' "$v" "$(grep -c -E "^$v  \[probe:" "$WORK/probe.out" || true)"
done
echo
if grep -q -E '^(BLIND|ERROR)  \[probe:' "$WORK/probe.out"; then status=1; fi
exit $status
