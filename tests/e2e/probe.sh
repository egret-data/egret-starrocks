#!/usr/bin/env bash
# Probe the paths nobody has measured against a StarRocks allin1 image with access_control = ranger.
#
#   tests/e2e/probe.sh <allin1-image>
#
# Unlike run.sh this is not a gate: every check prints a verdict (ENFORCED, LEAK, BLIND, N/A, SKIP, ERROR,
# see probe_lib.py). The run fails only on BLIND (a check that cannot see) or ERROR (a check that broke).
#
#   PROBE_SKIP=<names>  comma list of probes to leave out: udf python-udf hive jdbc paimon stream-load
#                       routine-load in-namespace (an unknown name stops the run with exit 2)
#   BE_HTTP_AUTH=1      mitigation variant: enable_http_auth = true in be.conf
#   UDF_JAVA_POLICY=1   mitigation variant: the BE's JVM runs with a security policy that grants nothing
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
# Used by later tasks: the UDF jar build and the in-namespace container.
JDK_IMAGE=eclipse-temurin:17.0.16_8-jdk@sha256:06ee07a59dc7011f643baaa45889ecd15a0b9176490943b0e4379630e832ac2d
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

# Probe users: udfdev and loader get their policies from policies.py --probe; nat gets a native GRANT (probe 3).
POLICY_ARGS=(--probe)
SR_RUN_ARGS=(-p "$BE_HTTP_PORT:8040")
if [ "${UDF_JAVA_POLICY:-0}" = 1 ]; then
    SR_RUN_ARGS+=(-v "$HERE/udf/deny-all.policy:/opt/egret-probe/deny-all.policy:ro")
fi

mkdir -p "$WORK/canary-files"
CANARY_LOG=$WORK/canary.log
: > "$CANARY_LOG"
"$PY" -I "$HERE/canary.py" "$WORK/canary-files" "$CANARY_PORT" "$CANARY_LOG" &
CANARY_PID=$!

stack_fake_ranger
stack_network
stack_rustfs
stack_iceberg_rest

start_postgres() {
    docker run -d --name "$NAME-pg" --network "$NET" --network-alias pg \
        -e POSTGRES_PASSWORD=pgsecret -e POSTGRES_DB=sales "$PG_IMAGE" >/dev/null
    for _ in $(seq 1 30); do
        docker exec "$NAME-pg" pg_isready -U postgres -d sales >/dev/null 2>&1 && return 0
        sleep 2
    done
    echo "Postgres never became ready" >&2
    return 1
}

start_hive_metastore() {
    docker run -d --name "$NAME-hms" --network "$NET" --network-alias hive-metastore \
        -e SERVICE_NAME=metastore -e DB_DRIVER=derby "$HIVE_IMAGE" >/dev/null
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
# The mitigation variants edit the conf the container is about to read.
if [ "${BE_HTTP_AUTH:-0}" = 1 ]; then
    printf 'enable_http_auth = true\n' >> "$WORK/be.conf"
fi
if [ "${UDF_JAVA_POLICY:-0}" = 1 ]; then
    sed -i.bak 's#^JAVA_OPTS="#JAVA_OPTS="-Djava.security.policy=/opt/egret-probe/deny-all.policy #' "$WORK/be.conf"
    grep -q 'java.security.policy' "$WORK/be.conf" || { echo "UDF_JAVA_POLICY=1: be.conf has no JAVA_OPTS line to edit" >&2; exit 1; }
fi
stack_starrocks
stack_wait_starrocks
stack_bucket
stack_seed
for u in udfdev loader nat; do
    root -e "CREATE USER $u IDENTIFIED BY '${u}pw'"
done
stack_auditloader
stack_wait_policies
stack_wait_tags

# Each probe's seed: later tasks fill these in (udf: task 2; catalogs: tasks 3 and 4; loads: task 5).
seed_udf() { :; }
seed_catalogs() { :; }
seed_loads() { :; }
seed_in_namespace() { :; }
seed_udf
seed_catalogs
seed_loads
seed_in_namespace

# The probe files, in order. A file that a later task has not written yet is named, not silently passed over.
status=0
: > "$WORK/probe.out"
for f in udf_checks catalog_checks load_checks inns_checks; do
    if [ ! -f "$HERE/$f.py" ]; then
        echo "not written yet: $f.py" | tee -a "$WORK/probe.out"
        continue
    fi
    echo "$f start $(date -u +%T)"
    "$PY" -I "$HERE/$f.py" "$SR_PORT" "$SR_HTTP_PORT" "$FE_FLIGHT_PORT" "$BE_HTTP_PORT" "$CANARY_LOG" 2>&1 | tee -a "$WORK/probe.out" || status=1
done

echo
echo "combined verdicts"
for v in ENFORCED LEAK BLIND N/A SKIP ERROR; do
    printf '%s %s  ' "$v" "$(grep -c -E "^$v  \[probe:" "$WORK/probe.out" || true)"
done
echo
if grep -q -E '^(BLIND|ERROR)  \[probe:' "$WORK/probe.out"; then status=1; fi
exit $status
