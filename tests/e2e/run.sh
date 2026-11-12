#!/usr/bin/env bash
# Run the security checks against a StarRocks allin1 image with access_control = ranger.
#
#   tests/e2e/run.sh <allin1-image>
#
# Starts, on a private docker network: RustFS (S3), an Iceberg REST catalog, the StarRocks image
# and, on the host, a fake Ranger Admin serving policies.py's policies. KEEP=1 leaves it all running.
# The start-up steps are the functions of stack.sh.
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

# shellcheck source=stack.sh
. "$HERE/stack.sh"
trap stack_cleanup EXIT

stack_venv
PY=$HERE/.venv/bin/python

stack_fake_ranger
stack_network
stack_rustfs
stack_iceberg_rest
stack_conf
stack_starrocks
stack_wait_starrocks
stack_bucket
stack_seed
stack_auditloader
stack_wait_policies
stack_wait_tags

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
