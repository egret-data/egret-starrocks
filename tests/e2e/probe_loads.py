"""Probe 3, stream load and routine load:
probe_loads.py <mysql port> <http port> <flight port> <be http port> <canary log> <run_id>

Environment (probe.sh): LOADS_PHASE=before|after, LOADS_STATE (a JSON file the two phases share),
NAT_GRANT_OUT (the outcome of root's GRANT INSERT ON demo.s_target TO nat), AUDITLOADER_LOADING.

probe.sh seeds demo.s_target and demo.r_target (duplicate key) and demo.pk_target (primary key, ids 1 to 3),
and policies.py --probe gives loader INSERT on the three and the row filter id = 1 on pk_target; eve has
nothing, bob SELECT only, nat a native GRANT and no Ranger policy. S1 to S11 and R1 to R8 follow the spec
(docs/en/specs/2026-11-09-starrocks-unmeasured-paths-probe-design.md, probe 3).

Phase "before" runs S1-S11, then R1-R6, R8, and records R7's state before the revoke; probe.sh then serves
policy version 2 without loader's INSERT and runs phase "after": R7 and its control R7-sql.

Every load carries a marker <check>-<run_id> in its v column, so a row count belongs to one check only.
"""
import base64
import functools
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I does not put the script's directory on the path
import sqlpaths  # noqa: E402
from probe_lib import DENIED_CODES, Probe, ProbeCheck, run_checks, skipped_probes  # noqa: E402
from sqlpaths import DENIED, PASSWORDS, text  # noqa: E402

sqlpaths.configure(sys.argv[1], sys.argv[2], sys.argv[3])
FE_HTTP_PORT = int(sys.argv[2])
BE_HTTP_PORT = int(sys.argv[4])
RUN_ID = sys.argv[6]
PHASE = os.environ.get("LOADS_PHASE", "before")
STATE_FILE = os.environ.get("LOADS_STATE", "")
NAT_GRANT_OUT = os.environ.get("NAT_GRANT_OUT", "")
AUDITLOADER_LOADING = os.environ.get("AUDITLOADER_LOADING") == "1"
SR_CONTAINER = "egs-probe-sr"        # probe.sh's $NAME-sr
KAFKA_CONTAINER = "egs-probe-kafka"  # probe.sh's $NAME-kafka
KAFKA_PRODUCER = "/opt/kafka/bin/kafka-console-producer.sh"  # in the pinned apache/kafka:3.9.1 image
TOPIC = "probe-r"
KAFKA_SECRET = "kafkasecret"
FE_AUDIT_LOG = "/data/deploy/starrocks/fe/log/fe.audit.log"
AUDIT_TABLE = "starrocks_audit_db__.starrocks_audit_tbl__"
ROUTINE_WAIT_S = 60

S, R = Probe.STREAM_LOAD, Probe.ROUTINE_LOAD


def detail(check, value):
    """The whole of a result the verdict line cuts at 110 characters, for the report (not counted by probe.sh)."""
    print(f"  detail {check}: {value}")
    return value


def marker(check):
    return f"{check}-{RUN_ID}"


def is_failure(r):
    """A failed request (not a refusal): sqlpaths' "ERROR ..." strings other than probe_lib's DENIED codes."""
    return isinstance(r, str) and r.startswith("ERROR ") and not any(r.startswith(f"ERROR {n}") for n in DENIED_CODES)


def root_rows(sql):
    r = text("root", sql)
    if not isinstance(r, list):
        raise RuntimeError(f"root {sql!r}: {r}")
    return r


def count(table, where):
    return root_rows(f"SELECT count(*) FROM demo.{table} WHERE {where}")[0][0]


def marker_rows(table, check):
    return count(table, f"v LIKE '%{marker(check)}%'")


# ---------------------------------------------------------------------------------------------------------
# The stream load client.

REWRITES = []  # the FE redirects this run rewrote, printed once


def basic(user):
    return "Basic " + base64.b64encode(f"{user}:{PASSWORDS[user]}".encode()).decode()


def request(method, port, path, headers, body=b"", host="127.0.0.1"):
    conn = http.client.HTTPConnection(host, port, timeout=60)
    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read().decode(errors="replace")
    finally:
        conn.close()


def resolves(host):
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def be_target(location):
    """(host, port, path) of a BE URL. The BE registers an address that may not resolve from the host, or is the
    container's 127.0.0.1: either is rewritten to the published BE HTTP port, and the rewrite is recorded."""
    u = urllib.parse.urlsplit(location)
    path = u.path + (f"?{u.query}" if u.query else "")
    if u.hostname == "127.0.0.1" or not resolves(u.hostname):
        rewrite = f"{u.hostname}:{u.port} -> 127.0.0.1:{BE_HTTP_PORT}"
        if rewrite not in REWRITES:
            REWRITES.append(rewrite)
            print(f"rewritten: the BE address {rewrite}")
        return "127.0.0.1", BE_HTTP_PORT, path
    return u.hostname, u.port, path


def stream_load(user, table, rows, label, via="fe", extra=None):
    """PUT /api/demo/<table>/_stream_load as `user`, CSV id,v. via "fe": to the FE, following one 307 by hand;
    via "be": straight to the BE. Returns {"http": status, "json": the answer or None, "body": text, "via": ...}."""
    body = "".join(f"{i},{v}\n" for i, v in rows).encode()
    # The FE refuses a load without Expect: 100-continue ("There is no 100-continue header"); http.client sends
    # the body at once and skips an interim 100 answer.
    headers = {"Authorization": basic(user), "label": label, "column_separator": ",", "columns": "id,v",
               "Expect": "100-continue", "Content-Type": "text/plain", "Content-Length": str(len(body))}
    headers.update(extra or {})
    path = f"/api/demo/{table}/_stream_load"
    hops = []
    if via == "fe":
        status, h, text_ = request("PUT", FE_HTTP_PORT, path, headers, body)
        hops.append(status)
        if status == 307:
            location = h.get("Location") or h.get("location")
            host, port, path2 = be_target(location)
            status, h, text_ = request("PUT", port, path2, headers, body, host=host)
            hops.append(status)
    else:
        status, h, text_ = request("PUT", BE_HTTP_PORT, path, headers, body)
        hops.append(status)
    try:
        answer = json.loads(text_)
    except ValueError:
        answer = None
    return {"http": hops, "json": answer, "body": text_[:300], "via": via}


def load_denied(r):
    """The load was refused by a privilege or login check: `Access denied` in the answer's Message, or 401/403."""
    if r["http"][-1] in (401, 403):
        return True
    msg = (r["json"] or {}).get("Message", "") if isinstance(r["json"], dict) else ""
    return "Access denied" in msg or "Access denied" in r["body"]


def load_ok(r):
    j = r["json"]
    return isinstance(j, dict) and j.get("Status") in ("Success", "Publish Timeout")


def load_outcome(r):
    if load_denied(r):
        return "DENIED"
    if load_ok(r):
        return f"loaded ({r['json'].get('Status')}, {r['json'].get('NumberLoadedRows')} rows)"
    raise RuntimeError(f"stream load neither refused nor loaded: http {r['http']} {r['body']}")


def wait_count(fn, want, timeout):
    """Poll fn() until it reaches `want` or `timeout` seconds pass; return the last value."""
    deadline = time.time() + timeout
    n = fn()
    while n < want and time.time() < deadline:
        time.sleep(2)
        n = fn()
    return n


# ---------------------------------------------------------------------------------------------------------
# Stream load checks.

@functools.cache
def loader_load(check, via):
    """loader's control load (S4 via the FE, S5 directly to the BE): the answer and the marker rows after it."""
    r = stream_load("loader", "s_target", [(100, marker(check))], marker(check), via)
    return r, marker_rows("s_target", check)


def loader_sight(check, via):
    r, n = loader_load(check, via)
    return load_ok(r) and n == 1


def outsider_load(user, check, via):
    """A load by someone policies refuse: {"outcome": DENIED | loaded ..., "marker rows": n}. Not refused and not
    loaded (a Fail for another reason) raises: ERROR, not ENFORCED."""
    r = stream_load(user, "s_target", [(200, marker(check))], marker(check), via)
    rows = marker_rows("s_target", check)
    detail(check, f"{user} via {via}: http {r['http']} {' '.join(r['body'].split())[:300]}")
    if rows:
        return {"outcome": f"loaded (http {r['http']}, {(r['json'] or {}).get('Status')})", "marker rows": rows}
    return {"outcome": load_outcome(r), "marker rows": rows}


def outsider_leaked(r):
    return r["outcome"] != "DENIED" or r["marker rows"] > 0


def nat_grant():
    try:
        with open(NAT_GRANT_OUT) as f:
            return f.read().strip()
    except OSError as e:
        raise RuntimeError(f"NAT_GRANT_OUT: {e}")


def s6_na():
    out = nat_grant()
    if out != "OK":
        return f"root's GRANT INSERT ON demo.s_target TO nat was refused under access_control = ranger: {out}"
    return None


def s6_sight():
    # loader's SQL INSERT and her direct BE load go through: the paths work for someone the policies allow.
    sql = text("loader", f"INSERT INTO demo.s_target VALUES (300, '{marker('S6-sight')}')")
    return sql == [] and marker_rows("s_target", "S6-sight") == 1 and loader_sight("S5", "be")


def s6_actual():
    sql = text("nat", f"INSERT INTO demo.s_target VALUES (301, '{marker('S6-sql')}')")
    if is_failure(sql):
        return sql
    return detail("S6", {"grant": nat_grant(), "nat SQL INSERT": "DENIED" if sql == DENIED else "inserted",
                         "nat stream load (BE)": outsider_load("nat", "S6-load", "be"),
                         "marker rows (SQL)": marker_rows("s_target", "S6-sql")})


def s6_leaked(r):
    return (r["nat SQL INSERT"] != "DENIED" or r["marker rows (SQL)"] > 0
            or outsider_leaked(r["nat stream load (BE)"]))


def txn(user, action, label, table="s_target"):
    headers = {"Authorization": basic(user), "label": label, "db": "demo", "table": table,
               "Content-Length": "0"}
    status, _, body = request("POST", BE_HTTP_PORT, f"/api/transaction/{action}", headers)
    try:
        return status, json.loads(body)
    except ValueError:
        return status, {"raw": body[:300]}


def txn_ok(answer):
    return answer[0] == 200 and answer[1].get("Status") == "OK"


def s7_sight():
    label = marker("S7-sight")
    began = txn("loader", "begin", label)
    if txn_ok(began):
        txn("loader", "rollback", label)
    return txn_ok(began)


def s7_actual():
    label = marker("S7")
    status, answer = txn("eve", "begin", label)
    if status == 200 and answer.get("Status") == "OK":
        txn("root", "rollback", label)
        return {"eve begin": "OK", "answer": answer}
    msg = str(answer.get("Message", answer))
    if status in (401, 403) or "Access denied" in msg:
        return {"eve begin": "DENIED", "answer": msg[:160]}
    raise RuntimeError(f"eve's begin neither refused nor begun: http {status} {answer}")


# S8: loader's error log, fetched by eve and by no one.
@functools.cache
def s8_load():
    m = f"egret-errlog-{RUN_ID}"
    # strict_mode: without it a non-numeric id loads as NULL instead of being rejected into the error log.
    r = stream_load("loader", "s_target", [("x", m), (11, marker("S8"))], marker("S8"), "be",
                    extra={"max_filter_ratio": "1", "strict_mode": "true"})
    url = (r["json"] or {}).get("ErrorURL") if isinstance(r["json"], dict) else None
    return m, r, url


def fetch_error_log(user):
    _, r, url = s8_load()
    if not url:
        raise RuntimeError(f"loader's malformed load returned no ErrorURL: {r['body']}")
    host, port, path = be_target(url)
    headers = {"Authorization": basic(user)} if user else {}
    status, _, body = request("GET", port, path, headers, host=host)
    return status, body


def s8_sight():
    m, r, url = s8_load()
    if not (load_ok(r) and url):
        return False
    status, body = fetch_error_log("root")
    return status == 200 and m in body


def s8_actual(user):
    def go():
        m = s8_load()[0]
        status, body = fetch_error_log(user)
        detail(f"S8-{user or 'anon'}", f"ErrorURL {s8_load()[2]}: http {status}, marker in body: {m in body}")
        return {"http": status, "marker in body": m in body, "body": body[:80]}
    return go


# S9: loader's labels in the load listings.
S9_PATHS = {
    "SHOW LOAD": "SHOW LOAD FROM demo WHERE LABEL = '{label}'",
    "information_schema.loads": "SELECT label FROM information_schema.loads WHERE label = '{label}'",
}


@functools.cache
def s9_labels():
    """The labels of loader's loads: S4's stream load, and an INSERT with a label of its own."""
    ins = marker("S9-insert")
    r = text("loader", f"INSERT INTO demo.s_target WITH LABEL `{ins}` VALUES (400, '{ins}')")
    if r != []:
        raise RuntimeError(f"loader's labelled INSERT: {r}")
    loader_load("S4", "fe")
    return (marker("S4"), ins)


def listing(user, path, label):
    return text(user, S9_PATHS[path].format(label=label))


def names(r, label):
    return isinstance(r, list) and label in str(r)


def s9_visible_to_root():
    """{(path, label): bool}: what root sees. A path where root sees neither label cannot be judged."""
    return {(p, label): names(listing("root", p, label), label) for p in S9_PATHS for label in s9_labels()}


def s9_sight():
    seen = s9_visible_to_root()
    return all(any(seen[(p, label)] for label in s9_labels()) for p in S9_PATHS)


def s9_actual():
    seen = s9_visible_to_root()
    out = {}
    for (p, label), root_sees in seen.items():
        if not root_sees:
            out[f"{p} {label}"] = "root does not see it either"
            continue
        r = listing("eve", p, label)
        if is_failure(r):
            return r
        out[f"{p} {label}"] = "DENIED" if r == DENIED else ("visible" if names(r, label) else "invisible")
    return detail("S9", out)


def s9_leaked(r):
    return any(v == "visible" for v in r.values())


# S10: loader overwrites id = 2 of pk_target, a row her filter hides.
def pk_value(i):
    rows = root_rows(f"SELECT v FROM demo.pk_target WHERE id = {i}")
    return rows[0][0] if rows else None


def pk_reset():
    if text("root", "INSERT INTO demo.pk_target VALUES (2, 'seed-2')") != []:
        raise RuntimeError("root could not reset pk_target id = 2")
    return pk_value(2) == "seed-2"


def s10_sight():
    # The harness reads id = 2 as root, and loader's filter hides it from her (the policy is live).
    return pk_reset() and text("loader", "SELECT id FROM demo.pk_target") in ([(1,)], DENIED)


def s10_actual():
    sql = text("loader", "INSERT INTO demo.pk_target VALUES (2, 'over')")
    if is_failure(sql):
        return sql
    after_sql = pk_value(2)
    pk_reset()
    r = stream_load("loader", "pk_target", [(2, "over")], marker("S10"), "fe")
    outcome = load_outcome(r)
    after_load = pk_value(2)
    pk_reset()
    return detail("S10", {"SQL INSERT": "DENIED" if sql == DENIED else "accepted", "id 2 after SQL": after_sql,
                          "stream load": outcome, "id 2 after stream load": after_load})


def s10_leaked(r):
    """The two paths disagree (one overwrites the hidden row, the other does not)."""
    return (r["id 2 after SQL"] == "over") != (r["id 2 after stream load"] == "over")


# S11: one audit row per load (S4, S5), with user loader.
def audit_table_rows(where):
    r = text("root", f"SELECT `user`, stmt FROM {AUDIT_TABLE} WHERE {where}")
    if isinstance(r, str) and ((r.startswith("ERROR 5501") and "starrocks_audit_db__" in r)
                               or (r.startswith("ERROR 5502") and "starrocks_audit_tbl__" in r)):
        return None
    if not isinstance(r, list):
        raise RuntimeError(f"audit table: {r}")
    return r


def audit_log_lines(pattern):
    p = subprocess.run(["docker", "exec", SR_CONTAINER, "grep", "-F", pattern, FE_AUDIT_LOG],
                       capture_output=True, text=True, timeout=60)
    if p.returncode not in (0, 1):
        raise RuntimeError(f"grep {FE_AUDIT_LOG}: {p.stderr.strip()}")
    return [line for line in p.stdout.splitlines() if "starrocks_audit_tbl__" not in line]


def s11_na():
    if not AUDITLOADER_LOADING:
        return "this image loads no audit table (no AuditLoader): nothing for package A to read"
    return None


def s11_sight():
    # The loads happened, and the table receives loader's statements at all (her labelled INSERT of S9).
    if not (loader_sight("S4", "fe") and loader_sight("S5", "be")):
        return False
    ins = s9_labels()[1]
    for _ in range(15):
        rows = audit_table_rows(f"stmt LIKE '%{ins}%' AND `user` = 'loader'")
        if rows:
            return True
        time.sleep(2)
    return False


def s11_actual():
    time.sleep(6)  # one more AuditLoader batch (5 s)
    out = {}
    for check in ("S4", "S5"):
        # The load's own event: it names the label, and is loader's or not a SQL statement at all. The harness's
        # SQL that names the label (root's counts, eve's S9 listings) is left out; loader's SQL never names it.
        label = marker(check)
        rows = audit_table_rows(f"stmt LIKE '%{label}%' AND (`user` = 'loader' OR command NOT LIKE 'MySQL.%')")
        out[check] = [r[0] for r in rows]
        out[f"{check} fe.audit.log"] = len([line for line in audit_log_lines(label)
                                            if "User=loader|" in line or "|Stmt=" not in line])
    return detail("S11", out)


def s11_leaked(r):
    """An audit gap: a load without exactly one row naming loader."""
    return any(r[c] != ["loader"] for c in ("S4", "S5"))


# ---------------------------------------------------------------------------------------------------------
# Routine load checks.

def produce(check, n=3, start=1):
    lines = "".join(f"{1000 + start + i},{marker(check)}-{i}\n" for i in range(n))
    p = subprocess.run(["docker", "exec", "-i", KAFKA_CONTAINER, KAFKA_PRODUCER, "--bootstrap-server",
                        "kafka:9092", "--topic", TOPIC], input=lines, capture_output=True, text=True, timeout=120)
    if p.returncode != 0:
        raise RuntimeError(f"kafka-console-producer: {p.stderr.strip()[:200]}")


def routine_sql(job, broker, extra=""):
    # The job's prefix goes into v, so the rows of the two jobs (which read the same topic) stay apart.
    return (f"CREATE ROUTINE LOAD demo.{job} ON r_target COLUMNS TERMINATED BY ',', "
            f"COLUMNS (id, m, v = concat('{job}|', m)) "
            "PROPERTIES ('desired_concurrent_number' = '1', 'max_batch_interval' = '5') "
            f"FROM KAFKA ('kafka_broker_list' = '{broker}', 'kafka_topic' = '{TOPIC}', "
            f"'property.kafka_default_offsets' = 'OFFSET_BEGINNING'{extra})")


SASL = (", 'property.security.protocol' = 'SASL_PLAINTEXT', 'property.sasl.mechanism' = 'PLAIN', "
        f"'property.sasl.username' = 'probe', 'property.sasl.password' = '{KAFKA_SECRET}'")


def job_rows(job, check):
    return count("r_target", f"v LIKE '{job}|{marker(check)}-%'")


def job_state(job):
    """(State, ReasonOfStateChanged) from root's SHOW ROUTINE LOAD, or None when root sees no such job."""
    conn = sqlpaths.connect("root")
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(f"SHOW ALL ROUTINE LOAD FOR demo.{job}")
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        return None
    row = max(rows, key=lambda r: int(r["Id"]))  # the newest job of that name (SHOW ALL keeps stopped ones)
    return (str(row.get("State")), str(row.get("ReasonOfStateChanged") or "")[:200])


@functools.cache
def r3():
    """loader's PLAINTEXT job and its 3 rows: R3's control, and the sight of R1, R2 and R7."""
    created = text("loader", routine_sql("r_plain", "kafka:9092"))
    if created != []:
        return {"create": created, "rows": 0}
    produce("R3")
    return {"create": "OK", "rows": wait_count(lambda: job_rows("r_plain", "R3"), 3, ROUTINE_WAIT_S),
            "state": job_state("r_plain")}


@functools.cache
def r4():
    created = text("loader", routine_sql("r_sasl", "kafka:9093", SASL))
    if created != []:
        return {"create": created, "rows": 0}
    produce("R4")
    return {"create": "OK", "rows": wait_count(lambda: job_rows("r_sasl", "R4"), 3, ROUTINE_WAIT_S),
            "state": job_state("r_sasl")}


def r3_sight():
    return r3()["rows"] >= 3


def outsider_create(user, job):
    def go():
        r = text(user, routine_sql(job, "kafka:9092"))
        if r == []:
            text("root", f"STOP ROUTINE LOAD FOR demo.{job}")
            return "created"
        return r
    return go


R5_PATHS = {
    "SHOW ROUTINE LOAD": "SHOW ROUTINE LOAD FROM demo",
    "SHOW ALL ROUTINE LOAD": "SHOW ALL ROUTINE LOAD FROM demo",
    "information_schema.routine_load_jobs": "SELECT * FROM information_schema.routine_load_jobs WHERE DB_NAME = 'demo'",
}
JOBS = ("r_plain", "r_sasl")


def r5_root_sees():
    r3()
    r4()
    return all(all(j in str(text("root", sql)) for j in JOBS) for sql in R5_PATHS.values())


def r5_actual(user):
    def go():
        out = {}
        for name, sql in R5_PATHS.items():
            r = text(user, sql)
            if is_failure(r):
                return r
            out[name] = "DENIED" if r == DENIED else [j for j in JOBS if j in str(r)]
        return out
    return go


def r5_leaked(r):
    return any(v != "DENIED" and v for v in r.values())


def r6_sight():
    # StarRocks writes r_sasl's CREATE to fe.audit.log, and root's SHOW ROUTINE LOAD lists the job.
    r4()
    return bool(audit_log_lines("CREATE ROUTINE LOAD demo.r_sasl")) and "r_sasl" in str(
        text("root", R5_PATHS["SHOW ROUTINE LOAD"]))


def r6_actual():
    outputs = []
    for user in ("eve", "bob"):
        for sql in R5_PATHS.values():
            outputs.append(str(text(user, sql)))
    table = audit_table_rows(f"stmt LIKE '%{KAFKA_SECRET}%'")
    return detail("R6", {"eve/bob outputs": sum(KAFKA_SECRET in o for o in outputs),
            "audit table rows": "no audit table (no AuditLoader)" if table is None else len(table),
            "fe.audit.log lines": len(audit_log_lines(KAFKA_SECRET)),
            "root SHOW ROUTINE LOAD (recorded)": "clear" if KAFKA_SECRET in str(
                text("root", "SHOW ROUTINE LOAD FOR demo.r_sasl")) else "redacted or absent"})


def r6_leaked(r):
    n = r["audit table rows"]
    return r["eve/bob outputs"] > 0 or (isinstance(n, int) and n > 0) or r["fe.audit.log lines"] > 0


def wait_state(job, states, timeout=30):
    deadline = time.time() + timeout
    s = job_state(job)
    while (s is None or s[0] not in states) and time.time() < deadline:
        time.sleep(2)
        s = job_state(job)
    return s


def r8_sight():
    # loader may pause and resume her own job.
    r4()
    if text("loader", "PAUSE ROUTINE LOAD FOR demo.r_sasl") != []:
        return False
    paused = wait_state("r_sasl", ("PAUSED",))
    if text("loader", "RESUME ROUTINE LOAD FOR demo.r_sasl") != []:
        return False
    resumed = wait_state("r_sasl", ("RUNNING", "NEED_SCHEDULE"))
    return paused is not None and paused[0] == "PAUSED" and resumed is not None and resumed[0] != "PAUSED"


def r8_actual():
    out = {}
    for stmt in ("PAUSE", "STOP"):
        r = text("eve", f"{stmt} ROUTINE LOAD FOR demo.r_sasl")
        if is_failure(r):
            return r
        out[f"eve {stmt}"] = "DENIED" if r == DENIED else "accepted"
    out["r_sasl state"] = job_state("r_sasl")
    return detail("R8", out)


def r8_leaked(r):
    return r["eve PAUSE"] != "DENIED" or r["eve STOP"] != "DENIED" or (r["r_sasl state"] or ("",))[0] in (
        "PAUSED", "STOPPED")


# R7: before the revoke (phase "before") and after it (phase "after").
def r7_record():
    """Phase "before": the jobs' state and loader's SQL INSERT, kept for phase "after"."""
    sql = text("loader", f"INSERT INTO demo.r_target VALUES (500, '{marker('R7-sql-before')}')")
    state = {"r3 rows": r3()["rows"], "r_plain": job_state("r_plain"), "r_sasl": job_state("r_sasl"),
             "loader SQL INSERT before": "OK" if sql == [] else str(sql)}
    with open(STATE_FILE, "w") as f:
        json.dump(state, f)
    return detail("R7-pre", state)


def r7_before():
    with open(STATE_FILE) as f:
        return json.load(f)


def r7_sight():
    # R3's rows arrived before the revoke, and the job was running then: a job that had already stopped would
    # load nothing whatever the policy.
    b = r7_before()
    return b["r3 rows"] >= 3 and b["r_plain"] is not None and b["r_plain"][0] in ("RUNNING", "NEED_SCHEDULE")


@functools.cache
def r7_measure():
    produce("R7")
    time.sleep(ROUTINE_WAIT_S)
    return detail("R7", {"new rows": count("r_target", f"v LIKE '%|{marker('R7')}-%'"),
                         "r_plain": job_state("r_plain"), "r_sasl": job_state("r_sasl")})


def r7_leaked(r):
    return r["new rows"] > 0


def r7_sql_sight():
    return r7_before()["loader SQL INSERT before"] == "OK"


def r7_sql_actual():
    r7_measure()  # after R7's wait, so this INSERT is not counted as a routine-load row (its v has no "|")
    r = text("loader", f"INSERT INTO demo.r_target VALUES (501, '{marker('R7-sql')}')")
    if is_failure(r):
        return r
    return "DENIED" if r == DENIED else "inserted"


# ---------------------------------------------------------------------------------------------------------

def before_checks():
    def denied_not(r):
        return r != DENIED

    return [
        ProbeCheck("S1", S, "eve stream load via the FE", lambda: loader_sight("S4", "fe"),
                   lambda: outsider_load("eve", "S1", "fe"), outsider_leaked),
        ProbeCheck("S2", S, "eve stream load directly to the BE (H8)", lambda: loader_sight("S5", "be"),
                   lambda: outsider_load("eve", "S2", "be"), outsider_leaked),
        ProbeCheck("S3", S, "bob (SELECT only) stream load via the FE", lambda: loader_sight("S4", "fe"),
                   lambda: outsider_load("bob", "S3", "fe"), outsider_leaked),
        ProbeCheck("S4", S, "loader via the FE (control: rows loaded)", lambda: loader_sight("S4", "fe"),
                   lambda: loader_load("S4", "fe")[0]["json"], lambda r: False),
        ProbeCheck("S5", S, "loader directly to the BE (control: rows loaded)", lambda: loader_sight("S5", "be"),
                   lambda: loader_load("S5", "be")[0]["json"], lambda r: False),
        ProbeCheck("S6", S, "nat (native GRANT, no Ranger policy) SQL INSERT and stream load to the BE",
                   s6_sight, s6_actual, s6_leaked, s6_na),
        ProbeCheck("S7", S, "eve /api/transaction/begin on the BE", s7_sight, s7_actual,
                   lambda r: r["eve begin"] != "DENIED"),
        ProbeCheck("S8-eve", S, "eve fetches loader's ErrorURL (H4)", s8_sight, s8_actual("eve"),
                   lambda r: r["marker in body"]),
        ProbeCheck("S8-anon", S, "an unauthenticated fetch of loader's ErrorURL (H4)", s8_sight, s8_actual(None),
                   lambda r: r["marker in body"]),
        ProbeCheck("S9", S, "eve SHOW LOAD / information_schema.loads for loader's labels", s9_sight, s9_actual,
                   s9_leaked),
        ProbeCheck("S10", S, "loader overwrites hidden id = 2 of pk_target: SQL INSERT vs stream load", s10_sight,
                   s10_actual, s10_leaked),
        ProbeCheck("S11", S, "audit table: one row per load (S4, S5) with user loader", s11_sight, s11_actual,
                   s11_leaked, s11_na),
        ProbeCheck("R1", R, "eve CREATE ROUTINE LOAD on demo.r_target", r3_sight, outsider_create("eve", "r1_eve"),
                   denied_not),
        ProbeCheck("R2", R, "bob CREATE ROUTINE LOAD on demo.r_target", r3_sight, outsider_create("bob", "r2_bob"),
                   denied_not),
        ProbeCheck("R3", R, "loader job r_plain (PLAINTEXT): 3 rows within 60 s (control)", r3_sight, r3,
                   lambda r: False),
        ProbeCheck("R4", R, "loader job r_sasl (SASL PLAIN): 3 rows within 60 s (control)",
                   lambda: r4()["rows"] >= 3, r4, lambda r: False),
        ProbeCheck("R5-eve", R, "eve SHOW [ALL] ROUTINE LOAD / information_schema.routine_load_jobs", r5_root_sees,
                   r5_actual("eve"), r5_leaked),
        ProbeCheck("R5-bob", R, "bob SHOW [ALL] ROUTINE LOAD / information_schema.routine_load_jobs", r5_root_sees,
                   r5_actual("bob"), r5_leaked),
        ProbeCheck("R6", R, f"no {KAFKA_SECRET} for eve/bob, in the audit table or fe.audit.log", r6_sight,
                   r6_actual, r6_leaked),
        ProbeCheck("R8", R, "eve PAUSE and STOP ROUTINE LOAD on loader's r_sasl", r8_sight, r8_actual, r8_leaked),
        ProbeCheck("R7-pre", R, "state before the revoke (recorded for R7)", r3_sight, r7_record, lambda r: False),
    ]


def after_checks():
    return [
        ProbeCheck("R7", R, "after the revoke of loader's INSERT: 3 more messages, no new rows in 60 s", r7_sight,
                   r7_measure, r7_leaked),
        ProbeCheck("R7-sql", R, "after the revoke: loader's SQL INSERT into r_target (the revoke is live)",
                   r7_sql_sight, r7_sql_actual, lambda r: r != DENIED),
    ]


def main():
    skipped = skipped_probes(os.environ.get("PROBE_SKIP", ""))
    checks = before_checks() if PHASE == "before" else after_checks()
    sys.exit(run_checks(checks, skipped))


if __name__ == "__main__":
    main()
