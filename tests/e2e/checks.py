"""Security checks against a running StarRocks: checks.py <mysql port> <http port> <flight sql port>.

Every check reads through one path as one user and compares the result with what the policies in
policies.py allow. Exit code 1 when any check fails. The `patch` column names the fork patch a check
covers ("-" for a control that must hold on the official image too, "guard" for a check that a
patch must not break).
"""
import base64
import json
import sys
import urllib.error
import urllib.request

import adbc_driver_flightsql.dbapi as flight_sql
import mysql.connector

PORT = int(sys.argv[1])
HTTP_PORT = int(sys.argv[2])
FLIGHT_PORT = int(sys.argv[3])
PASSWORDS = {"root": "", "alice": "alicepw", "bob": "bobpw", "eve": "evepw", "svc": "svcpw", "tina": "tinapw", "mallory": "mallorypw"}
DENIED = "DENIED"

CUSTOMERS_ALL = [(1, "010-1111-2222"), (2, "010-3333-4444"), (3, "010-5555-6666")]
CUSTOMERS_BOB = [(1, None)]
ORDERS_ALL = [(1, "us", "a@x.io"), (2, "eu", "b@x.io"), (3, "us", "c@x.io"), (4, "eu", "d@x.io")]
ORDERS_BOB = [(1, "us", None), (3, "us", None)]

CUSTOMERS_SQL = "SELECT id, phone FROM default_catalog.demo.customers WHERE id >= {p} ORDER BY id"
ORDERS_SQL = "SELECT id, region, email FROM ice.sales.orders WHERE id >= {p} ORDER BY id"


def connect(user, execute_as=None):
    conn = mysql.connector.connect(host="127.0.0.1", port=PORT, user=user, password=PASSWORDS[user],
                                   autocommit=True)
    if execute_as:
        conn.cursor().execute(f"EXECUTE AS {execute_as} WITH NO REVERT")
    return conn


def norm(rows):
    return [tuple(v.decode() if isinstance(v, (bytes, bytearray)) else v for v in r) for r in rows]


def run(fn):
    try:
        return fn()
    except mysql.connector.Error as e:
        if e.errno in (5203, 5204, 5210, 5211, 5212) or "Access denied" in str(e):
            return DENIED
        return f"ERROR {e.errno}: {e.msg}"
    except Exception as e:  # a broken check must report, not stop the run
        return f"ERROR {type(e).__name__}: {e}"


def text(user, sql, session=None):
    def go():
        conn = connect(user)
        cur = conn.cursor()
        for stmt in session or []:
            cur.execute(stmt)
        cur.execute(sql)
        return norm(cur.fetchall())
    return run(go)


def sql_prepare(user, sql_template):
    def go():
        conn = connect(user)
        cur = conn.cursor()
        stmt = sql_template.format(p="?").replace("'", "''")
        cur.execute(f"PREPARE p1 FROM '{stmt}'")
        cur.execute("SET @p = 0")
        cur.execute("EXECUTE p1 USING @p")
        return norm(cur.fetchall())
    return run(go)


def binary(user, sql_template, execute_as=None):
    """COM_STMT_PREPARE + COM_STMT_EXECUTE with the parameter sent as text, as egret's connector does."""
    def go():
        conn = connect(user, execute_as)
        cur = conn.cursor(prepared=True)
        cur.execute(sql_template.format(p="CAST(%s AS BIGINT)"), ("0",))
        return norm(cur.fetchall())
    return run(go)


def http(user, catalog, db, sql):
    """The FE's HTTP SQL API (POST /api/v1/catalogs/<catalog>/databases/<db>/sql, newline-delimited JSON)."""
    def go():
        auth = base64.b64encode(f"{user}:{PASSWORDS[user]}".encode()).decode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{HTTP_PORT}/api/v1/catalogs/{catalog}/databases/{db}/sql",
            data=json.dumps({"query": sql + ";"}).encode(), method="POST",
            headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=60) as resp:
            lines = [json.loads(line) for line in resp.read().decode().splitlines() if line.strip()]
        for line in lines:
            if line.get("status") == "FAILED":
                msg = line.get("msg", "")
                return DENIED if "Access denied" in msg else f"ERROR {msg}"
        return [tuple(line["data"]) for line in lines if "data" in line]
    return run(go)


def flight(user, sql):
    """Arrow Flight SQL (the FE's arrow_flight_port)."""
    def go():
        try:
            with flight_sql.connect(f"grpc://127.0.0.1:{FLIGHT_PORT}",
                                    db_kwargs={"username": user, "password": PASSWORDS[user]}) as conn:
                with conn.cursor() as cur:
                    cur.execute(sql)
                    return norm(cur.fetchall())
        except Exception as e:  # ADBC raises its own error types
            return DENIED if "Access denied" in str(e) else f"ERROR {type(e).__name__}: {str(e)[:200]}"
    return run(go)


S3 = ('"aws.s3.endpoint" = "http://s3:9000", "aws.s3.access_key" = "e2e", "aws.s3.secret_key" = "e2esecret", '
      '"aws.s3.enable_path_style_access" = "true", "aws.s3.region" = "us-east-1"')
FILES_ORDERS = f'FILES("path" = "s3://warehouse/sales/orders/data/*", "format" = "parquet", {S3})'
PIVOT_REGION = ("SELECT * FROM (SELECT id, region FROM ice.sales.orders) t "
                "PIVOT (count(id) FOR region IN ('us' AS us, 'eu' AS eu))")
PIVOT_EMAIL = ("SELECT * FROM (SELECT id, email FROM ice.sales.orders) t "
               "PIVOT (max(email) FOR id IN (1 AS a, 2 AS b))")


def nonempty(result):
    return isinstance(result, list) and len(result) > 0


CHECKS = [
    # name, patch, actual (thunk), expected value or predicate
    ("alice text customers", "-", lambda: text("alice", CUSTOMERS_SQL.format(p=0)), CUSTOMERS_ALL),
    ("bob text customers (mask+filter)", "-", lambda: text("bob", CUSTOMERS_SQL.format(p=0)), CUSTOMERS_BOB),
    ("eve text customers", "-", lambda: text("eve", CUSTOMERS_SQL.format(p=0)), DENIED),
    ("bob SQL PREPARE customers", "0002", lambda: sql_prepare("bob", CUSTOMERS_SQL), CUSTOMERS_BOB),
    ("bob COM_STMT_EXECUTE customers", "0002", lambda: binary("bob", CUSTOMERS_SQL), CUSTOMERS_BOB),
    ("svc AS bob COM_STMT_EXECUTE customers", "0002",
     lambda: binary("svc", CUSTOMERS_SQL, execute_as="bob"), CUSTOMERS_BOB),
    ("alice COM_STMT_EXECUTE customers", "-", lambda: binary("alice", CUSTOMERS_SQL), CUSTOMERS_ALL),
    ("alice text orders", "-", lambda: text("alice", ORDERS_SQL.format(p=0)), ORDERS_ALL),
    ("bob text orders (mask+filter)", "-", lambda: text("bob", ORDERS_SQL.format(p=0)), ORDERS_BOB),
    # Guards 0001's exemption for metadata collect jobs: passes on the official image too, and must
    # keep passing (refusing the job would break distributed planning for any user with a policy).
    ("bob text orders, plan_mode=distributed", "guard",
     lambda: text("bob", ORDERS_SQL.format(p=0), ["SET plan_mode = 'distributed'"]), ORDERS_BOB),
    ("bob COM_STMT_EXECUTE orders", "0002", lambda: binary("bob", ORDERS_SQL), ORDERS_BOB),
    ("alice orders$files", "-",
     lambda: text("alice", "SELECT record_count FROM ice.sales.`orders$files`"), nonempty),
    ("eve orders$files", "0001",
     lambda: text("eve", "SELECT lower_bounds, upper_bounds FROM ice.sales.`orders$files`"), DENIED),
    ("eve orders$snapshots", "0001",
     lambda: text("eve", "SELECT snapshot_id FROM ice.sales.`orders$snapshots`"), DENIED),
    ("bob orders$files (masked, filtered)", "0001",
     lambda: text("bob", "SELECT lower_bounds, upper_bounds FROM ice.sales.`orders$files`"), DENIED),
    # SELECT * has the table's own columns for every user: a policy rewrite must not add _file and _pos.
    ("alice SELECT * orders", "-",
     lambda: text("alice", "SELECT * FROM ice.sales.orders ORDER BY id"), ORDERS_ALL),
    ("bob SELECT * orders (mask+filter)", "0003",
     lambda: text("bob", "SELECT * FROM ice.sales.orders ORDER BY id"), ORDERS_BOB),
    ("bob SELECT o.* orders (mask+filter)", "0003",
     lambda: text("bob", "SELECT o.* FROM ice.sales.orders o ORDER BY id"), ORDERS_BOB),
    # Guards 0003: the hidden columns stay nameable under a policy (an Iceberg DELETE reads them).
    ("bob SELECT _file, _pos orders (filter)", "guard",
     lambda: text("bob", "SELECT id, _pos FROM ice.sales.orders WHERE _file IS NOT NULL ORDER BY id"),
     lambda r: isinstance(r, list) and [row[0] for row in r] == [1, 3]),
    ("bob WITH x AS (SELECT * orders)", "0003",
     lambda: text("bob", "WITH x AS (SELECT * FROM ice.sales.orders) SELECT * FROM x ORDER BY id"), ORDERS_BOB),
    # PIVOT: the rewrite must reach the relation under a pivot.
    ("alice PIVOT orders by region", "-", lambda: text("alice", PIVOT_REGION), [(2, 2)]),
    ("bob PIVOT orders by region (filter)", "0002", lambda: text("bob", PIVOT_REGION), [(2, 0)]),
    ("bob PIVOT orders email (mask+filter)", "0002", lambda: text("bob", PIVOT_EMAIL), [(None, None)]),
    # The FE's HTTP SQL API and Arrow Flight SQL run user SQL outside the MySQL protocol.
    ("alice HTTP SQL orders", "-",
     lambda: http("alice", "ice", "sales", "SELECT id, region, email FROM orders ORDER BY id"), ORDERS_ALL),
    ("bob HTTP SQL orders (mask+filter)", "0004",
     lambda: http("bob", "ice", "sales", "SELECT id, region, email FROM orders ORDER BY id"), ORDERS_BOB),
    ("alice Flight SQL orders", "-", lambda: flight("alice", ORDERS_SQL.format(p=0)), ORDERS_ALL),
    ("bob Flight SQL orders (mask+filter)", "0004", lambda: flight("bob", ORDERS_SQL.format(p=0)), ORDERS_BOB),
    # SHOW CREATE CATALOG prints a catalog's endpoints and the ends of its keys.
    ("eve SHOW CREATE CATALOG ice", "0005", lambda: text("eve", "SHOW CREATE CATALOG ice"), DENIED),
    ("bob SHOW CREATE CATALOG ice (has grants in it)", "guard",
     lambda: text("bob", "SHOW CREATE CATALOG ice"), nonempty),
    # FILES() reads object storage with no table privilege, mask or row filter.
    ("eve FILES() on orders' data files", "0006",
     lambda: text("eve", f"SELECT * FROM {FILES_ORDERS}"), DENIED),
    ("bob FILES() on orders' data files", "0006",
     lambda: text("bob", f"SELECT * FROM {FILES_ORDERS}"), DENIED),
    ("root FILES() (OPERATE on SYSTEM)", "guard",
     lambda: text("root", f"SELECT count(*) FROM {FILES_ORDERS}"), [(4,)]),
    # Write paths of a user under a mask and a row filter (mallory, on demo.customers).
    # Tag policies: tina's mask, row filter and deny come only from tags (policies.py).
    ("tina text customers (tag PII mask)", "tag",
     lambda: text("tina", CUSTOMERS_SQL.format(p=0)), [(1, None), (2, None), (3, None)]),
    ("tina text orders (tag row filter + tag PII mask)", "tag",
     lambda: text("tina", ORDERS_SQL.format(p=0)), [(1, "us", None), (3, "us", None)]),
    ("tina COM_STMT_EXECUTE orders (tags)", "tag", lambda: binary("tina", ORDERS_SQL), [(1, "us", None), (3, "us", None)]),
    ("tina SELECT grade (tag SECRET deny)", "tag",
     lambda: text("tina", "SELECT grade FROM default_catalog.demo.customers"), DENIED),
    ("tina SELECT id (untagged column)", "tag",
     lambda: text("tina", "SELECT id FROM default_catalog.demo.customers ORDER BY id"), [(1,), (2,), (3,)]),
    ("tina SELECT * orders (tags)", "tag",
     lambda: text("tina", "SELECT * FROM ice.sales.orders ORDER BY id"), [(1, "us", None), (3, "us", None)]),
    ("mallory CTAS over customers keeps her policy", "-",
     lambda: text("mallory", "SELECT * FROM demo.m_ctas ORDER BY id",
                  ["CREATE TABLE IF NOT EXISTS demo.m_ctas AS SELECT * FROM demo.customers"]), [(1, None, "A")]),
    # A materialized view's refresh reads the base table without her policy and stores every row in the clear.
    ("mallory CREATE MATERIALIZED VIEW over customers", "0007",
     lambda: text("mallory", "CREATE MATERIALIZED VIEW demo.m_mv DISTRIBUTED BY HASH(id) REFRESH MANUAL "
                             "PROPERTIES ('replication_num' = '1') AS SELECT id, phone FROM demo.customers"),
     DENIED),
]


def main():
    failed = 0
    width = max(len(c[0]) for c in CHECKS)
    for name, patch, actual_fn, expected in CHECKS:
        actual = actual_fn()
        ok = expected(actual) if callable(expected) else actual == expected
        failed += 0 if ok else 1
        shown = actual if len(str(actual)) < 110 else str(actual)[:107] + "..."
        print(f"{'PASS' if ok else 'FAIL'}  [{patch}]  {name:<{width}}  {shown}")
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
