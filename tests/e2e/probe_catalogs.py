"""Probe 2, external catalogs: probe_catalogs.py <mysql port> <http port> <flight port> <be http port> <canary log> <run_id>.

probe.sh seeds <catalog>.sales.orders with the rows of ice.sales.orders, and policies.py --probe gives it the
policies of ice.sales.orders: alice reads all, bob and mallory get MASK_NULL on email and the row filter
region = 'us', eve nothing. C1 to C16 (docs/en/specs/2026-11-09-starrocks-unmeasured-paths-probe-design.md,
probe 2) run once per catalog, as one ProbeCheck list each.

Catalogs: jdbc (Postgres) and hive (Hive Metastore, data on RustFS). Paimon is task 4: it adds a Catalog to
CATALOGS; until then its probe prints one ERROR line unless PROBE_SKIP names it.
"""
import dataclasses
import functools
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I does not put the script's directory on the path
import sqlpaths  # noqa: E402
from probe_lib import DENIED_CODES, Probe, ProbeCheck, canary_hits, run_checks, skipped_probes  # noqa: E402
from sqlpaths import DENIED, binary, flight, http, text  # noqa: E402

sqlpaths.configure(sys.argv[1], sys.argv[2], sys.argv[3])
CANARY_LOG = sys.argv[5]
RUN_ID = sys.argv[6]
SR_CONTAINER = "egs-probe-sr"  # probe.sh's $NAME-sr
FE_AUDIT_LOG = "/data/deploy/starrocks/fe/log/fe.audit.log"
CANARY = "http://host.docker.internal:18778"  # probe.sh's CANARY_PORT, as the StarRocks container reaches it

# checks.py's literals (checks.py runs its checks on import, so they are copied, not imported).
ORDERS_ALL = [(1, "us", "a@x.io"), (2, "eu", "b@x.io"), (3, "us", "c@x.io"), (4, "eu", "d@x.io")]
ORDERS_BOB = [(1, "us", None), (3, "us", None)]


@dataclasses.dataclass
class Catalog:
    name: str
    probe: Probe
    secret: str                      # the credential in the catalog's properties (C10, C15)
    shown_key: str                   # a property SHOW CREATE CATALOG prints in the clear (C9, C10 sight)
    star_order: tuple[int, ...]      # SELECT * column order, as indexes into (id, region, email)
    # C14: (sql, name) candidates for a partition listing, tried in order as alice; empty: not applicable.
    partition_listings: tuple[tuple[str, str], ...] = ()
    c14_na: str = ""                 # the reason C14 does not apply, when partition_listings is empty


CATALOGS = [
    Catalog("jdbc", Probe.JDBC, "pgsecret", "jdbc_uri", (0, 1, 2),
            c14_na="a JDBC catalog has no partition or file metadata of its own to list"),
    Catalog("hive", Probe.HIVE, "e2esecret", "hive.metastore.uris", (0, 2, 1), partition_listings=(
        ("SHOW PARTITIONS FROM hive.sales.orders", "SHOW PARTITIONS"),
        ("SELECT * FROM information_schema.partitions_meta WHERE DB_NAME = 'sales' AND TABLE_NAME = 'orders'",
         "information_schema.partitions_meta"),
    )),
]


def is_failure(r):
    """A failed request (not a refusal): sqlpaths' "ERROR ..." strings other than probe_lib's DENIED codes."""
    return isinstance(r, str) and r.startswith("ERROR ") and not any(r.startswith(f"ERROR {n}") for n in DENIED_CODES)


def rows_leak(r, width=3, order=(0, 1, 2)):
    """bob's rows carry what his policy refuses: an eu row, a clear email, or columns beyond the table's."""
    if not isinstance(r, list):
        return False
    for row in r:
        if len(row) != width:
            return True
        region, email = row[order.index(1)], row[order.index(2)]
        if region != "us" or email is not None:
            return True
    return False


def star(rows, order):
    return [tuple(row[i] for i in order) for row in rows]


def first_failure(results):
    """A dict of results whose any member is a failed request is that failure, so the check reads ERROR."""
    for r in results.values():
        if is_failure(r):
            return r
    return results


def names_sales_or_orders(r):
    return isinstance(r, list) and any("sales" in str(v) or "orders" in str(v) for row in r for v in row)


def docker_exec(*cmd):
    return subprocess.run(["docker", "exec", SR_CONTAINER, *cmd], capture_output=True, text=True, timeout=60)


def checks_for(c: Catalog) -> list[ProbeCheck]:
    t = f"{c.name}.sales.orders"
    orders_sql = f"SELECT id, region, email FROM {t} WHERE id >= {{p}} ORDER BY id"
    http_sql = "SELECT id, region, email FROM orders ORDER BY id"
    star_sql = f"SELECT * FROM {t} ORDER BY id"
    star_all = star(ORDERS_ALL, c.star_order)

    @functools.cache
    def alice(path):
        return {
            "text": lambda: text("alice", orders_sql.format(p=0)),
            "binary": lambda: binary("alice", orders_sql),
            "as": lambda: binary("svc", orders_sql, execute_as="alice"),
            "http": lambda: http("alice", c.name, "sales", http_sql),
            "flight": lambda: flight("alice", orders_sql.format(p=0)),
            "star": lambda: text("alice", star_sql),
        }[path]()

    def sees(path, expected=ORDERS_ALL):
        return lambda: alice(path) == expected

    leak = rows_leak
    star_leak = functools.partial(rows_leak, order=c.star_order)

    # C11: eve's view of the catalog's metadata, and alice's as its sight.
    def metadata(user):
        return {
            "databases": text(user, f"SHOW DATABASES FROM {c.name}"),
            "tables": text(user, f"SHOW TABLES FROM {c.name}.sales"),
            "information_schema": text(user, f"SELECT table_schema, table_name FROM {c.name}.information_schema.tables "
                                             "WHERE table_schema = 'sales'"),
        }

    def c11_sight():
        m = metadata("alice")
        return all(names_sales_or_orders(r) for r in m.values())

    # C14: the first listing alice can read is the probe for bob.
    @functools.cache
    def c14_listing():
        errors = []
        for sql, name in c.partition_listings:
            r = text("alice", sql)
            if isinstance(r, list) and r:
                return sql, name, None
            errors.append(f"{name}: {r}")
        return None, None, "; ".join(errors)

    def c14_na():
        if not c.partition_listings:
            return c.c14_na
        sql, _, errors = c14_listing()
        return None if sql else f"alice can read no partition listing ({errors})"

    def c14_actual():
        sql, name, _ = c14_listing()
        return {"via": name, "bob": text("bob", sql)}

    def c14_leaked(r):
        b = r["bob"]
        return isinstance(b, list) and any("eu" in str(v) for row in b for v in row)

    def c14_sight():
        sql, _, _ = c14_listing()
        r = text("alice", sql)
        return isinstance(r, list) and any("eu" in str(v) for row in r for v in row)

    # C15: root's CREATE EXTERNAL CATALOG <name> in the audit table (when the image loads one) and fe.audit.log.
    create_stmt = f"CREATE EXTERNAL CATALOG {c.name} "

    def audit_table(pattern):
        """Rows of the audit table whose stmt holds `pattern` and the catalog's CREATE; None without the table."""
        r = text("root", "SELECT count(*) FROM starrocks_audit_db__.starrocks_audit_tbl__ "
                         f"WHERE stmt LIKE '%{create_stmt}%' AND stmt LIKE '%{pattern}%' "
                         "AND stmt NOT LIKE '%starrocks_audit_tbl__%'")
        if isinstance(r, str) and "starrocks_audit_db__" in r:  # the official images have no audit table
            return None
        if is_failure(r):
            raise RuntimeError(f"audit table: {r}")
        return r[0][0]

    def audit_log(pattern):
        """fe.audit.log lines with `pattern` and the catalog's CREATE, the harness's own queries left out."""
        p = docker_exec("grep", "-F", pattern, FE_AUDIT_LOG)
        if p.returncode not in (0, 1):
            raise RuntimeError(f"grep {FE_AUDIT_LOG}: {p.stderr.strip()}")
        return [line for line in p.stdout.splitlines()
                if create_stmt in line and "starrocks_audit_tbl__" not in line]

    def c15_sight():
        # The CREATE statement itself reaches both trails (the table within its 5 s batches).
        if not audit_log(create_stmt):
            return False
        for _ in range(15):
            n = audit_table(create_stmt)
            if n is None or n > 0:
                return True
            time.sleep(2)
        return False

    def c15_actual():
        n = audit_table(c.secret)
        return {"audit table rows": "no audit table (no AuditLoader)" if n is None else n,
                "fe.audit.log lines": len(audit_log(c.secret))}

    def c15_leaked(r):
        n = r["audit table rows"]
        return (isinstance(n, int) and n > 0) or r["fe.audit.log lines"] > 0

    # C16: eve makes the FE load a driver (jdbc), or point a catalog at a metastore (hive).
    if c.probe is Probe.JDBC:
        marker = f"c16-{RUN_ID}"
        sight_marker = f"c16-sight-{RUN_ID}"

        def jdbc_catalog(name, jar):
            return (f'CREATE EXTERNAL CATALOG {name} PROPERTIES ("type" = "jdbc", "user" = "postgres", '
                    f'"password" = "x", "jdbc_uri" = "jdbc:postgresql://pg:5432/sales", '
                    f'"driver_url" = "{CANARY}/{jar}.jar", "driver_class" = "org.postgresql.Driver")')

        def c16_sight():
            # The canary is live and root's same statement reaches it from the StarRocks container.
            if not canary_hits(CANARY_LOG, "/canary-live-"):
                return False
            text("root", jdbc_catalog(f"c16_sight_{RUN_ID}", sight_marker))
            text("root", f"DROP CATALOG IF EXISTS c16_sight_{RUN_ID}")
            return bool(canary_hits(CANARY_LOG, sight_marker))

        def c16_actual():
            r = text("eve", jdbc_catalog(f"c16_eve_{RUN_ID}", marker))
            if isinstance(r, str) and r.startswith("ERROR 20"):  # the client's own errors (2003, 2013): no answer
                return r
            # An engine error (say, the driver failed to load) means eve got past the privilege check: keep it as
            # the result, with the canary's hits.
            return {"eve": r, "canary hits": canary_hits(CANARY_LOG, marker)}

        def c16_leaked(r):
            return r["eve"] != DENIED or bool(r["canary hits"])
        c16_name = "eve CREATE EXTERNAL CATALOG (JDBC, canary driver_url)"
    else:
        def hive_catalog(name):
            return (f'CREATE EXTERNAL CATALOG {name} PROPERTIES ("type" = "hive", '
                    '"hive.metastore.uris" = "thrift://hive-metastore:9083")')

        def c16_sight():
            r = text("root", hive_catalog(f"c16h_sight_{RUN_ID}"))
            text("root", f"DROP CATALOG IF EXISTS c16h_sight_{RUN_ID}")
            return r == []

        def c16_actual():
            return {"eve": text("eve", hive_catalog(f"c16h_eve_{RUN_ID}"))}

        def c16_leaked(r):
            return r["eve"] != DENIED
        c16_name = "eve CREATE EXTERNAL CATALOG (Hive)"

    def show_create_sight():
        """Root's SHOW CREATE CATALOG prints the properties: a secret printed in the clear would be seen."""
        return c.shown_key in str(text("root", f"SHOW CREATE CATALOG {c.name}"))

    mv = f"demo.m_mv_{c.name}_{RUN_ID}"
    view = f"demo.m_v_{c.name}_{RUN_ID}"

    def check(id_, name, sight, actual, leaked, na=lambda: None):
        return ProbeCheck(id=f"{id_}-{c.name}", probe=c.probe, name=name, sight=sight, actual=actual, leaked=leaked,
                          na_reason=na)

    def not_denied(r):
        return r != DENIED

    return [
        check("C1", "alice text (sight control for C2-C7)", sees("text"), lambda: alice("text"),
              lambda r: r != ORDERS_ALL),
        check("C2", "bob text", sees("text"), lambda: text("bob", orders_sql.format(p=0)), leak),
        check("C3", "bob COM_STMT_EXECUTE", sees("binary"), lambda: binary("bob", orders_sql), leak),
        check("C4", "svc EXECUTE AS bob + COM_STMT_EXECUTE", sees("as"),
              lambda: binary("svc", orders_sql, execute_as="bob"), leak),
        check("C5", "bob HTTP SQL API", sees("http"), lambda: http("bob", c.name, "sales", http_sql), leak),
        check("C6", "bob Arrow Flight SQL", sees("flight"), lambda: flight("bob", orders_sql.format(p=0)), leak),
        check("C7", "bob SELECT * (three columns)", sees("star", star_all), lambda: text("bob", star_sql), star_leak),
        check("C8", "eve SELECT", sees("text"), lambda: text("eve", orders_sql.format(p=0)), not_denied),
        check("C9", f"eve SHOW CREATE CATALOG {c.name}", show_create_sight,
              lambda: text("eve", f"SHOW CREATE CATALOG {c.name}"), not_denied),
        check("C10", f"bob SHOW CREATE CATALOG {c.name} (no full secret)", show_create_sight,
              lambda: text("bob", f"SHOW CREATE CATALOG {c.name}"), lambda r: c.secret in str(r)),
        check("C11", "eve SHOW DATABASES / SHOW TABLES / information_schema.tables", c11_sight,
              lambda: first_failure(metadata("eve")),
              lambda r: isinstance(r, dict) and any(names_sales_or_orders(v) for v in r.values())),
        check("C12", "bob EXPLAIN COSTS",
              lambda: isinstance(text("alice", f"EXPLAIN COSTS SELECT id, region FROM {t}"), list),
              lambda: text("bob", f"EXPLAIN COSTS SELECT id, region FROM {t}"), not_denied),
        check("C13", "mallory CREATE MATERIALIZED VIEW",
              lambda: isinstance(text("mallory", f"CREATE VIEW {view} AS SELECT id FROM {t}"), list),
              lambda: text("mallory", f"CREATE MATERIALIZED VIEW {mv} DISTRIBUTED BY HASH(id) "
                                      "REFRESH MANUAL PROPERTIES ('replication_num' = '1') "
                                      f"AS SELECT id, region, email FROM {t}"),
              not_denied),
        check("C14", "bob partition listing (no eu)", c14_sight, c14_actual, c14_leaked, c14_na),
        check("C15", "audit table and fe.audit.log: no secret", c15_sight, c15_actual, c15_leaked),
        check("C16", c16_name, c16_sight, c16_actual, c16_leaked),
    ]


def paimon_hook() -> list[ProbeCheck]:
    """Task 4 replaces this with a Catalog in CATALOGS. Until then a run that does not skip paimon fails loudly."""
    def not_yet():
        raise NotImplementedError("the Paimon catalog checks are task 4")
    return [ProbeCheck(id="C0-paimon", probe=Probe.PAIMON, name="Paimon catalog checks", sight=lambda: True,
                       actual=not_yet, leaked=lambda r: False)]


def main():
    skipped = skipped_probes(os.environ.get("PROBE_SKIP", ""))
    checks: list[ProbeCheck] = []
    for c in CATALOGS:
        checks += checks_for(c)
    checks += paimon_hook()
    sys.exit(run_checks(checks, skipped))


if __name__ == "__main__":
    main()
