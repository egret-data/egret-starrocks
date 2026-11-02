"""Audit checks, after checks.py: audit_checks.py <mysql port>.

The AuditLoader plugin (shipped at /opt/egret/auditloader.zip) loads every audit event into
starrocks_audit_db__.starrocks_audit_tbl__. Each check looks for the row of one statement checks.py ran,
through one path, and compares who, how and with what result it was recorded. Exit code 1 when any
check fails. All checks are tagged "audit": they fail on an image without the plugin.
"""
import sys
import time

import mysql.connector

PORT = int(sys.argv[1])
TABLE = "starrocks_audit_db__.starrocks_audit_tbl__"
# A statement with a double quote, a backslash and a newline: the plugin built its JSON without
# escaping, so this broke the whole batch and every event in it was lost (patch auditloader/0001).
MARKER = 'SELECT \'egret-audit "marker" \\\\ end\' AS a,\n  2 AS b'


def connect(user="root", password=""):
    return mysql.connector.connect(host="127.0.0.1", port=PORT, user=user, password=password, autocommit=True)


def rows(sql, args=()):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(sql, args)
        return [tuple(v.decode() if isinstance(v, (bytes, bytearray)) else v for v in r) for r in cur.fetchall()]
    finally:
        conn.close()


def recorded(where, args=()):
    """(user, authorizedUser, state, command, querySource, stmt) of the rows matching `where`."""
    try:
        return rows(f"SELECT `user`, authorizedUser, state, command, querySource, stmt FROM {TABLE} "
                    f"WHERE {where} ORDER BY `timestamp`", args)
    except mysql.connector.Error as e:
        return f"ERROR {e.errno}: {e.msg}"


def wait_for_marker():
    conn = connect("alice", "alicepw")
    try:
        cur = conn.cursor()
        cur.execute(MARKER)
        cur.fetchall()
    finally:
        conn.close()
    deadline = time.time() + 60
    while time.time() < deadline:
        found = recorded("stmt LIKE %s", ("%egret-audit%marker%",))
        if isinstance(found, list) and found:
            return found
        time.sleep(2)
    return recorded("stmt LIKE %s", ("%egret-audit%marker%",))


def one(where, args=()):
    return lambda: recorded(where, args)


def has(user, auth, state, command, source="EXTERNAL"):
    def ok(found):
        return isinstance(found, list) and any(
            r[0] == user and auth in (r[1] or "") and r[2] == state and r[3] == command and r[4] == source
            for r in found)
    return ok


CUSTOMERS = "SELECT id, phone FROM default_catalog.demo.customers WHERE id >= 0 ORDER BY id"
ORDERS_TEXT = "SELECT id, region, email FROM ice.sales.orders WHERE id >= 0 ORDER BY id"
CHECKS = [
    ("the marker statement (quote, backslash, newline) is stored verbatim", lambda: None, None),
    ("bob text query", one("`user` = 'bob' AND stmt = %s", (CUSTOMERS,)),
     has("bob", "'bob'", "EOF", "MySQL.Query")),
    ("eve denied text query", one("`user` = 'eve' AND stmt = %s", (CUSTOMERS,)),
     has("eve", "'eve'", "ERR", "MySQL.Query")),
    ("bob COM_STMT_EXECUTE", one("`user` = 'bob' AND command = 'MySQL.COM_STMT_EXECUTE'"),
     has("bob", "'bob'", "EOF", "MySQL.COM_STMT_EXECUTE")),
    ("svc EXECUTE AS bob, COM_STMT_EXECUTE: both users", one("`user` = 'svc' AND command = 'MySQL.COM_STMT_EXECUTE'"),
     has("svc", "'bob'", "EOF", "MySQL.COM_STMT_EXECUTE")),
    ("bob HTTP SQL API", one("`user` = 'bob' AND command = 'HTTP.Query'"),
     has("bob", "'bob'", "EOF", "HTTP.Query")),
    ("bob Arrow Flight SQL", one("`user` = 'bob' AND stmt = %s AND command LIKE 'ARROW%%'", (ORDERS_TEXT,)),
     has("bob", "'bob'", "EOF", "ARROW_FLIGHT_SQL.Query")),
    ("eve denied FILES() with double quotes in it", one("`user` = 'eve' AND stmt LIKE '%%FILES(\"path\"%%'"),
     has("eve", "'eve'", "ERR", "MySQL.Query")),
    ("mallory denied CREATE MATERIALIZED VIEW", one("`user` = 'mallory' AND stmt LIKE 'CREATE MATERIALIZED VIEW%%'"),
     has("mallory", "'mallory'", "ERR", "MySQL.Query")),
    ("no stored statement carries the storage secret", one("stmt LIKE '%%e2esecret%%'"),
     lambda found: found == []),
]


def main():
    failed = 0
    marker = wait_for_marker()
    width = max(len(c[0]) for c in CHECKS)
    for name, actual_fn, expected in CHECKS:
        if expected is None:
            actual = marker
            ok = isinstance(marker, list) and len(marker) == 1 and marker[0][5] == MARKER and marker[0][0] == "alice"
            if isinstance(marker, list):
                print("  marker sent:   " + repr(MARKER))
                for r in marker:
                    print("  marker stored: " + repr(r[5]))
        else:
            actual = actual_fn()
            ok = expected(actual)
        failed += 0 if ok else 1
        shown = actual if len(str(actual)) < 110 else str(actual)[:107] + "..."
        print(f"{'PASS' if ok else 'FAIL'}  [audit]  {name:<{width}}  {shown}")
    print(f"\n{len(CHECKS) - failed}/{len(CHECKS)} audit checks passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
