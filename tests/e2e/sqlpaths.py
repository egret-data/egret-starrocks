"""The ways a user reaches StarRocks, shared by checks.py and the probes.

Every helper returns the rows, DENIED when a privilege check refused the request, or an "ERROR ..." string.
configure() sets the ports before the first call.
"""
import base64
import json
import urllib.error
import urllib.request

import adbc_driver_flightsql.dbapi as flight_sql
import mysql.connector

PORT = HTTP_PORT = FLIGHT_PORT = None
# loader and nat exist only on a probe stack (policies.py --probe).
PASSWORDS = {"root": "", "alice": "alicepw", "bob": "bobpw", "eve": "evepw", "svc": "svcpw", "tina": "tinapw", "mallory": "mallorypw",
             "loader": "loaderpw", "nat": "natpw"}
DENIED = "DENIED"


def configure(port, http_port, flight_port):
    global PORT, HTTP_PORT, FLIGHT_PORT
    PORT, HTTP_PORT, FLIGHT_PORT = int(port), int(http_port), int(flight_port)


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
        if e.errno in (5203, 5204, 5210, 5211, 5212, 5213, 5214) or "Access denied" in str(e):
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
