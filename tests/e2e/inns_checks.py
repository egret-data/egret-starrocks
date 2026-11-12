"""Probe 4, the CN/BE ports from inside the engine namespace (M5: a pod on the probe network
with no StarRocks credentials). Standard library only: it runs inside a throwaway
python:3.12-slim container on the probe network, so it cannot use the venv, docker, or mysql.

    python -I /e2e/inns_checks.py <host> <run_id> <segment path> <segment sha256> <n3 pattern>
        [--auth user:pw] [--no-destructive] [--mutant-n8-root] [--n3-sight ok|no]

<host> is the StarRocks container name, reachable by Docker's embedded DNS on the probe network;
the ports are the container-internal ones (not the published host ports). probe.sh finds the
segment path + sha256 (SHOW TABLET + find, as root) and the n3 pattern (the S4 load label, confirmed
in be.INFO) beforehand, and folds this script's verdict counts into the combined summary.

N1 to N11 follow docs/en/specs/2026-11-09-starrocks-unmeasured-paths-probe-design.md, probe 4.
Ordering constraints (the brief): N5 runs before and after N4; N4 is restored (enable_token_check=true)
at once after N5-after; N11 runs last, then the script exits. --no-destructive skips N4, N5 and N11
(Task 7 on kind uses it, so an unauthenticated OPERATE call never stops a shared engine).

The BE_HTTP_AUTH=1 variant (probe.sh passes --auth eve:evepw): N1 to N5 and N11 are rerun both with
no credentials (must flip to ENFORCED) and with eve's Basic auth (the OPERATE endpoints must stay
refused; /api/_load_error_log, measured by probe_loads.py S8, needs only a login).

The verdict rules match probe_lib: SKIP, N/A (full reason), BLIND when the sight control fails,
ERROR on an exception or a request failure (a timeout or a connection refusal is ERROR, never
ENFORCED), LEAK when the result carries what the policies refuse, else ENFORCED. An HTTP 401/403
counts as ENFORCED only when N1's reachability control succeeded.
"""
import argparse
import base64
import hashlib
import http.client
import os
import socket
import struct
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # python -I omits the script's dir
from probe_lib import Probe, ProbeCheck, run_checks  # noqa: E402  (stdlib-only; safe to import)

IN = Probe.IN_NAMESPACE

# Container-internal ports (allin1). The probe reaches them by the container name on the probe net.
BE_HTTP = 8040      # be_http_port: /api/health, /varz, /greplog, /api/update_config, /api/_download_load, /api/_stop_be
FE_HTTP = 8030      # http_port: /api/show_proc, /metrics
FE_THRIFT = 9020    # rpc_port: FrontendService (getDbNames, forward)
BRPC = 8060         # brpc_port on the BE: built-in /flags, /vars
BE_THRIFT = 9060    # be_port
HEARTBEAT = 9050    # heartbeat_service_port
PORT_9070 = 9070    # recorded by N7 (spec)

args = argparse.Namespace()


def detail(check, value):
    """The whole of a result the verdict line cuts at 110 chars, for the report (not counted by probe.sh)."""
    print(f"  detail {check}: {value}")
    return value


# ---------------------------------------------------------------------------------------------------------
# HTTP client. A request that cannot be made raises, which the verdict model turns into ERROR.

def http_req(method, port, path, auth=None, timeout=20):
    conn = http.client.HTTPConnection(args.host, port, timeout=timeout)
    try:
        headers = {}
        if auth:
            headers["Authorization"] = "Basic " + base64.b64encode(auth.encode()).decode()
        conn.request(method, path, headers=headers)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def tcp_open(port, timeout=5):
    try:
        with socket.create_connection((args.host, port), timeout=timeout):
            return True
    except OSError:
        return False


# Reachability controls, probed once at start. Reachable means the port answered (an HTTP status,
# or a TCP handshake): a 401 under BE_HTTP_AUTH is still reachable. A connection refusal is not.
REACHABLE_BE = False
BE_HEALTH = None
REACHABLE_FE = False
REACHABLE_THRIFT = False


def probe_reachability():
    global REACHABLE_BE, BE_HEALTH, REACHABLE_FE, REACHABLE_THRIFT
    for auth in (None, args.auth):  # anon first; under auth health needs a login (HealthAction::need_auth()==true)
        try:
            BE_HEALTH, _ = http_req("GET", BE_HTTP, "/api/health", auth=auth)
            REACHABLE_BE = True
            break
        except OSError:
            continue
    try:
        http_req("GET", FE_HTTP, "/api/health")
        REACHABLE_FE = True
    except OSError:
        REACHABLE_FE = tcp_open(FE_HTTP)
    REACHABLE_THRIFT = tcp_open(FE_THRIFT)


def be_sight():
    return REACHABLE_BE


# ---------------------------------------------------------------------------------------------------------
# A minimal TBinaryProtocol (strict message header) over a plain buffered socket. The FE's thrift
# service is an SRTThreadPoolServer on a TServerSocket with a TBinaryProtocol.Factory, i.e. unframed,
# strict: ThriftServer.java sets `new TBinaryProtocol.Factory(strict_mode, true, max_body, -1)`.
# TType ids and the strict version word are the Thrift wire constants.
T_STOP, T_BOOL, T_BYTE, T_DOUBLE, T_I16, T_I32, T_I64, T_STRING, T_STRUCT, T_MAP, T_SET, T_LIST = \
    0, 2, 3, 4, 6, 8, 10, 11, 12, 13, 14, 15
MSG_CALL, MSG_REPLY, MSG_EXCEPTION = 1, 2, 3
VERSION_1 = 0x80010000
VERSION_MASK = 0xFFFF0000


class TWriter:
    def __init__(self):
        self.buf = bytearray()

    def _u32(self, v):
        self.buf += struct.pack(">I", v & 0xFFFFFFFF)

    def byte(self, v):
        self.buf += struct.pack(">b", v)

    def i16(self, v):
        self.buf += struct.pack(">h", v)

    def i32(self, v):
        self.buf += struct.pack(">i", v)

    def string(self, s):
        data = s.encode() if isinstance(s, str) else s
        self.i32(len(data))
        self.buf += data

    def msg_begin(self, name, mtype, seqid=0):
        self._u32(VERSION_1 | mtype)
        self.string(name)
        self.i32(seqid)

    def field(self, ftype, fid):
        self.byte(ftype)
        self.i16(fid)

    def field_bool(self, fid, v):
        self.field(T_BOOL, fid)
        self.byte(1 if v else 0)

    def field_string(self, fid, v):
        self.field(T_STRING, fid)
        self.string(v)

    def stop(self):
        self.byte(T_STOP)


class TReader:
    def __init__(self, sock):
        self.sock = sock

    def _read(self, n):
        out = b""
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise EOFError("thrift: connection closed mid-message")
            out += chunk
        return out

    def ubyte(self):
        return self._read(1)[0]

    def i16(self):
        return struct.unpack(">h", self._read(2))[0]

    def i32(self):
        return struct.unpack(">i", self._read(4))[0]

    def i64(self):
        return struct.unpack(">q", self._read(8))[0]

    def string(self):
        n = self.i32()
        return self._read(n) if n > 0 else b""

    def msg_begin(self):
        first = struct.unpack(">I", self._read(4))[0]
        if first & 0x80000000:
            if (first & VERSION_MASK) != VERSION_1:
                raise ValueError(f"thrift: bad version {first:#x}")
            mtype = first & 0xFF
            name = self.string().decode(errors="replace")
            return name, mtype, self.i32()
        name = self._read(first).decode(errors="replace")  # old (non-strict) layout
        mtype = self.ubyte()
        return name, mtype, self.i32()

    def value(self, ftype):
        if ftype == T_BOOL:
            return self.ubyte() != 0
        if ftype == T_BYTE:
            return self.ubyte()
        if ftype == T_DOUBLE:
            return struct.unpack(">d", self._read(8))[0]
        if ftype == T_I16:
            return self.i16()
        if ftype == T_I32:
            return self.i32()
        if ftype == T_I64:
            return self.i64()
        if ftype == T_STRING:
            return self.string()
        if ftype == T_STRUCT:
            return self.struct()
        if ftype == T_MAP:
            kt, vt, n = self.ubyte(), self.ubyte(), self.i32()
            return [(self.value(kt), self.value(vt)) for _ in range(n)]
        if ftype in (T_LIST, T_SET):
            et, n = self.ubyte(), self.i32()
            return [self.value(et) for _ in range(n)]
        raise ValueError(f"thrift: unknown field type {ftype}")

    def struct(self):
        out = {}
        while True:
            ftype = self.ubyte()
            if ftype == T_STOP:
                return out
            fid = self.i16()
            out[fid] = self.value(ftype)


def thrift_call(port, method, write_args, timeout=15):
    """Send one unframed strict-TBinaryProtocol CALL and read the reply. Returns ('reply', struct) or
    ('exception', TApplicationException-struct). Raises on a connection or protocol failure (-> ERROR)."""
    sock = socket.create_connection((args.host, port), timeout=timeout)
    sock.settimeout(timeout)
    try:
        w = TWriter()
        w.msg_begin(method, MSG_CALL)
        write_args(w)   # the method's args struct, then its stop
        sock.sendall(bytes(w.buf))
        r = TReader(sock)
        _, mtype, _ = r.msg_begin()
        body = r.struct()
        return ("exception" if mtype == MSG_EXCEPTION else "reply"), body
    finally:
        sock.close()


# FrontendService.thrift (work/starrocks/gensrc/thrift), field ids checked against the IDL:
#   getDbNames(1: TGetDbsParams params)                         FrontendService.thrift:2447
#   struct TGetDbsParams { 1 pattern; 2 user(dep); 3 user_ip(dep);
#       4 current_user_ident: Types.TUserIdentity; 5 catalog_name }   FrontendService.thrift:342-351
#   struct TGetDbsResult { 1: list<string> dbs }                FrontendService.thrift:354-356
#   struct TUserIdentity { 1 username; 2 host; 3 is_domain; ... }     Types.thrift:521-527
def write_getdbnames(username, host):
    def f(w):
        w.field(T_STRUCT, 1)                       # getDbNames_args.params (field 1)
        w.field(T_STRUCT, 4)                       # TGetDbsParams.current_user_ident (field 4)
        w.field_string(1, username)                # TUserIdentity.username (field 1)
        w.field_string(2, host)                    # TUserIdentity.host     (field 2)
        w.field_bool(3, False)                     # TUserIdentity.is_domain(field 3)
        w.stop()                                   # end TUserIdentity
        w.field_string(5, "default_catalog")       # TGetDbsParams.catalog_name (field 5)
        w.stop()                                   # end TGetDbsParams
        w.stop()                                   # end getDbNames_args
    return f


# FrontendService.thrift:2483  TMasterOpResult forward(1: TMasterOpRequest params)
#   struct TMasterOpRequest { 1: required string user; 2: required string db;
#       3: required string sql; ... 14: current_user_ident }    FrontendService.thrift:910-935
# Only the three required fields are written (the brief).
def write_forward(user, db, sql):
    def f(w):
        w.field(T_STRUCT, 1)                       # forward_args.params (field 1)
        w.field_string(1, user)                    # TMasterOpRequest.user (field 1, required)
        w.field_string(2, db)                      # TMasterOpRequest.db   (field 2, required)
        w.field_string(3, sql)                     # TMasterOpRequest.sql  (field 3, required)
        w.stop()                                   # end TMasterOpRequest
        w.stop()                                   # end forward_args
    return f


def collect_strings(value, out):
    if isinstance(value, bytes):
        out.append(value.decode(errors="replace"))
    elif isinstance(value, dict):
        for v in value.values():
            collect_strings(v, out)
    elif isinstance(value, list):
        for v in value:
            if isinstance(v, tuple):
                for e in v:
                    collect_strings(e, out)
            else:
                collect_strings(v, out)


# ---------------------------------------------------------------------------------------------------------
# The checks.

def n1_actual():
    # Live, so a connection refusal is ERROR, not a silent pass. Health is public by design: never a leak.
    # Under BE_HTTP_AUTH anonymous health is 401 (HealthAction::need_auth()==true); that still proves reach.
    status, _ = http_req("GET", BE_HTTP, "/api/health")
    return detail("N1", f"GET :{BE_HTTP}/api/health -> http {status}")


def n1_eve_actual():
    status, _ = http_req("GET", BE_HTTP, "/api/health", auth=args.auth)
    detail("N1-eve", f"GET :{BE_HTTP}/api/health (eve) -> http {status}")
    return {"http": status}


def mk_http_get(check, port, path, auth, want_marker=None):
    """A GET whose body is inspected. LEAK when served (200) and, if want_marker is set, the marker is in
    the body; ENFORCED when refused (401/403) and the BE is reachable; otherwise the raw outcome is recorded."""
    def actual():
        status, body = http_req("GET", port, path, auth=auth)
        text = body.decode(errors="replace")
        hit = (want_marker in text) if want_marker else None
        detail(f"{check}{'/'+auth.split(':')[0] if auth else ''}",
               f"GET :{port}{path} -> http {status}" + (f", marker in body: {hit}" if want_marker else f", {len(body)} bytes"))
        return {"http": status, "marker": hit, "len": len(body), "head": text[:120]}

    def leaked(r):
        if want_marker is not None:
            return r["http"] == 200 and bool(r["marker"])
        return r["http"] == 200 and r["len"] > 0
    return actual, leaked


def n4_actual():
    # POST /api/update_config?enable_token_check=false with no credentials (or eve's). LEAK when the OPERATE
    # endpoint accepts the change (200). The behavioural proof that the token check is then off is N5-after.
    status, body = http_req("POST", BE_HTTP, "/api/update_config?enable_token_check=false", auth=args._n4_auth)
    text = body.decode(errors="replace")
    ok = status == 200 and ("OK" in text or '"status"' in text)
    detail(f"N4{'/'+args._n4_auth.split(':')[0] if args._n4_auth else ''}",
           f"POST :{BE_HTTP}/api/update_config?enable_token_check=false -> http {status}: {text[:80]}")
    return {"http": status, "applied": ok}


def n4_leaked(r):
    return bool(r["applied"])


def restore_token_check(auth=None):
    try:
        http_req("POST", BE_HTTP, "/api/update_config?enable_token_check=true", auth=auth, timeout=8)
    except OSError:
        pass


def mk_n5(when, auth):
    """GET /api/_download_load?file=<segment> with no token. LEAK only when the real tablet file is served
    (200 and its sha256 matches what probe.sh computed as root). 'after' restores enable_token_check at once."""
    def actual():
        path = "/api/_download_load?file=" + _urlquote(args.seg_path)
        try:
            status, body = http_req("GET", BE_HTTP, path, auth=auth)
            sha = hashlib.sha256(body).hexdigest()
            served = status == 200 and sha == args.seg_sha
            detail(f"N5-{when}{'/'+auth.split(':')[0] if auth else ''}",
                   f"GET _download_load (no token) -> http {status}, sha match: {served} ({sha[:12]} vs {args.seg_sha[:12]})")
            return {"http": status, "served": served}
        finally:
            if when == "after":
                restore_token_check(auth=None)   # restore right after N5-after, whatever it saw
    return actual, (lambda r: bool(r["served"]))


def n5_sight():
    return REACHABLE_BE and bool(args.seg_sha) and bool(args.seg_path)


def _urlquote(s):
    out = []
    for ch in s:
        if ch.isalnum() or ch in "-_.~/":
            out.append(ch)
        else:
            out.append("".join(f"%{b:02X}" for b in ch.encode()))
    return "".join(out)


def n6_actual():
    # brpc built-in services on the BE's brpc port. "not served" is egret-desired; recorded either way.
    out = {}
    for page in ("/flags", "/vars"):
        try:
            status, body = http_req("GET", BRPC, page, timeout=8)
            out[page] = f"http {status}, {len(body)} bytes"
        except OSError as e:
            out[page] = f"not served over HTTP ({type(e).__name__})"
    detail("N6", f":{BRPC} brpc built-ins {out}")
    return out


def n6_leaked(out):
    return any(isinstance(v, str) and v.startswith("http 200") for v in out.values())


def n6_sight():
    return tcp_open(BRPC)


def n7_actual():
    # Reachability only (recorded): which engine ports accept a TCP handshake from a namespace peer.
    ports = {"be_thrift 9060": BE_THRIFT, "heartbeat 9050": HEARTBEAT, "brpc 8060": BRPC,
             "9070": PORT_9070, "fe_thrift 9020": FE_THRIFT}
    seen = {name: ("open" if tcp_open(p) else "closed") for name, p in ports.items()}
    detail("N7", seen)
    return seen


def n8_actual():
    # getDbNames with current_user_ident = root, then = eve (H6). egret-desired: no 'demo' for either.
    # The FE trusting the request-supplied identity shows as 'demo' appearing. The mutant feeds the eve
    # slot with root's identity: 'demo' then appears, proving the predicate reads the identity field.
    out = {}
    for who, ident in (("root", "root"), ("eve", "root" if args.mutant_n8_root else "eve")):
        kind, body = thrift_call(FE_THRIFT, "getDbNames", write_getdbnames(ident, "%"))
        if kind == "exception":
            out[who] = f"TApplicationException {body}"
        else:
            dbs = body.get(0) if isinstance(body.get(0), dict) else {}
            names = sorted(b.decode(errors="replace") for b in dbs.get(1, []) if isinstance(b, bytes))
            out[who] = names
        detail(f"N8-{who}", f"getDbNames(ident={ident}) -> {out[who]}")
    return out


def n8_leaked(out):
    # A credential-less thrift caller getting 'demo' back for any supplied identity is the leak.
    return any(isinstance(v, list) and "demo" in v for v in out.values())


def n8_sight():
    return REACHABLE_THRIFT


def n9_actual():
    # forward(TMasterOpRequest as root, SELECT 1) (H6): expected ENFORCED ("request from invalid host").
    kind, body = thrift_call(FE_THRIFT, "forward", write_forward("root", "", "SELECT 1"))
    strings = []
    collect_strings(body, strings)
    joined = " | ".join(s for s in strings if s)
    detail("N9", f"forward -> {kind}: {joined[:160]}")
    return {"kind": kind, "text": joined}


REJECTION_MARKERS = ("invalid host", "not master", "not a leader", "non-leader", "access denied",
                     "denied", "forbidden", "unauthorized", "is not a frontend", "request from invalid")


def n9_leaked(r):
    low = r["text"].lower()
    if r["kind"] == "exception":
        return False
    if any(m in low for m in REJECTION_MARKERS):
        return False
    return True   # a reply with no rejection means the FE forwarded the statement for a namespace peer


def n10_show_actual():
    status, body = http_req("GET", FE_HTTP, "/api/show_proc?path=/backends", auth=args._n10_auth)
    text = body.decode(errors="replace")
    detail(f"N10-show_proc{'/'+args._n10_auth.split(':')[0] if args._n10_auth else ''}",
           f"GET :{FE_HTTP}/api/show_proc?path=/backends -> http {status}: {text[:90]}")
    return {"http": status, "has_backend": ("BackendId" in text or "\"IP\"" in text or "Alive" in text)}


def n10_show_leaked(r):
    return r["http"] == 200 and r["has_backend"]


def n10_metrics_actual():
    # FE /metrics is recorded: whether it names tables or users (not just metric names).
    status, body = http_req("GET", FE_HTTP, "/metrics", auth=args._n10_auth)
    text = body.decode(errors="replace")
    names = [t for t in ("demo", "customers", "orders", "alice", "bob", "eve", "loader", "mallory")
             if t in text]
    detail("N10-metrics", f"GET :{FE_HTTP}/metrics -> http {status}, {len(body)} bytes, identifiers seen: {names}")
    return {"http": status, "names": names}


def n10_metrics_leaked(r):
    return r["http"] == 200 and bool(r["names"])


def fe_sight():
    return REACHABLE_FE


def n11_actual():
    # /api/_stop_be, last and only in the throwaway allin1 container. 401 under BE_HTTP_AUTH; otherwise it
    # stops the BE (the heartbeat drops in SHOW BACKENDS -- probe.sh records that after this script exits).
    status, body = http_req("GET", BE_HTTP, "/api/_stop_be", auth=args._n11_auth, timeout=10)
    text = body.decode(errors="replace")
    detail(f"N11{'/'+args._n11_auth.split(':')[0] if args._n11_auth else ''}",
           f"GET :{BE_HTTP}/api/_stop_be -> http {status}: {text[:80]}")
    return {"http": status}


def n11_leaked(r):
    return r["http"] == 200


def skip_line(cid, name, reason):
    print(f"SKIP  [probe:{IN.value}]  {cid} {name}  {reason}")


def build_checks():
    checks = []

    def add(cid, name, sight, actual, leaked):
        checks.append(ProbeCheck(cid, IN, name, sight, actual, leaked))

    add("N1", "GET :8040/api/health (reachability control for N2-N11)", lambda: True, n1_actual, lambda r: False)
    if args.auth:
        add("N1-eve", "GET :8040/api/health with eve's credentials (needs only a login)", be_sight,
            n1_eve_actual, lambda r: False)

    a2, l2 = mk_http_get("N2", BE_HTTP, "/varz", None)
    add("N2", "GET :8040/varz without credentials (H4)", be_sight, a2, l2)
    if args.auth:
        ea2, el2 = mk_http_get("N2", BE_HTTP, "/varz", args.auth)
        add("N2-eve", "GET :8040/varz with eve's credentials (H4)", be_sight, ea2, el2)

    a3, l3 = mk_http_get("N3", BE_HTTP, f"/greplog?pattern={_urlquote(args.n3_pattern)}", None, want_marker=args.n3_pattern)
    add("N3", "GET :8040/greplog (BE log) without credentials", n3_sight, a3, l3)
    if args.auth:
        ea3, el3 = mk_http_get("N3", BE_HTTP, f"/greplog?pattern={_urlquote(args.n3_pattern)}", args.auth,
                               want_marker=args.n3_pattern)
        add("N3-eve", "GET :8040/greplog with eve's credentials", n3_sight, ea3, el3)

    add("N6", "GET :8060/flags and /vars (brpc built-ins): not served", n6_sight, n6_actual, n6_leaked)
    add("N7", "TCP reachability of 9060/9050/8060/9070/9020 (recorded)", lambda: True, n7_actual, lambda r: False)
    add("N8", "FE thrift getDbNames as root then eve (H6): no demo for either", n8_sight, n8_actual, n8_leaked)
    add("N9", "FE thrift forward(root, SELECT 1) (H6 control): rejected", n8_sight, n9_actual, n9_leaked)
    add("N10-show_proc", "GET :8030/api/show_proc?path=/backends without credentials", fe_sight,
        n10_show_actual, n10_show_leaked)
    add("N10-metrics", "GET :8030/metrics without credentials (recorded)", fe_sight,
        n10_metrics_actual, n10_metrics_leaked)

    # Destructive block: N5-before, N4, N5-after (+ restore), then N11 last.
    if args.no_destructive:
        for cid, name in (("N4", "POST :8040/api/update_config enable_token_check=false (H5)"),
                          ("N5-before", "GET :8040/api/_download_load before N4 (H5)"),
                          ("N5-after", "GET :8040/api/_download_load after N4 (H5)"),
                          ("N11", "GET :8040/api/_stop_be (OPERATE, last)")):
            skip_line(cid, name, "--no-destructive")
        return checks, []

    a5b, l5b = mk_n5("before", None)
    add("N5-before", "GET :8040/api/_download_load (no token) before N4 (H5)", n5_sight, a5b, l5b)
    if args.auth:
        ea5b, el5b = mk_n5("before", args.auth)
        add("N5-before-eve", "GET :8040/api/_download_load (eve, no token) before N4", n5_sight, ea5b, el5b)

    add("N4", "POST :8040/api/update_config enable_token_check=false (H5)", be_sight, n4_actual, n4_leaked)
    if args.auth:
        def ea4():
            prev = args._n4_auth
            args._n4_auth = args.auth
            try:
                return n4_actual()
            finally:
                args._n4_auth = prev
        add("N4-eve", "POST :8040/api/update_config (eve): OPERATE stays refused", be_sight, ea4, n4_leaked)

    a5a, l5a = mk_n5("after", None)
    add("N5-after", "GET :8040/api/_download_load (no token) after N4 (H5)", n5_sight, a5a, l5a)
    if args.auth:
        ea5a, el5a = mk_n5("after", args.auth)
        add("N5-after-eve", "GET :8040/api/_download_load (eve, no token) after N4", n5_sight, ea5a, el5a)

    # N11 last. In the auth variant the eve pass is appended after the anon pass, still last.
    last = [ProbeCheck("N11", IN, "GET :8040/api/_stop_be without credentials (last)", be_sight, n11_actual, n11_leaked)]
    if args.auth:
        def e11():
            prev = args._n11_auth
            args._n11_auth = args.auth
            try:
                return n11_actual()
            finally:
                args._n11_auth = prev
        last.append(ProbeCheck("N11-eve", IN, "GET :8040/api/_stop_be with eve's credentials (OPERATE stays refused)",
                               be_sight, e11, n11_leaked))
    return checks, last


def n3_sight():
    return REACHABLE_BE and args.n3_sight == "ok" and bool(args.n3_pattern)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("host")
    p.add_argument("run_id")
    p.add_argument("seg_path")
    p.add_argument("seg_sha")
    p.add_argument("n3_pattern")
    p.add_argument("--auth", default=None, help="user:pw sent as Basic auth in the mitigation variant")
    p.add_argument("--no-destructive", action="store_true", help="skip N4, N5 and N11 (Task 7 on kind)")
    p.add_argument("--mutant-n8-root", action="store_true", help="feed N8's eve slot with root's identity")
    p.add_argument("--n3-sight", default="ok", choices=("ok", "no"),
                   help="whether probe.sh confirmed the n3 pattern is in be.INFO")
    p.parse_args(namespace=args)
    # Per-check auth holders, default anonymous; the auth-variant checks flip them for their eve pass.
    args._n4_auth = None
    args._n10_auth = None
    args._n11_auth = None

    probe_reachability()
    print(f"reachability: BE :{BE_HTTP} {'up' if REACHABLE_BE else 'DOWN'} (health {BE_HEALTH}), "
          f"FE :{FE_HTTP} {'up' if REACHABLE_FE else 'DOWN'}, FE-thrift :{FE_THRIFT} "
          f"{'up' if REACHABLE_THRIFT else 'DOWN'}; auth={'eve' if args.auth else 'none'}, "
          f"destructive={'no' if args.no_destructive else 'yes'}")

    checks, last = build_checks()
    try:
        rc = run_checks(checks + last, set())
    finally:
        if not args.no_destructive:
            restore_token_check()  # belt-and-suspenders if N5-after did not run
    sys.exit(rc)


if __name__ == "__main__":
    main()
