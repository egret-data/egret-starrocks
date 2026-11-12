"""An egress canary: canary.py <dir> <port> <log>.

GET /files/<name> serves <dir>/<name> (the JDBC driver). Any other request gets 200 and
appends "<path> <peer>" to <log>, which the checks read with probe_lib.canary_hits."""
import http.server
import os
import sys

ROOT = os.path.realpath(sys.argv[1])
LOG = sys.argv[3]
FILES = "/files/"


class Handler(http.server.BaseHTTPRequestHandler):
    def reply(self, status, body=b""):
        self.send_response(status)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith(FILES):
            path = os.path.realpath(os.path.join(ROOT, self.path[len(FILES):].split("?")[0]))
            if path.startswith(ROOT + os.sep) and os.path.isfile(path):
                with open(path, "rb") as f:
                    self.reply(200, f.read())
            else:
                self.reply(404)
            return
        with open(LOG, "a") as f:
            f.write(f"{self.path} {self.client_address[0]}\n")
        self.reply(200, b"canary\n")

    do_POST = do_PUT = do_HEAD = do_GET

    def log_message(self, fmt, *args):
        pass


http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[2])), Handler).serve_forever()
