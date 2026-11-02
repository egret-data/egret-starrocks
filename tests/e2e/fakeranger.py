"""A Ranger Admin stand-in: serves one policy JSON on the plugin's download endpoint."""
import http.server
import sys

BODY = open(sys.argv[1], "rb").read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if "/service/plugins/policies/download/" in self.path:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(BODY)))
            self.end_headers()
            self.wfile.write(BODY)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write(self.path + "\n")


http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[2])), Handler).serve_forever()
