"""A Ranger Admin stand-in: fakeranger.py <policies.json> <tags.json> <port>.

Serves the policy JSON on the plugin's policy download endpoint and the tags on its tag download endpoint
(either, plain or secure), and logs every request path to stderr."""
import http.server
import sys

BODY = open(sys.argv[1], "rb").read()
TAGS = open(sys.argv[2], "rb").read()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = None
        if "/policies/download/" in self.path:
            body = BODY
        elif "/tags/" in self.path and "download" in self.path:
            body = TAGS
        if body is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write(self.path + "\n")


http.server.ThreadingHTTPServer(("0.0.0.0", int(sys.argv[3])), Handler).serve_forever()
