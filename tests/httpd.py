#!/usr/bin/env python3

import sys

try:
    from http.server import *
except ImportError:
    from BaseHTTPServer import *

STORE = {}

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        val = STORE.get(self.path, None)
        if val is not None:
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", "%d" % len(val))
            self.end_headers()
            self.wfile.write(val)
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_PUT(self):
        try:
            cl = int(self.headers['Content-Length'])
            STORE[self.path] = self.rfile.read(cl)
            self.send_response(200)
        except ValueError:
            self.send_response(400)

        self.send_header("Content-Length", "0")
        self.end_headers()

httpd = HTTPServer(("", int(sys.argv[1])), Handler)
httpd.serve_forever()
