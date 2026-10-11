#!/usr/bin/env python3
# pki-tsa.py  -  RFC 3161 time stamp authority over HTTP, using `openssl ts -reply`.
# POST application/timestamp-query  ->  application/timestamp-reply.   nginx proxies http://tsa.<domain>/ to this process.
# Usage: pki-tsa.py <openssl> <tsa.cnf> [listen-port]
# Agantra Inovatif OU  -  Nicko Satria Utama  -  nicko@nextmantra.com
import http.server, socketserver, subprocess, sys, tempfile, threading, os

LOCK = threading.Lock()   # openssl ts keeps the serial number in a file: one reply at a time

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "pki-tsa"
    protocol_version = "HTTP/1.0"

    def _text(self, code, text):
        b = text.encode()
        self.send_response(code); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)

    def do_GET(self):
        self._text(200, "Agantra Inovatif time stamp authority (RFC 3161). POST application/timestamp-query to this URL.\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 65536:
            return self._text(400, "bad request length\n")
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype not in ("application/timestamp-query", "application/octet-stream", ""):
            return self._text(415, "Content-Type must be application/timestamp-query\n")
        query = self.rfile.read(n)
        with tempfile.TemporaryDirectory(prefix="tsa-") as d:
            qf, rf = os.path.join(d, "q.tsq"), os.path.join(d, "r.tsr")
            with open(qf, "wb") as f:
                f.write(query)
            with LOCK:
                p = subprocess.run([self.server.openssl, "ts", "-reply", "-config", self.server.cnf, "-section", "tsa_config1",
                                    "-queryfile", qf, "-out", rf], capture_output=True, timeout=30)
            if p.returncode != 0 or not os.path.exists(rf):
                sys.stderr.write("openssl ts failed: %s\n" % p.stderr.decode(errors="replace")[:400])
                return self._text(500, "time stamping failed\n")
            body = open(rf, "rb").read()
        self.send_response(200); self.send_header("Content-Type", "application/timestamp-reply")
        self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    srv = Server(("127.0.0.1", int(sys.argv[3]) if len(sys.argv) > 3 else 2560), Handler)
    srv.openssl, srv.cnf = sys.argv[1], sys.argv[2]
    srv.serve_forever()
