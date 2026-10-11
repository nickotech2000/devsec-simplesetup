#!/usr/bin/env python3
# pki-ocsp-dispatch.py  -  ONE OCSP URL for SEVERAL issuing CAs.
# The certificates carry a single OCSP URL (http://ocsp.nextmantra.internal). An OCSP request names its issuer only by hash,
# so nginx cannot choose the right responder. This dispatcher offers the request to every `openssl ocsp` responder
# (one per CA, 127.0.0.1:<port>) and returns the first answer that is not "unauthorized" (the CA does not match).
# Because OpenSSL 4 answers "unknown" (status successful) for a certificate of another CA, the backends file also carries the SHA-1
# hash of each CA's public key: the request names its issuer by that hash, so the matching responder is asked first (and alone).
# Usage: pki-ocsp-dispatch.py <backends-file> [listen-port]
#   backends-file: one responder per line:  <port> [<issuer key hash, hex>]   (re-read on every request)
# Agantra Inovatif OU  -  Nicko Satria Utama  -  nicko@nextmantra.com
import http.client, http.server, socketserver, sys, os, base64, urllib.parse

UNAUTHORIZED = bytes([0x30, 0x03, 0x0A, 0x01, 0x06])   # OCSPResponse { responseStatus unauthorized }

def status_of(b):
    if len(b) < 5 or b[0] != 0x30:
        return None
    i = 1
    l = b[i]
    i += (1 + (l & 0x7F)) if (l & 0x80) else 1
    if i + 2 < len(b) and b[i] == 0x0A and b[i + 1] == 1:
        return b[i + 2]
    return None

def backends(path):
    out = []
    try:
        for line in open(path):
            line = line.strip()
            f = line.split()
            if f and f[0].isdigit():
                out.append((int(f[0]), bytes.fromhex(f[1]) if len(f) > 1 else None))
    except OSError:
        pass
    return out

class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "pki-ocsp-dispatch"
    protocol_version = "HTTP/1.0"

    def _answer(self, body):
        self.send_response(200)
        self.send_header("Content-Type", "application/ocsp-response")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _dispatch(self, method, body):
        best = None
        req = body
        if req is None:
            try:
                req = base64.b64decode(urllib.parse.unquote(self.path.rsplit("/", 1)[-1]))
            except Exception:
                req = b""
        allb = backends(self.server.backends_file)
        mine = [b for b in allb if b[1] and b[1] in req]
        for port, _h in (mine if mine else allb):
            try:
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=8)
                hdr = {"Connection": "close"}
                if body is not None:
                    hdr["Content-Type"] = "application/ocsp-request"
                c.request(method, self.path, body, hdr)
                data = c.getresponse().read()
                c.close()
            except Exception:
                continue
            st = status_of(data)
            if st == 0:
                return self._answer(data)
            if st is not None and st != 6 and best is None:
                best = data
        self._answer(best if best is not None else UNAUTHORIZED)

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n <= 0 or n > 65536:
            self.send_error(400, "bad length"); return
        self._dispatch("POST", self.rfile.read(n))

    def do_GET(self):
        if self.path in ("/", "/health"):
            b = ("pki-ocsp-dispatch: %d responder(s)\n" % len(backends(self.server.backends_file))).encode()
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b); return
        self._dispatch("GET", None)

    def log_message(self, fmt, *a):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2559
    srv = Server(("127.0.0.1", port), Handler)
    srv.backends_file = sys.argv[1]
    srv.serve_forever()
