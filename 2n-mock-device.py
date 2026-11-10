# 2n-mock-device.py - local stand-in for a 2N intercom firmware API, to test 2n-fw-update.ps1 without a device.
# Behaves as the 2N HTTP API manual 5.1.1 / 5.2.1-5.2.3 describes: system/info open without login, digest login
# (admin / testpw) elsewhere, PUT api/firmware (multipart blob-fw), apply?fileid=, reject?fileId=, 8 s restart gap.
# Usage: python 2n-mock-device.py <port> <running-version> <image-version> [reject]   ("reject" = refuse the file)
#   env MOCK_CERT + MOCK_KEY (PEM files) switch it to HTTPS. Listens on 127.0.0.1 only.
import hashlib, json, sys, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

port, ver, newver = int(sys.argv[1]), sys.argv[2], sys.argv[3]
reject = len(sys.argv) > 4
state = {"ver": ver, "down_until": 0, "uploaded": 0}
import base64, os
BASIC = bool(os.environ.get("MOCK_BASIC"))  # env MOCK_BASIC=1: device asks for Basic instead of Digest
USER, PW, REALM, NONCE = "admin", "testpw", "2N", "abc123"


class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def authed(self):
        h = self.headers.get("Authorization", "")
        if BASIC: return h == "Basic " + base64.b64encode(f"{USER}:{PW}".encode()).decode()
        if not h.startswith("Digest "): return False
        f = dict(x.strip().split("=", 1) for x in h[7:].split(","))
        f = {k: v.strip('"') for k, v in f.items()}
        ha1 = hashlib.md5(f"{USER}:{REALM}:{PW}".encode()).hexdigest()
        ha2 = hashlib.md5(f"{self.command}:{f['uri']}".encode()).hexdigest()
        exp = hashlib.md5(f"{ha1}:{NONCE}:{f['nc']}:{f['cnonce']}:auth:{ha2}".encode()).hexdigest()
        return f.get("response") == exp

    def reply(self, obj, code=200, hdr=None):
        b = json.dumps(obj).encode()
        self.send_response(code)
        for k, v in (hdr or {}).items(): self.send_header(k, v)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)

    def handle_any(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if time.time() < state["down_until"]:
            self.close_connection = True; self.connection.close(); return
        path = self.path.split("?")[0]; qs = self.path.partition("?")[2]
        if path == "/api/system/info":
            return self.reply({"success": True, "result": {"variant": "2N IP Verso", "swVersion": state["ver"]}})
        if not self.authed():
            return self.reply({"success": False, "error": {"code": 9, "description": "authorisation required"}}, 401,
                              {"WWW-Authenticate": 'Basic realm="2N"' if BASIC else f'Digest realm="{REALM}", nonce="{NONCE}", qop="auth"'})
        path = self.path.split("?")[0]
        if path == "/api/system/info":
            return self.reply({"success": True, "result": {"variant": "2N IP Verso", "swVersion": state["ver"]}})
        if path == "/api/firmware" and self.command == "PUT":
            if reject or b'name="blob-fw"' not in body:
                return self.reply({"success": False, "error": {"code": 12, "description": "invalid parameter value"}})
            state["uploaded"] = len(body)
            return self.reply({"success": True, "result": {"version": newver, "downgrade": newver < state["ver"], "fileId": "f1a2b3c4"}})
        if path == "/api/firmware/apply":
            if qs != "fileid=f1a2b3c4": return self.reply({"success": False, "error": {"code": 14, "description": "new firmware not found"}})
            state["ver"], state["down_until"] = newver, time.time() + 8
            return self.reply({"success": True})
        if path == "/api/firmware/reject":
            if qs != "fileId=f1a2b3c4": return self.reply({"success": False, "error": {"code": 14, "description": "new firmware not found"}})
            return self.reply({"success": True})
        self.reply({"success": False, "error": {"code": 1, "description": "function is not supported"}})

    do_GET = do_PUT = do_POST = handle_any


srv = ThreadingHTTPServer(("127.0.0.1", port), H)
import os, ssl
if os.environ.get("MOCK_CERT"):
    c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain(os.environ["MOCK_CERT"], os.environ["MOCK_KEY"])
    srv.socket = c.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()
