"""
Deliberately vulnerable demo target (port 5001) for the Adaptive Security Gateway.

Everything here is INTENTIONALLY broken so the gateway has something to catch.
Each flaw is labelled with its weakness and the payload that trips it.

  POST /login            SQL injection      string-concatenated query (sqlite)
  GET  /search           reflected XSS      unescaped echo of q= into HTML
  GET  /download         path traversal     joins user path inside ./sandbox
  GET  /run              command injection  os.system("echo " + cmd)
  GET  /profile          blind SQLi-ish     500 on apostrophe (error oracle)
  GET  /api/items        JSON API           benign, used as the forward-path proof

Run:  python demo-app/app.py         (binds 0.0.0.0:5001)
"""
import html
import os
import re
import socket
import sqlite3
import subprocess
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, unquote

PORT = 5001
HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX = os.path.join(HERE, "sandbox")

os.makedirs(SANDBOX, exist_ok=True)
for name, body in (("readme.txt", "demo sandbox file\n"),
                   ("notes.txt", "gateway training notes\n")):
    p = os.path.join(SANDBOX, name)
    if not os.path.exists(p):
        with open(p, "w") as f:
            f.write(body)

DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, user TEXT, pass TEXT, role TEXT)")
DB.executemany("INSERT INTO users (user, pass, role) VALUES (?,?,?)",
               [("alice", "wonderland", "user"), ("bob", "builder", "admin"),
                ("carol", "secret", "user"), ("dave", "hunter2", "user")])
DB.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, price INTEGER)")
DB.executemany("INSERT INTO items (name, price) VALUES (?,?)",
               [("laptop", 900), ("phone", 500), ("desk", 150),
                ("chair", 80), ("monitor", 220), ("keyboard", 45)])
DB.commit()

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Demo Shop</title><style>
body{font-family:system-ui,sans-serif;max-width:760px;margin:2rem auto;padding:0 1rem;color:#1a1a2e}
nav a{margin-right:1rem} .ok{color:#0a7d34} .bad{color:#b3261e}
input,button{font-size:1rem;padding:.4rem} code{background:#f1f1f4;padding:.1rem .3rem;border-radius:4px}
footer{margin-top:2rem;font-size:.85rem;color:#666;border-top:1px solid #e3e3e8;padding-top:.6rem}
</style></head><body>
<h1>Demo Shop</h1>
<nav><a href="/">Home</a><a href="/login">Login</a><a href="/search">Search</a>
<a href="/download?file=readme.txt">Download</a><a href="/run?cmd=hello">Run</a>
<a href="/api/items">API</a></nav>
{body}
<footer>Vulnerable demo target for the Adaptive Security Gateway &mdash; do not deploy.</footer>
</body></html>"""

ITEM_ROWS = "".join(
    "<tr><td>%s</td><td>$%d</td></tr>" % (n, p)
    for n, p in DB.execute("SELECT name, price FROM items ORDER BY id"))


def lan_ip():
    """IP of the interface that reaches the LAN (for the startup banner)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        return "127.0.0.1"


def render(body):
    return PAGE.replace("{body}", body).encode()


def do_login(parsed, method="GET", raw=b""):
    if method == "GET":
        return render("""<h2>Login</h2>
<form method="POST" action="/login">
<label>user <input name="user"></label><br><br>
<label>pass <input name="pass" type="password"></label><br><br>
<button type="submit">Sign in</button></form>""")
    qs = parse_qs(raw.decode("utf-8", "replace"))
    u = (qs.get("user") or qs.get("username") or [""])[0]
    p = (qs.get("pass") or qs.get("password") or [""])[0]
    # VULN: SQL injection - concatenated straight into the query
    query = "SELECT id, user, role FROM users WHERE user='%s' AND pass='%s'" % (u, p)
    try:
        rows = DB.execute(query).fetchall()
    except Exception as exc:
        return render('<h2>Login</h2><p class="bad">SQL error: %s</p>' % html.escape(str(exc))), 500
    if rows:
        uid, name, role = rows[0]
        return render('<h2>Login</h2><p class="ok">Welcome back <b>%s</b> (role: %s).</p>'
                      '<p>Account id <code>%d</code>.</p>' % (html.escape(name), role, uid))
    return render('<h2>Login</h2><p class="bad">Login failed for <code>%s</code>.</p>'
                  % html.escape(u)), 401


def do_search(parsed):
    q = (parse_qs(parsed.query).get("q", [""])[0])
    hits = [r for r in DB.execute("SELECT name FROM items WHERE name LIKE ?",
                                  ("%" + q + "%",))] if q else []
    rows = "".join("<li>%s</li>" % html.escape(n) for (n,) in hits) or "<li>none</li>"
    # VULN: reflected XSS - q is echoed raw above the escaped list
    return render("""<h2>Search</h2>
<form method="GET"><input name="q" value="%s" placeholder="search products">
<button type="submit">Go</button></form>
<p>Raw query: %s</p><ul>%s</ul>""" % (q, q, rows))


def do_download(parsed):
    fname = (parse_qs(parsed.query).get("file", ["readme.txt"])[0])
    rel = unquote(fname)
    # VULN: path traversal - the sandbox prefix is string-joined, not realpath-checked
    target = os.path.normpath(os.path.join(SANDBOX, rel))
    try:
        with open(target, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        return render('<h2>Download</h2><p>File <code>%s</code>:</p><pre>%s</pre>'
                      % (html.escape(rel), html.escape(data[:4000])))
    except Exception as exc:
        return render('<h2>Download</h2><p class="bad">Cannot read: %s</p>'
                      % html.escape(str(exc))), 404


def do_run(parsed):
    cmd = (parse_qs(parsed.query).get("cmd", ["hello"])[0])
    # VULN: command injection - os.system with the parameter appended
    out = subprocess.run("echo " + cmd, shell=True, capture_output=True, text=True, timeout=5)
    return render('<h2>Run</h2><p>$ <code>echo %s</code></p><pre>%s</pre>'
                  % (html.escape(cmd), html.escape(out.stdout + out.stderr)))


def do_profile(parsed):
    ident = (parse_qs(parsed.query).get("id", ["1"])[0])
    # VULN: error oracle - unescaped identifier makes sqlite throw
    row = DB.execute("SELECT user, role FROM users WHERE id=%s" % ident).fetchone()
    if row is None:
        return render("<h2>Profile</h2><p>No user with id <code>%s</code>.</p>"
                      % html.escape(ident)), 404
    return render("<h2>Profile</h2><p>%s / %s</p>" % row)


def do_index(parsed):
    return render("""<h2>Catalogue</h2>
<p>6 products in stock. Try the links above &mdash; every one of them is vulnerable on
purpose, so a request through the gateway shows up in the admin dashboard.</p>
<table><tr><th>Product</th><th>Price</th></tr>%s</table>
<p class="bad">Login SQLi example: <code>' OR '1'='1' -- </code> &middot;
Traversal: <code>../../config.json</code> &middot;
XSS: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code></p>""" % ITEM_ROWS)


def do_api(parsed):
    return ({"items": [{"name": n, "price": p}
                       for n, p in DB.execute("SELECT name, price FROM items ORDER BY id")]},
            200, "application/json")


ROUTES = {
    "/": do_index, "/login": do_login, "/search": do_search,
    "/download": do_download, "/run": do_run, "/profile": do_profile,
}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "DemoShop/1.0"

    def _send(self, data, status=200, ctype="text/html; charset=utf-8"):
        if isinstance(data, dict):
            import json as _j
            data = _j.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Demo-App", "vulnerable-on-purpose")
        self.end_headers()
        self.wfile.write(data)

    def _bounce_to_gateway(self):
        """Browser hits on :5001 are redirected (307) to the gateway so every
        request is inspected and visible on the dashboard. Requests coming FROM
        the gateway (x-requested-by) or non-browser clients (tests, profiler)
        are served directly."""
        if self.headers.get("x-requested-by") == "aegis-gateway":
            return False
        if "text/html" not in (self.headers.get("Accept") or ""):
            return False
        host = (self.headers.get("Host") or "127.0.0.1:5001").split(":")[0]
        target = self.path if self.path != "/" else "/login"
        self.send_response(307)
        self.send_header("Location", "http://%s:8090%s" % (host, target))
        self.send_header("Content-Length", "0")
        self.end_headers()
        return True

    def do_GET(self):
        if self._bounce_to_gateway():
            return
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        if path == "/api/items":
            d, s, c = do_api(parsed)
            return self._send(d, s, c)
        fn = ROUTES.get(path)
        if fn is None:
            return self._send(render("<h2>404</h2><p>No route <code>%s</code>.</p>"
                                     % html.escape(path)), 404)
        out = fn(parsed)
        if isinstance(out, tuple):
            return self._send(out[0], out[1])
        return self._send(out)

    def do_POST(self):
        if self._bounce_to_gateway():
            return
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        parsed = urlparse(self.path)
        if (parsed.path.rstrip("/") or "/") == "/login":
            out = do_login(parsed, "POST", raw)
            if isinstance(out, tuple):
                return self._send(out[0], out[1])
            return self._send(out)
        return self._send(render("<h2>405</h2><p>POST only supported on /login.</p>"), 405)

    def log_message(self, fmt, *args):
        print("[demo %s] %s" % (time.strftime("%H:%M:%S"), fmt % args))


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    print("=" * 60)
    print("  Vulnerable demo target")
    print("    PC   ->  http://127.0.0.1:%d" % PORT)
    print("    LAN  ->  http://%s:%d   (other devices on this network)" % (lan_ip(), PORT))
    print("  Endpoints: /login /search /download /run /profile /api/items")
    print("  Browsers hitting :5001 are bounced to the gateway on :8090")
    print("=" * 60)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
