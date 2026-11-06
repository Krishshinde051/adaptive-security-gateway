import re, httpx

H = {"Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
     "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"}

# 1. direct browser hit on :5001 bounces to gateway
r = httpx.get("http://127.0.0.1:5001/login", headers=H, follow_redirects=False, timeout=5)
print("1. direct 5001 ->", r.status_code, r.headers.get("location"))

# 2. follow to gateway
r2 = httpx.get("http://127.0.0.1:5001/login", headers=H, follow_redirects=True, timeout=5)
print("2. followed ->", r2.status_code, "(gateway logged it)")

# 3. MEDIUM request -> CAPTCHA html page
r3 = httpx.get("http://127.0.0.1:8080/profile?redirect=http://evil.com", headers=H, timeout=5)
print("3. medium ->", r3.status_code, "captcha page:", "Additional verification" in r3.text)
q = re.search(r'class="q">([^<]+)', r3.text)
tok = re.search(r"token:'([^']+)'", r3.text)
print("   question:", q.group(1) if q else None)

# 4. solve captcha and resend
if tok and q:
    a, b = [int(x) for x in re.findall(r"\d+", q.group(1))[:2]]
    ans = eval("%d%s%d" % (a, q.group(1)[len(str(a)):len(str(a))+1], b)) if False else None
    expr = re.sub(r"[^0-9+\-*/ ]", "", q.group(1))
    ans = eval(expr)
    r4 = httpx.post("http://127.0.0.1:8080/api/challenge",
                    json={"token": tok.group(1), "answer": ans}, timeout=5)
    print("4. solve ->", r4.status_code, r4.json())
    r5 = httpx.get("http://127.0.0.1:8080/profile?redirect=http://evil.com",
                   headers=H, cookies=r4.cookies, timeout=5)
    print("5. resend with clearance ->", r5.status_code)

# 6. dashboard sees everything
logs = httpx.get("http://127.0.0.1:8080/api/logs", params={"limit": 5}, timeout=5).json()
for l in logs["logs"]:
    resp = l.get("response") or {}
    print("   log id=%s %s %s -> %s score=%s http=%s resp_len=%s" %
          (l["id"], l["method"], l["url"][:60], l["action"], l["score"],
           l["status"], resp.get("length")))
