"""Phase 5-10 gate harness. Run: python test_phases.py"""
import json
import re
import sys
import time

import httpx

GW = "http://127.0.0.1:8080"
APP = "http://127.0.0.1:5001"
P = []


def ck(name, cond, detail=""):
    P.append((name, bool(cond), detail))
    print(("  PASS  " if cond else "  FAIL  ") + name + (("  | " + str(detail)[:160]) if detail else ""))


def unblock():
    try:
        httpx.post(GW + "/api/unblock", json={"ip": "127.0.0.1"}, timeout=5)
    except Exception:
        pass


def reset():
    try:
        httpx.post(GW + "/api/reset", json={}, timeout=5)
    except Exception:
        pass
    unblock()


def g(path, hdrs=None, t=15):
    return httpx.get(GW + path, headers=hdrs or {}, timeout=t, follow_redirects=False)


def post(path, data, hdrs=None, t=15):
    return httpx.post(GW + path, json=data, headers=hdrs or {}, timeout=t)


# =============================================================== PHASE 5
def phase5():
    print("\n--- PHASE 5 threat intelligence")
    reset()
    t0 = time.time()
    r = g("/api/health")
    ck("5.1 health responds fast (no VT hang)", r.status_code == 200 and time.time() - t0 < 2,
       "%.2fs" % (time.time() - t0))

    t0 = time.time()
    r = g("/login")
    lat = time.time() - t0
    ck("5.1b proxied request fast for private IP (VT skipped)",
       r.status_code == 200 and lat < 4, "%s in %.2fs" % (r.status_code, lat))

    h = httpx.get(GW + "/api/health", timeout=5).json()
    ck("5.2 no VT lookups for private client IP",
       h["threat_intel"]["lookups"] == 0, json.dumps(h["threat_intel"]))

    r = post("/api/reputation", {"ip": "127.0.0.1", "note": "phase5 test"})
    ck("5.3a local reputation blacklisted", r.json().get("ok") is True)
    r = g("/login")
    body = r.text if r.status_code == 200 else ""
    try:
        body = json.dumps(r.json())
    except Exception:
        pass
    ck("5.3b blacklisted source hard-blocked at 2.3",
       r.status_code == 403 and "Threat intelligence" in body, body[:200])
    r = httpx.get(GW + "/api/logs?limit=3", timeout=5).json()["logs"]
    ck("5.3c block recorded with threat category",
       any(l.get("category") == "malicious_source" for l in r),
       [l.get("category") for l in r])
    post("/api/reputation", {"remove": "127.0.0.1"})
    unblock()
    r = g("/login")
    ck("5.3d released after removal", r.status_code == 200, r.status_code)


# =============================================================== PHASE 6
def phase6():
    print("\n--- PHASE 6 dashboard & audit log")
    reset()
    r = httpx.get(GW + "/", timeout=5)
    ok = r.status_code == 200 and "Adaptive Security Gateway" in r.text
    ck("6.1 setup/dashboard page served", ok)
    for p in ("/login", "/api/items", "/search?q=laptop"):
        g(p)
    post("/login", {})          # may 500/401 upstream, still logged
    logs = httpx.get(GW + "/api/logs?limit=50", timeout=5).json()["logs"]
    ck("6.2 requests logged", len(logs) >= 3, len(logs))
    need = ["id", "ts", "ip", "method", "url", "action", "status", "score",
            "severity", "category", "reason", "tier", "components", "body",
            "ml", "target", "duration_ms"]
    miss = [k for k in need if k not in (logs[0] if logs else {})]
    ck("6.3 record carries payload + reason + breakdown", not miss, "missing %s" % miss)
    has_ml = logs[0].get("ml", {}).get("proba_attack") is not None
    ck("6.4 RF probability present per record", has_ml, logs[0].get("ml"))
    st = httpx.get(GW + "/api/stats", timeout=5).json()
    ck("6.5 stats segregate stage-4 outputs",
       set(st.get("by_action", {})) <= {"ALLOW", "MONITOR", "CHALLENGE", "BLOCK", "ERROR"}
       and st.get("total", 0) > 0, st.get("by_action"))
    # a blocked request must expose WHY (honeytoken path is a guaranteed BLOCK)
    g("/admin-backup")
    logs = httpx.get(GW + "/api/logs?limit=10", timeout=5).json()["logs"]
    blk = [l for l in logs if l.get("action") == "BLOCK"]
    if blk:
        l = blk[0]
        ck("6.6 blocked record shows components + reason",
           l.get("components") and l.get("reason") and l.get("score", 0) > 0,
           "%s / %s" % (l.get("score"), (l.get("reason") or "")[:60]))
    else:
        ck("6.6 blocked record shows components + reason", False, "no BLOCK captured")


# =============================================================== PHASE 7
def phase7():
    print("\n--- PHASE 7 exploit proof: vulnerable directly, caught by gateway")
    reset()
    # direct (no gateway)
    d = httpx.post(APP + "/login", data={"user": "' OR '1'='1' --", "pass": "x"},
                   timeout=5, follow_redirects=False)
    ck("7.1 app is SQLi-vulnerable directly (200 welcome)",
       d.status_code == 200 and "Welcome" in d.text, d.status_code)
    d = httpx.get(APP + "/search", params={"q": "<script>alert(1)</script>"}, timeout=5)
    ck("7.2 app is XSS-vulnerable directly (raw script echoed)",
       "<script>alert(1)</script>" in d.text, d.status_code)
    d = httpx.get(APP + "/download", params={"file": "../../config.json"}, timeout=5)
    ck("7.3 app is traversal-vulnerable directly", "gateway_port" in d.text, d.status_code)
    d = httpx.get(APP + "/run", params={"cmd": "hi & whoami"}, timeout=6)
    ck("7.4 app is command-injection-vulnerable directly",
       d.status_code == 200 and "whoami" in d.text.lower() or "hi" in d.text, d.status_code)

    # through gateway -> must not be allowed
    cases = [
        ("7.5 SQLi blocked via gateway", "POST", "/login",
         {"user": "' OR '1'='1' --", "pass": "x"}),
    ]
    for name, m, p, data in cases:
        r = httpx.post(GW + p, data=data, timeout=10, follow_redirects=False)
        bad = r.status_code in (200,) and "Welcome" in r.text
        ck(name, r.status_code in (401, 403) and not bad, r.status_code)
    r = g("/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    ck("7.6 XSS blocked via gateway",
       r.status_code in (401, 403) and "<script>alert(1)</script>" not in r.text, r.status_code)
    r = g("/download?file=..%2F..%2F..%2F..%2Fconfig.json")
    ck("7.7 traversal blocked via gateway",
       r.status_code in (401, 403) and "gateway_port" not in r.text, r.status_code)
    r = g("/run?cmd=hi%20%26%20whoami")
    ck("7.8 command injection blocked via gateway",
       r.status_code in (401, 403) and "whoami" not in r.text, r.status_code)


# =============================================================== PHASE 8
def phase8():
    print("\n--- PHASE 8 application discovery / profiler")
    r = post("/api/profile", {"url": APP}, t=45)
    data = r.json()
    if not data.get("ok"):
        ck("8.1 profile built", False, data.get("detail"))
        return
    p = data["profile"]
    ck("8.1 profile built", p.get("endpoints", 0) >= 3, p.get("endpoints"))
    ck("8.2 stack fingerprinted", bool(p.get("stack")), p.get("stack"))
    ck("8.3 parameter vocabulary mapped", len(p.get("params", [])) >= 3, p.get("params"))
    ck("8.4 endpoints clustered (ML)", "DBSCAN" in str(p.get("cluster_method")),
       p.get("cluster_method"))
    ck("8.5 adaptations emitted", bool(p.get("adaptations")),
       [a["key"] for a in p.get("adaptations", [])])
    ck("8.6 thresholds adapted", p.get("thresholds", {}).get("block", 0) >= 81,
       p.get("thresholds"))
    s = httpx.get(GW + "/api/profile", timeout=5).json()
    ck("8.7 profile persisted for dashboard",
       bool(s.get("current") and s["current"].get("adaptations")))


# =============================================================== PHASE 9
def phase9():
    print("\n--- PHASE 9 decoy / honeytoken")
    reset()
    r = g("/login")
    m = re.search(r"/internal/agent/exec\?k=([A-Za-z0-9_\-]+)", r.text)
    ck("9.1 canary planted in proxied HTML", bool(m), (m.group(1)[:12] + "…") if m else "none")
    if m:
        tok = m.group(1)
        r2 = g("/internal/agent/exec?k=" + tok)
        ck("9.2 canary hit -> BLOCK at 4.2", r2.status_code == 403 and
           "Honeytoken" in r2.text, r2.status_code)
        r3 = g("/login")
        ck("9.3 canary hit escalates IP to blocklist",
           r3.status_code == 403 and "blocked" in r3.text.lower(), r3.status_code)
        unblock()
    else:
        ck("9.2 canary hit -> BLOCK at 4.2", False, "no canary")
        ck("9.3 canary hit escalates IP to blocklist", False, "no canary")
    r = g("/admin-backup")
    ck("9.4 decoy path -> BLOCK", r.status_code == 403, r.status_code)
    unblock()
    r = g("/api/assistant/chat")
    ck("9.5 decoy persona engages", r.status_code in (200, 403),
       r.status_code)
    if r.status_code == 200:
        try:
            j = r.json()
            ck("9.6 persona is inert (aegis.decoy flag, no tools)",
               j.get("aegis", {}).get("decoy") is True, j.get("aegis"))
        except Exception:
            ck("9.6 persona is inert (aegis.decoy flag, no tools)", False, "not json")
    unblock()


# =============================================================== PHASE 10
def phase10():
    print("\n--- PHASE 10 end-to-end through the gateway")
    reset()
    r = g("/login")
    ck("10.1 benign request forwarded (4.1)", r.status_code == 200, r.status_code)
    logs = httpx.get(GW + "/api/logs?limit=1", timeout=5).json()["logs"]
    if logs:
        ck("10.1b benign scored LOW and ALLOW",
           logs[0]["action"] in ("ALLOW", "MONITOR") and logs[0]["score"] < 31,
           "%s/%s" % (logs[0]["score"], logs[0]["action"]))

    r = httpx.post(GW + "/login", data={"user": "' OR '1'='1' --", "pass": "x"},
                   timeout=10, follow_redirects=False)
    ck("10.2 attack scored high and BLOCKED (4.2)",
       r.status_code == 403 and r.json().get("score", 0) >= 81,
       "%s/%s" % (r.status_code, r.json().get("score")))

    # medium band -> CAPTCHA -> solve -> forward
    candidates = [
        ("/redirect?url=https://evil.example.com", "open-redirect"),
        ("/search?q=%22%20onmouseover%3Dalert(1)%20x%3D%22", "xss-probe"),
        ("/search?q=union%20select%20password%20from%20users", "sqli-probe"),
        ("/profile?id=1%20or%201%3D1", "sqli-or"),
        ("/?q=../../etc/passwd", "traversal-probe"),
    ]
    token = answer = None
    for path, label in candidates:
        rr = g(path, hdrs={"accept": "application/json"})
        if rr.status_code == 401:
            try:
                j = rr.json()
            except Exception:
                j = {}
            if j.get("token"):
                token, answer, used = j["token"], j["question"], label
                break
    ck("10.3 medium/unsure request -> CAPTCHA (4.3)", bool(token),
       "candidate=%s" % (used if token else "none hit 401"))
    if token:
        m = re.match(r"(\d+)\s*([-+*])\s*(\d+)", str(answer))
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        ans = {"+": a + b, "-": a - b, "*": a * b}[op]
        cr = post("/api/challenge", {"token": token, "answer": ans})
        ck("10.4 CAPTCHA solved -> clearance issued",
           cr.status_code == 200 and cr.json().get("ok") is not False, cr.json())
        cookie = ""
        for k, v in cr.headers.items():
            if k.lower() == "set-cookie" and "aegis_clear=" in v:
                cookie = v.split("aegis_clear=")[1].split(";")[0]
        ck("10.5 clearance cookie bound to client", bool(cookie), cookie[:16])
        if cookie:
            rr2 = g(used and candidates[[c[1] for c in candidates].index(used)][0],
                    hdrs={"cookie": "aegis_clear=" + cookie, "accept": "application/json"})
            ck("10.6 cleared request forwarded (not re-challenged)",
               rr2.status_code != 401, rr2.status_code)
        unblock()

    # double-encoded payload
    r = g("/search?q=%2527%2520OR%2520%25271%2527%253D%25271")
    allowed = r.status_code == 200 and "' OR '1'='1" in r.text
    ck("10.7 double-encoded payload caught after decoding",
       not allowed and r.status_code in (401, 403), r.status_code)

    # reputation block then honey escalation (last, it blocks our IP)
    post("/api/reputation", {"ip": "127.0.0.1", "note": "e2e"})
    r = g("/login")
    ck("10.8 malicious source blocked at 2.3", r.status_code == 403 and
       "Threat" in r.text, r.status_code)
    post("/api/reputation", {"remove": "127.0.0.1"})
    unblock()

    r = g("/admin-backup")
    r2 = g("/login")
    ck("10.9 honeytoken IP escalation -> tier-1 blocklist on next request",
       r.status_code == 403 and r2.status_code == 403 and "1-blocklist" in r2.text,
       "%s then %s" % (r.status_code, r2.status_code))
    unblock()


def main():
    reset()
    for fn in (phase5, phase6, phase7, phase8, phase9, phase10):
        try:
            fn()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            ck(fn.__name__ + " completed without exception", False, exc)
    fails = [p for p in P if not p[1]]
    print("\n" + "=" * 64)
    print("PHASE 5-10 GATE: %s  (%d/%d checks passed)"
          % ("PASS" if not fails else "FAIL", len(P) - len(fails), len(P)))
    for n, _, d in fails:
        print("  FAILED: %s  ->  %s" % (n, d))
    print("=" * 64)
    sys.exit(1 if fails else 0)


if __name__ == "__main__":
    main()
