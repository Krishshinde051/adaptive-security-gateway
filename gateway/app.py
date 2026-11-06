"""
ADAPTIVE SECURITY GATEWAY - main entry point.

Pipeline (each stage lives in its own file so the flow can be pointed at in a viva):

  STAGE 1  interception & parser          -> this file (_parse, _proxy)
           blocklist gate (pre-score)     -> decision.DecisionEngine.is_blocked
  STAGE 2  feature extraction             -> features.extract
     2.1  rule based detector             -> rules.scan / rules.score
     2.2  behavioural analysis            -> behaviour.Tracker / behaviour.score
     2.3  threat intelligence (IP/domain) -> threatintel.ThreatIntel.check  (may hard-block)
     2.4  deception / honeytokens         -> deception.Deception.match      (may hard-block)
  STAGE 3  risk scoring 0-100             -> scoring.Scorer.score
  STAGE 4  decision engine                -> decision.DecisionEngine.decide
           4.1 LOW     -> forward         4.2 HIGH -> 403   4.3 MEDIUM/unsure -> CAPTCHA
  STAGE 5  admin dashboard                -> /  + /api/*
"""
import json
import os
import re
import socket
import time
from collections import deque
from urllib.parse import unquote, unquote_plus, urljoin, urlparse

import httpx
import uvicorn
from fastapi import FastAPI, Request, Response
from fastapi.responses import (HTMLResponse, JSONResponse, PlainTextResponse,
                               RedirectResponse)
from fastapi.staticfiles import StaticFiles

import behaviour as B
import decision as D
import features as F
import rules as R
import scoring as S
import threatintel as TI

try:
    import deception as DEC
except Exception:                                  # pragma: no cover
    DEC = None
try:
    import profiler as PR
except Exception:                                  # pragma: no cover
    PR = None

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
CONFIG = os.path.join(BASE, "config.json")
STATE = os.path.join(BASE, "state")
LOG_FILE = os.path.join(STATE, "requests.json")
STATIC = os.path.join(HERE, "static")

HOP_BY_HOP = {"connection", "keep-alive", "transfer-encoding", "te", "trailer",
              "upgrade", "proxy-authenticate", "proxy-authorization",
              "content-encoding", "content-length", "accept-encoding"}
MAX_BODY = 2 * 1024 * 1024
MAX_LOG = 500

DEFAULT_CONFIG = {
    "gateway_port": 8080,
    "target_url": "http://127.0.0.1:5001",
    "trust_proxy": True,
    "upstream_proxy": "",
    "secret": "",
    "decision": {"block": 81, "challenge": 31, "unsure": 10,
                 "grey_zone": [0.45, 0.80], "mode": "block",
                 "captcha_ttl_s": 600, "captcha_max_attempts": 3},
    "scoring": {"ml_weight": 0.30, "ml_cap": 30, "iforest_cap": 15, "max": 100},
    "behaviour_cap": 25,
    "threat_intel": {"enabled": True, "vt_api_key": "", "timeout_s": 3.0,
                     "cache_hours": 24, "cap": 40},
    "blocklist": {"enabled": True, "ttl_hours": [1, 24, 168], "escalate_subnet": True},
    "deception": {"enabled": True, "inject": True, "auto_block": True},
    "profiler": {"enabled": True, "max_endpoints": 50, "rate_per_s": 2,
                 "allow_private": True, "depth": 2},
    "log_size": MAX_LOG,
}


def load_config():
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(CONFIG):
        try:
            with open(CONFIG, encoding="utf-8") as f:
                user = json.load(f)
            for k, v in user.items():
                if isinstance(v, dict) and isinstance(cfg.get(k), dict):
                    cfg[k] = {**cfg[k], **v}
                else:
                    cfg[k] = v
        except Exception as exc:
            print("[config] ignored invalid config.json: %s" % exc)
    return cfg


def save_config(cfg):
    with open(CONFIG, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


CFG = load_config()

scorer = S.Scorer(CFG)
engine = D.DecisionEngine(CFG)
tracker = B.Tracker()
intel = TI.ThreatIntel(CFG.get("threat_intel", {}))
deception = DEC.Deception(CFG.get("deception", {})) if DEC else None
profiler = PR.Profiler(CFG.get("profiler", {})) if PR else None

if profiler:
    # restore the most recent crawled profile so the dashboard survives a restart
    try:
        pdir = os.path.join(STATE, "profiles")
        if os.path.isdir(pdir):
            files = sorted((os.path.join(pdir, f) for f in os.listdir(pdir)
                            if f.endswith(".json")),
                           key=os.path.getmtime, reverse=True)
            if files:
                with open(files[0], encoding="utf-8") as f:
                    profiler.current = json.load(f)
    except Exception:
        pass

LOG = deque(maxlen=int(CFG.get("log_size", MAX_LOG)))
SEQ = {"n": 0}


def _persist_log():
    try:
        os.makedirs(STATE, exist_ok=True)
        with open(LOG_FILE, "w", encoding="utf-8") as f:
            json.dump(list(LOG), f)
    except Exception:
        pass


# ----------------------------------------------------------------------
# helpers
# ----------------------------------------------------------------------
def client_ip(request: Request):
    if CFG.get("trust_proxy"):
        xff = request.headers.get("x-forwarded-for")
        if xff:
            return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _public_headers(headers):
    return {k: v for k, v in headers.items() if k.lower() not in HOP_BY_HOP}


def categorise(hits, honey=None, threat=None, ml_flagged=False):
    if honey:
        return "ai_agent_probe"
    if threat and threat.get("malicious"):
        return "malicious_source"
    if hits:
        best = max(hits, key=lambda h: h["confidence"])
        return best["category"]
    return "attack_ml_only" if ml_flagged else "benign"


def _make_record(ctx):
    SEQ["n"] += 1
    return dict(ctx, id=SEQ["n"], ts=time.time())


_OL2 = re.compile(r"%(c[0-9a-f])%([89ab][0-9a-f])", re.IGNORECASE)
_OL3 = re.compile(r"%(e[0-9a-f])%([89ab][0-9a-f])%([89ab][0-9a-f])", re.IGNORECASE)


def _deobfuscate(text):
    """Collapse overlong / 2- and 3-byte percent-encoded UTF-8 before detection.

    %c0%af -> /  and  %c0%a0 -> space.  Python's unquote() would turn these into
    U+FFFD, so paths like ..%c0%af..%c0%afetc/passwd looked harmless to every rule
    while a normalising proxy or DB still resolved them to a real traversal.
    """
    def d3(m):
        b = [int(g, 16) for g in m.groups()]
        return chr(((b[0] & 0x0F) << 12) | ((b[1] & 0x3F) << 6) | (b[2] & 0x3F))

    def d2(m):
        b = [int(g, 16) for g in m.groups()]
        return chr(((b[0] & 0x1F) << 6) | (b[1] & 0x3F))

    return _OL3.sub(d3, _OL2.sub(d2, text))


def _scan_decode(raw, plus=False):
    """unquote twice (as before) but deobfuscate at every layer, so both
    %c0%a0 and double-encoded %25c0%25a0 get normalised."""
    step = unquote_plus if plus else unquote
    text = raw or ""
    for _ in range(2):
        text = step(_deobfuscate(text))
    return text


def _resp_summary(status, content_type, body):
    """Compact upstream/gateway response snapshot stored on every log record."""
    ct = str(content_type or "")
    if isinstance(body, (bytes, bytearray)):
        data = bytes(body)
        textlike = any(t in ct for t in ("text", "json", "html", "xml",
                                         "javascript", "css", "form-urlencoded"))
        if textlike or not ct:
            snippet = data[:1500].decode("utf-8", "replace")
        else:
            snippet = "<binary %d bytes>" % len(data)
    else:
        data = str(body or "").encode("utf-8", "replace")
        snippet = data[:1500].decode("utf-8", "replace")
    return {"status": int(status), "content_type": ct or "-",
            "length": len(data), "body": snippet}


# ----------------------------------------------------------------------
# STAGE 1 + full pipeline
# ----------------------------------------------------------------------
async def pipeline(request: Request, path: str):
    t_start = time.perf_counter()
    ip = client_ip(request)
    method = request.method.upper()
    url = "/" + path + (("?" + request.url.query) if request.url.query else "")

    # --- blocklist gate: checked before anything else (no ML, no proxy) ---
    blocked_entry = engine.is_blocked(ip)
    if blocked_entry:
        rec = _make_record({
            "method": method, "url": url, "ip": ip,
            "ua": request.headers.get("user-agent", ""),
            "action": D.BLOCK, "status": 403, "score": 100, "severity": "CRITICAL",
            "category": "blocked_ip",
            "reason": "IP already blocked: %s" % blocked_entry.get("reason", "-"),
            "tier": "1-blocklist", "components": {}, "rules": [], "ml": {},
            "body": "", "target": CFG.get("target_url"),
        })
        content = {
            "blocked": True, "score": 100, "action": "BLOCK",
            "reason": rec["reason"], "requestId": rec["id"],
            "tier": "1-blocklist", "ttl_hours": blocked_entry.get("ttl_hours"),
        }
        rec["response"] = _resp_summary(403, "application/json", json.dumps(content))
        LOG.appendleft(rec)
        _persist_log()
        return JSONResponse(status_code=403, content=content)

    # --- body ---
    body = b""
    if method not in ("GET", "HEAD"):
        try:
            body = await request.body()
        except Exception:
            body = b""
    if len(body) > MAX_BODY:
        body = body[:MAX_BODY]
    body_text = body.decode("utf-8", "replace")

    headers = {k: v for k, v in request.headers.items()}

    # --- STAGE 2.0 features (behaviour observed first so rpm is current) ---
    tracker.observe(ip, url.split("?")[0])
    beh = tracker.stats(ip)
    # scan the RAW request line: ASGI's scope["path"] is already percent-decoded
    # (invalid UTF-8 becomes U+FFFD), which would hide %c0%af-style obfuscation.
    raw_path = request.scope.get("raw_path") or b""
    raw_qs = request.scope.get("query_string") or b""
    raw_url = raw_path.decode("latin-1") or url
    if raw_qs:
        raw_url += "?" + raw_qs.decode("latin-1")
    scan_url = _scan_decode(raw_url)
    scan_body = _scan_decode(body_text, plus=True) if body_text else ""
    vec = F.extract(method, scan_url, headers, scan_body, beh)

    # --- STAGE 2.1 rules ---
    # a same-origin/private Referer is normal browsing, not an SSRF target:
    # only keep it in the scan material when it points somewhere external
    rule_headers = headers
    ref = headers.get("referer", "")
    if ref:
        try:
            ref_host = (urlparse(ref).hostname or "").lower()
        except Exception:
            ref_host = ""
        if (not ref_host or ref_host == "localhost" or ref_host == "::1"
                or ref_host.startswith(("127.", "192.168.", "10.", "172."))):
            rule_headers = {k: v for k, v in headers.items()
                            if k.lower() != "referer"}
    hits = R.scan(method, scan_url, scan_body, rule_headers)
    rule_points, rule_notes = R.score(hits, vec, scan_url + " " + scan_body)

    # --- STAGE 2.4 deception (honeytoken registry) ---
    honey = None
    if deception:
        honey = deception.match(request, url)

    # Class C decoy persona: engage the bot with the scripted reply, execute nothing
    if honey and honey.get("kind") == "persona" and deception:
        rec = _make_record({
            "method": method, "url": url, "ip": ip, "ua": headers.get("user-agent", ""),
            "action": "MONITOR", "status": 200, "score": 0, "severity": "LOW",
            "category": "decoy", "reason": honey.get("detail", "decoy persona engaged"),
            "tier": "2.4-deception", "components": {}, "rules": [], "ml": {},
            "body": body_text[:2000], "target": CFG.get("target_url"),
            "duration_ms": round((time.perf_counter() - t_start) * 1000, 2),
        })
        persona = deception.persona_reply(body_text)
        rec["response"] = _resp_summary(200, "application/json", json.dumps(persona))
        LOG.appendleft(rec)
        _persist_log()
        return JSONResponse(status_code=200, content=persona)

    # --- STAGE 2.3 threat intelligence (short-circuits on malicious) ---
    threat = intel.check(ip, referer=headers.get("referer"))
    threat_points = int(threat.get("points", 0))

    # --- STAGE 3 scoring (rules + ML + isoforest + behaviour + intel) ---
    beh_points, beh_notes = B.score(beh, {"behaviour_cap": CFG.get("behaviour_cap", 25)})
    score = scorer.score(vec, rule_points, beh_points, threat_points,
                         rule_notes, beh_notes)

    # --- STAGE 4 decision ---
    clearance = request.cookies.get("aegis_clear")
    decision = engine.decide(
        score["score"], score["severity"], score["ml"],
        threat_hard=bool(threat.get("hard_block")),
        honey_hit=honey,
        blocked_entry=blocked_entry,
        clearance_ok=engine.has_clearance(clearance, ip),
    )

    category = categorise(hits, honey, threat, score["ml"].get("flagged"))
    if category == "ai_agent_probe" and honey and honey.get("kind") == "bait":
        category = "decoy"

    # escalate IP after a deception/threat-intel hard block
    if decision["action"] == D.BLOCK and (honey or threat.get("hard_block")):
        if honey:
            engine.block_ip(ip, "followed honeytoken %s" % honey.get("path", "-"),
                            category="ai_agent_probe")
        elif threat.get("hard_block"):
            engine.block_ip(ip, threat.get("detail", "malicious source"),
                            category="malicious_source")

    duration = round((time.perf_counter() - t_start) * 1000, 2)

    # --- CHALLENGE (4.3) ---
    if decision["action"] == D.CHALLENGE:
        ch = engine.new_challenge(ip)
        rec = _make_record({
            "method": method, "url": url, "ip": ip, "ua": headers.get("user-agent", ""),
            "action": D.CHALLENGE, "status": 401, "score": score["score"],
            "severity": score["severity"], "category": category,
            "reason": decision["reason"], "tier": decision["tier"],
            "components": score["components"], "rules": hits, "ml": score["ml"],
            "isoforest": score["isoforest"], "notes": score["notes"],
            "explain": score["explainability"], "counterfactual": _cf(score, vec),
            "behaviour": beh, "threat": threat,
            "body": body_text[:2000], "target": CFG.get("target_url"),
            "duration_ms": duration, "features": dict(zip(F.FEATURES, vec)),
        })
        accept = headers.get("accept", "")
        if "text/html" in accept and "application/json" not in accept:
            html_content = _challenge_html(ch, url, rec)
            rec["response"] = _resp_summary(401, "text/html; charset=utf-8", html_content)
            LOG.appendleft(rec)
            _persist_log()
            return HTMLResponse(status_code=401, content=html_content)
        content = {
            "action": "CHALLENGE", "challenge": "captcha-required", "token": ch["token"],
            "question": ch["question"], "score": score["score"],
            "reason": decision["reason"], "requestId": rec["id"],
            "howto": "POST /api/challenge {token, answer} then resend with cookie aegis_clear",
        }
        rec["response"] = _resp_summary(401, "application/json", json.dumps(content))
        LOG.appendleft(rec)
        _persist_log()
        return JSONResponse(status_code=401, content=content)

    # --- BLOCK (4.2) ---
    if decision["action"] == D.BLOCK:
        rec = _make_record({
            "method": method, "url": url, "ip": ip, "ua": headers.get("user-agent", ""),
            "action": D.BLOCK, "status": 403, "score": score["score"],
            "severity": score["severity"], "category": category,
            "reason": decision["reason"], "tier": decision["tier"],
            "components": score["components"], "rules": hits, "ml": score["ml"],
            "isoforest": score["isoforest"], "notes": score["notes"],
            "explain": score["explainability"], "counterfactual": _cf(score, vec),
            "behaviour": beh, "threat": threat, "honeytoken": honey,
            "body": body_text[:2000], "target": CFG.get("target_url"),
            "duration_ms": duration, "features": dict(zip(F.FEATURES, vec)),
        })
        content = {
            "blocked": True, "action": "BLOCK", "score": score["score"],
            "severity": score["severity"], "category": category,
            "reason": decision["reason"], "tier": decision["tier"],
            "requestId": rec["id"],
            "components": score["components"],
            "topReasons": [t["label"] for t in score["explainability"]],
            "counterfactual": rec.get("counterfactual"),
        }
        rec["response"] = _resp_summary(403, "application/json", json.dumps(content))
        LOG.appendleft(rec)
        _persist_log()
        return JSONResponse(status_code=403, content=content)

    # --- 4.1 FORWARD (ALLOW / MONITOR) ---
    upstream_status, upstream_headers, upstream_body, err = await _proxy(
        request, method, url, headers, body)

    if upstream_status is None:
        rec = _make_record({
            "method": method, "url": url, "ip": ip, "ua": headers.get("user-agent", ""),
            "action": "ERROR", "status": 502, "score": score["score"],
            "severity": score["severity"], "category": category,
            "reason": "upstream error: %s" % err, "tier": "1-proxy",
            "components": score["components"], "rules": hits, "ml": score["ml"],
            "body": body_text[:2000], "target": CFG.get("target_url"),
            "duration_ms": duration,
        })
        content = {
            "error": "Bad Gateway", "detail": err, "target": CFG.get("target_url")}
        rec["response"] = _resp_summary(502, "application/json", json.dumps(content))
        LOG.appendleft(rec)
        _persist_log()
        return JSONResponse(status_code=502, content=content)

    tracker.observe_status(ip, upstream_status, url)

    # deception: seed honeytokens into the proxied response
    final_headers = _public_headers(upstream_headers)
    final_body = upstream_body
    seeded = []
    if deception and CFG.get("deception", {}).get("inject", True):
        final_body, seeded = deception.inject(final_headers, final_body, url)
        if seeded:
            final_headers.pop("content-length", None)

    rec = _make_record({
        "method": method, "url": url, "ip": ip, "ua": headers.get("user-agent", ""),
        "action": decision["action"], "status": upstream_status,
        "score": score["score"], "severity": score["severity"], "category": category,
        "reason": decision["reason"], "tier": decision["tier"],
        "components": score["components"], "rules": hits, "ml": score["ml"],
        "isoforest": score["isoforest"], "notes": score["notes"],
        "explain": score["explainability"], "counterfactual": _cf(score, vec),
        "behaviour": beh, "threat": threat,
        "body": body_text[:2000], "target": CFG.get("target_url"),
        "duration_ms": duration, "features": dict(zip(F.FEATURES, vec)),
        "seeded_decoys": len(seeded),
        "response": _resp_summary(upstream_status,
                                  final_headers.get("content-type", ""),
                                  final_body),
    })
    LOG.appendleft(rec)
    _persist_log()

    return Response(content=final_body, status_code=upstream_status,
                    headers=final_headers)


def _cf(score, vec):
    try:
        return scorer.counterfactual(vec, score["ml"]["proba_attack"],
                                     CFG["decision"]["challenge"] / 100.0)
    except Exception:
        return {"available": False}


async def _proxy(request, method, url, headers, body):
    target = CFG.get("target_url", "").rstrip("/")
    if not target:
        return None, {}, b"", "no target URL configured"
    dest = urljoin(target + "/", url.lstrip("/"))
    fwd = _public_headers(headers)
    fwd["host"] = urlparse(dest).netloc
    fwd["x-forwarded-for"] = client_ip(request)
    fwd["x-forwarded-proto"] = "http"
    fwd["x-requested-by"] = "aegis-gateway"
    proxy = CFG.get("upstream_proxy") or None
    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=False,
                                     proxy=proxy, trust_env=False) as client:
            r = await client.request(method, dest, headers=fwd,
                                     content=body if body else None)
        return r.status_code, dict(r.headers), r.content, None
    except Exception as exc:
        return None, {}, b"", "%s: %s" % (type(exc).__name__, exc)


def _challenge_html(ch, url, rec):
    return """<!doctype html><html><head><meta charset=utf-8>
<title>AEGIS Gateway - Verification required</title>
<style>body{font-family:system-ui;background:#0b1220;color:#e6edf3;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}
.card{background:#141d2e;padding:32px 36px;border:1px solid #24324a;border-radius:14px;
max-width:460px;width:100%%}h1{font-size:19px;margin:0 0 6px}
p{color:#93a4bd;font-size:13px;line-height:1.6}
.q{font-size:26px;font-weight:700;background:#0b1220;border:1px solid #2b3b57;
padding:14px;border-radius:9px;text-align:center;margin:16px 0;letter-spacing:2px}
input,button{width:100%%;padding:12px;border-radius:8px;border:1px solid #2b3b57;
background:#0b1220;color:#e6edf3;font-size:15px;box-sizing:border-box}
button{background:#2563eb;border:none;font-weight:600;cursor:pointer;margin-top:10px}
button:hover{background:#1d4ed8}.meta{font-size:11px;color:#5c7292;margin-top:14px;
word-break:break-all}</style></head><body><div class="card">
<h1>&#128737; Additional verification required</h1>
<p>The gateway scored this request <b style="color:#f59e0b">%d</b> (%s)<br>%s</p>
<div class="q">%s = ?</div>
<input id="a" type="text" inputmode="numeric" placeholder="answer" autofocus>
<button onclick="go()">Verify &amp; retry request</button>
<p class="meta">request #%d &middot; %s &middot; token %s</p>
<script>
async function go(){
  const r=await fetch('/api/challenge',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({token:'%s',answer:document.getElementById('a').value})});
  const j=await r.json();
  if(j.ok){location.reload();}else{alert(j.detail||'verification failed');}
}
document.getElementById('a').addEventListener('keydown',e=>{if(e.key==='Enter')go();});
</script></div></body></html>""" % (rec["score"], rec["severity"], rec["reason"],
                                    ch["question"], rec["id"], url, ch["token"],
                                    ch["token"])


# ----------------------------------------------------------------------
# API routes
# ----------------------------------------------------------------------
app = FastAPI(title="AEGIS Adaptive Security Gateway", version="1.0")


@app.get("/api/health")
def health():
    return {"ok": True, "target": CFG.get("target_url"),
            "mode": CFG["decision"].get("mode"), "requests_logged": len(LOG),
            "blocked_ips": len(engine.list_blocked()), "threat_intel": intel.stats()}


@app.get("/api/target")
def get_target():
    return {"target": CFG.get("target_url"), "trust_proxy": CFG.get("trust_proxy"),
            "upstream_proxy": CFG.get("upstream_proxy")}


@app.post("/api/target")
async def set_target(request: Request):
    data = await request.json()
    url = str(data.get("url", "")).strip()
    if not url.startswith(("http://", "https://")):
        return JSONResponse(status_code=400,
                            content={"ok": False, "detail": "URL must start with http(s)://"})
    old = CFG.get("target_url")
    CFG["target_url"] = url.rstrip("/")
    save_config(CFG)
    check = await _ping(CFG["target_url"])
    return {"ok": True, "target": CFG["target_url"], "reachable": check,
            "previous": old}


async def _ping(url):
    try:
        async with httpx.AsyncClient(timeout=5.0, trust_env=False) as c:
            r = await c.get(url)
        return {"status": r.status_code, "server": r.headers.get("server", ""),
                "ct": r.headers.get("content-type", "")}
    except Exception as exc:
        return {"error": "%s: %s" % (type(exc).__name__, exc)}


@app.get("/api/config")
def get_config():
    safe = {k: v for k, v in CFG.items() if k != "secret"}
    ti = dict(safe.get("threat_intel", {}))
    key = ti.get("vt_api_key", "")
    ti["vt_api_key"] = (key[:6] + "..." + key[-4:]) if len(key) > 12 else ""
    ti["vt_key_set"] = bool(key)
    safe["threat_intel"] = ti
    return safe


@app.post("/api/config")
async def set_config(request: Request):
    data = await request.json()
    for key in ("decision", "scoring", "threat_intel", "blocklist", "deception",
                "profiler"):
        if key in data and isinstance(data[key], dict):
            merged = dict(CFG.get(key, {}))
            incoming = dict(data[key])
            if key == "threat_intel" and "vt_api_key" in incoming:
                if incoming["vt_api_key"].endswith("...") or not incoming["vt_api_key"]:
                    incoming.pop("vt_api_key")     # never clobber a real key with the mask
            merged.update(incoming)
            CFG[key] = merged
    for key in ("target_url", "trust_proxy", "upstream_proxy"):
        if key in data:
            CFG[key] = data[key]
    save_config(CFG)
    intel.__init__(CFG.get("threat_intel", {}))
    engine.mode = CFG["decision"].get("mode", "block")
    engine.block_thr = int(CFG["decision"].get("block", 81))
    engine.challenge_thr = int(CFG["decision"].get("challenge", 31))
    engine.unsure_thr = int(CFG["decision"].get("unsure", 10))
    return {"ok": True, "config": await get_config()}


@app.get("/api/logs")
def get_logs(limit: int = 100, action: str = "", category: str = ""):
    out = list(LOG)[:limit]
    if action:
        out = [r for r in out if r.get("action") == action]
    if category:
        out = [r for r in out if r.get("category") == category]
    return {"total": len(LOG), "logs": out}


@app.get("/api/stats")
def get_stats():
    total = len(LOG)
    by_action, by_cat, by_score = {}, {}, {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for r in LOG:
        by_action[r.get("action", "?")] = by_action.get(r.get("action", "?"), 0) + 1
        by_cat[r.get("category", "?")] = by_cat.get(r.get("category", "?"), 0) + 1
        s = r.get("severity", "LOW")
        by_score[s] = by_score.get(s, 0) + 1
    avg = (sum(r.get("score", 0) for r in LOG) / total) if total else 0
    return {"total": total, "by_action": by_action, "by_category": by_cat,
            "by_severity": by_score, "avg_score": round(avg, 1),
            "blocked_ips": len(engine.list_blocked()),
            "target": CFG.get("target_url"), "mode": CFG["decision"].get("mode")}


@app.get("/api/model")
def get_model():
    info = scorer.model_info()
    info["thresholds"] = CFG.get("decision", {})
    return info


@app.get("/api/blocked")
def get_blocked():
    return {"ips": engine.list_blocked()}


@app.post("/api/unblock")
async def unblock(request: Request):
    data = await request.json()
    engine.unblock(str(data.get("ip", "")))
    return {"ok": True, "ips": engine.list_blocked()}


@app.get("/api/reputation")
def get_reputation():
    return intel.reputation


@app.post("/api/reputation")
async def set_reputation(request: Request):
    data = await request.json()
    if data.get("remove"):
        intel.remove_reputation(data["remove"])
    else:
        intel.add_reputation(str(data.get("ip", "")).strip(),
                             note=str(data.get("note", "manual")), score=100)
    return {"ok": True, "entries": intel.reputation.get("entries", [])}


@app.post("/api/challenge")
async def challenge(request: Request):
    data = await request.json()
    ip = client_ip(request)
    ok, detail = engine.verify_challenge(str(data.get("token", "")),
                                         data.get("answer", ""), ip)
    if not ok:
        return JSONResponse(status_code=400, content={"ok": False, "detail": detail})
    resp = JSONResponse(content={"ok": True, "detail": "verified - resend the request"})
    resp.set_cookie("aegis_clear", detail, httponly=True, samesite="lax",
                    max_age=CFG["decision"].get("captcha_ttl_s", 600))
    return resp


@app.get("/api/profile")
def get_profile():
    if not profiler:
        return {"enabled": False}
    return profiler.status()


@app.post("/api/profile")
async def run_profile(request: Request):
    data = await request.json() if request.body else {}
    if not profiler:
        return JSONResponse(status_code=500, content={"ok": False, "detail": "profiler unavailable"})
    url = str(data.get("url") or CFG.get("target_url") or "")
    result = await profiler.crawl(url)
    if result.get("ok") and result.get("profile", {}).get("adaptations"):
        CFG["profile"] = result["profile"]
        save_config(CFG)
    return result


@app.post("/api/reset")
def reset_logs():
    LOG.clear()
    SEQ["n"] = 0
    tracker.reset()
    _persist_log()
    return {"ok": True}


# ----------------------------------------------------------------------
# static + catch-all proxy (registered last so /api wins)
# ----------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index():
    p = os.path.join(STATIC, "index.html")
    if not os.path.exists(p):
        return HTMLResponse("<h1>AEGIS gateway</h1><p>dashboard missing: %s</p>" % p)
    with open(p, encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/static/{fname}")
def static_file(fname: str):
    p = os.path.join(STATIC, fname)
    if not os.path.isfile(p):
        return PlainTextResponse("not found", status_code=404)
    with open(p, "rb") as fh:
        return Response(content=fh.read(), media_type="text/css"
                        if p.endswith(".css") else "application/javascript")


@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE",
                                        "HEAD", "OPTIONS"])
async def catch_all(request: Request, path: str):
    # registered /api/* and /static/* routes win above; anything else (incl. the
    # target app's own /api/* endpoints) goes through the security pipeline
    return await pipeline(request, path)


def main():
    port = int(CFG.get("gateway_port", 8080))
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            lan = s.getsockname()[0]
        finally:
            s.close()
    except Exception:
        lan = None
    print("=" * 70)
    print("  AEGIS ADAPTIVE SECURITY GATEWAY  (bound 0.0.0.0:%d - LAN reachable)" % port)
    print("  gateway   http://127.0.0.1:%d" % port)
    if lan and not lan.startswith("127."):
        print("  dashboard http://%s:%d   <- open this from other devices" % (lan, port))
    print("  target    %s" % CFG.get("target_url"))
    print("  mode      %s" % CFG["decision"].get("mode"))
    print("  thresholds block>=%s  challenge>=%s  unsure>=%s"
          % (CFG["decision"].get("block"), CFG["decision"].get("challenge"),
             CFG["decision"].get("unsure")))
    print("  ML        RandomForest acc=%s f1=%s | IsolationForest=%s"
          % (scorer.model_cfg.get("test_acc"), scorer.model_cfg.get("test_f1"),
             "yes" if scorer.iforest is not None else "no"))
    print("  VT key    %s" % ("set" if intel.api_key else "not set (offline mode)"))
    print("=" * 70)
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="warning")


if __name__ == "__main__":
    main()
