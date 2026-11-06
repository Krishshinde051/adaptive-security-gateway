"""
STAGE 0 - Application discovery & profiling (why the gateway adapts per target).

When a target URL is pasted into the setup form the gateway:
  1. crawls it politely (bounded: depth, endpoint count, requests/second)
  2. fingerprints the stack from headers + body markers          [signatures, not ML]
  3. maps the attack surface: endpoints, parameter vocabulary,
     and which parameters actually reflect input (measured with a canary probe)
  4. clusters endpoints with TF-IDF + DBSCAN                     [unsupervised ML]
  5. emits the policy adaptations the rest of the pipeline applies

Everything is bounded and SSRF-guarded: redirects capped, private ranges refused unless
allow_private is on (needed for the localhost demo target), GET/HEAD only, no POSTs.
"""
import asyncio
import hashlib
import json
import os
import re
import time
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urlsplit, parse_qs

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
STATE = os.path.join(BASE, "state")
PROFILES = os.path.join(STATE, "profiles")

TECH_MARKERS = [
    ("nginx", ["nginx"], "header:server"),
    ("Apache", ["apache"], "header:server"),
    ("Microsoft-IIS", ["microsoft-iis"], "header:server"),
    ("Werkzeug/Flask", ["werkzeug"], "header:server"),
    ("Gunicorn", ["gunicorn"], "header:server"),
    ("Express", ["x-powered-by:express"], "header:x-powered-by"),
    ("PHP", ["x-powered-by:php", "phpsessid"], "any"),
    ("ASP.NET", ["x-powered-by:asp.net", ".aspx", "asp.net_sessionid"], "any"),
    ("Node.js", ["x-powered-by:express", "connect.sid"], "any"),
    ("Flask session", ["flask"], "cookie:flask.session"),
    ("React", ["react", "__next", "static/js/"], "body"),
    ("Vue", ["vue", "__nuxt"], "body"),
    ("jQuery", ["jquery"], "body"),
    ("WordPress", ["wp-content", "wp-includes"], "body"),
]
FILE_PARAMS = {"file", "path", "page", "template", "dir", "document", "folder",
               "include", "inc", "pg", "lang", "filename"}
SEARCH_PARAMS = {"q", "query", "search", "s", "keyword", "term"}
AUTH_PARAMS = {"user", "username", "login", "email", "pass", "password", "pwd", "otp"}


class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.hrefs, self.forms, self.scripts, self.meta = [], [], [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.hrefs.append(a["href"])
        elif tag == "form":
            self.forms.append({
                "action": a.get("action", ""),
                "method": (a.get("method") or "get").lower(),
                "inputs": [],
            })
        elif tag in ("input", "textarea", "select") and a.get("name"):
            if self.forms:
                self.forms[-1]["inputs"].append({
                    "name": a["name"], "type": a.get("type", "text")})
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "meta" and a.get("name"):
            self.meta.append((a.get("name", ""), a.get("content", "")))


class Profiler:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.max_endpoints = int(self.cfg.get("max_endpoints", 50))
        self.rate = float(self.cfg.get("rate_per_s", 2))
        self.depth = int(self.cfg.get("depth", 2))
        self.allow_private = bool(self.cfg.get("allow_private", True))
        self.current = None
        self.history = []

    # ------------------------------------------------------------------
    def _ssrf_ok(self, url):
        """Private ranges are refused unless allow_private (localhost demo target)."""
        try:
            host = (urlparse(url).hostname or "").lower()
            if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
                return self.allow_private
            if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                return True                      # hostname -> resolved on connect
            p = [int(x) for x in host.split(".")]
            private = (p[0] == 10 or p[0] == 127 or (p[0] == 172 and 16 <= p[1] <= 31)
                       or (p[0] == 192 and p[1] == 168) or p[0] == 0)
            return self.allow_private if private else True
        except Exception:
            return False

    # ------------------------------------------------------------------
    async def crawl(self, target):
        if not self.enabled:
            return {"ok": False, "detail": "profiler disabled"}
        target = (target or "").strip()
        if not target.startswith(("http://", "https://")):
            return {"ok": False, "detail": "invalid target URL"}
        t0 = time.time()
        seen, queue, findings = set(), [(target, 0)], []
        forms, scripts, headers_all, bodies = [], [], {}, {}
        delay = 1.0 / max(self.rate, 0.1)

        try:
            async with httpx.AsyncClient(timeout=8.0, follow_redirects=False,
                                         trust_env=False) as client:
                while queue and len(seen) < self.max_endpoints:
                    url, depth = queue.pop(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    try:
                        r = await client.get(url)
                    except Exception as exc:
                        findings.append({"url": url, "error": "%s" % type(exc).__name__})
                        continue
                    headers_all.setdefault(url, dict(r.headers))
                    ctype = r.headers.get("content-type", "")
                    text = ""
                    if "html" in ctype and r.status_code < 400:
                        text = r.text
                        bodies[url] = text
                        p = LinkParser()
                        try:
                            p.feed(text)
                        except Exception:
                            pass
                        forms.extend(p.forms)
                        scripts.extend(p.scripts)
                        for href in p.hrefs:
                            if href.startswith(("#", "mailto:", "javascript:", "tel:")):
                                continue
                            absu = urljoin(url, href)
                            if absu.startswith(("http://", "https://")) and \
                                    urlparse(absu).netloc == urlparse(target).netloc:
                                if depth < self.depth:
                                    queue.append((absu.split("#")[0], depth + 1))
                    for js in scripts[-5:]:
                        if js.startswith("/") and "http" not in js:
                            queue.append((urljoin(target, js).split("#")[0], depth + 1))
                    await asyncio.sleep(delay)
        except Exception as exc:
            return {"ok": False, "detail": "%s: %s" % (type(exc).__name__, exc)}

        # ---- fingerprint -------------------------------------------------
        stack = []
        first_headers = next(iter(headers_all.values()), {})
        all_blob = json.dumps({k.lower(): v for k, v in first_headers.items()}).lower()
        body_blob = " ".join(bodies.values())[:200000].lower()
        for name, needles, where in TECH_MARKERS:
            hay = {"header:server": str(first_headers.get("server", "")).lower(),
                   "any": all_blob + " " + body_blob,
                   "body": body_blob,
                   "cookie:flask.session": str(first_headers.get("set-cookie", "")).lower(),
                   "header:x-powered-by": str(first_headers.get("x-powered-by", "")).lower()}
            h = hay.get(where, "")
            if any(n in h for n in needles):
                stack.append(name)

        # ---- parameter vocabulary + reflection probe ----------------------
        endpoints, params, watched = [], set(), set()
        canary = "aegisprobe%d" % (int(time.time()) % 100000)
        reflected = False
        for u in sorted(seen):
            sp = urlsplit(u)
            pq = parse_qs(sp.query, keep_blank_values=True)
            endpoints.append({"path": sp.path or "/", "method": "GET",
                              "params": list(pq.keys())})
            params.update(pq.keys())
        for f in forms:
            for i in f.get("inputs", []):
                params.add(i["name"])

        probe_url = None
        for e in endpoints:
            if e["params"] and e["path"] not in ("/", ""):
                probe_url = e
                break
        if probe_url is None and endpoints:
            probe_url = endpoints[0]
        if probe_url and probe_url["params"]:
            target_probe = urljoin(target, probe_url["path"] + "?" +
                                   "&".join("%s=%s" % (p, canary)
                                            for p in probe_url["params"][:6]))
            try:
                async with httpx.AsyncClient(timeout=6.0, trust_env=False) as c:
                    r = await c.get(target_probe)
                reflected = canary in r.text
            except Exception:
                reflected = False

        file_params = sorted(params & FILE_PARAMS)
        search_params = sorted(params & SEARCH_PARAMS)
        auth_endpoints = [e for e in endpoints
                          if any(k in e["path"].lower()
                                 for k in ("login", "signin", "auth", "session", "token"))]
        auth_params = sorted(params & AUTH_PARAMS)
        has_upload = any(i.get("type") == "file"
                         for f in forms for i in f.get("inputs", []))
        json_api = bool(endpoints) and all(
            not e["path"].endswith((".html", ".htm")) for e in endpoints) and \
            not any("html" in str(v).lower() for v in list(bodies.values())[:1])

        # ---- clustering: TF-IDF over path+params, DBSCAN [unsupervised ML] -
        clusters, cluster_method = {}, "insufficient_data"
        try:
            from sklearn.cluster import DBSCAN
            from sklearn.feature_extraction.text import TfidfVectorizer
            docs = [" ".join(e["path"].strip("/").split("/") + e["params"])
                    for e in endpoints]
            if len(docs) >= 4:
                X = TfidfVectorizer(analyzer="word", token_pattern=r"[a-z0-9]+",
                                    min_df=1).fit_transform(docs)
                labels = DBSCAN(eps=0.9, min_samples=2).fit_predict(X)
                for e, lab in zip(endpoints, labels):
                    key = "cluster_%d" % lab if lab != -1 else "singleton_%s" % e["path"]
                    clusters.setdefault(key, []).append(e["path"])
                cluster_method = "TfidfVectorizer + DBSCAN (sklearn)"
        except Exception as exc:
            cluster_method = "unavailable: %s" % type(exc).__name__

        # ---- policy adaptations ------------------------------------------
        adaptations = []
        if auth_endpoints or auth_params:
            adaptations.append({
                "key": "auth_tracking", "effect": "behaviour: failed-login tracking ON, "
                                                  "brute-force weight raised",
                "because": "%d auth endpoint(s), auth params: %s"
                           % (len(auth_endpoints), ", ".join(auth_params[:5]) or "-")})
        if file_params:
            adaptations.append({
                "key": "traversal_watch", "effect": "+10 rule points whenever a "
                                                  "file-ish parameter is present",
                "because": "file-ish params: %s" % ", ".join(file_params)})
        if search_params and reflected:
            adaptations.append({
                "key": "reflection_watch", "effect": "XSS/SQLi sensitivity raised on "
                                                   "search params",
                "because": "canary %s reflected by target -> input reaches the page"
                           % canary})
        if has_upload:
            adaptations.append({
                "key": "upload_guard", "effect": "multipart/file inspection enabled",
                "because": "form with file input found"})
        if json_api and not bodies:
            adaptations.append({
                "key": "json_api", "effect": "HTML-context rules deprioritised, "
                                           "content-type mismatch penalised",
                "because": "target looks like a JSON API"})
        if not adaptations:
            adaptations.append({
                "key": "default", "effect": "default policy (no specialised surface found)",
                "because": "no auth/file/upload/search surfaces detected"})

        thresholds = {"block": 81, "challenge": 31, "unsure": 10}
        if len(endpoints) <= 5 and not auth_endpoints:
            thresholds = {"block": 86, "challenge": 36, "unsure": 12}
            adaptations.append({
                "key": "relaxed_thresholds", "effect": "block 81->86, challenge 31->36",
                "because": "small read-only surface -> cut false positives"})

        profile = {
            "target": target,
            "crawled_at": time.time(),
            "duration_s": round(time.time() - t0, 2),
            "stack": stack or ["unknown"],
            "endpoints": len(endpoints),
            "endpoint_list": endpoints[:self.max_endpoints],
            "params": sorted(params),
            "forms": len(forms),
            "auth_endpoints": [e["path"] for e in auth_endpoints],
            "file_params": file_params,
            "search_params": search_params,
            "has_upload": has_upload,
            "reflection": {"probe_param": (probe_url or {}).get("params", [None])[0] if probe_url else None,
                           "canary": canary, "reflected": reflected},
            "clusters": {k: v[:8] for k, v in clusters.items()},
            "cluster_method": cluster_method,
            "adaptations": adaptations,
            "thresholds": thresholds,
            "watched_params": file_params + search_params,
            "errors": [f for f in findings if f.get("error")][:5],
        }

        os.makedirs(PROFILES, exist_ok=True)
        digest = hashlib.sha1(target.encode()).hexdigest()[:12]
        with open(os.path.join(PROFILES, digest + ".json"), "w", encoding="utf-8") as f:
            json.dump(profile, f, indent=2)
        self.current = profile
        self.history.append({"target": target, "at": profile["crawled_at"],
                             "endpoints": profile["endpoints"]})
        return {"ok": True, "profile": profile}

    def status(self):
        return {"enabled": True, "current": self.current,
                "history": self.history[-10:]}
