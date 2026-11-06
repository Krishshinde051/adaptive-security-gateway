"""
STAGE 2.3 - Threat intelligence checker (source IP / domain reputation).

Two sources, in order:
  1. Local reputation list  state/reputation.json  - always on, editable from the dashboard
  2. VirusTotal v3 API      - used only when config.threat_intel.vt_api_key is set

Behaviour contract (tested in Phase 5):
  * private/loopback addresses are never sent to an external API (and are not "bad")
  * every external call has a hard timeout so a request can never hang on VT
  * responses are cached on disk for cache_hours, so repeat checks cost nothing
  * a positive (malicious) verdict sets hard_block=True, which short-circuits the
    decision engine before risk scoring completes - "block it there only", as specified

No API key yet? The module still works: it reports status="skipped" and the dashboard
shows it honestly instead of pretending a lookup happened.
"""
import ipaddress
import json
import os
import time

import httpx

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
STATE = os.path.join(BASE, "state")
REP_FILE = os.path.join(STATE, "reputation.json")
VT_CACHE = os.path.join(STATE, "vt_cache.json")

VT_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"

MALICIOUS_THRESHOLD = 5   # VT engines flagging the indicator
BENIGN_THRESHOLD = 2


def _load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save_json(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast)
    except ValueError:
        return True  # unparseable -> treat as non-routable, never send out


class ThreatIntel:
    def __init__(self, cfg):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.api_key = (self.cfg.get("vt_api_key") or "").strip()
        self.timeout = float(self.cfg.get("timeout_s", 3.0))
        self.cache_hours = float(self.cfg.get("cache_hours", 24))
        self.cap = int(self.cfg.get("cap", 40))
        self.reputation = _load_json(REP_FILE, {"entries": []})
        self.cache = _load_json(VT_CACHE, {})
        self.lookups = 0
        self.cache_hits = 0

    # ---------- local reputation ----------
    def add_reputation(self, ip, note="manual", score=100):
        ents = [e for e in self.reputation.get("entries", []) if e.get("ip") != ip]
        ents.append({"ip": ip, "note": note, "score": int(score), "added": time.time()})
        self.reputation["entries"] = ents
        _save_json(REP_FILE, self.reputation)

    def remove_reputation(self, ip):
        self.reputation["entries"] = [e for e in self.reputation.get("entries", [])
                                      if e.get("ip") != ip]
        _save_json(REP_FILE, self.reputation)

    # ---------- cache ----------
    def _cached(self, key):
        entry = self.cache.get(key)
        if not entry:
            return None
        if time.time() - entry.get("ts", 0) > self.cache_hours * 3600:
            self.cache.pop(key, None)
            return None
        return entry

    # ---------- VirusTotal ----------
    def _vt_lookup(self, url, key):
        cached = self._cached(key)
        if cached:
            self.cache_hits += 1
            return cached
        if not self.api_key:
            return None
        try:
            with httpx.Client(timeout=self.timeout, trust_env=False) as client:
                r = client.get(url, headers={"x-apikey": self.api_key,
                                             "User-Agent": "AEGIS-Security-Gateway/1.0"})
            if r.status_code == 404:
                out = {"malicious": False, "suspicious": False, "engines": 0,
                       "verdict": "not_found", "raw": "404 - unknown indicator"}
            elif r.status_code == 429:
                out = {"malicious": False, "suspicious": False, "engines": 0,
                       "verdict": "rate_limited", "raw": "429 - VT rate limit (free tier: 4 req/min)"}
            elif r.status_code != 200:
                out = {"malicious": False, "suspicious": False, "engines": 0,
                       "verdict": "http_%d" % r.status_code, "raw": str(r.status_code)}
            else:
                stats = (r.json().get("data", {}).get("attributes", {})
                         .get("last_analysis_stats", {}))
                mal = int(stats.get("malicious", 0))
                sus = int(stats.get("suspicious", 0))
                out = {
                    "malicious": mal >= MALICIOUS_THRESHOLD,
                    "suspicious": sus >= 3,
                    "engines": mal,
                    "verdict": "malicious" if mal >= MALICIOUS_THRESHOLD else "clean",
                    "raw": "malicious=%d suspicious=%d harmless=%d"
                           % (mal, sus, int(stats.get("harmless", 0))),
                }
            self.lookups += 1
            self.cache[key] = {"ts": time.time(), **out}
            _save_json(VT_CACHE, self.cache)
            return out
        except Exception as exc:  # network/timeout/parse -> never break the proxy
            self.lookups += 1
            out = {"malicious": False, "suspicious": False, "engines": 0,
                   "verdict": "error", "raw": "%s: %s" % (type(exc).__name__, exc)}
            self.cache[key] = {"ts": time.time(), **out}
            _save_json(VT_CACHE, self.cache)
            return out

    # ---------- public entry point ----------
    def check(self, ip, referer=None):
        if not self.enabled:
            return {"status": "disabled", "malicious": False, "points": 0,
                    "hard_block": False, "detail": "threat intel switched off"}

        # local reputation FIRST: an explicit admin entry must win even for a
        # private/loopback source (the demo client is 127.0.0.1). The private
        # skip only guards EXTERNAL lookups below.
        for e in self.reputation.get("entries", []):
            if e.get("ip") == ip:
                return {"status": "local_list", "malicious": True,
                        "points": self.cap, "hard_block": True,
                        "detail": "listed locally: %s" % e.get("note", "-"),
                        "source": "local_reputation"}

        if is_private(ip):
            return {"status": "private", "malicious": False, "points": 0,
                    "hard_block": False, "detail": "%s is a private/loopback address - "
                                                   "no external lookup performed" % ip}

        if not self.api_key:
            return {"status": "skipped", "malicious": False, "points": 0,
                    "hard_block": False,
                    "detail": "no VirusTotal API key configured (offline mode)"}

        res = self._vt_lookup(VT_IP_URL.format(ip=ip), "ip:" + ip)
        res = res or {"malicious": False, "verdict": "error", "raw": "no result"}
        if res.get("malicious"):
            return {"status": "virustotal", "malicious": True, "points": self.cap,
                    "hard_block": True, "source": "virustotal",
                    "detail": "VirusTotal: %d engines flagged %s" % (res.get("engines", 0), ip),
                    "raw": res.get("raw", "")}
        return {"status": "virustotal", "malicious": False, "points": 0,
                "hard_block": False, "source": "virustotal",
                "detail": "VirusTotal: %s (%s)" % (res.get("verdict", "?"), res.get("raw", "")),
                "raw": res.get("raw", "")}

    def stats(self):
        return {"vt_key_configured": bool(self.api_key),
                "lookups": self.lookups, "cache_hits": self.cache_hits,
                "local_entries": len(self.reputation.get("entries", [])),
                "cache_size": len(self.cache)}
