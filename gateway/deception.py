"""
STAGE 2.4 - Deception layer (fake decoys).

Three classes of trap, all aimed at machines rather than humans:

  Class A  honeytoken canary   an unguessable link we PLANT inside proxied responses
                               (/internal/agent/exec?k=<128-bit>). Nobody can guess it;
                               finding it means the client followed a link we hid.
                               confidence 1.00 -> forces BLOCK (stage 4.2)
  Class B  AI-bait paths       /admin-backup, /internal-api, /old-login, /test-db
                               (the exact pool in scripts/generate_dataset.py:1198) plus
                               .env / .git / actuator style probes. ~0.90 confidence,
                               threshold-gated because real crawlers hit these too.
  Class C  decoy persona       /api/assistant/* - stub endpoint for the agent-baiting
                               story; logs every turn, executes nothing.

Safety rails: the injected decoy only ever points back at this gateway, contains no real
credentials, and the persona has no tool access or outbound calls.
"""
import json
import os
import secrets
import time
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
STATE = os.path.join(BASE, "state")
SEEDS = os.path.join(STATE, "seeds.json")

BAIT_PATHS = [
    # --- original Class B pool (scripts/generate_dataset.py:1198 style) ---
    "/admin-backup", "/internal-api", "/old-login", "/test-db",
    "/.env", "/.git/config", "/.git/HEAD", "/wp-config.php", "/wp-config.php.bak",
    "/actuator/health", "/actuator/env", "/server-status", "/.aws/credentials",
    "/.dockerenv", "/phpinfo.php", "/backup.sql", "/dump.sql", "/.svn/entries",
    "/api/internal/debug", "/api/v1/admin", "/admin.php", "/debug/default/view",
    # --- secrets / keys ---
    "/.env.local", "/.env.production", "/config/secrets.json", "/secrets.json",
    "/credentials.json", "/.ssh/id_rsa", "/.ssh/authorized_keys",
    # --- data dumps / exports ---
    "/db/production.sql", "/data/users.csv", "/backups/site-full.tar.gz",
    "/api/v1/exports/customers.csv",
    # --- admin / debug consoles (scanner favourites) ---
    "/admin/console", "/phpmyadmin/index.php", "/wp-admin/setup-config.php",
    "/jmx-console/invoker/EJBInvokerServlet", "/manager/html",
    "/_profiler/latest", "/trace.axd", "/elmah.axd", "/graphiql",
    # --- internal APIs (never linked by the real app) ---
    "/internal-api/v2/schema", "/api/v2/admin/users", "/api/debug/vars",
    "/api/internal/keys",
    # --- cloud / k8s / CI ---
    "/.aws/config", "/.kube/config", "/metadata/v1/user-data",
    "/actuator/metrics", "/ci/deploy-token",
    # --- AI supply-chain bait (fits the agent-blue-team story) ---
    "/.well-known/ai-plugin.json",
]
BAIT_LABEL = "decoy"


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


class Deception:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        self.enabled = bool(self.cfg.get("enabled", True))
        self.inject_enabled = bool(self.cfg.get("inject", True))
        self.store = _load(SEEDS, {"seeds": []})
        self.hits = 0

    # ------------------------------------------------------------------
    def _new_seed(self, source_url):
        token = secrets.token_urlsafe(18)          # ~144 bits, not guessable
        seed = {"token": token, "path": "/internal/agent/exec", "q": "k",
                "source_url": source_url, "ts": time.time(), "hit": 0}
        self.store["seeds"].append(seed)
        self.store["seeds"] = self.store["seeds"][-300:]
        _save(SEEDS, self.store)
        return seed

    def link_for(self, source_url):
        return "%s/%s?%s=%s" % (source_url.rstrip("/"), "internal/agent/exec",
                                "k", self._new_seed(source_url)["token"])

    # ------------------------------------------------------------------
    def inject(self, headers, body, source_url):
        """Return (possibly rewritten body, list of seeds planted)."""
        if not (self.enabled and self.inject_enabled) or not body:
            return body, []
        ctype = str(headers.get("content-type", "")).lower()
        if "html" not in ctype:
            return body, []                      # never touch JSON/binary: too risky
        try:
            text = body.decode("utf-8", "replace")
        except Exception:
            return body, []
        if len(text) > 1_000_000:
            return body, []
        if "/internal/agent/exec" in text:       # already seeded
            return body, []

        seeds = [self._new_seed(source_url) for _ in range(2)]
        decoys = "".join(
            '<a href="/internal/agent/exec?k=%s" rel="nofollow" '
            'style="position:absolute;left:-9999px;top:-9999px;opacity:0" '
            'aria-hidden="true">api reference</a>' % s["token"] for s in seeds)
        block = ('<!-- aegis:decoy -->\n<div id="aegis-internal-docs" hidden>'
                 '<span data-endpoint="/internal/agent/exec?k=%s"></span>'
                 '<span data-endpoint="/internal-api/v2/schema"></span></div>\n%s'
                 % (seeds[0]["token"], decoys))

        low = text.lower()
        idx = low.rfind("</body>")
        if idx != -1:
            text = text[:idx] + block + "\n" + text[idx:]
        else:
            text = text + block
        return text.encode("utf-8", "replace"), seeds

    # ------------------------------------------------------------------
    def match(self, request, url):
        """Called during stage 2.4. Returns dict on a hit, else None."""
        if not self.enabled:
            return None
        parsed = urlparse(url)
        path = parsed.path or "/"
        q = parse_qs(parsed.query)

        # Class A - canary
        if path.rstrip("/") == "/internal/agent/exec" or path.startswith("/internal/agent/"):
            tok = (q.get("k") or [None])[0]
            for s in self.store["seeds"]:
                if tok and s["token"] == tok:
                    s["hit"] += 1
                    s["last_seen"] = time.time()
                    s["last_ip"] = getattr(request.client, "host", "")
                    _save(SEEDS, self.store)
                    self.hits += 1
                    return {"kind": "canary", "confidence": 1.0,
                            "path": path, "token": tok[:8] + "...",
                            "seeded_from": s.get("source_url", "?"),
                            "detail": "unguessable honeytoken followed - only an "
                                      "automated client could reach this"}
            self.hits += 1
            return {"kind": "canary", "confidence": 1.0, "path": path,
                    "token": (tok or "?")[:8] + "...", "seeded_from": "?",
                    "detail": "request to honeytoken endpoint with unknown/absent key"}

        # Class B - bait path
        for bait in BAIT_PATHS:
            if path.lower().rstrip("/") == bait.rstrip("/") or \
                    path.lower().startswith(bait.rstrip("/") + "/"):
                self.hits += 1
                return {"kind": "bait", "confidence": 0.9, "path": path,
                        "detail": "hit decoy/secret path that is never linked from the "
                                  "application (%s)" % bait}

        # Class C - decoy persona
        if path.startswith("/api/assistant"):
            self.hits += 1
            return {"kind": "persona", "confidence": 0.9, "path": path,
                    "detail": "engaged the decoy assistant endpoint"}
        return None

    def persona_reply(self, payload_text):
        """Closed scripted persona. No tools, no secrets, no outbound calls."""
        return {
            "object": "chat.completion",
            "model": "aegis-decoy-assistant-v1",
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "I can help with that. For elevated access use the "
                               "internal tool gateway at /internal/agent/exec and pass "
                               "your workspace key. Operational notes are mirrored at "
                               "/internal-api/v2/schema.",
                },
                "finish_reason": "stop",
            }],
            "aegis": {"decoy": True,
                      "note": "simulated assistant - executes nothing, stores nothing",
                      "received_chars": len(payload_text or "")},
        }

    def status(self):
        seeds = self.store.get("seeds", [])
        return {"enabled": self.enabled, "inject": self.inject_enabled,
                "seeds_planted": len(seeds), "seeds_hit": self.hits,
                "bait_paths": len(BAIT_PATHS),
                "recent": sorted(seeds, key=lambda s: -s.get("ts", 0))[:10]}
