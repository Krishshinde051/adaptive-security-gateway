"""
STAGE 4 - Decision engine.

Implements exactly the three-way split specified:
    4.1  risk LOW      (<  challenge)  -> FORWARD to the application
    4.2  risk HIGH     (>= block)      -> BLOCK (403), request never reaches the app
    4.3  risk MEDIUM   or "unsure"     -> CHALLENGE (CAPTCHA); correct answer -> pass

Hard overrides that bypass scoring entirely:
    * IP present in the blocklist            (checked upstream in stage 1)
    * VirusTotal / local reputation positive  (stage 2.3)
    * honeytoken hit                         (deception layer)

"Unsure" = the RF probability sits in the grey zone [0.45, 0.80] while the score is still
sub-threshold - i.e. the model itself is not confident, so we ask a human instead of
guessing. That is the argument for why this is not a pile of if/else statements.

CAPTCHA is fully offline (arithmetic challenge, in-memory store, HMAC-signed clearance
token bound to the client IP) - no external service, no internet required.
"""
import hashlib
import hmac
import json
import os
import random
import secrets
import time
from collections import deque

HERE = os.path.dirname(os.path.abspath(__file__))
BASE = os.path.dirname(HERE)
STATE = os.path.join(BASE, "state")
BLOCK_FILE = os.path.join(STATE, "blocked_ips.json")

ALLOW, MONITOR, CHALLENGE, BLOCK = "ALLOW", "MONITOR", "CHALLENGE", "BLOCK"


def _load(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def _save(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _status_for(action):
    return {ALLOW: 200, MONITOR: 200, CHALLENGE: 401, BLOCK: 403}[action]


class DecisionEngine:
    def __init__(self, cfg=None):
        self.cfg = cfg or {}
        dec = self.cfg.get("decision", {})
        self.block_thr = int(dec.get("block", 81))
        self.challenge_thr = int(dec.get("challenge", 31))
        self.unsure_thr = int(dec.get("unsure", 10))
        self.grey_zone = tuple(dec.get("grey_zone", [0.45, 0.80]))
        self.mode = dec.get("mode", "block")           # block | monitor
        self.captcha_ttl = int(dec.get("captcha_ttl_s", 600))
        self.captcha_max_attempts = int(dec.get("captcha_max_attempts", 3))

        blk = self.cfg.get("blocklist", {})
        self.ttl_hours = [int(h) for h in blk.get("ttl_hours", [1, 24, 168])]
        self.escalate_subnet = bool(blk.get("escalate_subnet", True))
        self.enabled = bool(blk.get("enabled", True))

        self.secret = self.cfg.get("secret") or secrets.token_hex(32)
        self.blocked = _load(BLOCK_FILE, {"ips": {}})
        self.challenges = {}     # token -> {answer, ip, ts, attempts}
        self.clearances = {}     # token -> {ip, ts, exp}
        self.audit = deque(maxlen=500)

    # ------------------------------------------------------------------
    # blocklist
    # ------------------------------------------------------------------
    def is_blocked(self, ip, now=None):
        if not self.enabled or not ip:
            return None
        now = now or time.time()
        entry = self.blocked["ips"].get(ip)
        if not entry:
            if self.escalate_subnet and ":" not in ip and ip.count(".") == 3:
                entry = self.blocked["ips"].get(".".join(ip.split(".")[:3]) + ".0/24")
            if not entry:
                return None
        if now - entry.get("ts", 0) > entry.get("ttl_s", 3600):
            self.blocked["ips"].pop(ip, None)
            self._save_block()
            return None
        return entry

    def block_ip(self, ip, reason, category="ai_agent_probe", now=None):
        if not ip:
            return None
        now = now or time.time()
        cur = self.blocked["ips"].get(ip)
        hits = (cur.get("hits", 0) + 1) if cur else 1
        tier = min(hits - 1, len(self.ttl_hours) - 1)
        ttl_h = self.ttl_hours[tier]
        entry = {"ip": ip, "reason": reason, "category": category, "hits": hits,
                 "ts": now, "ttl_s": ttl_h * 3600, "ttl_hours": ttl_h,
                 "expires": now + ttl_h * 3600, "tier": tier + 1}
        self.blocked["ips"][ip] = entry
        if self.escalate_subnet and hits >= 3 and ":" not in ip and ip.count(".") == 3:
            net = ".".join(ip.split(".")[:3]) + ".0/24"
            self.blocked["ips"][net] = dict(entry, ip=net,
                                            reason="subnet escalation from %s" % ip)
        self._save_block()
        self._audit("BLOCK_IP", ip, reason)
        return entry

    def unblock(self, ip):
        self.blocked["ips"].pop(ip, None)
        self._save_block()
        self._audit("UNBLOCK", ip, "manual")

    def list_blocked(self, now=None):
        now = now or time.time()
        out = []
        for ip, e in list(self.blocked["ips"].items()):
            left = max(0, int(e.get("ts", 0) + e.get("ttl_s", 0) - now))
            out.append(dict(e, remaining_s=left,
                            remaining="%dh%02dm" % (left // 3600, (left % 3600) // 60)))
        out.sort(key=lambda x: -x.get("hits", 0))
        return out

    def _save_block(self):
        _save(BLOCK_FILE, self.blocked)

    # ------------------------------------------------------------------
    # CAPTCHA
    # ------------------------------------------------------------------
    def new_challenge(self, ip):
        a, b = random.randint(2, 9), random.randint(2, 9)
        ops = [("+", a + b), ("-", a - b), ("*", a * b)]
        sym, ans = random.choice(ops)
        token = secrets.token_urlsafe(16)
        self.challenges[token] = {"answer": ans, "ip": ip, "ts": time.time(), "attempts": 0,
                                  "question": "%d %s %d = ?" % (a, sym, b)}
        self._prune_challenges()
        return {"token": token, "question": "%d %s %d" % (a, sym, b),
                "expires_in": self.captcha_ttl, "max_attempts": self.captcha_max_attempts}

    def verify_challenge(self, token, answer, ip):
        self._prune_challenges()
        ch = self.challenges.get(token)
        if not ch:
            return False, "challenge not found or expired"
        if ch["ip"] != ip:
            return False, "challenge issued to a different client"
        if time.time() - ch["ts"] > self.captcha_ttl:
            self.challenges.pop(token, None)
            return False, "challenge expired"
        ch["attempts"] += 1
        if ch["attempts"] > self.captcha_max_attempts:
            self.challenges.pop(token, None)
            return False, "too many attempts"
        try:
            given = int(str(answer).strip())
        except ValueError:
            return False, "answer must be a number"
        if given != ch["answer"]:
            return False, "wrong answer (%d/%d)" % (ch["attempts"], self.captcha_max_attempts)
        self.challenges.pop(token, None)
        clear = secrets.token_urlsafe(16)
        self.clearances[clear] = {"ip": ip, "ts": time.time(),
                                  "exp": time.time() + self.captcha_ttl}
        return True, clear

    def has_clearance(self, token, ip):
        if not token:
            return False
        c = self.clearances.get(token)
        if not c or c["ip"] != ip:
            return False
        if time.time() > c["exp"]:
            self.clearances.pop(token, None)
            return False
        return True

    def _prune_challenges(self):
        now = time.time()
        for t in [t for t, c in self.challenges.items() if now - c["ts"] > self.captcha_ttl]:
            self.challenges.pop(t, None)
        for t in [t for t, c in self.clearances.items() if now > c["exp"]]:
            self.clearances.pop(t, None)

    # ------------------------------------------------------------------
    def decide(self, score, severity, ml, threat_hard=False, honey_hit=None,
               blocked_entry=None, clearance_ok=False):
        """Return dict(action, status, reason, tier)."""
        if blocked_entry:
            return self._res(BLOCK, "IP blocked: %s (tier %d, %sh left)"
                             % (blocked_entry.get("reason", "-"),
                                blocked_entry.get("tier", 1),
                                blocked_entry.get("ttl_hours", 1)),
                             tier="4.2-blocklist", override=True)
        if honey_hit:
            return self._res(BLOCK, "Honeytoken followed: %s" % honey_hit.get("path", "-"),
                             tier="4.2-deception", override=True)
        if threat_hard:
            return self._res(BLOCK, "Threat intelligence: malicious source",
                             tier="2.3-block", override=True)

        grey = bool(ml.get("grey_zone"))
        if score >= self.block_thr:
            action = CHALLENGE if clearance_ok else BLOCK
            reason = ("risk %d >= %d (severity %s)%s"
                      % (score, self.block_thr, severity,
                         " - cleared by CAPTCHA" if clearance_ok else ""))
            return self._res(action, reason, tier="4.2-high-risk" if not clearance_ok
                             else "4.3-cleared")
        if score >= self.challenge_thr:
            if clearance_ok:
                return self._res(ALLOW, "risk %d - cleared by CAPTCHA" % score,
                                 tier="4.3-cleared")
            return self._res(CHALLENGE, "risk %d in medium band (%d-%d)" %
                             (score, self.challenge_thr, self.block_thr - 1),
                             tier="4.3-medium")
        if grey and score >= self.unsure_thr:
            if clearance_ok:
                return self._res(ALLOW, "model unsure (%.0f%%) - cleared by CAPTCHA"
                                 % (ml.get("proba_attack", 0) * 100), tier="4.3-cleared")
            return self._res(CHALLENGE,
                             "model unsure: attack probability %.0f%% sits in grey zone %.0f-%.0f%%"
                             % (ml.get("proba_attack", 0) * 100,
                                self.grey_zone[0] * 100, self.grey_zone[1] * 100),
                             tier="4.3-unsure")
        if self.mode == "monitor":
            return self._res(MONITOR, "risk %d below %d - monitor mode, forwarded"
                             % (score, self.challenge_thr), tier="4.1-monitor")
        return self._res(ALLOW, "risk %d below %d - legitimate" % (score, self.challenge_thr),
                         tier="4.1-low")

    def _res(self, action, reason, tier="", override=False):
        if self.mode == "monitor" and action == BLOCK and not override:
            action = MONITOR
            reason += " (monitor mode - forwarded for observation)"
        return {"action": action, "status": _status_for(action), "reason": reason,
                "tier": tier}

    # ------------------------------------------------------------------
    def _audit(self, kind, ip, detail):
        self.audit.append({"ts": time.time(), "kind": kind, "ip": ip, "detail": detail})
