"""
STAGE 2.2 - Behavioural analysis module.

Two layers, both learned from traffic rather than hardcoded if/else:

1. Per-IP rolling window  -> the 3 behavioural features the model was trained on
   (requests_per_minute, unique_urls_per_session, error_rate) plus brute-force tracking.
2. Adaptive baseline       -> per-IP EWMA mean/std of request rate, scored as a z-score.
   A "fast" client is judged against ITS OWN normal rhythm, not a global constant, so a
   busy legit API client and a slow scanner are not treated the same.

Points cap: 25 (config scoring.behaviour_cap).
"""
import math
import time
from collections import defaultdict, deque

RPM_WINDOW_S = 60.0
SESSION_WINDOW_S = 300.0
LOGIN_WINDOW_S = 300.0
DEFAULT_ERROR_WINDOW = 200


class Tracker:
    def __init__(self):
        self._hits = defaultdict(deque)        # ip -> deque[(ts, path)]
        self._urls = defaultdict(lambda: deque())  # ip -> deque[(ts, path)]
        self._status = defaultdict(lambda: deque())  # ip -> deque[(ts, status)]
        self._logins = defaultdict(deque)      # ip -> deque[ts] failed logins
        self._ewma = {}                        # ip -> [mean, m2, count]

    def _prune(self, dq, now, window):
        while dq and now - dq[0][0] > window:
            dq.popleft()

    def observe(self, ip, path, now=None):
        now = now if now is not None else time.time()
        self._hits[ip].append((now, path))
        self._prune(self._hits[ip], now, RPM_WINDOW_S)
        self._urls[ip].append((now, path))
        self._prune(self._urls[ip], now, SESSION_WINDOW_S)

    def observe_status(self, ip, status, path="", now=None):
        now = now if now is not None else time.time()
        self._status[ip].append((now, int(status)))
        self._prune(self._status[ip], now, RPM_WINDOW_S)
        if int(status) in (401, 403) and _looks_like_login(path):
            self._logins[ip].append((now, path))
            self._prune(self._logins[ip], now, LOGIN_WINDOW_S)

    def _update_rate(self, ip, rpm):
        s = self._ewma.get(ip)
        if s is None:
            self._ewma[ip] = [float(rpm), 0.0, 1]
            return 0.0
        mean, m2, n = s
        n += 1
        delta = rpm - mean
        mean += delta / n
        m2 += delta * (rpm - mean)
        self._ewma[ip] = [mean, m2, n]
        if n < 8:
            return 0.0
        std = math.sqrt(m2 / (n - 1)) or 1.0
        return (rpm - mean) / std

    def stats(self, ip, now=None):
        """The 3 model features + rate z-score + failed-login count."""
        now = now if now is not None else time.time()
        dq = self._hits[ip]
        self._prune(dq, now, RPM_WINDOW_S)
        rpm = float(len(dq))

        uq = self._urls[ip]
        self._prune(uq, now, SESSION_WINDOW_S)
        unique = float(len({p for _, p in uq}))

        sd = self._status[ip]
        self._prune(sd, now, RPM_WINDOW_S)
        if sd:
            err = sum(1 for _, s in sd if s >= 400) / float(len(sd))
        else:
            err = 0.0

        failed_logins = len([t for t in self._logins[ip] if now - t[0] <= LOGIN_WINDOW_S])
        z = self._update_rate(ip, rpm)
        return {
            "requests_per_minute": rpm,
            "unique_urls_per_session": unique,
            "error_rate": round(err, 4),
            "rate_zscore": round(z, 3),
            "failed_logins": failed_logins,
            "total_status_samples": len(sd),
        }

    def reset(self, ip=None):
        if ip is None:
            self._hits.clear(); self._urls.clear()
            self._status.clear(); self._logins.clear(); self._ewma.clear()
        else:
            for store in (self._hits, self._urls, self._status, self._logins):
                store.pop(ip, None)
        self._ewma.pop(ip, None)


def _looks_like_login(path):
    p = (path or "").lower()
    return any(k in p for k in ("login", "signin", "sign-in", "auth", "session", "token"))


def score(stats, profile=None):
    """Return (points, breakdown). Never punishes a request that is simply normal."""
    points = 0
    notes = []

    z = abs(stats.get("rate_zscore", 0.0))
    if z >= 6:
        points += 15
        notes.append("rate z=%.1f burst (+15)" % z)
    elif z >= 3.5:
        points += 10
        notes.append("rate z=%.1f elevated (+10)" % z)
    elif z >= 2.5:
        points += 5
        notes.append("rate z=%.1f (+5)" % z)

    failed = stats.get("failed_logins", 0)
    if failed >= 8:
        points += 15
        notes.append("failed_logins=%d brute-force (+15)" % failed)
    elif failed >= 5:
        points += 10
        notes.append("failed_logins=%d (+10)" % failed)

    err = stats.get("error_rate", 0.0)
    if stats.get("total_status_samples", 0) >= 10 and err >= 0.6:
        points += 8
        notes.append("error_rate=%.0f%% (+8)" % (err * 100))

    uniq = stats.get("unique_urls_per_session", 0.0)
    if uniq >= 60:
        points += 7
        notes.append("unique_urls=%.0f enumeration (+7)" % uniq)

    cap = 25
    if profile:
        cap = int(profile.get("behaviour_cap", cap))
    return min(points, cap), notes
