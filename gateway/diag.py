"""Diagnostics: per-category detection + real inference timing (not a gate)."""
import collections
import importlib.util
import sys
import time

import numpy as np

sys.path.insert(0, ".")
import behaviour as B  # noqa: E402
import features as F   # noqa: E402
import rules as R      # noqa: E402
import scoring as S    # noqa: E402

spec = importlib.util.spec_from_file_location("gd", r"..\scripts\generate_dataset.py")
gd = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gd)

sc = S.Scorer({})
BEH = {"requests_per_minute": 3.0, "unique_urls_per_session": 2.0, "error_rate": 0.0}

POOLS = {
    "sqli": "SQLI_PAYLOADS", "xss": "XSS_PAYLOADS",
    "command_injection": "COMMAND_INJECTION_PAYLOADS",
    "path_traversal": "PATH_TRAVERSAL_PAYLOADS", "ssrf": "SSRF_PAYLOADS",
    "xxe": "XXE_PAYLOADS", "ldap": "LDAP_PAYLOADS",
    "nosql": "NOSQL_INJECTION_PAYLOADS", "prompt_injection": "PROMPT_INJECTION_PAYLOADS",
    "header_injection": "HEADER_INJECTION_PAYLOADS",
    "csrf_bypass": "CSRF_BYPASS_PAYLOADS", "open_redirect": "OPEN_REDIRECT_PAYLOADS",
}

miss = collections.defaultdict(list)
stats = {}
for cat, const in POOLS.items():
    n = r = m = 0
    for p in getattr(gd, const):
        url = "/search?q=" + p.replace(" ", "%20")
        vec = F.extract("GET", url, {"User-Agent": "t"}, "", BEH)
        hits = R.scan("GET", url, "", {"user-agent": "t"})
        rp, _ = R.score(hits, vec)
        out = sc.score(vec, rp, 0, 0)
        n += 1
        if rp > 0:
            r += 1
        if out["ml"]["flagged"] or rp > 0:
            m += 1
        else:
            miss[cat].append((p[:70], round(out["ml"]["proba_attack"], 3), rp))
    stats[cat] = (n, r, m)

print("%-20s %5s %5s %5s %7s" % ("category", "n", "rule", "det", "rate"))
for c, (n, r, m) in stats.items():
    print("%-20s %5d %5d %5d %6.1f%%" % (c, n, r, m, 100 * m / n))

print("\n--- MISSED PAYLOADS ---")
for c, v in miss.items():
    print("%s (%d missed):" % (c, len(v)))
    for p, pr, rp in v[:5]:
        print("   proba=%.3f rules=%d  %s" % (pr, rp, p))

print("\n--- TIMING (properly warmed) ---")
v = F.extract("GET", "/search?q=test", {"User-Agent": "x"}, "", BEH)
x = sc.scaler.transform([v])
for _ in range(30):
    sc.rf.predict_proba(x)
t0 = time.perf_counter()
for _ in range(300):
    sc.rf.predict_proba(x)
print("RF single-row : %.3f ms" % ((time.perf_counter() - t0) * 1000 / 300))
batch = np.vstack([x] * 100)
for _ in range(5):
    sc.rf.predict_proba(batch)
t0 = time.perf_counter()
for _ in range(20):
    sc.rf.predict_proba(batch)
print("RF batch100   : %.3f ms total -> %.4f ms/req"
      % ((time.perf_counter() - t0) * 1000 / 20, (time.perf_counter() - t0) * 1000 / 2000))
xi = sc.if_scaler.transform([v])
for _ in range(30):
    sc.iforest.decision_function(xi)
t0 = time.perf_counter()
for _ in range(300):
    sc.iforest.decision_function(xi)
print("iForest single: %.3f ms" % ((time.perf_counter() - t0) * 1000 / 300))
