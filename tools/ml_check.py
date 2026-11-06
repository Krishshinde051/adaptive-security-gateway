import sys, urllib.parse, importlib
sys.path.insert(0, r"D:\D me se sab idar hai\adaptive-security-gateway\gateway")
import features as F, rules as R
from scoring import Scorer

body = urllib.parse.unquote_plus(urllib.parse.unquote_plus("user=krish&pass=%27+OR+1%3D1--"))
sc = Scorer({})
for label, m, u, b in [
    ("SQLi POST (your case)", "POST", "/login", body),
    ("benign POST", "POST", "/login", "user=krish&pass=secret123"),
    ("benign GET", "GET", "/api/items", ""),
]:
    vec = F.extract(m, u, {"user-agent": "Mozilla/5.0"}, b,
                    {"requests_per_minute": 1, "unique_urls_per_session": 1, "error_rate": 0})
    hits = R.scan(m, u, b, {"user-agent": "Mozilla/5.0"})
    rp, rn = R.score(hits, vec, u + " " + b)
    out = sc.score(vec, rp, 0, 0, rn, [])
    print("%-24s rules=%-3d ml_p=%-6s ml_pts=%-5s total=%-3d %s" %
          (label, rp, out["ml"].get("proba_attack"),
           out["components"].get("ml"), out["score"], out["severity"]))
