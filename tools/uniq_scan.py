import sys
sys.path.insert(0, r"D:\D me se sab idar hai\adaptive-security-gateway\gateway")
import features as F
from scoring import Scorer

sc = Scorer({})
H = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"}
for u in (1, 2, 3, 4, 5, 6, 7, 8, 12, 20):
    v = F.extract("GET", "/api/items", H, "", {"requests_per_minute": 1, "unique_urls_per_session": u, "error_rate": 0})
    out = sc.score(v, 0, 0, 0, [], [])
    p = out["ml"]["proba_attack"]
    band = "BLOCK" if p >= 0.8 else ("GREY->CAPTCHA" if p >= 0.45 else "clear")
    print("uniq=%-3d proba=%.3f ml_pts=%-5.1f %s" % (u, p, out["components"]["ml"], band))
