import sys, urllib.parse
sys.path.insert(0, r"D:\D me se sab idar hai\adaptive-security-gateway\gateway")
import rules as R, features as F

att = [
    "/search?q=Or+1%3D1--",
    "/search?q=%27+OR+1%3D1--",
    "/login?user=Or+1=1--",
    "/search?q=1' or '1'='1",
    "/search?q=1 or 1=1",
    "/search?q=admin' or 1=1--",
    "/search?q=1'||'1'='1",
    "/search?q=1 and 1=1#",
    "/search?q=x' OR (1=1)--",
    "/search?q=)) OR 1=1--",
    "/search?q=%27%20OR%20%271%27%3D%271",
    "/search?q=or%281%3D1%29",
    "/search?q=1%20AND%20SLEEP(5)",
]
ben = [
    "/api/items",
    "/login",
    "/search?q=red%20shoes",
    "/search?q=cat%20or%20dog",
    "/search?q=and%20the%20rest",
    "/?page=2&sort=price&dir=asc",
    "/search?q=black%20%26%20white",
    "/search?q=Q%26A%20session",
    "/profile?id=42",
    "/download?file=report.pdf",
    "/search?q=apples%20oranges%20bananas",
    "/search?q=100%25%20cotton",
    "/search?q=error%3A%20expected%20value",
    "/search?q=Tom%20and%20Jerry",
    "/search?q=5%20%26%206%20years",
    "/search?q=date%3D2024-01-01",
    "/search?q=a%3D1%26b%3D2",
]

def run(label, urls, expect_hit):
    bad = []
    for u in urls:
        d = urllib.parse.unquote(urllib.parse.unquote(u))
        hits = R.scan("GET", d, "", {"user-agent": "Mozilla/5.0"})
        sqli = [h["label"] for h in hits if h["category"] == "sqli"]
        pts, notes = R.score(hits, None, d)
        ok = bool(sqli) == expect_hit
        if not ok:
            bad.append((u, sqli, pts))
        print("  %-4s %-42s sqli=%-28s rules=%s" % ("ok" if ok else "MISS", u, ",".join(sqli)[:28], pts))
    return bad

print("ATTACK payloads (expect sqli hit):")
b1 = run("a", att, True)
print("\nBENIGN queries (expect NO sqli hit):")
b2 = run("b", ben, False)
print("\nFP/MISS: attacks missed=%d  benign flagged=%d" % (len(b1), len(b2)))
