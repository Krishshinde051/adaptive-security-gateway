import sys
sys.stdout.reconfigure(encoding="utf-8", errors="replace")
sys.path.insert(0, r"D:\D me se sab idar hai\adaptive-security-gateway\gateway")
import app as A
for t in ["%c0%a0", "%c0%af", "%e0%80%af", "%c3%a9", "%2527", "/search?q=1'%c0%a0OR%c0%a01%3d1", "..%c0%af..%c0%afetc%c0%afpasswd"]:
    print("%-42s -> %s" % (t, ascii(A._scan_decode(t))))
