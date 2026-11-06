"""
STAGE 2.1 - Rule based detector (deterministic signatures).

Weights mirror gateway middleware riskScoring.js from the companion project so the two
codebases quote the same numbers in a viva:
    SQL_INJECTION 40 | XSS 25 | PATH_TRAVERSAL 20 | COMMAND_INJECTION 20
    XXE 25 | SSI 20 | NOSQL 25 | LDAP 25 | SSRF 20 | OPEN_REDIRECT 15
    HEADER_INJECTION 15 | PROMPT_INJECTION 15 | CSRF 10 | DECOY 15 | ENCODING 10

Design rule that keeps the false-positive rate down:
  contextual bonuses (entropy / special chars / keyword counts) are only applied when at
  least one signature matched. Pure benign traffic therefore scores exactly 0 from rules.
  The ML stage still sees benign traffic - rules are not asked to guess.
"""
import base64
import re

import features as F

RULES = [
    # (category, regex, confidence, human label)
    ("sqli", r"union\s+(all\s+)?select", 40, "UNION SELECT"),
    ("sqli", r"(\b(or|and)\b|\|\||&&)[\s(+]*['\"]?\s*\d+['\"]?\s*=\s*['\"]?\d+\b", 40, "tautology comparison"),
    ("sqli", r"\b(or|and)\b[\s(+]*['\"][^'\"]*['\"]\s*=\s*['\"][^'\"]*['\"]", 35, "string tautology"),
    ("sqli", r"information_schema", 40, "information_schema probe"),
    ("sqli", r"(sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(", 45, "time-based blind"),
    ("sqli", r"(group_concat|concat\s*\(|load_file|into\s+(outfile|dumpfile))", 35, "data exfil fn"),
    ("sqli", r"(xp_cmdshell|extractvalue|updatexml|gtid_subset)", 45, "dbms-specific fn"),
    ("sqli", r"--(\s|$)", 20, "SQL comment terminator"),
    ("sqli", r"/\*", 20, "block comment opener"),
    ("sqli", r"%27\s*(or|and)%20", 40, "encoded tautology"),
    ("sqli", r";\s*(select|insert|update|delete|drop|union|alter|truncate|exec)\b", 35, "stacked query"),
    ("sqli", r"\bselect\b[\s(]*\*", 30, "SELECT * probe"),
    ("sqli", r"(['\"]|\b(?:or|and)\b)\s+between\s+\d+\s+and\s+\d+", 40, "BETWEEN predicate"),
    ("sqli", r"['\"]\s*(--|/\*)", 30, "quote + comment breakout"),
    ("nosql", r"\$(ne|gt|lt|gte|lte|in|nin|regex|where)\b", 30, "mongo operator"),
    ("nosql", r"['\"]\s*(or|and)\s*['\"][\w.]+['\"]\s*:\s*\{", 30, "nosql operator object"),
    ("ldap", r"\(\|?\([a-z]+=.*\)\)", 25, "ldap filter"),
    ("ldap", r"\*\)\(&\(", 30, "ldap injection chain"),
    ("ldap", r"\)\s*\(\s*[&|]", 30, "ldap filter chaining"),
    ("ldap", r"\*\s*\)\s*\(", 30, "ldap wildcard chain"),
    ("ldap", r"=\s*\*\s*\)", 30, "ldap presence wildcard"),
    ("xss", r"<\s*script\b", 30, "script tag"),
    ("xss", r"javascript\s*:", 30, "javascript: uri"),
    ("xss", r"on(error|load|click|mouseover|focus|submit|change)\s*=", 30, "inline event handler"),
    ("xss", r"<\s*(img|svg|iframe|body|input|object|embed)\b[^>]*(src=|onerror|onload)", 30, "tag w/ handler"),
    ("xss", r"document\s*\.\s*(cookie|write|location)", 30, "document access"),
    ("xss", r"(alert|prompt|confirm)\s*\(", 20, "js dialog call"),
    ("xss", r"(fromcharcode|atob\s*\()", 25, "string obfuscation"),
    ("path_traversal", r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|%252e)", 25, "dot-dot traversal"),
    ("path_traversal", r"/etc/(passwd|shadow|hosts)", 35, "unix sensitive file"),
    ("path_traversal", r"/(etc|proc|var)/[a-z0-9_./-]+", 30, "sensitive system path"),
    ("path_traversal", r"[a-z0-9_-]+\.(cnf|conf|cfg|ini|yml|yaml|log)\b", 20, "config/log file"),
    ("path_traversal", r"(c:\\|boot\.ini|win\.ini|system32)", 30, "windows sensitive file"),
    ("path_traversal", r"/proc/self|/var/log", 30, "fs enumeration"),
    ("command_injection", r";\s*(ls|cat|whoami|id|pwd|uname)\b", 35, "chained command"),
    ("command_injection", r"(\|\s*(cat|ls|whoami|curl|wget|nc)\b)", 35, "pipe command"),
    ("command_injection", r"(&&\s*(ls|cat|whoami|bash|sh)\b)", 35, "&& chained command"),
    ("command_injection", r"(^|[?&=;|\s])&\s*(ls|cat|whoami|id|pwd|curl|wget|ping|dir|type)\b", 35,
     "single-& chained command"),
    ("command_injection", r"(\$\(|`)[^)`]*\b(ls|cat|id|whoami|ping|curl|wget|nc|sh|bash|zsh|python|perl|ruby|rev|eval|base64|uname|type|dir|drives|net|powershell|tftp|ftp|ncat)\b",
     40, "command substitution"),
    ("command_injection", r"(/bin/(sh|bash)|cmd\.exe|powershell(?!\s*/\d)|cmd\s*/c)", 40, "shell binary"),
    ("command_injection", r"(;\s*|\|\s*)(sleep|ping)\s+\d", 35, "time-based cmd"),
    ("xxe", r"<!\s*entity", 35, "XXE entity decl"),
    ("xxe", r"system\s+[\"']file:", 40, "XXE file read"),
    ("xxe", r"<!\s*doctype[^>]*\[", 30, "XXE doctype"),
    ("xxe", r"xinclude", 30, "XInclude"),
    ("ssi", r"<!--#", 30, "SSI directive"),
    ("header_injection", r"(\r|\n|%0d%0a|%0a)(content-length|set-cookie|location|transfer-encoding)\s*:", 40, "response splitting"),
    ("header_injection", r"(\r|\n|%0d%0a|%0a)[ \t]*x-[a-z0-9-]{1,40}\s*:", 40, "header injection (arbitrary name)"),
    ("header_injection", r"(aegis_clear|aegis[-_]clear)\s*[:=]", 40, "clearance cookie forgery"),
    ("ssti", r"\{\{[^}]{1,150}\}\}", 40, "template expression"),
    ("ssti", r"(config\.__|__class__|__mro__|os\.popen|jinja)", 35, "template escape probe"),
    ("ssti", r"\$\{\s*['\"]?\d+['\"]?\s*[-+*/%]\s*['\"]?\d+['\"]?\s*\}", 40, "template arithmetic"),
    ("ssti", r"<%\s*[=#]?\s*[\d(].{0,40}[-+*/].{0,40}%>", 35, "server-side script tag"),
    ("ssti", r"#\{\s*\d+\s*[-+*/]\s*\d+\s*\}", 35, "expression language tag"),
    ("ssti", r"\{\{\s*\$\{", 35, "nested template marker"),
    ("config_injection", r"(__proto__|constructor\s*\[\s*[\"']?prototype)", 35, "prototype pollution"),
    ("command_injection", r"\$\{(IFS|PATH|HOME|PWD|USER|SHELL)\}", 40, "shell var obfuscation"),
    ("header_injection", r"(x-forwarded-host|x-original-url|x-rewrite-url)\s*:", 25, "host/header override"),
    ("prompt_injection", r"(ignore\s+(all|previous|above)|disregard\s+(the|all|previous))", 40, "instruction override"),
    ("prompt_injection", r"(developer\s+mode|jailbreak|system\s+prompt|do\s+anything\s+now)", 40, "jailbreak phrase"),
    ("prompt_injection", r"(you\s+are\s+now|act\s+as\s+(a|if)|role\s*play)", 30, "persona shift"),
    ("ssrf", r"(169\.254\.169\.254|metadata\.google|100\.100\.100\.200)", 45, "cloud metadata target"),
    ("ssrf", r"(gopher|dict|file|ldap)://", 30, "dangerous URI scheme"),
    ("ssrf", r"https?://(\d{6,10}|0x[0-9a-f]{6,}|\d{1,3}(\.\d{1,3}){3})", 30, "IP-form SSRF target"),
    ("ssrf", r"https?://[^/\s]*@", 30, "userinfo@ host confusion"),
    ("ssrf", r"(?<![\d.])(localhost|127\.0\.0\.1|0\.0\.0\.0|::1|0177\.127\.0\.1)(?![\d])", 15, "loopback target"),
    ("ssrf", r"//[a-z0-9.-]+\.[a-z]{2,}", 20, "absolute URL fetch target"),
    ("open_redirect", r"(redirect|next|return|url|dest|continue|goto)=(https?://|//|%2f%2f)", 25, "external redirect param"),
    ("open_redirect", r"(https?:)?//[a-z0-9-]+(\.[a-z0-9-]+)+", 20, "external URL"),
    ("csrf", r"((_[a-z]*token)|csrf|xsrf|authenticity_token)\s*=\s*($|&|null|undefined|0|none)", 20, "empty csrf token"),
    ("csrf", r"_method=(delete|put|patch)", 15, "method override"),
    ("decoy", r"(?:^|[\s?&=])/(admin-backup|internal-api|old-login|test-db)(/|$|\?)", 30, "decoy path probe"),
    ("decoy", r"(?:^|[\s?&=])/(\.env|\.git|wp-config\.php|actuator/health|server\.status|\.aws/credentials)(/|$|\?)", 35, "secret file probe"),
    ("encoding", r"%252f|%255c|%2527|%253c", 25, "double URL encoding"),
    ("encoding", r"%00", 30, "null byte"),
    ("encoding", r"base64[,\s-]+decode", 15, "base64 marker"),
]

COMPILED = [(cat, re.compile(p, re.IGNORECASE), conf, label) for cat, p, conf, label in RULES]

B64_CANDIDATE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

# The gateway issues this cookie itself after a correct CAPTCHA; a client echoing it back
# in the Cookie header is normal. Forgery still scores everywhere else (URL, body, Referer,
# injected headers) and the value is HMAC + IP-bound anyway, so it cannot be forged.
OWN_CLEARANCE = re.compile(r"aegis[-_]clear\s*=\s*[^;]*;?", re.IGNORECASE)


def _decode_base64_candidates(text):
    """Obfuscation-aware pass: an attacker base64-encodes the payload to dodge every
    signature. Decode plausible blobs and re-run the same rules on the plaintext."""
    out = []
    for cand in set(B64_CANDIDATE.findall(text or "")):
        if len(cand) % 4:                       # base64 needs padding to a multiple of 4
            cand += "=" * (-len(cand) % 4)
        try:
            raw = base64.b64decode(cand, validate=True)
        except Exception:
            continue
        try:
            decoded = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if decoded.isprintable() and len(decoded) >= 6:
            out.append(decoded)
    return out


def scan(method, path_query, body, headers):
    """Return every signature hit found in the full request material."""
    parts = [method or "GET", path_query or "", body or ""]
    hdrs = {str(k).lower(): v for k, v in (headers or {}).items()}
    for h in ("user-agent", "referer", "x-forwarded-host", "x-original-url",
              "x-rewrite-url", "x-forwarded-for", "x-real-ip", "forwarded",
              "content-type", "cookie"):
        v = hdrs.get(h)
        if v:
            v = str(v)
            if h == "cookie":
                v = OWN_CLEARANCE.sub("", v)
            parts.append(v)
    material = " ".join(parts)
    hits = []
    seen = set()

    def _run(m):
        for cat, rx, conf, label in COMPILED:
            m2 = rx.search(m)
            if m2:
                key = (cat, label, m2.group(0)[:40])
                if key in seen:
                    continue
                seen.add(key)
                hits.append({"category": cat, "confidence": conf, "label": label,
                             "match": m2.group(0)[:80]})

    _run(material)
    for decoded in _decode_base64_candidates(material):
        before = len(hits)
        _run(decoded)
        for h in hits[before:]:
            h["label"] = "base64-decoded: " + h["label"]
            h["match"] = decoded[:60] + " -> " + h["match"]
    return hits


def score(hits, features=None, text=""):
    """points = strongest category sum (capped 100) + contextual bonuses (only if hits).

    `text` is the full decoded request material (url + body): keyword bonuses must see
    payloads that arrived in a POST body, which the URL-only feature vector cannot.
    """
    if not hits:
        return 0, []

    by_cat = {}
    for h in hits:
        by_cat.setdefault(h["category"], []).append(h)

    base = 0
    cats = sorted(by_cat, key=lambda c: -max(x["confidence"] for x in by_cat[c]))
    for cat in cats:
        # top-2 corroboration: two independent signatures in one category
        # (e.g. tautology + string tautology + SQL comment) raise confidence
        confs = sorted((x["confidence"] for x in by_cat[cat]), reverse=True)
        base += sum(confs[:2])

    bonus = 0
    notes = []
    if features is not None:
        (url_len, url_ent, special, encoded, sql_kw, js_kw, trav, cmd,
         xxe, ssi, inj, prompt, enc, _bl, _be, _nh, _ua, _rpm, _uniq, _err) = features
        if text:
            low = text.lower()
            sql_kw = max(int(sql_kw), sum(1 for p in F.SQL_KEYWORDS if p in low))
            js_kw = max(int(js_kw), sum(1 for p in F.JS_KEYWORDS if p in low))
            if any(p in low for p in F.TRAVERSAL_PATTERNS):
                trav = max(trav, 1)
            if any(p in low for p in F.CMD_PATTERNS):
                cmd = max(cmd, 1)

        if sql_kw > 0:
            bonus += min(15, 5 * int(sql_kw))
            notes.append("sql_keywords x%d (+%d)" % (int(sql_kw), min(15, 5 * int(sql_kw))))
        if js_kw > 0:
            b = min(10, 2 * int(js_kw))
            bonus += b
            notes.append("js_keywords x%d (+%d)" % (int(js_kw), b))
        if trav > 0:
            bonus += 10
            notes.append("traversal_flags (+10)")
        if cmd > 0:
            bonus += 10
            notes.append("cmd_flags (+10)")
        if encoded > 5:
            bonus += 5
            notes.append("encoded_chars=%d (+5)" % int(encoded))
        if special > 20:
            bonus += 5
            notes.append("special_chars=%d (+5)" % int(special))
        if url_ent > 4.5 and special > 8:
            bonus += 10
            notes.append("high_entropy_payload (+10)")

    total = min(100, base + bonus)
    return total, notes
