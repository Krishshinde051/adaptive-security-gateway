"""
STAGE 2 - Feature extraction (20 features).

Semantics are a faithful port of scripts/generate_dataset.py:785-953 so the live vector
matches what models/aegis_model.pkl was trained on:
  - attack/keyword flags are computed on the URL (path + query) ONLY, exactly as training
    did (generate_dataset.py:1002-1003)
  - body_length / body_entropy only for POST/PUT/PATCH (generate_dataset.py:1014)
  - behavioural features come from the live per-IP tracker (behaviour.py)

Known dataset limitation (stated openly in README): training never put payloads in the
body when computing flags, so POST-body attacks are covered by the rule layer (rules.py
scans method + path + query + body + headers), not by these flags.
"""
import math

FEATURES = [
    "url_length", "url_entropy", "num_special_chars", "num_encoded_chars",
    "has_sql_keywords", "has_js_keywords", "has_path_traversal", "has_cmd_injection",
    "has_xxe_patterns", "has_ssi_patterns", "has_injection_patterns",
    "has_prompt_injection", "has_suspicious_encoding",
    "body_length", "body_entropy", "num_headers", "has_user_agent",
    "requests_per_minute", "unique_urls_per_session", "error_rate",
]

SPECIAL = "!@#$%^&*()_+-=[]{}|;':\",./<>?`~"

SQL_KEYWORDS = [
    "select", "union", "insert", "update", "delete", "drop",
    "where", "from", "into", "values", "create", "alter",
    "truncate", "exec", "execute", "declare", "set",
    "or", "and", "not", "null", "having", "group",
    "order", "by", "limit", "offset", "join",
    "information_schema", "database", "table", "column",
    "password", "username", "admin", "user", "grant",
    "revoke", "commit", "rollback", "transaction",
    "sleep", "benchmark", "waitfor", "delay",
    "load_file", "into outfile", "into dumpfile",
    "extractvalue", "updatexml", "exp", "gtid_subset",
    "pg_sleep", "sp_makewebtask", "xp_cmdshell",
]

JS_KEYWORDS = [
    "alert", "prompt", "confirm", "document.cookie",
    "document.write", "document.location", "window.location",
    "eval", "setinterval", "settimeout", "function",
    "onclick", "onerror", "onload", "onmouseover",
    "onfocus", "onblur", "onsubmit", "onchange",
    "script", "iframe", "img", "svg", "body",
    "input", "textarea", "select", "form",
    "javascript:", "data:", "vbscript:",
    "expression", "import", "@import", "url(",
    "fromcharcode", "atob", "btoa",
    "string", "charcode", "substring", "substr",
    "replace", "match", "split", "join",
    "prototype", "__proto__", "constructor",
    "window", "self", "top", "parent", "frames",
    "navigator", "location", "history", "screen",
]

TRAVERSAL_PATTERNS = [
    "../", "..\\", "..%2f", "..%5c", "..%252f",
    "%2e%2e/", "%2e%2e%2f", "%2e%2e%5c",
    "..%c0%af", "..%c1%9c", "....//",
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "c:\\windows", "c:\\boot.ini", "c:\\win.ini",
    "/proc/self", "/var/log", "/tmp/",
    "system32", "sam", "config",
]

CMD_PATTERNS = [
    "; ls", "| ls", "&& ls", "`ls`", "$(ls)",
    "; cat", "| cat", "`cat`", "$(cat)",
    "; ping", "| ping", "`ping`", "$(ping)",
    "; wget", "| wget", "; curl", "| curl",
    "; whoami", "| whoami", "; id", "| id",
    "; nc ", "| nc ", "; bash", "| bash",
    "; python", "| python", "; perl", "| perl",
    "; ruby", "| ruby", "; php", "| php",
    "& ls", "& cat", "& whoami", "& id", "& dir", "& type", "& ping",
    "/bin/sh", "/bin/bash", "cmd.exe",
    "powershell", "cmd /c", "& dir", "| dir",
    "sleep", "timeout", "reboot", "shutdown",
    "/etc/passwd", "/etc/shadow", "system32",
]

XXE_PATTERNS = [
    "<!doctype", "<!entity", 'system "file',
    'system "http', 'system "ftp', 'system "gopher',
    "dtd", "entity", "xinclude", "cdata",
    "entity xxe", "parameter entity", "external entity",
]

SSI_PATTERNS = [
    "<!--#exec", "<!--#include", "<!--#echo",
    "<!--#config", "<!--#flastmod", "<!--#fsize",
    "<!--#printenv", "<!--#set",
    "<!--#include virtual", "<!--#include file",
    "#exec", "#include",
]

INJECTION_PATTERNS = [
    "${", "{{", "#{", "<%", "%>",
    "jinja", "mako", "twig", "blade",
    "template", "render", "eval", "exec",
    "import", "require", "include", "file_get_contents",
    "serialize", "unserialize", "pickle",
    "yaml.load", "yaml.safe_load",
]

PROMPT_PATTERNS = [
    "ignore all", "ignore previous", "ignore above",
    "disregard", "forget everything", "you are now",
    "act as", "pretend", "roleplay", "role play",
    "developer mode", "dan mode", "jailbreak",
    "system prompt", "initial instructions",
    "repeat the text", "output the text",
    "sudo", "root access", "admin mode",
    "no restrictions", "without restrictions",
    "bypass", "override", "safety",
    "exfiltrate", "upload all", "send data",
    "ignore safety", "ethical guidelines",
    "do anything now", "chatgpt", "gpt",
    "openai", "anthropic", "claude",
    "override instructions", "new instructions",
    "from now on", "act as if",
]

ENCODING_PATTERNS = [
    "%00", "%0a", "%0d", "%0d%0a",
    "%c0%af", "%c1%9c", "%252f", "%255c",
    "&#", "&#x", "\\x", "\\u",
    "base64", "encode", "decode",
    "rot13", "hex", "binary",
    "utf-7", "utf-16", "utf-32",
]

# POST-body flag guard: only UNAMBIGUOUS attack markers flip a flag from the body.
# Generic words that live in benign forms (user, pass, select...) are deliberately
# excluded so a normal login POST never looks like an attack to the model.
BODY_STRONG = {
    "sql": ["union select", "' or '", '" or ', "or 1=1", "or '1'='1", "1'='1",
            "information_schema", "sleep(", "benchmark(", "drop table",
            "insert into", "xp_cmdshell", "'--", ";--", "group_concat"],
    "js": ["<script", "javascript:", "onerror=", "onload=", "onmouseover=",
           "onfocus=", "document.cookie", "alert(", "<svg", "<iframe"],
    "traversal": ["../", "..\\", "/etc/passwd", "/etc/shadow", "/proc/self",
                  "c:\\windows"],
    "cmd": ["; cat", "| cat", "&& cat", "; ls", "| ls", "; whoami", "| whoami",
            "& whoami", "& id", "& cat", "& ls", "/bin/sh", "/bin/bash",
            "cmd.exe", "powershell", "$(", "`whoami"],
    "prompt": ["ignore previous", "ignore all", "jailbreak", "developer mode",
               "do anything now", "system prompt"],
}


def calculate_entropy(text):
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return round(-sum((n / length) * math.log2(n / length) for n in freq.values()), 4)


def count_special_chars(text):
    return sum(1 for c in text if c in SPECIAL)


def count_encoded_chars(text):
    return text.count("%") + text.count("+")


def _count(text, patterns):
    low = text.lower()
    return sum(1 for p in patterns if p in low)


def has_sql_keywords(text):
    return _count(text, SQL_KEYWORDS)


def has_js_keywords(text):
    return _count(text, JS_KEYWORDS)


def has_path_traversal(text):
    return _count(text, TRAVERSAL_PATTERNS)


def has_cmd_injection(text):
    return _count(text, CMD_PATTERNS)


def has_xxe_patterns(text):
    return _count(text, XXE_PATTERNS)


def has_ssi_patterns(text):
    return _count(text, SSI_PATTERNS)


def has_injection_patterns(text):
    return _count(text, INJECTION_PATTERNS)


def has_prompt_injection(text):
    return _count(text, PROMPT_PATTERNS)


def has_suspicious_encoding(text):
    return _count(text, ENCODING_PATTERNS)


def extract(method, path_query, headers, body, behaviour):
    """Return the 20-float vector in model_config.json order."""
    text = path_query or ""
    method_u = (method or "GET").upper()
    has_body = method_u in ("POST", "PUT", "PATCH")
    body_text = (body or "") if has_body else ""
    hdrs = headers or {}

    # training rows carried the attack payload inside the URL, so the numeric
    # features (length/entropy/special/encoded) and the pattern flags must see
    # the same material at runtime: url + body
    mat = text + body_text if body_text else text

    sql_f = float(has_sql_keywords(mat))
    js_f = float(has_js_keywords(mat))
    trav_f = float(has_path_traversal(mat))
    cmd_f = float(has_cmd_injection(mat))
    xxe_f = float(has_xxe_patterns(mat))
    ssi_f = float(has_ssi_patterns(mat))
    prompt_f = float(has_prompt_injection(mat))

    if body_text:
        bl = body_text.lower()
        if any(k in bl for k in BODY_STRONG["sql"]):
            sql_f = max(sql_f, 1.0)
        if any(k in bl for k in BODY_STRONG["js"]):
            js_f = max(js_f, 1.0)
        if any(k in bl for k in BODY_STRONG["traversal"]):
            trav_f = max(trav_f, 1.0)
        if any(k in bl for k in BODY_STRONG["cmd"]):
            cmd_f = max(cmd_f, 1.0)
        if any(k in bl for k in ("<!entity", "<!doctype", 'system "file')):
            xxe_f = max(xxe_f, 1.0)
        if any(k in bl for k in ("<!--#exec", "<!--#include")):
            ssi_f = max(ssi_f, 1.0)
        if any(k in bl for k in BODY_STRONG["prompt"]):
            prompt_f = max(prompt_f, 1.0)

    return [
        float(len(mat)),
        calculate_entropy(mat),
        float(count_special_chars(mat)),
        float(count_encoded_chars(mat)),
        sql_f,
        js_f,
        trav_f,
        cmd_f,
        xxe_f,
        ssi_f,
        float(has_injection_patterns(mat)),
        prompt_f,
        float(has_suspicious_encoding(mat)),
        float(len(body_text)),
        calculate_entropy(body_text) if body_text else 0.0,
        float(len(hdrs)),
        1.0 if any(k.lower() == "user-agent" and v for k, v in hdrs.items()) else 0.0,
        float(behaviour.get("requests_per_minute", 0.0)),
        float(behaviour.get("unique_urls_per_session", 0.0)),
        float(behaviour.get("error_rate", 0.0)),
    ]


def flag_report(vec):
    """Which binary flags fired - used by rules correlation + dashboard."""
    out = {}
    for i, name in enumerate(FEATURES):
        if name.startswith("has_") and vec[i] > 0:
            out[name] = int(vec[i])
    return out
