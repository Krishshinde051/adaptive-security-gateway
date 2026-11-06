import io, os, sys
p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.py")
s = io.open(p, encoding="utf-8").read()
reps = [
    ('DB.executemany("INSERT INTO users (user, pass, role) VALUES (?,?,?))"',
     'DB.executemany("INSERT INTO users (user, pass, role) VALUES (?,?,?)"'),
    ('return PAGE.format(body=body).encode()',
     'return PAGE.replace("{body}", body).encode()'),
    ("""    qs = parse_qs(raw.decode("utf-8", "replace"))
    user = (qs.get("user", [""])[0], qs.get("pass", [""])[0]
            if "user" in qs else (qs.get("username", [""])[0], qs.get("password", [""])[0]))
    u, p = user""",
     """    qs = parse_qs(raw.decode("utf-8", "replace"))
    u = (qs.get("user") or qs.get("username") or [""])[0]
    p = (qs.get("pass") or qs.get("password") or [""])[0]"""),
]
for old, new in reps:
    if old not in s:
        print("MISSING:", old.splitlines()[0][:70])
        sys.exit(1)
    s = s.replace(old, new)
s = s.replace("{{", "{").replace("}}", "}")
io.open(p, "w", encoding="utf-8", newline="\n").write(s)
print("patched")
