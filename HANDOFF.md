# AEGIS — HANDOFF DOC (read this first, no need to read all the code)

> Purpose: a future session resumes from THIS FILE alone.
> Last verified: **2026-10-07** — all gates GREEN (numbers in §9).

---

## 0. TL;DR STATUS

| Check | Result |
|---|---|
| `python gateway\test_pipeline.py` (phases 2-4 gate) | **PASS, EXIT=0** |
| `python gateway\test_phases.py` (phases 5-10 gate) | **44/44 PASS, EXIT=0** |
| `tools\mutation_audit.py` (71 Burp-style mutated payloads) | **0 leaks** (everything ≥ CHALLENGE) |
| `tools\rule_check.py` (offline) | 13/13 attacks detected, **0/17 benign false positives** |
| `startall.bat` | created + tested (one double-click starts both apps) |
| `decoys.json` | total = **52** |

**No open blockers.** Open *optional* items are in §13.

---

## 1. WHAT THE PROJECT IS

An **Adaptive Security Gateway** (reverse proxy) placed in front of a deliberately
vulnerable "DemoShop" app. Every client request is inspected by 4 stages and given a
**risk score 0-100**, which maps to an action:

- **score ≥ 81 → BLOCK** (403)
- **31-80 → CHALLENGE** (401 + arithmetic CAPTCHA; correct answer sets `aegis_clear` cookie → next request passes)
- **< 31 → ALLOW** (200, proxied to the target app)
- special overrides: honeytoken/decoy hit, malicious source IP, already-blocked IP → **forced BLOCK**

Selling points (viva): full request **and response** visibility, explainable ML
(feature contribution + counterfactual), deception layer (canary tokens, 52 decoy
paths, a fake AI "persona"), adaptive profiling of the target app, per-IP behaviour
tracking, threat-intel hook.

---

## 2. STACK

- Python **3.12** at `C:\Users\tecky\AppData\Local\Programs\Python\Python312\python.exe`
- **FastAPI + uvicorn** → gateway, port **8080**, binds `0.0.0.0`
- Demo app → Python stdlib `http.server`, port **5001**, binds `0.0.0.0`
- **scikit-learn**: `RandomForest(100, depth=12)` (attack proba) + `IsolationForest`
- `httpx` (proxying + threat intel), `numpy`
- Dashboard = one static file, no build step: `gateway/static/index.html` (vanilla JS,
  polls `/api/logs`, `/api/stats`, `/api/model`, `/api/blocked`, `/api/config`)
- Machine LAN IP is **DHCP** (Wi-Fi, e.g. 172.16.14.123) — `startall.bat` detects the
  default-route NIC and prints the LAN URLs (WSL/Hyper-V vEthernet IPs are excluded,
  they are unreachable from other devices). Firewall: `python.exe` inbound **Allow**
  (Public profile, RemoteAddress Any) — verified 2026-10-07. Both apps bind `0.0.0.0`
  → reachable from every device on the network.

### Ports / URLs
- Dashboard (PC): `http://127.0.0.1:8080/`
- Dashboard (LAN/phone): `http://<LAN-IP>:8080/`  ← LAN IP is printed by `startall.bat`
- Demo app direct: `http://127.0.0.1:5001` (or `http://<LAN-IP>:5001`) → browser hits
  get **307-redirected** to the gateway on the *same host* (Host header is reused), so
  phone traffic lands on the gateway and shows up in the PC dashboard.

---

## 3. HOW TO START

| File | Does |
|---|---|
| **`startall.bat`** | kills anything on :5001/:8080, opens 2 windows (demo + gateway), waits for health, prints PC + phone URLs, opens the dashboard. **Use this one.** |
| `run.bat` | gateway only |
| `demo.bat` | demo app only |

Manual (if you need it in a script/terminal):
```
python demo-app\app.py
python -m uvicorn app:app --host 0.0.0.0 --port 8080 --app-dir gateway
```
Working dir must be the project root:
`D:\D me se sab idar hai\adaptive-security-gateway`

---

## 4. THE PIPELINE (all in `gateway/app.py`, function `pipeline()`)

```
Stage 1   blocklist gate      IP already banned? -> 403 JSON immediately (no ML/proxy)
Stage 2.0 features            behaviour observed FIRST (so rpm is current), then features.extract()
Stage 2.1 rules               rules.scan() -> rules.score()   (deterministic signatures)
Stage 2.4 deception           honeytoken / decoy-path / persona match (persona -> MONITOR, inert)
Stage 3   scoring             rules + ML + iforest + behaviour + threat-intel  (sum, capped 100)
Stage 4   decision            decision.DecisionEngine.decide() -> ALLOW / CHALLENGE / BLOCK
Stage 5   forward             httpx -> target app, capture upstream response
Stage 6   record              _resp_summary() stores status/content-type/length/body snippet -> _persist_log()
```

### Decision order inside `decision.py decide()` (important)
1. `blocked_entry` → BLOCK (override)
2. `honey_hit` → BLOCK (override)
3. `threat_hard` → BLOCK (override)
4. `score >= 81` → BLOCK, **but CHALLENGE if clearance_ok**
5. `score >= 31` → CHALLENGE, **but ALLOW if clearance_ok**
6. grey zone (proba 0.45-0.80) **and** `score >= 10` → CHALLENGE, ALLOW if clearance_ok
7. else → ALLOW

### Scoring math (`gateway/scoring.py`)
`score = min(100, rules + ML + iforest + behaviour + threat_intel)`
- ML = `proba_attack * 100 * 0.30`, **cap 30**
- iforest cap 15, behaviour cap 25, threat cap 40
- rules = sum of top-2 confidence **per category** (across categories), capped 100,
  then contextual bonuses (sql/js keywords, traversal/cmd flags, entropy) —
  bonuses only apply if at least one signature matched (keeps benign at 0).

### Config (`config.json`) — thresholds
```json
"decision": { "block": 81, "challenge": 31, "unsure": 10,
              "grey_zone": [0.45, 0.80], "captcha_ttl_s": 600, "mode": "block" }
"blocklist": { "ttl_hours": [1, 24, 168] }     // tier escalation
"behaviour_cap": 25
"target_url": "http://127.0.0.1:5001"          // MUST stay :5001, never :8080 (self-loop!)
```

---

## 5. FILE MAP — "I want to change X → edit Y"

| Want to change | File |
|---|---|
| Pipeline order, proxying, response capture, scan decode | `gateway/app.py` |
| Signature rules (SQLi/XSS/SSRF/SSTI/… confidences) | `gateway/rules.py` (`RULES` list) |
| Feature vector for the model | `gateway/features.py` (`extract()`, `SQL_KEYWORDS`, `JS_KEYWORDS`) |
| Bands/CAPTTCHA/clearance/blocklist logic | `gateway/decision.py` |
| Point arithmetic, caps, explanations | `gateway/scoring.py` |
| rpm / unique_urls / error_rate, per-IP windows | `gateway/behaviour.py` |
| Decoy paths, canary planting, persona bot | `gateway/deception.py` (registry also in `decoys.json`) |
| Target-app crawler / adaptive thresholds | `gateway/profiler.py` |
| Threat intel (VirusTotal etc.) | `gateway/threatintel.py` |
| Dashboard UI / drawer / filters | `gateway/static/index.html` |
| Vulnerable endpoints (SQLi, traversal, cmd, redirect) | `demo-app/app.py` |
| Thresholds / target / caps | `config.json` |
| Test gates | `gateway/test_pipeline.py`, `gateway/test_phases.py` |
| Verification scripts (payload suites) | `tools\` (see §9) |

### Rule format (one line, easy to add)
```python
("category", r"regex", confidence, "human label"),   # categories: sqli, xss, nosql,
                                                     # ldap, path_traversal, command_injection,
                                                     # xxe, ssi, header_injection, ssti,
                                                     # config_injection, prompt_injection,
                                                     # ssrf, csrf, decoy, encoding
```

---

## 6. API ENDPOINTS (all on :8080)

`GET /` dashboard (gateway owns root; other paths are proxied)
`GET /api/health` · `GET|POST /api/target` · `GET|POST /api/config`
`GET /api/logs?limit=N` · `GET /api/stats` · `GET /api/model`
`GET /api/blocked` · `POST /api/unblock {"ip":"..."}` ← **you will need this (see §11)**
`GET|POST /api/reputation` · `POST /api/challenge {token, answer}`
`GET|POST /api/profile` (build target profile) · `POST /api/reset` (clear logs/state)

---

## 7. DASHBOARD UI — WHERE THINGS ARE (incl. decoy demo)

Layout: header `AEGIS · Adaptive Security Gateway` + status pills → left column
(Setup / Stage 4 segregation / Inspected requests) → right column (Model & pipeline /
Blocked clients / Source reputation / Application profile / Gateway config) →
clicking a request row opens a **drawer**.

Drawer sections: `Score breakdown (stage 3)` → `Stage 4 decision` → `Stage 2 findings`
→ `Request payload` → `Response` (status, content-type, length, body snippet).

### Step-by-step: demo the FAKE DECOYS (bait infrastructure)
1. Double-click **`startall.bat`**. Wait for the dashboard to open (`http://127.0.0.1:8080/`).
2. In **Setup**, confirm target = `http://127.0.0.1:5001` → click **Secure this app**.
3. Click **Reset log** so the table starts clean.
4. Open a new tab and request a decoy path on the gateway, e.g.
   `http://127.0.0.1:8080/.env`  (or `/.git/config`, `/admin/console`, `/.kube/config`,
   `/api/v2/admin/users`, `/.well-known/ai-plugin.json`, `/backup.sql`, `/server-status`)
   → the browser gets **403**.
5. Back in the dashboard, filter **Blocked** → the top row shows:
   - action `BLOCK`, status 403, tier `2.4-deception`, category decoy,
   - reason like `Honeytoken followed: /.git/config` or `decoy path probe`.
6. Click the row → drawer → `Stage 4 decision` shows the override reason;
   `Response` shows the JSON body the attacker received.
7. **Important effect:** your IP is now on the blocklist for 1h — the *next* request
   (even a benign `/login`) returns 403 with `tier: 1-blocklist` and reason
   `IP already blocked: followed honeytoken ...`. Show that second row too — it proves
   escalation.
8. To continue browsing: **Blocked clients** panel → click **remove** next to
   `127.0.0.1` (or `POST /api/unblock {"ip":"127.0.0.1"}`).
9. Bonus demos:
   - **Canary token**: the gateway plants a random canary in proxied HTML; requesting it
     → BLOCK at tier `4.2-deception` (test 9.2).
   - **Persona**: hitting a Class-C decoy returns a 200 scripted "AI assistant" reply
     that is inert (`aegis.decoy: true`, executes nothing, stores nothing) → MONITOR row.
   - **Benign baseline**: `/login` → 200, score ~5, `4.1-low`, tier Forwarded filter.

### Other one-click demos
- Injection: `http://127.0.0.1:8080/search?q=Or+1%3D1--` → **403 BLOCK** (score ~90+).
- CAPTCHA: `http://127.0.0.1:8080/profile?redirect=http://evil.com` → **401** with math
  question → POST `/api/challenge {"token":"...","answer":8}` → reload with the
  `aegis_clear` cookie → 200 (tier `4.3-cleared`).
- Phone: same URLs but `http://192.168.1.10:8080/...` — rows appear in the PC dashboard.

---

## 8. WHAT WAS ALREADY DONE (chronological)

**Phase A — foundation (earlier sessions)**
- Gateway + demo app + dashboard; 4-stage pipeline; CAPTCHA challenge flow;
  blocklist with tier escalation (1h/24h/168h); threat-intel hook; profiler;
  deception layer; ML + iforest trained (`trained_rows 499755`, acc 0.885, f1 0.833).
- Bound everything to `0.0.0.0` (gateway, demo app, run.bat) → LAN/phone reachable.
- Demo app `_bounce_to_gateway()` 307 redirect for browser requests only
  (`x-requested-by: aegis-gateway` or non-HTML Accept = served directly, keeps tests working).
- **Response visibility**: `_resp_summary()` in `app.py`; every record site (blocklist,
  persona, challenge HTML/JSON, block, error, forwarded) sets `rec["response"]` BEFORE
  `_persist_log()`. Dashboard drawer shows `Request payload` + `Response`, table `req`
  cell shows `HTTP <status> · <content-type> · <bytes>`.

**Phase B — false-positive fixes**
- `powershell(?!\s*/\d)` → `WindowsPowerShell/5.1` UA no longer matches the shell-binary rule.
- Loopback SSRF rule → lookbehind/lookahead so `Chrome/120.0.0.0` no longer matches.
- CSS `width:100%}` in `_challenge_html` broke Python `%`-formatting → **500**; escaped to `100%%` (page renders).
- `features.extract()` now computes numeric + pattern features over `url + body` (ML was
  blind to POST bodies) → SQLi POST now `rules 70 + ml 10.8 = 81 → BLOCK`.

**Phase C — detection hardening**
- nosql fixed to `\$(ne|gt|lt|...|where)\b`; added ssti template/escape rules,
  prototype-pollution rule, `${IFS}` shell-var rule.
- Decoy registry 22 → **52** paths, categorized, written to `decoys.json`.

**Phase D — this session (2026-10-07)**
1. **`startall.bat`** created + tested.
2. **SQLi `Or+1=1--` was only CHALLENGE** (user complaint). Root cause: the tautology
   rule required a `'` or digit *before* `or`, and the gateway's scan URL is `unquote()`
   (not `unquote_plus`), so `+` was never a space. Rewrote to
   `\b(or|and)\b|\|\||&&` + `[\s(+]*` separator → now **60 rules + ML → BLOCK**.
3. **Test 10.6 failed**: the `clearance cookie forgery` rule matched the *legitimate*
   `Cookie: aegis_clear=...`, adding +40 and pushing a cleared request over the block
   band. Fix: `OWN_CLEARANCE` regex strips that one pair from the Cookie header before
   scanning (forgery still detected in URL/body/Referer/other headers; value is
   HMAC+IP-bound anyway).
4. **Overlong UTF-8 obfuscation leaked** (`%c0%a0` = space, `%c0%af` = `/`): Python's
   `unquote()` turns them into `U+FFFD`, and ASGI's `scope["path"]` is *already* decoded.
   Added `_deobfuscate()` + `_scan_decode()` in `app.py`, and scan now uses
   **`scope["raw_path"]` + `scope["query_string"]`** (latin-1) so the raw request line is
   what rules see. Also `_scan_decode` runs per layer so double-encoded `%25c0%25af` works.
5. **New rules**: stacked query (`;SELECT/INSERT/...`), `SELECT *`, `BETWEEN n and m`,
   quote+comment breakout (`'--`), template arithmetic `${7*7}` / `<%= %>` / `#{}` /
   nested marker, arbitrary-name header injection after CRLF (`\r\nX-Foo:`);
   broadened command-substitution wordlist (added sh/bash/python/perl/nc/rev/eval/base64/type/dir…).
6. **`rules.scan()` now also reads** `x-original-url`, `x-rewrite-url`, `x-forwarded-for`,
   `x-real-ip`, `forwarded` (the `x-original-url` rule could never fire before — the
   header wasn't in the material), and header lookup is **case-insensitive**.
7. **Fixed two dead rules**: both `decoy` signatures used `^/` but the scan material
   starts with `GET`, so they never matched (decoys were only caught by the deception
   registry). Changed to `(?:^|[\s?&=])/`.

---

## 9. VERIFICATION SUITE (copy of these lives in `tools\`)

| Script | What it proves |
|---|---|
| `gateway\test_pipeline.py` | phases 2-4 gate: rules on dataset payloads, benign gate, decision bands, CAPTCHA, blocklist escalation. Prints `PHASE 2-4 GATE: PASS`, exit 0. |
| `gateway\test_phases.py` | phases 5-10: 44 checks — discovery, forward, attacks, profiler, decoys/honeytokens, end-to-end. Prints `44/44`, exit 0. |
| `tools\mutation_audit.py` | 71 mutated Burp-style payloads (encoding/case/comments/method/header changes) → prints leaks; **must print 0**. Auto-unblocks 127.0.0.1 at the end. |
| `tools\rule_check.py` | offline: 13 attack payloads must hit `sqli`, 17 benign queries must not. Prints `attacks missed=0 benign flagged=0`. |
| `tools\ml_check.py` | ML points for SQLi/benign POST/benign GET. |
| `tools\hard_payloads.py` | 10 PhD-level payloads (XXE, Log4Shell, decimal-IP SSRF…) → all must be ≥ CHALLENGE. |
| `tools\verify_flow.py`, `uniq_scan.py`, `ol_unit.py` | flow / unique_urls sensitivity / overlong decoding unit checks. |

**Run order after ANY change to rules/features/config:**
```
python tools\rule_check.py
python gateway\test_pipeline.py
python gateway\test_phases.py
python tools\mutation_audit.py
```
Restart the gateway after editing any `gateway\*.py` (uvicorn does not auto-reload).

---

## 10. GOTCHAS — things that WILL bite you

1. **Your own IP gets blocked** whenever you touch a decoy path (by design). Everything
   then 403s with `tier: 1-blocklist` and it looks like a bug. Fix:
   `POST /api/unblock {"ip":"127.0.0.1"}` (or Blocked clients → remove).
   All test scripts must unblock themselves.
2. **Scores wobble ±20** because `requests_per_minute` (60s window) and
   `unique_urls_per_session` (300s window) feed the model. Hammering requests inflates
   them. Rule of thumb: **unique_urls ≥ 6 in 5 min → ML proba ~0.57 (grey zone) →
   CAPTCHA even for benign traffic.** This is *by design* (unsure → CAPTCHA); solving it
   once issues `aegis_clear` (600s) and subsequent requests are ALLOW.
   Never conclude "false positive" without waiting ~60s between probes.
3. **The gateway scan URL uses `unquote` (NOT `unquote_plus`)** — `+` stays `+`.
   Any rule matching space-separated payloads must accept `+` as a separator.
4. **ASGI decodes `scope["path"]`** (invalid UTF-8 → U+FFFD). Always scan the raw
   `raw_path`/`query_string` if you want to catch obfuscation.
5. **`target_url` must be `http://127.0.0.1:5001`.** If someone sets it to `:8080` the
   gateway proxies to itself → gate timeouts. Repair with `POST /api/target`.
6. **Server logs flood the terminal** (the dashboard polls every ~2s). Always redirect:
   `-RedirectStandardError <file>` or you won't see your own output.
7. **PowerShell `<`/`&`/quotes break inline `python -c`** → write the script with a
   here-string + `Set-Content`, then run it.
8. `startall.bat` opens real windows; testing it from a shell with `< nul` prints
   `Input redirection is not supported` (harmless, from `timeout /t`).
9. Demo app quirks (NOT gateway bugs): `/profile?id=42` and `/download?file=report.pdf`
   → 404 (route not found), `/profile?id=1 regexp '[a-z]'` → **502** because the demo
   app itself crashes on that SQL (gateway logs an ERROR record).
10. Not a git repo → no history. **Back up by copying files** (or `git init` if wanted).

---

## 11. OPEN / TODO (optional — nothing is blocking)

1. **Re-verify from the phone** on the LAN after this session's rule changes
   (`http://192.168.1.10:8080` + a decoy path + an injection → check rows on the PC).
2. **Demo-app 502** on `/profile?id=1 regexp ...` — either wrap the demo handlers in
   try/except (return 500 instead of crashing) or accept it as "upstream error" theatre.
3. **Benign CAPTCHA pressure**: decide whether `unique_urls >= 6` in 5 min should still
   CAPTCHA a normal browser. Options: lengthen `SESSION_WINDOW_S` (behaviour.py:19 = 300),
   or require grey-zone CAPTCHA only when `score >= challenge` — note `test_pipeline`
   Phase 4 expects `score=15 + grey → CHALLENGE`, so don't break that.
4. **Write README.md** (installation, architecture diagram, how to run gates) if a report
   or viva needs it.
5. Consider `git init` + initial commit for real versioning.
6. Optional: persist blocklist/clearances across restarts (currently **in memory only** —
   a restart wipes blocks and CAPTCHA clearances).

---

## 12. HOW TO RESUME — first 5 commands

```bat
cd /d "D:\D me se sab idar hai\adaptive-security-gateway"
startall.bat                       :: starts demo + gateway, opens dashboard
python tools\rule_check.py         :: offline FP/miss check  -> missed=0 flagged=0
python gateway\test_pipeline.py    :: -> PHASE 2-4 GATE: PASS, exit 0
python gateway\test_phases.py      :: -> 44/44, exit 0
python tools\mutation_audit.py     :: -> leaks: 0
```
Then open `http://127.0.0.1:8080/` and read §7 for what to click.
If everything 403s → §10.1 (unblock your IP).
