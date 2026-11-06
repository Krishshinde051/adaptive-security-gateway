# AEGIS — DOUBTS LOG (Q&A with the mentor-me sessions)

> Purpose: my doubts + the answers, so the next session can resume without re-explaining.
> Created: 2026-10-09. Colab cells are NOT stored here (see `AEGIS_colab.ipynb`).

---

## Q1. How many actual datasets are used while the project runs?
**3 datasets in the chain, but only 1 does the real training.**

| Step | Script | Dataset | What's inside |
|---|---|---|---|
| 1. generate | `scripts/generate_dataset.py` | `dataset/aegis_dataset.csv` (500k×31) | raw generated HTTP requests + **leaky** `risk_score`, `severity` |
| 2. split | `scripts/split_datasets.py` | `dataset/ml_dataset.csv` (500k×29) | same, leaky cols removed |
| 3. **clean** | `scripts/fix_overfitting.py` | **`dataset/ml_dataset_fixed.csv`** (500k×29) | behavioural features re-sampled so benign/attack overlap → no leakage |
| 4. train/export | `scripts/train_fixed.py`, `scripts/export_model.py` | reads **`ml_dataset_fixed.csv`** | → `models/aegis_model.pkl` + `scaler.pkl` |
| 5. **gateway running** | — | **0 CSVs** | loads `.pkl` only |

Deleted 2026-10-09: `dataset/gateway_dataset.csv` (unused duplicate), old `models/isolation_forest*` trio, `__pycache__`. Freed 136.75 MB.

---

## Q2. The gateway doesn't read a dataset — is it just "raw code thinking it's doing its job"?
No. **The `.pkl` IS your dataset, compressed.** Trained once on `ml_dataset_fixed.csv`, then loaded forever.
- `rules.py` = hand-written regex signatures (no data needed)
- `features.py` = converts a live request into the **same 20 features** the dataset had → the model can read it
- Dataset is never touched while running.

## Q3. Why 2 pkl files (model + scaler)?
- `aegis_model.pkl` = RandomForest (the brain)
- `scaler.pkl` = StandardScaler (mean/std of each of the 20 features = the measuring scale)
Both must ship together, otherwise live values land in a different range → wrong predictions.
Loaded together at `gateway/scoring.py:75-76`. Same pairing in `gateway/models/` (iforest + if_scaler).

---

## Q4. RF exists — where does Isolation Forest come in?
**Not in sequence. They run in PARALLEL on the same request; points are summed.**
```
rules + RF(≤30) + iForest(≤15) + behaviour(≤25) + threat(≤40)  → min(100) → 81/31 bands
```
- RF = supervised, knows the 13 trained attack types (known attacks)
- iForest = unsupervised, knows only "normal" (unknown/zero-day shapes)
- Only ordered stage: blocklist check happens FIRST (banned IP → 403, no scoring at all).

## Q5. Does the dataset contain normal AND malicious rows?
Yes — `ml_dataset_fixed.csv`: **299,755 benign (label 0)** + **200,000 attack (label 1)**.
Each row = one HTTP request + 20 features + label + attack_type.
- RF needs the label (supervised)
- iForest uses the same rows but **ignores the label** (unsupervised)

---

## Q6. Login page with correct credentials — what happens at the backend?
```
1 blocklist (IP banned?) → no
2 behaviour → first request of session → 0
3 features → 20 numbers
4 rules/regex → no attack strings → 0
5 deception → no honeytoken → 0
6 score: rules 0 + RF ~0.6 + iForest 0 + behaviour 0 ≈ 1
7 decision → ALLOW (200) → proxy to :5001 → creds checked → 200
8 record → tier 4.1-low
```

## Q7. But my username/password is NEW — won't the model think it's unknown?
**The model never reads credentials.** It only sees 20 statistics (length, entropy, special chars, flags).
`features.py:138` deliberately excludes generic form words (`user`, `pass`, `select`) from the body flags
*"so a normal login POST never looks like an attack"*.
Behaviour layer (`behaviour.py:127`) is what reacts: **5 wrong passwords +10, 8+ +15 (brute force), rate z≥6 +15, error_rate≥60% +8** → 31 = CAPTCHA, 81 = BLOCK (IP blocked 1h → 24h → 168h).

## Q8. If RF misses the attack, does iForest catch it?
Both score in parallel. Example (partial zero-day): rules 66 + RF 8.7 = 74 → CHALLENGE;
**with iForest +15 → 89 → BLOCK.** iForest's 15 points turn a solvable CAPTCHA into a hard 403.
If *everything* is blind: 0+4.5+15+0 = 19 → **MONITOR row** (still forwarded, flagged on dashboard) —
by design iForest alone can never block (recall only 0.12).

---

## Q9. Is Isolation Forest suitable here? (config numbers)
`gateway/models/iforest_config.json`: 20 features, n_estimators 200, contamination 0.40,
threshold = **train 5th percentile ≈ 95% specificity** (`decision_threshold = -0.10526`), inference **0.095 ms**.
Measured: precision **0.9996**, specificity **0.99997** (2 FP / 59,951 benign), recall **0.121**.
→ Precision-tuned safety net: caps at +15/100, fires only on extreme outliers.

## Q10. Does CAPTCHA make any difference?
Yes — it's the middle safety valve (score 31-80).
Without it those requests would be ALLOW (bot walks in) or BLOCK (innocent kicked out).
With it: scripts stop, you get a detection point, human solves once → `aegis_clear` cookie (600s).
**Limits:** humans/OCR solve it → it's an automation brake, not a filter.

## Q11. Solve the CAPTCHA → does the malicious request then bypass the gateway?
**YES, for the middle band.** Verified 2026-10-09 by running `DecisionEngine.decide()` directly
(`C:\Users\tecky\AppData\Local\Temp\opencode\captcha_flow.py`):

| score | no cookie | with `aegis_clear` | reaches backend? |
|---|---|---|---|
| 19 (low) | ALLOW | ALLOW | yes |
| **45 / 79 (31-80)** | CHALLENGE 401 | **ALLOW 200** | **YES = bypass** |
| **grey zone** (proba .45-.80, score>=10) | CHALLENGE 401 | **ALLOW 200** | **YES = bypass** |
| 95 (>=81) | BLOCK 403 | CHALLENGE 401 (asks again) | no = infinite CAPTCHA loop |
| honeytoken / banned IP / malicious source | BLOCK | BLOCK | no |

- Path: `decision.py:221-224` returns ALLOW "cleared by CAPTCHA" → `app.py:412` proxies it.
- `decision.py:215`: >=81 with clearance only demotes BLOCK->CHALLENGE, never ALLOW.
- Hard overrides checked BEFORE clearance (`decision.py:200-211`) → clearance useless there.

**Extra weaknesses:**
1. Clearance is bound to **IP only** (`decision.py:174` = {ip, ts, exp}), NOT to the request/URL.
   Solve once → **all** 31-80 requests from that IP pass for `captcha_ttl_s` = **600 s**.
2. Cookie: random 16-byte token, server-side in-memory, `httponly`, `samesite=lax`,
   3 attempts max → not forgeable (`rules.py:72` even scores `aegis_clear` injection +40).
3. Honest framing for the panel: **CAPTCHA = automation brake, not a security boundary.**
   Stops scripts/OCR-at-scale, gives a detection log line, lets humans through.
   It does NOT validate what the payload does.

**Re my payloads: P1=7 and P2=5 → ALLOW on the FIRST try, CAPTCHA never appears.**
CAPTCHA-bypass only matters for medium-band payloads (classic `admin' -- x` = 67).

Possible mitigation **F7**: bind clearance to (IP + request-hash), or re-check the score after
clearance and keep the request in MONITOR + log instead of silent ALLOW.

---

## Q12. Payload that outsmarts BOTH models (verified 2026-10-09)
Harness: offline replica of `app.py` stages 2-4 using real `rules.py`/`features.py`/`scoring.py`/`decision.py`
+ real `.pkl`s. (Was run from temp dir — rebuild if gone: insert `gateway/` on sys.path, load config.json,
instantiate `Scorer` + `DecisionEngine`, `scan_decode` = 2× unquote, behaviour = zeros.)

**PAYLOAD 1 — SQLi login bypass**
```
POST /login
user='+or+1+like+1+--%26x=1&pass=whatever
→ decoded: user=' or 1 like 1 --&x=1&pass=whatever
SQL run by demo app: SELECT ... WHERE user='' or 1 like 1 --' AND pass='whatever'
→ 4 rows returned → LOGGED IN as alice   (IMPACT PROVEN)
Gateway: rules 0 hits | RF 0.2215→6.6 | iForest +0.0348 vs -0.10526 → +0 | TOTAL 7 | ALLOW 200
```
Why signatures miss it: tautology rules need `\d+=\d+` (we used `1 like 1`) or `'x'='y'`;
`--(\s|$)` needs whitespace/EOL but ours is followed by `&`.

**PAYLOAD 2 — RCE via `&` separator**
```
GET /run?cmd=hello%26whoami   → cmd=hello&whoami
demo app runs: echo hello&whoami → output "hello" + "tr0janfaith\tecky"  (IMPACT PROVEN)
Gateway: rules 0 hits | RF 0.1519→4.6 | iForest -0.0123 → +0 | TOTAL 5 | ALLOW 200
```
Why it misses: `rules.py:59` requires `&` preceded by `(^|[?&=;|\s])`; ours is preceded by `o` in `hello`.

**CONTROLS (defence does work):**
- classic `user=admin' -- x` → rules 60 → **67 → CHALLENGE**
- `/download?file=../../etc/passwd` → rules 85 + RF 29.9 + iForest +15 = **100 → BLOCK**

**Root-cause findings:**
1. RF never sees payload text or the path — only 20 numbers. Its vector for `cmd=hello;whoami`
   is **identical** to `cmd=hello&whoami` → RF gives 0.1519 to BOTH → **RF does not detect
   command injection at all; rules do.**
2. `has_sql_keywords` is noise: **53.8% of benign rows (161,369/299,755) have it >0** (list
   contains `user`, `admin`, `or`, `and`, `set`), benign p95 = 3.
3. Dataset holes: **0 benign `/run?` rows, 0 benign rows with `&` in URL, 0 benign
   `has_cmd_injection`, 0 benign `has_suspicious_encoding`.**
4. **Structural gap:** `ml_cap = 30` (`scoring.py:217`) **<** `challenge_thr = 31` (`decision.py:221`)
   → a 100%-confident RF alone can never trigger even a CAPTCHA. Rules are the de-facto primary
   detector — and they're regex.

**Fixes proposed (F1-F6):** F1 add `\r?\n` + `&\s*(cmdword)\b(?!=)` separators in `rules.py:59`;
F2 add `like/rlike/glob/regexp` boolean predicates + `--` inside quoted value (`rules.py:22-35`);
F3 new feature = shell/SQL metacharacters inside decoded param values (needs retrain);
F4 add benign `/run?` rows + `&`/newline attack variants to `generate_dataset.py`;
F5 raise `ml_cap` to 40 or "proba≥0.95 ⇒ at least CHALLENGE"; F6 real fix = parameterised SQL
+ `shell=False` (WAF = defence-in-depth only).

---

## Standing facts to quote in the viva
- Gates (all green 2026-10-07): `test_pipeline.py` PASS, `test_phases.py` 44/44,
  `mutation_audit.py` 0 leaks, `rule_check.py` 13/13 attacks, 0/17 benign FP.
- Model: RandomForest(100, depth 12), trained_rows 499,755, test_acc 0.885, f1 0.833.
- Bands: ≥81 BLOCK · 31-80 CHALLENGE · <31 ALLOW · grey zone 0.45-0.80.
- Leakage story: first runs scored 1.0000 (label-derived cols) → removed → 0.9988 →
  behavioural resample → honest 0.885 with train-test gap -0.0004.
