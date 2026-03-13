# Agent & LLM Integration — Complete Technical Documentation

> **Who this is for:** Anyone who wants to understand exactly what the agent
> does, how it thinks, how it talks to the LLM, and where every piece of data
> goes. Written specifically for this hackathon project.

---

# Table of Contents

1. [What the Agent Is](#1-what-the-agent-is)
2. [File Structure & Responsibilities](#2-file-structure--responsibilities)
3. [The Big Picture — Data Flow](#3-the-big-picture--data-flow)
4. [The Agent Reasoning Loop](#4-the-agent-reasoning-loop)
5. [File 1 — rules_engine.py (Detection Brain)](#5-file-1--rules_enginepy-detection-brain)
   - [Constants & Configuration](#51-constants--configuration)
   - [The ThreatAlert Dataclass](#52-the-threatalert-dataclass)
   - [Helper Functions](#53-helper-functions)
   - [The 8 Detection Rules](#54-the-8-detection-rules)
   - [run_all_rules — The Master Caller](#55-run_all_rules--the-master-caller)
   - [MITIGATIONS & get_mitigation](#56-mitigations--get_mitigation)
6. [File 2 — llm_client.py (LLM Integration)](#6-file-2--llm_clientpy-llm-integration)
   - [What Ollama Is](#61-what-ollama-is)
   - [Configuration](#62-configuration)
   - [How the Agent Talks to Ollama](#63-how-the-agent-talks-to-ollama)
   - [check_ollama_health](#64-check_ollama_health)
   - [generate_hypothesis](#65-generate_hypothesis)
   - [generate_incident_report](#66-generate_incident_report)
   - [What Is and Is NOT Stored](#67-what-is-and-is-not-stored)
7. [File 3 — main.py (The Core Loop)](#7-file-3--mainpy-the-core-loop)
   - [Startup](#71-startup)
   - [Database Helpers](#72-database-helpers)
   - [_build_observation](#73-_build_observation)
   - [_enrich_with_llm](#74-_enrich_with_llm)
   - [_run_agent_cycle — One Full Loop](#75-_run_agent_cycle--one-full-loop)
   - [main — The Infinite Loop](#76-main--the-infinite-loop)
   - [Console Output Functions](#77-console-output-functions)
8. [The Database — Where Everything Is Stored](#8-the-database--where-everything-is-stored)
9. [Confidence Score System](#9-confidence-score-system)
10. [The LLM Boundary — What AI Does and Does Not Do](#10-the-llm-boundary--what-ai-does-and-does-not-do)
11. [Full Walk-Through — One Attack, Start to Finish](#11-full-walk-through--one-attack-start-to-finish)
12. [Error Handling & Resilience](#12-error-handling--resilience)
13. [Integration With Teammates](#13-integration-with-teammates)

---

---

# 1. What the Agent Is

The agent is a **continuously running Python process** that sits between the
backend database and the dashboard. It does nothing manually — it runs in an
infinite loop, waking up every 5 seconds, checking for suspicious activity,
and going back to sleep.

It is modelled after how a real **SOC analyst** (Security Operations Centre
analyst) thinks. A SOC analyst does not sit and stare at every single network
packet. They set rules, watch for threshold breaches, form a hypothesis about
what is happening, investigate the evidence, make a decision, and then write
a report. The agent does all of this automatically.

The agent has two completely separate responsibilities:

**Responsibility 1 — Detection (no AI involved)**
Using hardcoded mathematical rules, it looks at the logs written by the
backend and decides if something is suspicious. This part produces a definite
yes/no answer with a confidence score.

**Responsibility 2 — Explanation (AI involved)**
Once a threat is confirmed by the rules, the agent calls a local LLM (Ollama)
to produce two pieces of human-readable text: a hypothesis (what kind of attack
is this?) and an incident report (a polished SOC paragraph for the dashboard).
The LLM never makes a security decision. It only writes sentences.

---

---

# 2. File Structure & Responsibilities

```
agent/
├── main.py          The entry point. Contains the infinite polling loop,
│                    database read/write logic, LLM enrichment calls,
│                    and console output. This is the conductor — it
│                    coordinates everything but does not do detection itself.
│
├── rules_engine.py  The detection brain. Contains every detection rule,
│                    all thresholds, the ThreatAlert data model, and the
│                    deterministic mitigation strings. Zero AI here.
│
├── llm_client.py    The LLM integration layer. Handles all HTTP
│                    communication with Ollama. The only file that knows
│                    Ollama exists. Provides two public functions:
│                    generate_hypothesis() and generate_incident_report().
│
└── requirements.txt One dependency: requests>=2.31.0
                     (sqlite3, json, os, sys, time, dataclasses, datetime
                      are all Python standard library — no install needed)

data/
└── logs.sqlite      The shared SQLite database.
                     ├── logs table   → written by backend, read by agent
                     └── alerts table → written by agent, read by dashboard
```

---

---

# 3. The Big Picture — Data Flow

This is the journey of data from an attacker's request all the way to the
dashboard screen.

```
ATTACKER
  │
  │  (sends malicious HTTP requests via browser / Requestly)
  ▼
BACKEND (Teammate 1 — backend/api.py)
  │
  │  Receives the request, processes it, writes one row to:
  ▼
data/logs.sqlite  ←──────────────────────────────────────────┐
  │  (logs table)                                            │
  │                                              backend keeps writing
  │  Agent polls this every 5 seconds
  ▼
AGENT — rules_engine.py
  │
  │  Runs 8 SQL queries against the logs table.
  │  Each query checks one attack pattern.
  │  If a threshold is crossed → creates a ThreatAlert object.
  │
  ▼
AGENT — main.py
  │
  │  Phase 1: Writes the ThreatAlert to the alerts table IMMEDIATELY
  │  (dashboard can already display the detection at this point)
  │
  ▼
AGENT — llm_client.py
  │
  │  Sends two HTTP POST requests to localhost:11434 (Ollama server):
  │    POST 1 → generate_hypothesis()   → gets 1-2 sentence hypothesis
  │    POST 2 → generate_incident_report() → gets 2-3 sentence SOC report
  │
  ▼
AGENT — main.py
  │
  │  Phase 2: Updates the existing alerts row with the LLM text
  │
  ▼
data/logs.sqlite
  │  (alerts table — now fully populated)
  │
  ▼
DASHBOARD (Teammate 3 — dashboard/app.py)
  │
  │  Polls the alerts table every few seconds (Streamlit auto-refresh)
  │  Displays all fields including LLM text, converts timestamps to IST
  │
  ▼
JUDGES SEE THE RESULT ON SCREEN
```

---

---

# 4. The Agent Reasoning Loop

The agent's loop is directly modelled on the 5-step SOC analyst workflow
defined in the project brief. Here is how each step maps to actual code:

```
STEP 1 — OBSERVE
  What:  Read new events from the logs table
  Where: main.py → _run_agent_cycle() calls run_all_rules()
  How:   Each rule function runs a SQL SELECT against logs
  AI?    No

STEP 2 — HYPOTHESIZE
  What:  Form a theory about what the attack might be
  Where: main.py → _enrich_with_llm() calls llm_client.generate_hypothesis()
  How:   _build_observation() converts ThreatAlert fields into a sentence,
         that sentence is sent to Ollama as a prompt
  AI?    YES — this is the first of two LLM calls

STEP 3 — INVESTIGATE
  What:  Apply rules and bonus conditions to calculate confidence
  Where: rules_engine.py → inside each check_* function
  How:   SQL COUNT queries + Python if-conditions + additive confidence scoring
  AI?    No

STEP 4 — DECIDE
  What:  Is the confidence score high enough to raise a formal alert?
  Where: main.py → _run_agent_cycle()
  How:   confirmed = [a for a in candidates if a.confidence >= 40]
  AI?    No

STEP 5 — EXPLAIN
  What:  Format the findings into a polished incident report
  Where: main.py → _enrich_with_llm() calls llm_client.generate_incident_report()
  How:   Threat type, IP, evidence dict, mitigation string, and hypothesis
         are all sent to Ollama as a structured prompt
  AI?    YES — this is the second of two LLM calls
```

The loop runs every **5 seconds** (`POLL_INTERVAL_SECONDS = 5` in main.py).

---

---

# 5. File 1 — rules_engine.py (Detection Brain)

This is the largest and most important file. It contains zero AI. Every
decision it makes is based on counting, comparing, and pattern matching against
the logs table.

---

## 5.1 Constants & Configuration

### `BASELINE` (dict)

Defined at the top of `rules_engine.py`. Contains every numeric threshold
that controls how sensitive the agent is. Change these numbers to make the
agent more or less aggressive in its detections.

```
BASELINE = {
    "max_failed_logins_per_min":      5    → Rule 1 (Brute Force) fires above this
    "max_restricted_hits_per_min":    3    → Rule 2 (Recon) fires above this
    "max_401_403_per_min":            6    → Rule 3 (Auth Scan) fires above this
    "max_distinct_users_per_min":     8    → Rule 4 (Cred Stuffing) fires above this
    "account_takeover_min_failures":  3    → Rule 5 needs at least this many failures
    "account_takeover_window_seconds":300  → Rule 5 looks back 5 minutes
    "max_data_requests_per_min":      20   → Rule 6 (Data Exfil) fires above this
    "path_traversal_min_attempts":    1    → Rule 7 fires on even 1 traversal request
    "max_requests_per_min":           100  → Rule 8 (DoS) fires above this
    "alert_cooldown_seconds":         300  → same threat+IP suppressed for 5 minutes
    "trusted_ips":                    ["10.0.0.1", "127.0.0.1"]
}
```

### `RESTRICTED_PATHS` (list)

List of URL paths that regular users should never be hitting. Used by
Rule 2 (Endpoint Reconnaissance). Any IP that hits more than 3 of these
paths in 60 seconds is flagged.

```
["/admin", "/config", "/internal", "/dashboard",
 "/api/keys", "/env", "/.env", "/settings"]
```

### `DATA_ENDPOINTS` (list)

List of URL paths that serve user data. Used by Rule 6 (Data Exfiltration).
An IP making more than 20 successful GET requests to any of these endpoints
in 60 seconds is flagged.

```
["/api/users", "/api/user", "/users", "/user", "/export",
 "/download", "/data", "/api/data", "/files", "/reports",
 "/backup", "/api/export", "/dump"]
```

Note: Rule 6 also uses LIKE patterns to catch `/api/anything`,
`/data/anything`, `/export/anything`, `/download/anything`, `/files/anything`
even if the exact path is not in the list above.

### `RULE_CONFIDENCE` (dict)

Every named rule condition has a numeric weight. Confidence is built
additively — each condition that fires adds its weight to the running total.
The result is then clamped to the range 0–100.

```
Base rules (always fire when a threshold is crossed):
  rule_high_login_failure   → 55
  rule_restricted_recon     → 60
  rule_auth_scan            → 50
  rule_credential_stuffing  → 65
  rule_account_takeover     → 85   ← highest base (success after failure is critical)
  rule_data_scraping        → 60
  rule_path_traversal       → 70
  rule_dos_flood            → 55

Bonus rules (fire when extra conditions are met):
  rule_single_ip_brute      → +25  (90%+ of IP's logins are failures)
  rule_multi_path_recon     → +20  (3+ distinct restricted paths hit)
  rule_rapid_auth_failures  → +20  (count >= 3× threshold)
  rule_many_distinct_users  → +15  (>15 distinct usernames tried)
  rule_high_failure_pre_success → +10 (≥10 failures before the success)
  rule_high_volume_scrape   → +15  (>2× data request threshold)
  rule_encoded_traversal    → +15  (traversal uses URL encoding — tool indicator)
  rule_extreme_flood        → +25  (>3× DoS threshold)
  rule_untrusted_ip         → +10  (IP not in trusted_ips list)
```

---

## 5.2 The ThreatAlert Dataclass

**File:** `rules_engine.py`
**Type:** Python `@dataclass`

This is the core data object of the entire system. Every detection rule
produces zero or more `ThreatAlert` objects. Every downstream step —
LLM enrichment, database write, console output, dashboard display — works
with this object.

```
@dataclass
class ThreatAlert:
    threat_type:     str        The name of the attack type
                                e.g. "Brute Force Attack", "Account Takeover"

    risk_level:      str        Derived from confidence score:
                                ≥80 → "CRITICAL"
                                ≥60 → "HIGH"
                                ≥40 → "MEDIUM"
                                <40 → "LOW"

    confidence:      int        0–100. Built additively from RULE_CONFIDENCE weights.
                                Clamped so it can never exceed 100 or go below 0.

    triggered_rules: List[str]  Names of every rule condition that fired.
                                e.g. ["rule_high_login_failure",
                                      "rule_single_ip_brute",
                                      "rule_untrusted_ip"]
                                Stored as a JSON array string in the database.

    source_ip:       str        The attacker's IP address.

    details:         Dict       Evidence dictionary — different keys per threat type.
                                e.g. {"failed_attempts": 20, "window_seconds": 60,
                                      "threshold": 5, "targeted_accounts": "admin"}
                                Stored as a JSON object string in the database.

    timestamp:       str        UTC ISO-format timestamp of when the alert was created.
                                Set automatically using datetime.now(timezone.utc).
                                e.g. "2025-07-15T14:30:22.451234+00:00"

    llm_hypothesis:  str        Initially empty "". Filled in by llm_client.py after
                                generate_hypothesis() returns.

    llm_report:      str        Initially empty "". Filled in by llm_client.py after
                                generate_incident_report() returns.
```

The object also has a `to_dict()` method that converts all fields to a plain
Python dictionary — used when serialising for storage.

---

## 5.3 Helper Functions

These are internal functions (prefixed with `_`) used by the rule functions.
They are not called from outside `rules_engine.py`.

### `_clamp(value, lo=0, hi=100)`

**File:** `rules_engine.py`

Ensures a confidence score never goes below 0 or above 100, no matter how
many bonus conditions fire.

```
Input:  value=95, lo=0, hi=100  →  Output: 95
Input:  value=115, lo=0, hi=100 →  Output: 100  (capped)
Input:  value=-5, lo=0, hi=100  →  Output: 0    (floored)
```

---

### `_risk_from_confidence(confidence)`

**File:** `rules_engine.py`

Converts a 0–100 integer confidence score into a human-readable risk label.

```
confidence >= 80  →  "CRITICAL"
confidence >= 60  →  "HIGH"
confidence >= 40  →  "MEDIUM"
confidence <  40  →  "LOW"
```

Called inside every `check_*` function just before creating the ThreatAlert.

---

### `_already_alerted(conn, threat_type, source_ip)`

**File:** `rules_engine.py`

**This is the duplicate suppression guard.** Without it, the agent would
create a new alert on every 5-second polling cycle for as long as the attack
is happening, flooding the dashboard.

It queries the `alerts` table:

```sql
SELECT COUNT(*) FROM alerts
WHERE threat_type = ?
  AND source_ip   = ?
  AND timestamp  >= datetime('now', '-300 seconds')
```

If a matching alert was created in the last 5 minutes (300 seconds =
`BASELINE["alert_cooldown_seconds"]`), this returns `True` and the calling
rule function skips creating a new alert.

```
Input:  conn, "Brute Force Attack", "192.168.1.4"
Output: True  (if an alert exists within the last 5 minutes → skip)
        False (if no recent alert → proceed with creating one)
```

Called at the very beginning of every `check_*` function, before any
confidence calculation.

---

## 5.4 The 8 Detection Rules

Each rule is a standalone function in `rules_engine.py`. Each one follows
the same internal structure:

```
1. Read the threshold from BASELINE
2. Run a SQL query against the logs table
3. For each row returned:
   a. Check _already_alerted() — skip if recently alerted
   b. Start confidence at the base RULE_CONFIDENCE value
   c. Check bonus conditions — add confidence for each that fires
   d. Check trusted_ips — add confidence if IP is untrusted
   e. Clamp confidence to 0–100
   f. Create and append a ThreatAlert object
4. Return the list of alerts
```

---

### Rule 1 — `check_brute_force(conn)`

**Detects:** Repeated failed login attempts against the same account(s) from
one IP address — the classic "try many passwords" attack.

**SQL logic:**
```sql
SELECT ip, COUNT(*) AS cnt, GROUP_CONCAT(DISTINCT username)
FROM logs
WHERE event_type = 'login_attempt'
  AND status     = 'fail'
  AND timestamp >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING cnt > 5
```

Groups all failed login events in the last 60 seconds by IP. Any IP with
more than 5 failures is a candidate.

**Bonus condition:** A second SQL query checks the total login attempts
from the same IP. If 90% or more are failures (fail/total >= 0.9), it means
virtually everything this IP is doing is failing, which strongly confirms
automation. Adds `rule_single_ip_brute` (+25 confidence).

**Output — ThreatAlert.details:**
```json
{
  "failed_attempts":   20,
  "window_seconds":    60,
  "threshold":         5,
  "targeted_accounts": "admin"
}
```

**Confidence range:** 55 (base) up to 90 (base + single_ip_brute + untrusted_ip)

---

### Rule 2 — `check_recon(conn)`

**Detects:** An IP systematically probing restricted administrative or
configuration endpoints — a reconnaissance pattern before a deeper attack.

**SQL logic:**
```sql
SELECT ip, COUNT(*) AS total_hits,
       COUNT(DISTINCT endpoint) AS unique_paths,
       GROUP_CONCAT(DISTINCT endpoint)
FROM logs
WHERE endpoint IN ('/admin', '/config', '/internal', '/dashboard',
                   '/api/keys', '/env', '/.env', '/settings')
  AND timestamp >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING total_hits > 3
```

**Bonus condition:** If the IP hit 3 or more *distinct* restricted paths
(not just the same one repeatedly), adds `rule_multi_path_recon` (+20).
Probing many different paths indicates deliberate scanning rather than
an accidental click.

**Output — ThreatAlert.details:**
```json
{
  "total_hits":     10,
  "unique_paths":   5,
  "paths_hit":      "/admin,/config,/internal,/env,/api/keys",
  "window_seconds": 60,
  "threshold":      3
}
```

**Confidence range:** 60 (base) up to 90 (base + multi_path + untrusted_ip)

---

### Rule 3 — `check_auth_scan(conn)`

**Detects:** An IP receiving many HTTP 401 (Unauthorized) or 403 (Forbidden)
responses — indicating it is probing the application for weakly-protected
endpoints, not just the login page.

This is distinct from brute force: brute force targets the login endpoint
specifically. Auth scanning hits many different endpoints looking for any
that might be accessible.

**SQL logic:**
```sql
SELECT ip, COUNT(*) AS cnt,
       GROUP_CONCAT(DISTINCT status_code),
       GROUP_CONCAT(DISTINCT endpoint)
FROM logs
WHERE status_code IN (401, 403)
  AND timestamp >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING cnt > 6
```

**Bonus condition:** If count >= 3× threshold (18+ failures), adds
`rule_rapid_auth_failures` (+20) — indicates an automated tool, not a human.

**Output — ThreatAlert.details:**
```json
{
  "auth_failures":  20,
  "status_codes":   "401,403",
  "endpoints_hit":  "/api/v1,/api/v2,/api/admin,/private,/secure",
  "window_seconds": 60,
  "threshold":      6
}
```

**Confidence range:** 50 (base) up to 80 (base + rapid + untrusted_ip)

---

### Rule 4 — `check_credential_stuffing(conn)`

**Detects:** An IP using a large list of leaked credentials — trying many
different *usernames*, each only once or twice. This is the opposite pattern
from brute force (which hammers one username repeatedly).

If brute force is "try 1000 passwords on admin", credential stuffing is
"try 1 password on 1000 different users".

**SQL logic:**
```sql
SELECT ip,
       COUNT(DISTINCT username) AS distinct_users,
       COUNT(*) AS total_attempts,
       GROUP_CONCAT(DISTINCT username)
FROM logs
WHERE event_type = 'login_attempt'
  AND status     = 'fail'
  AND username   IS NOT NULL
  AND timestamp >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING distinct_users > 8
```

The key column is `COUNT(DISTINCT username)` — this is what separates it
from brute force.

**Bonus condition:** If distinct_users > 15, adds `rule_many_distinct_users`
(+15) — indicates a large automated credential list.

**Output — ThreatAlert.details:**
```json
{
  "distinct_usernames_tried": 12,
  "total_attempts":           12,
  "sample_usernames":         "alice,bob,charlie,diana,eve,frank,...",
  "window_seconds":           60,
  "threshold":                8
}
```

Note: `sample_usernames` is capped at 200 characters to avoid oversized
database rows.

**Confidence range:** 65 (base) up to 90 (base + many_distinct + untrusted_ip)

---

### Rule 5 — `check_account_takeover(conn)`

**Detects:** The most dangerous signal in the entire system. An IP that was
previously failing logins *succeeds*. This means the attacker found a working
credential. The account is now compromised.

This rule is unique because it **cross-correlates two different event types**
(failed logins + successful login) from the same IP across a 5-minute window.
No other rule does this kind of temporal correlation.

**SQL logic (two-subquery JOIN):**
```sql
SELECT f.ip, f.failure_count, s.compromised_account
FROM (
    -- Subquery A: IPs with enough failures
    SELECT ip, COUNT(*) AS failure_count
    FROM logs
    WHERE event_type = 'login_attempt'
      AND status     = 'fail'
      AND timestamp >= datetime('now', '-300 seconds')
    GROUP BY ip
    HAVING failure_count >= 3
) f
JOIN (
    -- Subquery B: IPs that also had a success
    SELECT ip, GROUP_CONCAT(DISTINCT username) AS compromised_account
    FROM logs
    WHERE event_type = 'login_attempt'
      AND status     = 'success'
      AND timestamp >= datetime('now', '-300 seconds')
    GROUP BY ip
) s ON f.ip = s.ip
```

Only IPs that appear in BOTH subqueries get flagged. The JOIN on `f.ip = s.ip`
is the correlation step.

The window is 300 seconds (5 minutes) instead of 60 seconds, because attackers
often slow down before attempting a final successful login to avoid detection.

**Bonus condition:** If failure_count >= 10, adds `rule_high_failure_pre_success`
(+10) — more failures before success = more evidence of automation.

**Output — ThreatAlert.details:**
```json
{
  "failures_before_success": 8,
  "compromised_account":     "admin",
  "window_seconds":          300,
  "min_failures_threshold":  3
}
```

**Confidence range:** 85 (base) up to 100 (base + high_failure + untrusted_ip)

This rule has the highest base confidence (85) of all 8 rules because a
successful login after repeated failures is virtually always an account
compromise event.

---

### Rule 6 — `check_data_exfiltration(conn)`

**Detects:** After gaining access (or even without it), an attacker
systematically harvesting data by making many rapid successful GET requests
to data-serving endpoints.

**SQL logic:**
```sql
SELECT ip,
       COUNT(*) AS total_requests,
       COUNT(DISTINCT endpoint) AS unique_endpoints,
       GROUP_CONCAT(DISTINCT endpoint)
FROM logs
WHERE (
    endpoint IN ('/api/users', '/api/user', '/users', '/user',
                 '/export', '/download', '/data', '/api/data',
                 '/files', '/reports', '/backup', '/api/export', '/dump')
    OR endpoint LIKE '/api/%'
    OR endpoint LIKE '/data/%'
    OR endpoint LIKE '/export/%'
    OR endpoint LIKE '/download/%'
    OR endpoint LIKE '/files/%'
)
  AND method      = 'GET'
  AND status_code = 200
  AND timestamp  >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING total_requests > 20
```

Three filters make this precise:
- The endpoint must be data-serving (exact list OR LIKE prefix patterns)
- The HTTP method must be GET (read operation, not write)
- The response must be 200 OK (the request succeeded — data was returned)

**Bonus condition:** If total_requests >= 40 (2× threshold), adds
`rule_high_volume_scrape` (+15) — extreme volume confirms automated scraping.

**Output — ThreatAlert.details:**
```json
{
  "total_requests":   30,
  "unique_endpoints": 6,
  "endpoints_hit":    "/api/users,/api/data,/export,/download,/files,/reports",
  "window_seconds":   60,
  "threshold":        20
}
```

**Confidence range:** 60 (base) up to 85 (base + high_volume + untrusted_ip)

---

### Rule 7 — `check_path_traversal(conn)`

**Detects:** Requests containing directory traversal sequences in the URL.
This attack tries to escape the web server's root directory and read arbitrary
files on the server (e.g., `/etc/passwd`, SSH keys, `.env` files with secrets).

This rule is **zero tolerance** — even a single request triggers it
(`path_traversal_min_attempts = 1`).

**SQL logic (pattern matching):**
```sql
SELECT ip, COUNT(*) AS attempts, GROUP_CONCAT(endpoint, '|')
FROM logs
WHERE (
    endpoint LIKE '%../%'          -- basic:            ../
    OR endpoint LIKE '%..\\%'      -- Windows-style:    ..\
    OR endpoint LIKE '%2e%2e%2f%'  -- fully encoded:    %2e%2e%2f
    OR endpoint LIKE '%2e%2e/%'    -- partially encoded: %2e%2e/
    OR endpoint LIKE '%..%2f%'     -- partially encoded: ..%2f
    OR endpoint LIKE '%..%2F%'     -- partially encoded: ..%2F
    OR endpoint LIKE '%252e%252e%' -- double-encoded:   %252e%252e
    OR endpoint LIKE '%..../%'     -- bypass pattern:   ..../
    OR endpoint LIKE '%....\\%'    -- bypass pattern:   ....\
)
  AND timestamp >= datetime('now', '-300 seconds')
GROUP BY ip
HAVING attempts >= 1
```

The 5-minute lookback window is used instead of 60 seconds because a
sophisticated attacker might space traversal attempts out to avoid detection.

**Bonus condition:** If the actual endpoint strings contain `%2e`, `%252e`,
or `%2f` (URL-encoded sequences), adds `rule_encoded_traversal` (+15). Using
encoding indicates an automated penetration testing tool or a deliberate attempt
to bypass simple string filters.

**Output — ThreatAlert.details:**
```json
{
  "attempts":       3,
  "endpoints_used": "/files/../../../etc/passwd|/images/..%2F..%2Fetc%2Fshadow",
  "window_seconds": 300
}
```

Note: `endpoints_used` is capped at 300 characters to prevent oversized rows.

**Confidence range:** 70 (base) up to 95 (base + encoded + untrusted_ip)

---

### Rule 8 — `check_dos_flood(conn)`

**Detects:** Raw volumetric flood — an IP making an extreme number of requests
to any endpoint regardless of what they are or what status code they return.
This catches attacks that slip through all other rules because they might be
returning 200 OK on every request.

**SQL logic:**
```sql
SELECT ip, COUNT(*) AS total_requests, COUNT(DISTINCT endpoint)
FROM logs
WHERE timestamp >= datetime('now', '-60 seconds')
GROUP BY ip
HAVING total_requests > 100
```

Note: No filter on event_type, endpoint, status_code, or status. Counts
everything. This is intentional — a DoS flood doesn't care what it hits.

**Bonus condition:** If total_requests >= 300 (3× threshold), adds
`rule_extreme_flood` (+25). An extreme flood is clearly an automated tool,
not even a human clicking very fast.

**Output — ThreatAlert.details:**
```json
{
  "total_requests":   130,
  "unique_endpoints": 6,
  "window_seconds":   60,
  "threshold":        100
}
```

**Confidence range:** 55 (base) up to 90 (base + extreme_flood + untrusted_ip)

---

## 5.5 run_all_rules — The Master Caller

**File:** `rules_engine.py`
**Function:** `run_all_rules(conn)`

This is the single public entry point into the rules engine. `main.py` calls
only this function — it never calls individual `check_*` functions directly.

```python
def run_all_rules(conn: sqlite3.Connection) -> List[ThreatAlert]:
    alerts = []
    alerts.extend(check_account_takeover(conn))   # base 85 — highest first
    alerts.extend(check_path_traversal(conn))      # base 70
    alerts.extend(check_credential_stuffing(conn)) # base 65
    alerts.extend(check_recon(conn))               # base 60
    alerts.extend(check_data_exfiltration(conn))   # base 60
    alerts.extend(check_brute_force(conn))         # base 55
    alerts.extend(check_auth_scan(conn))           # base 50
    alerts.extend(check_dos_flood(conn))           # base 55
    return alerts
```

**Why this order matters:** The rules are called in descending order of base
confidence. This means the most severe alerts (Account Takeover, Path Traversal)
appear first in the returned list and therefore first in the console output and
first in the database. The dashboard always sees the most critical threat at the
top.

**Input:** An open `sqlite3.Connection` to `data/logs.sqlite`

**Output:** A flat `List[ThreatAlert]` — could be empty (no threats), or
contain between 1 and 8 objects (one per rule that fired). Multiple rules can
fire simultaneously if one IP is running multiple attack types at once.

---

## 5.6 MITIGATIONS & get_mitigation

**File:** `rules_engine.py`

`MITIGATIONS` is a plain Python dictionary at the bottom of `rules_engine.py`
that maps every threat type name to a deterministic, hardcoded mitigation string.
This is **not AI** — it is a static lookup table written by the developer.

```
"Brute Force Attack"       → Block IP, lock account, reset password, enable MFA
"Endpoint Reconnaissance"  → Rate-limit IP, review access-control, IP allow-listing
"Unauthorized Access Scan" → Block IP at reverse-proxy, audit auth middleware
"Credential Stuffing"      → Block IP, mass password reset, CAPTCHA, HaveIBeenPwned
"Account Takeover"         → CRITICAL: terminate sessions, force reset, audit actions
"Data Exfiltration"        → Block IP, revoke tokens, audit accessed data, rate-limit
"Path Traversal Attack"    → Block IP, sanitize path inputs, audit file-system logs
"DoS Rate Flood"           → Rate-limit at WAF, temporary IP ban, consider CDN
```

`get_mitigation(threat_type)` is the public accessor function that looks up
the mitigation string. It is called in two places:
- `main.py → _enrich_with_llm()` — passes the mitigation string to `generate_incident_report()` so the LLM can include it in the report
- `main.py → _print_alert_banner()` — prints the mitigation directly to the console

---

---

# 6. File 2 — llm_client.py (LLM Integration)

---

## 6.1 What Ollama Is

Ollama is a local application that runs LLM (Large Language Model) inference
entirely on your own machine. It works like a private web server:

```
You start it with:   ollama serve
It runs at:          http://localhost:11434
It exposes an API:   POST /api/generate  (send a prompt, get text back)
It loads:            llama3.1:8b  (the model file, stored in Ollama's local cache)
```

When the agent calls `generate_hypothesis()`, it is making an HTTP POST request
to `http://localhost:11434/api/generate` — the same machine, a different process,
over the local network loopback. No data ever leaves the computer.

The model `llama3.1:8b` is a 8-billion-parameter language model that was
pre-trained on a massive corpus of internet text. It already knows what a
brute force attack is, what credential stuffing looks like, what path traversal
means. We do not teach it anything — we just ask it questions.

---

## 6.2 Configuration

**File:** `llm_client.py`

```
OLLAMA_BASE_URL    = "http://localhost:11434"
MODEL_NAME         = "llama3.1:8b"
REQUEST_TIMEOUT    = 30  seconds  (GPU response time is 1-3s; 30s is safe headroom)

DEFAULT_OPTIONS:
  temperature      = 0.3   Low = focused, consistent, deterministic output
                            High = creative, unpredictable
  num_predict      = 220   Maximum tokens to generate (~3-4 sentences)
  top_p            = 0.9   Nucleus sampling — considers top 90% probable tokens
  repeat_penalty   = 1.1   Discourages repetition in the output
  num_ctx          = 2048  Context window size — how much text the model can "see"
```

**Why temperature 0.3?** We want the model to write professional, consistent
SOC reports — not creative fiction. Low temperature keeps it focused and
factual. If you run the same prompt twice, you will get very similar outputs.

**Why 220 tokens?** Enough for 3-4 complete sentences without generating
essays. The hypothesis needs 1-2 sentences; the incident report needs 2-3.

---

## 6.3 How the Agent Talks to Ollama

All communication goes through one internal function: `_query_ollama()`.

**File:** `llm_client.py`
**Function:** `_query_ollama(prompt, system_prompt="")`

This sends an HTTP POST to `/api/generate`:

```
Request body (JSON):
{
  "model":   "llama3.1:8b",
  "prompt":  "Security Observation: 20 failed logins from IP...",
  "system":  "You are a concise SOC analyst assistant...",
  "stream":  false,
  "options": { "temperature": 0.3, "num_predict": 220, ... }
}
```

`"stream": false` is critical. It tells Ollama to wait until the entire
response is generated and return it all at once as a single JSON object.
If `stream` were `true`, Ollama would send partial tokens back one at a time
like a typewriter — much more complex to handle.

```
Response body (JSON):
{
  "model":    "llama3.1:8b",
  "response": "This behavior strongly indicates a credential brute-force...",
  "done":     true,
  ...
}
```

The function extracts `result["response"]` and returns it as a plain string.

**Error handling inside `_query_ollama`:**
Every possible failure mode returns a human-readable placeholder string instead
of raising an exception. This means the agent keeps running even if Ollama fails.

```
ConnectionError  →  "[LLM Offline] Could not reach Ollama. Is it running? → ollama serve"
Timeout          →  "[LLM Timeout] Model took longer than 30s to respond."
HTTPError        →  "[LLM HTTP Error] ..."
JSONDecodeError  →  "[LLM Parse Error] Unexpected response format: ..."
Any other error  →  "[LLM Unknown Error] ..."
```

These placeholder strings are stored in `llm_hypothesis` and `llm_report` fields
of the alert — so the dashboard shows them instead of a blank field.

---

## 6.4 check_ollama_health()

**File:** `llm_client.py`
**Called by:** `main.py → _startup_checks()`
**Called once:** At agent startup only, not in the polling loop.

```
Step 1: GET http://localhost:11434/api/tags
        If this fails → return {"status": "error", "message": "Cannot connect..."}

Step 2: Parse the response to get the list of locally installed models
        Check if "llama3.1" appears in any model name

Step 3a: Model found     → return {"status": "ok",      "message": "Ollama is running ✓"}
Step 3b: Model not found → return {"status": "warning", "message": "llama3.1:8b not pulled"}
```

The agent startup prints this result to the console. A `"warning"` status means
the agent will continue but LLM calls will fail. An `"error"` status means Ollama
is not running at all — the agent continues in rules-only mode.

---

## 6.5 generate_hypothesis()

**File:** `llm_client.py`
**Called by:** `main.py → _enrich_with_llm()`

This is the **Hypothesize** step — the first LLM call for every confirmed alert.

**What it receives:**
A plain-English observation string built by `_build_observation()` in `main.py`.

Example observations for different threat types:
```
Brute Force:
  "20 failed login attempts from IP 10.10.10.1 in 60 seconds
   targeting account(s): admin."

Account Takeover:
  "IP 10.10.10.3 had 8 failed login attempts followed by a SUCCESSFUL login
   to account 'admin' within a 300 second window."

Path Traversal:
  "IP 10.10.10.7 sent 3 request(s) containing directory traversal sequences
   (../ or URL-encoded variants) in the URL path:
   /files/../../../etc/passwd|/images/..%2F..%2F..%2Fetc%2Fshadow"
```

**System prompt sent to Ollama:**
```
"You are a concise SOC analyst assistant.
 When given a security observation, respond with ONE to TWO sentences
 identifying the most likely attack scenario.
 Do not include greetings, bullet points, or extra explanation.
 Be direct and technical."
```

**User prompt sent to Ollama:**
```
"Security Observation: [observation string]

 What is the most likely attack scenario in 1-2 sentences?"
```

**Example output:**
```
"This behavior strongly indicates a credential brute-force or dictionary
 attack targeting a privileged administrator account."
```

**Where the output goes:**
Stored in `alert.llm_hypothesis` on the `ThreatAlert` object in memory.
Then written to the `llm_hypothesis` column of the `alerts` table by
`_update_alert_llm()` in `main.py`.

---

## 6.6 generate_incident_report()

**File:** `llm_client.py`
**Called by:** `main.py → _enrich_with_llm()`

This is the **Explain** step — the second LLM call, called immediately after
`generate_hypothesis()` returns.

**What it receives:**
Five arguments — all pre-calculated by the rules engine and `main.py`:
```
threat_type:  "Brute Force Attack"
source_ip:    "10.10.10.1"
details:      {"failed_attempts": 20, "window_seconds": 60, ...}
mitigation:   "Immediately block source IP at the firewall. Lock the
               targeted account(s) and force a password reset..."
hypothesis:   "This strongly indicates a credential brute-force attack..."
              (the string returned from generate_hypothesis() moments ago)
```

**System prompt sent to Ollama:**
```
"You are a professional SOC analyst writing a brief incident report.
 You will be given structured threat data.
 Summarise the incident in 2-3 sentences: what happened, from where,
 and what action is recommended.
 Be factual, professional, and concise. No bullet points."
```

**User prompt sent to Ollama:**
```
"Threat Type: Brute Force Attack
 Source IP: 10.10.10.1
 Evidence: {"failed_attempts": 20, "window_seconds": 60, "threshold": 5, ...}
 Analyst Hypothesis: This strongly indicates a credential brute-force attack...
 Recommended Mitigation: Immediately block source IP at the firewall...

 Write a 2-3 sentence incident report paragraph."
```

**Example output:**
```
"The system detected a credential brute-force attack originating from IP
 10.10.10.1, with 20 failed login attempts targeting the 'admin' account
 within a 60-second window. This behaviour is consistent with automated
 password-guessing tooling. Immediate action recommended: block the source IP
 at the firewall and enforce a mandatory password reset on the affected account."
```

**Where the output goes:**
Stored in `alert.llm_report` on the `ThreatAlert` object in memory.
Then written to the `llm_report` column of the `alerts` table by
`_update_alert_llm()` in `main.py`.

---

## 6.7 What Is and Is NOT Stored

This is a common question. Here is the precise answer:

**What Ollama stores:** Nothing. Zero. Ollama has no database, no conversation
history, no logs of prompts or responses. The model weights sit in GPU VRAM.
A prompt comes in as an HTTP POST, tokens are generated, the response goes out
as an HTTP response. Once that response is sent, Ollama forgets everything about
that interaction. Each call to `_query_ollama()` is completely independent and
stateless.

**What the agent stores:**
Only the final text outputs from the two LLM calls, written to SQLite:
```
alerts.llm_hypothesis  ← the 1-2 sentence hypothesis string
alerts.llm_report      ← the 2-3 sentence incident report string
```

The prompts themselves (observation strings, evidence dicts, system prompts)
are never stored anywhere. They exist in Python memory for the duration of the
`_query_ollama()` call and are then garbage-collected.

---

---

# 7. File 3 — main.py (The Core Loop)

`main.py` is the conductor. It does not do detection (that is `rules_engine.py`)
and it does not do LLM calls directly (that is `llm_client.py`). It coordinates
both, manages the database, and runs the infinite loop.

---

## 7.1 Startup

**Function:** `_startup_checks()`
**Called once:** Before the polling loop starts.

Performs three checks in order:

```
Check 1 — data/ directory
  Does data/ exist? If not, create it with os.makedirs().
  The agent needs this folder to open logs.sqlite.

Check 2 — Ollama health
  Calls llm_client.check_ollama_health().
  Prints result to console (OK / WARNING / ERROR).
  Non-fatal — agent continues even if Ollama is down.

Check 3 — Database file
  Does data/logs.sqlite exist?
  If not, waits up to 30 seconds (6 × 2-second pauses) for it to appear.
  This handles the case where the agent starts before the backend does.
  Non-fatal — the main loop handles a missing DB gracefully.
```

**Python version guard** (runs before `_startup_checks`, at the very top of
the file, before any imports):

```python
if sys.version_info < (3, 9):
    print("[ERROR] Python 3.9+ is required...")
    sys.exit(1)
```

This is the first thing that runs when `python main.py` is executed.

---

## 7.2 Database Helpers

### `_get_connection()`

Opens the SQLite database and returns a connection object.

```
conn = sqlite3.connect(DB_PATH, timeout=5)
```

- `timeout=5` means if the database is locked (backend is writing at the same
  instant), the agent waits up to 5 seconds before raising an error.
- `conn.row_factory = sqlite3.Row` makes rows accessible by column name
  (e.g., `row["ip"]`) instead of just by index (`row[0]`).
- `PRAGMA journal_mode=WAL` enables Write-Ahead Logging — allows the agent to
  read from the database at the same time the backend is writing to it, without
  locking conflicts.

The connection is opened at the start of `_run_agent_cycle()` and closed in the
`finally` block — even if an error occurs mid-cycle.

---

### `_ensure_alerts_table(conn)`

Creates the `alerts` table if it does not already exist. Uses
`CREATE TABLE IF NOT EXISTS` so it is safe to call on every cycle — it is a
no-op if the table is already there.

Also creates the index on `(source_ip, threat_type, timestamp)` which makes
`_already_alerted()` queries fast.

Called at the start of every `_run_agent_cycle()`.

---

### `_save_alert_initial(conn, alert)` → returns `int`

**Phase 1 of the two-phase save.**

Inserts a new row into the `alerts` table with all the detection fields
populated, but `llm_hypothesis` and `llm_report` set to empty strings `''`.

```sql
INSERT INTO alerts
    (timestamp, threat_type, risk_level, confidence, source_ip,
     triggered_rules, details, llm_hypothesis, llm_report)
VALUES (?, ?, ?, ?, ?, ?, ?, '', '')
```

Returns `cursor.lastrowid` — the SQLite auto-increment ID of the row just
inserted. This ID is passed to `_update_alert_llm()` later so it knows which
row to update.

**Why this exists:** Without this two-phase approach, the dashboard would see
nothing for 3-6 seconds (2 LLM calls × 1-3s each) after a detection. With
this approach, the dashboard sees the detection (threat type, risk level,
confidence, source IP, triggered rules, evidence) the instant the rules engine
fires. The LLM text fills in a moment later as an in-place update.

---

### `_update_alert_llm(conn, row_id, alert)`

**Phase 2 of the two-phase save.**

Updates the row that was just written by `_save_alert_initial()`, filling in
the two LLM fields.

```sql
UPDATE alerts
SET llm_hypothesis = ?,
    llm_report     = ?
WHERE id = ?
```

Uses the `row_id` returned by `_save_alert_initial()` to target exactly the
right row.

---

## 7.3 _build_observation()

**File:** `main.py`
**Called by:** `_enrich_with_llm()`

Converts a `ThreatAlert` object into a single plain-English observation string
that becomes the prompt for `generate_hypothesis()`.

Has one `if` branch per threat type (8 branches + 1 generic fallback), each
pulling the relevant fields from `alert.details` to build a natural sentence.

Examples:
```
Brute Force:
  "20 failed login attempts from IP 10.10.10.1 in 60 seconds
   targeting account(s): admin."

Credential Stuffing:
  "IP 10.10.10.2 attempted logins against 12 different user accounts
   (12 total attempts) in 60 seconds — sample accounts targeted:
   alice,bob,charlie,diana,eve,frank,grace,heidi,ivan,judy,kevin,linda."

Data Exfiltration:
  "IP 10.10.10.6 made 30 successful GET requests to 6 data-serving endpoints
   (/api/users,/api/data,/export,/download,/files,/reports) in 60 seconds."
```

**Why this function exists separately from the LLM call:** The observation
string is constructed from structured data (dicts, integers). Separating it
from the LLM call keeps `_enrich_with_llm()` clean and makes each observation
template easy to read and test individually.

---

## 7.4 _enrich_with_llm()

**File:** `main.py`
**Called by:** `_run_agent_cycle()`

Runs both LLM steps for one alert. Takes a `ThreatAlert`, mutates it in place
by filling `llm_hypothesis` and `llm_report`, returns it.

```python
def _enrich_with_llm(alert: ThreatAlert) -> ThreatAlert:
    observation = _build_observation(alert)

    # Call 1 — Hypothesize
    alert.llm_hypothesis = generate_hypothesis(observation)

    # Call 2 — Explain
    mitigation = get_mitigation(alert.threat_type)
    alert.llm_report = generate_incident_report(
        threat_type=alert.threat_type,
        source_ip=alert.source_ip,
        details=alert.details,
        mitigation=mitigation,
        hypothesis=alert.llm_hypothesis,
    )

    return alert
```

Note that the hypothesis output from Call 1 is passed as an argument into
Call 2. This means the incident report is aware of the hypothesis — producing
more coherent combined output on the dashboard.

---

## 7.5 _run_agent_cycle() — One Full Loop

**File:** `main.py`
**Called by:** `main()` every 5 seconds.

This is the core of the agent. One call = one complete Observe → Decide →
Save → Enrich → Update cycle.

```
Step 1: Open DB connection (_get_connection)
Step 2: Ensure alerts table exists (_ensure_alerts_table)
Step 3: Run all 8 rules → get List[ThreatAlert] (run_all_rules)
Step 4: Filter to only alerts with confidence >= 40 (Decide step)
Step 5: If no alerts → return empty list, close connection

For each confirmed alert:
  Step 6:  INSERT to DB immediately — LLM fields empty (_save_alert_initial)
           → Console: "Detection saved → HIGH | Brute Force | IP: ... | 90%"
  Step 7:  Call LLM — fills alert.llm_hypothesis and alert.llm_report (_enrich_with_llm)
           → Console: "↳ Hypothesizing via LLM for Brute Force from ..."
           → Console: "↳ Generating incident report..."
  Step 8:  UPDATE DB row with LLM text (_update_alert_llm)
           → Console: "↳ LLM report written for alert id=3"
  Step 9:  Append to saved list

Step 10: Close DB connection (always, in finally block)
Step 11: Return saved list to main()
```

---

## 7.6 main() — The Infinite Loop

**File:** `main.py`
**Entry point:** `if __name__ == "__main__": main()`

```python
def main():
    _startup_checks()   # run once

    while True:
        try:
            if not os.path.exists(DB_PATH):
                # wait and retry next cycle
                time.sleep(5)
                continue

            alerts = _run_agent_cycle()

            if alerts:
                for alert in alerts:
                    _print_alert_banner(alert)  # coloured console output
            else:
                # quiet heartbeat every 12 cycles (~60s)
                if cycle % 12 == 0:
                    _log("info", "No new threats detected. Agent is watching...")

        except sqlite3.OperationalError as e:
            _log("warn", f"DB temporarily unavailable. Retrying...")
        except Exception as e:
            _log("error", f"Unexpected error: {e}")
            traceback.print_exc()

        time.sleep(5)   # wait 5 seconds before next cycle
```

Key design choices:
- **`sqlite3.OperationalError` is caught separately** — this happens when the
  backend is writing at the exact same millisecond. Handled with a warning and
  retry, not a crash.
- **All other exceptions are caught** — an unexpected error in one cycle does
  not kill the agent. It logs the traceback and continues to the next cycle.
- **`KeyboardInterrupt` exits cleanly** — pressing Ctrl+C prints "Goodbye." and
  exits with code 0 instead of printing a Python traceback.

---

## 7.7 Console Output Functions

### `_log(level, message)`

Prints a timestamped, colour-coded line using ANSI escape codes.

```
[10:23:45] [  OK ] Ollama is running with model llama3.1:8b ✓    (green)
[10:23:50] [ALERT] Detection saved → HIGH | Brute Force | ...    (red)
[10:23:51] [INFO ] ↳ Hypothesizing via LLM...                    (white)
[10:23:53] [WARN ] DB temporarily unavailable. Retrying...       (yellow)
```

The local system time is used (not UTC) so the console shows IST if the
machine's clock is set to IST.

### `_print_alert_banner(alert)`

Prints a large, coloured block for every confirmed threat. Colour is determined
by `risk_level`:

```
CRITICAL → bright red
HIGH     → yellow
MEDIUM   → cyan
LOW      → white
```

The banner includes: threat type, risk level, confidence %, source IP,
rules fired, raw evidence dict, AI hypothesis (if available), incident report
(if available), and mitigation string.

---

---

# 8. The Database — Where Everything Is Stored

**File:** `data/logs.sqlite`

SQLite is a file-based database. The entire database lives in one file.
No server process, no network connection — just a file that any process
can read or write.

---

## The `logs` Table (owned by backend — Teammate 1)

Every HTTP request the victim app receives becomes one row here.

```
Column      Type     Example value             Purpose
----------  -------  ------------------------  --------------------------------
id          INTEGER  1, 2, 3...                Auto-increment primary key
timestamp   DATETIME 2025-07-15 08:55:22       UTC — when the request arrived
event_type  TEXT     login_attempt             Categorises the event
method      TEXT     POST                      HTTP verb
endpoint    TEXT     /login                    URL path of the request
username    TEXT     admin                     Logged-in or attempted username
ip          TEXT     192.168.1.4               Source IP of the request
status_code INTEGER  401                       HTTP response code
status      TEXT     fail                      success / fail / blocked
```

The agent READS from this table but NEVER writes to it.

---

## The `alerts` Table (owned by agent — you)

Every confirmed threat the agent detects becomes one row here.

```
Column          Type     Example value              Purpose
--------------  -------  -------------------------  ---------------------------------
id              INTEGER  1, 2, 3...                 Auto-increment primary key
timestamp       DATETIME 2025-07-15T08:55:27+00:00  UTC — when the alert was created
threat_type     TEXT     Brute Force Attack          Name of the attack type
risk_level      TEXT     HIGH                        CRITICAL/HIGH/MEDIUM/LOW
confidence      INTEGER  90                          0–100 score
source_ip       TEXT     192.168.1.4                Attacker's IP
triggered_rules TEXT     ["rule_high_login_failure", JSON array of rule names
                          "rule_single_ip_brute"]
details         TEXT     {"failed_attempts": 20,...} JSON object with evidence
llm_hypothesis  TEXT     "This indicates a brute..." 1-2 sentence Ollama hypothesis
llm_report      TEXT     "The system detected..."    2-3 sentence Ollama SOC report
```

The dashboard READS from this table but NEVER writes to it.

**Two-phase write sequence:**
```
Phase 1 (instant, ~1ms after detection):
  INSERT — all columns populated EXCEPT llm_hypothesis and llm_report (empty strings)

Phase 2 (after LLM responds, ~1-3s later on GPU):
  UPDATE — fills llm_hypothesis and llm_report for the specific row id
```

---

---

# 9. Confidence Score System

The confidence score is an integer from 0 to 100 that represents how certain
the agent is that the detected behaviour is a real attack (as opposed to a
false positive).

It is built **additively** — start at 0, add the base rule score, add any
bonus scores that apply. Clamp to 100 at the end.

**Example — Brute Force from an untrusted IP with concentrated failures:**
```
Base score:       rule_high_login_failure    +55
Bonus condition:  rule_single_ip_brute       +25   (90%+ activity is failures)
Bonus condition:  rule_untrusted_ip          +10   (not in trusted_ips list)
                                            ----
Total before clamp:                           90
After _clamp(90, 0, 100):                     90  → risk_level = "HIGH"
```

**Example — Path Traversal with URL encoding from untrusted IP:**
```
Base score:       rule_path_traversal        +70
Bonus condition:  rule_encoded_traversal     +15   (%2e%2e found in URL)
Bonus condition:  rule_untrusted_ip          +10
                                            ----
Total before clamp:                           95
After _clamp(95, 0, 100):                     95  → risk_level = "CRITICAL"
```

**Risk level thresholds:**
```
confidence >= 80  →  CRITICAL  (shown in red on console)
confidence >= 60  →  HIGH      (shown in yellow)
confidence >= 40  →  MEDIUM    (shown in cyan)
confidence <  40  →  LOW       (shown in white)
```

**Minimum confidence to create an alert:** `MIN_CONFIDENCE_TO_ALERT = 40`
(defined in `main.py`). Any `ThreatAlert` with confidence below 40 is filtered
out in `_run_agent_cycle()` before saving or calling the LLM.

---

---

# 10. The LLM Boundary — What AI Does and Does Not Do

This is the most important conceptual section. The project was specifically
designed to answer the judge question: **"How can you trust AI?"**

The answer is: **the AI doesn't make any decisions. The rules do.**

```
WHAT THE RULES ENGINE (rules_engine.py) DOES — 100% deterministic:
  ✓ Decides IF a threat exists
  ✓ Decides WHAT TYPE of threat it is
  ✓ Calculates the confidence score
  ✓ Determines the risk level (CRITICAL/HIGH/MEDIUM/LOW)
  ✓ Lists which rules fired as evidence
  ✓ Collects the supporting evidence (counts, endpoints, usernames)
  ✓ Selects the mitigation action

WHAT THE LLM (llm_client.py) DOES — AI involved:
  ✓ Writes a 1-2 sentence hypothesis in natural language
  ✓ Writes a 2-3 sentence professional incident report in natural language
  ✗ Does NOT decide if a threat exists
  ✗ Does NOT determine severity
  ✗ Does NOT suggest what the mitigation should be
     (it receives the mitigation as input and includes it in the report text)
  ✗ Does NOT have access to the raw logs
  ✗ Does NOT make any security judgement
```

In other words: the AI is a **text formatter**. It receives a pre-calculated,
structured set of facts and writes them up in professional English.

This is how you trust it: you can verify every claim in the LLM's output
by looking at the `triggered_rules` and `details` fields in the same database
row. The LLM cannot lie — it can only paraphrase what it was given.

---

---

# 11. Full Walk-Through — One Attack, Start to Finish

This section traces exactly what happens, function by function, when a brute
force attack occurs.

```
TIME: 10:01:00
Attacker sends 20 failed POST /login requests to the victim app.

TIME: 10:01:00 – 10:01:03
Teammate 1's backend receives each request and writes 20 rows to logs.sqlite:
  (10:01:00, login_attempt, POST, /login, admin, 192.168.1.4, 401, fail)  × 20

TIME: 10:01:05
main.py wakes up (POLL_INTERVAL_SECONDS = 5). Calls _run_agent_cycle().

  _run_agent_cycle() opens a DB connection via _get_connection().
  WAL mode is set. Busy-timeout = 5 seconds.

  _ensure_alerts_table() runs — alerts table already exists, no-op.

  run_all_rules(conn) is called. All 8 check_* functions run in order:

    check_account_takeover() → SQL runs, no success rows found → returns []
    check_path_traversal()   → SQL runs, no traversal patterns → returns []
    check_credential_stuffing() → SQL runs, only 1 distinct username → returns []
    check_recon()            → SQL runs, no restricted paths hit → returns []
    check_data_exfiltration() → SQL runs, no data endpoints → returns []

    check_brute_force() → SQL runs:
      SELECT ip, COUNT(*) AS cnt, GROUP_CONCAT(DISTINCT username)
      FROM logs
      WHERE event_type = 'login_attempt'
        AND status = 'fail'
        AND timestamp >= datetime('now', '-60 seconds')
      GROUP BY ip
      HAVING cnt > 5

      Result row: ("192.168.1.4", 20, "admin")
      20 > 5 → threshold crossed.

      _already_alerted(conn, "Brute Force Attack", "192.168.1.4") → False (first time)

      triggered = ["rule_high_login_failure"]
      confidence = 55

      Second SQL: total login attempts from 192.168.1.4 = 20, all failures.
      20/20 = 1.0 >= 0.9 → rule_single_ip_brute fires.
      triggered = ["rule_high_login_failure", "rule_single_ip_brute"]
      confidence = 55 + 25 = 80

      "192.168.1.4" not in trusted_ips → rule_untrusted_ip fires.
      triggered = [..., "rule_untrusted_ip"]
      confidence = 80 + 10 = 90

      _clamp(90) = 90
      _risk_from_confidence(90) = "CRITICAL"

      ThreatAlert created:
        threat_type     = "Brute Force Attack"
        risk_level      = "CRITICAL"
        confidence      = 90
        source_ip       = "192.168.1.4"
        triggered_rules = ["rule_high_login_failure", "rule_single_ip_brute", "rule_untrusted_ip"]
        details         = {"failed_attempts": 20, "window_seconds": 60,
                           "threshold": 5, "targeted_accounts": "admin"}
        llm_hypothesis  = ""   (empty for now)
        llm_report      = ""   (empty for now)

    check_auth_scan() → 20 rows with 401, but these are login_attempt events.
                        The rule counts status_code IN (401, 403) — these qualify.
                        Returns a second ThreatAlert for Unauthorized Access Scan too.

    check_dos_flood() → 20 total requests, threshold is 100. Returns [].

  run_all_rules() returns: [ThreatAlert(Brute Force), ThreatAlert(Auth Scan)]

  Back in _run_agent_cycle():
    confirmed = [a for a in candidates if a.confidence >= 40]
    Both alerts have confidence >= 40. Both confirmed.

TIME: 10:01:05 (still, within milliseconds)
  Processing ThreatAlert — Brute Force Attack (confidence 90, CRITICAL)

  PHASE 1: _save_alert_initial(conn, alert)
    INSERT INTO alerts (..., '', '') — llm fields empty
    Returns row_id = 1

  Console prints:
    [10:01:05] [ALERT] Detection saved → CRITICAL | Brute Force Attack |
                       IP: 192.168.1.4 | Confidence: 90%

  Dashboard can NOW see the alert (row id=1 exists in alerts table).

TIME: 10:01:05 — LLM Phase begins
  _enrich_with_llm(alert) is called.

  _build_observation(alert) runs:
    Returns: "20 failed login attempts from IP 192.168.1.4 in 60 seconds
              targeting account(s): admin."

  Console: [10:01:05] [INFO ] ↳ Hypothesizing via LLM for Brute Force Attack...

  generate_hypothesis(observation) called in llm_client.py:
    HTTP POST → http://localhost:11434/api/generate
    Body: {
      "model":  "llama3.1:8b",
      "prompt": "Security Observation: 20 failed login attempts from IP
                 192.168.1.4 in 60 seconds targeting account(s): admin.
                 What is the most likely attack scenario in 1-2 sentences?",
      "system": "You are a concise SOC analyst assistant...",
      "stream": false,
      "options": {"temperature": 0.3, "num_predict": 220, ...}
    }

    Ollama loads the prompt into GPU VRAM and generates tokens.
    RTX 4060 generates ~1-3 seconds worth of output.

    Response JSON arrives:
    { "response": "This behavior strongly indicates a credential brute-force
                   or dictionary attack targeting a privileged account." }

    _query_ollama() returns that string.

  alert.llm_hypothesis = "This behavior strongly indicates a credential
                           brute-force or dictionary attack..."

  Console: [10:01:07] [INFO ] ↳ Generating incident report...

  get_mitigation("Brute Force Attack") returns:
    "Immediately block source IP at the firewall. Lock the targeted account(s)
     and force a password reset. Enable MFA if not already active."

  generate_incident_report(...) called:
    HTTP POST → http://localhost:11434/api/generate
    Body: {
      "model":  "llama3.1:8b",
      "prompt": "Threat Type: Brute Force Attack\n
                 Source IP: 192.168.1.4\n
                 Evidence: {\"failed_attempts\": 20, ...}\n
                 Analyst Hypothesis: This behavior strongly indicates...\n
                 Recommended Mitigation: Immediately block source IP...\n\n
                 Write a 2-3 sentence incident report paragraph.",
      "system": "You are a professional SOC analyst writing a brief incident report..."
    }

    Response: "The system detected a credential brute-force attack originating
               from IP 192.168.1.4, with 20 failed login attempts against the
               'admin' account within a 60-second window. This is consistent
               with automated password-guessing tooling. Immediate action:
               block the source IP at the firewall and enforce a mandatory
               password reset on the affected account."

  alert.llm_report = that string.

TIME: 10:01:09
  PHASE 2: _update_alert_llm(conn, row_id=1, alert)
    UPDATE alerts
    SET llm_hypothesis = "This behavior strongly indicates...",
        llm_report     = "The system detected a credential brute-force..."
    WHERE id = 1

  Console: [10:01:09] [INFO ] ↳ LLM report written for alert id=1

  _print_alert_banner(alert) prints the full coloured block to console.

TIME: 10:01:09 — Dashboard side
  Teammate 3's Streamlit app is polling. It reads from alerts table.
  Row id=1 now has all fields populated.
  Dashboard renders:
    - Threat: Brute Force Attack
    - Risk: CRITICAL (shown in red)
    - Confidence: 90%
    - Source IP: 192.168.1.4
    - Rules: rule_high_login_failure, rule_single_ip_brute, rule_untrusted_ip
    - AI Hypothesis: "This behavior strongly indicates..."
    - Incident Report: "The system detected a credential brute-force..."
    - Timestamp: 15 Jul 2025, 03:31:09 PM IST  (converted from UTC by dashboard)

TIME: 10:01:09 — Alert #2 (Unauthorized Access Scan) is processed next
  Same flow. row_id = 2. Both LLM calls run. DB updated.

TIME: 10:01:14
  main() sleeps 5 seconds and wakes up for next cycle.
  run_all_rules() runs again.
  _already_alerted("Brute Force Attack", "192.168.1.4") → True (within 300s cooldown)
  No new alerts created.
  Console: (silent — heartbeat only every 60s)
```

---

---

# 12. Error Handling & Resilience

The agent is designed to keep running no matter what goes wrong. Every failure
mode has a specific, graceful response.

---

## Ollama is Offline

**Where caught:** `_query_ollama()` in `llm_client.py` catches `ConnectionError`.

**What happens:**
- Returns the string `"[LLM Offline] Could not reach Ollama. Is it running? → ollama serve"`
- This string is stored as `llm_hypothesis` and `llm_report` in the database
- Detection continues normally — the alert IS saved with all rule-based fields
- The dashboard shows the placeholder text instead of a blank field
- The agent does not crash or pause

---

## Database is Missing

**Where caught:** `main()` in `main.py` checks `os.path.exists(DB_PATH)`.

**What happens:**
- Prints a warning: "Database missing — waiting for backend..."
- Skips `_run_agent_cycle()` entirely for that cycle
- Sleeps 5 seconds and checks again
- No crash, no exception

---

## Database is Locked (Backend Writing Simultaneously)

**Where caught:** `main()` wraps `_run_agent_cycle()` in a try/except for
`sqlite3.OperationalError`.

**What happens:**
- WAL mode (`PRAGMA journal_mode=WAL`) means readers and writers rarely conflict
- If conflict does occur: logs a warning "DB temporarily unavailable. Retrying..."
- Sleeps 5 seconds and retries next cycle
- No crash

---

## LLM Timeout

**Where caught:** `_query_ollama()` catches `requests.exceptions.Timeout`.

**What happens:**
- Returns `"[LLM Timeout] Model took longer than 30s to respond."`
- Stored as placeholder in the database
- Agent continues to the next alert

---

## Unexpected Exception in a Cycle

**Where caught:** `main()` wraps the entire cycle in `except Exception as e`.

**What happens:**
- Logs the error message and prints a full traceback for debugging
- Does NOT kill the agent — execution continues to next cycle
- The next polling cycle starts normally after 5 seconds

---

## Python Version Too Old

**Where caught:** Version guard at the very top of `main.py`, before all imports.

**What happens:**
- Prints a clear, human-readable error message
- Calls `sys.exit(1)` — this is the only intentional crash in the entire codebase
- The error tells the user exactly what Python version they are running and what
  is required

---

---

# 13. Integration With Teammates

---

## What the Agent Needs From Teammate 1 (Backend)

The agent reads from the `logs` table. Teammate 1 must write rows to this table
that use exactly these column names and value formats:

```
Column      Required?  Expected values
----------  ---------  ------------------------------------------
timestamp   YES        UTC datetime string: "2025-07-15 10:01:22"
                       SQLite DEFAULT CURRENT_TIMESTAMP is fine.
event_type  YES        "login_attempt" for login events
                       "page_access" for GET requests to pages
                       "api_call" for API endpoint requests
method      YES        "GET", "POST", "PUT", "DELETE"
endpoint    YES        The raw URL path: "/login", "/admin", "/api/users"
                       Must NOT be URL-decoded (rule 7 needs raw encoded strings)
username    YES for     The username submitted in the login form.
            logins     NULL is fine for anonymous requests.
ip          YES        The client's IP address as a string.
status_code YES        The HTTP response code: 200, 401, 403, 404, 500, etc.
status      YES        "success" if the request succeeded (2xx response)
                       "fail"    if authentication failed (401, wrong password)
                       "blocked" if the request was rejected by middleware
```

**Critical rule for Teammate 1:**
- Login successes (`status='success'`) MUST be logged. Rule 5 (Account Takeover)
  only fires if it can see both failures AND a success from the same IP.
- The `endpoint` column must contain the raw, un-decoded URL. If FastAPI
  automatically URL-decodes the path before logging, path traversal attacks
  (Rule 7) will be invisible to the agent.

---

## What the Dashboard Gets From the Agent (Teammate 3)

The agent writes to the `alerts` table. Teammate 3 reads from it.

```python
# Recommended query for the dashboard
import sqlite3, pandas as pd

conn = sqlite3.connect("data/logs.sqlite")

df = pd.read_sql(
    "SELECT * FROM alerts ORDER BY timestamp DESC",
    conn
)

# Convert timestamps from UTC to IST before displaying
df["timestamp"] = (
    pd.to_datetime(df["timestamp"], utc=True)
      .dt.tz_convert("Asia/Kolkata")
      .dt.strftime("%d %b %Y, %I:%M:%S %p IST")
)

# triggered_rules and details are stored as JSON strings — parse them
import json
df["triggered_rules"] = df["triggered_rules"].apply(
    lambda x: json.loads(x) if x else []
)
df["details"] = df["details"].apply(
    lambda x: json.loads(x) if x else {}
)
```

**Key points for Teammate 3:**
- `llm_hypothesis` and `llm_report` may be empty strings `''` briefly
  (Phase 1 of the two-phase save). Handle empty strings gracefully in the UI —
  show a "Generating AI report..." spinner or placeholder if the field is empty.
- `triggered_rules` and `details` are JSON strings — always parse them before use.
- `timestamp` in the database is UTC — always convert to IST before displaying.
- Poll the `alerts` table every few seconds using `st.rerun()` in Streamlit
  to show new alerts as they arrive.

---

## The Three-Process Architecture

All three components run simultaneously on the integration laptop:

```
Terminal 1:  uvicorn api:app --reload        → backend writes to logs table
Terminal 2:  python agent/main.py            → agent reads logs, writes alerts
Terminal 3:  streamlit run dashboard/app.py  → dashboard reads alerts, displays
Terminal 4:  ollama serve                    → LLM server (GPU inference)
```

They communicate exclusively through `data/logs.sqlite`. No sockets, no shared
memory, no message queues. The file is the integration point.

```
backend  ──WRITE──►  logs.sqlite (logs table)   ──READ──►  agent
agent    ──WRITE──►  logs.sqlite (alerts table) ──READ──►  dashboard
```

The only rule is: **each component owns exactly one table and never writes to
the other's table.**


