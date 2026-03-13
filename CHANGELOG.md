# CHANGELOG — AI-Driven Cyber Threat Hunting Agent

All changes to this project are documented here in reverse-chronological order.
Every entry records: what changed, which file(s) were affected, and why the change was made.

---

## Format

```
[YYYY-MM-DD] | Prompt Session N | <short title>
```

---

---

## [Session 1] — Initial Project Scaffold & Agent Build

**Trigger:** First setup prompt. User confirmed responsibility for the `agent/` component and Ollama integration.

### Actions Taken

#### Deleted — Dataset folders (not needed)
- `Trendyol-Cybersecurity-Instruction-Tuning-Dataset/` — **Reason:** Fine-tuning dataset (53K instruction-response pairs for GPU training via SFTTrainer/LoRA). We are doing inference-only prompt engineering, not fine-tuning. Useless weight.
- `archive (2)/` (Microsoft GUIDE dataset) — **Reason:** Classification training dataset (13M evidence rows). No inference value. Removed.
- `cybersecurity-instruction-dataset/` — **Reason:** Another HuggingFace fine-tuning dataset in Parquet format. Not needed for inference. Removed.
- `llm_training_datasets.md` — **Reason:** Reference document listing fine-tuning datasets. Irrelevant since we are not fine-tuning. Removed.

#### Created — `data/schema.sql`
- **Why:** Defines the shared SQLite database contract between all three teammates.
- **What it contains:**
  - `logs` table — owned and written by Teammate 1 (backend). Fields: `id`, `timestamp`, `event_type`, `method`, `endpoint`, `username`, `ip`, `status_code`, `status`.
  - `alerts` table — owned and written by the agent. Fields: `id`, `timestamp`, `threat_type`, `risk_level`, `confidence`, `source_ip`, `triggered_rules`, `details`, `llm_hypothesis`, `llm_report`.
  - Indexes on `(ip, timestamp)`, `(event_type, timestamp)`, `(endpoint, timestamp)`, `(source_ip, threat_type, timestamp)` for fast rule queries.

#### Created — `agent/requirements.txt`
- **Why:** Isolated dependency list for the agent component.
- **Contents:** `requests>=2.31.0`, `pydantic>=2.0.0`

#### Created — `agent/llm_client.py`
- **Why:** All Ollama communication is isolated in one module so it can be swapped or mocked without touching detection logic.
- **What it contains:**
  - `MODEL_NAME = "llama3.2:1b"` — chosen for CPU-only environments (no dedicated GPU).
  - `check_ollama_health()` — pings `localhost:11434`, checks if the model is pulled. Returns status dict for startup logging.
  - `generate_hypothesis(observation)` — sends a raw observation string to Ollama and returns a 1-2 sentence attack scenario hypothesis. System prompt instructs the model to be concise and technical.
  - `generate_incident_report(threat_type, source_ip, details, mitigation, hypothesis)` — formats the agent's deterministic findings into a polished SOC paragraph. LLM adds NO new logic here — purely a text formatter.
  - `_query_ollama()` — internal POST to `/api/generate` with `stream: false`. Handles all error cases (ConnectionError, Timeout, HTTPError) with readable fallback strings so the agent keeps running if Ollama is offline.
  - CLI smoke test: `python llm_client.py` runs health check + two live generation tests.
- **Design principle enforced:** The LLM never makes security decisions. It only generates natural language to explain decisions the rules engine already made.

#### Created — `agent/rules_engine.py` (initial — 3 rules)
- **Why:** All detection logic must be deterministic and auditable. Completely separate from LLM code.
- **What it contains:**
  - `BASELINE` dict — configurable thresholds for all rules.
  - `RESTRICTED_PATHS` — list of paths that trigger recon detection.
  - `RULE_CONFIDENCE` dict — additive confidence weights per rule sub-condition.
  - `ThreatAlert` dataclass — the output object of every rule. Fields: `threat_type`, `risk_level`, `confidence`, `triggered_rules`, `source_ip`, `details`, `timestamp`, `llm_hypothesis`, `llm_report`. Includes `to_dict()`.
  - `_clamp()`, `_risk_from_confidence()`, `_already_alerted()` — helpers. `_already_alerted()` queries the alerts table to suppress duplicate alerts within a 5-minute cooldown window.
  - **Rule 1 — `check_brute_force()`:** Detects >5 failed login attempts from same IP in 60s. Bonus confidence if 90%+ of that IP's activity is failures. Base confidence: 55.
  - **Rule 2 — `check_recon()`:** Detects >3 hits on restricted paths from same IP in 60s. Bonus if ≥3 distinct paths. Base confidence: 60.
  - **Rule 3 — `check_auth_scan()`:** Detects >6 HTTP 401/403 responses to same IP in 60s. Bonus if count ≥ 3× threshold. Base confidence: 50.
  - `run_all_rules()` — calls all rule functions and returns combined list.
  - `MITIGATIONS` dict + `get_mitigation()` — deterministic per-threat mitigation strings. No AI.

#### Created — `agent/main.py`
- **Why:** The core agent loop. Entry point run by `python main.py`.
- **What it contains:**
  - Path setup to allow running from any working directory.
  - `_get_connection()` — opens SQLite with 5s busy-timeout and WAL journal mode for safe concurrent reads while backend writes.
  - `_ensure_alerts_table()` — idempotent CREATE TABLE IF NOT EXISTS for the alerts table, so the agent works even if schema.sql was never run manually.
  - `_save_alert()` — inserts a ThreatAlert into the alerts table with all fields serialized.
  - `_build_observation()` — builds a plain-English observation string from a ThreatAlert. Used as the Hypothesize prompt. Has a specific template per threat type and a generic fallback.
  - `_enrich_with_llm()` — calls `generate_hypothesis()` then `generate_incident_report()`. Mutates the alert in place. The agent keeps working if LLM is offline.
  - `_log()` — timestamped, ANSI-coloured console output with levels: info, warn, alert, error, ok.
  - `_print_alert_banner()` — coloured block banner for confirmed threats showing all fields including LLM output.
  - `_startup_checks()` — validates data directory exists, checks Ollama health, waits up to 30s for the database to appear.
  - `_run_agent_cycle()` — one full Observe→Investigate→Decide cycle. Opens/closes connection each cycle to avoid stale reads.
  - `main()` — infinite polling loop (5s interval). Handles SQLite lock errors gracefully. Prints a quiet heartbeat every 60s when no threats found. Catches Ctrl+C cleanly.
  - `MIN_CONFIDENCE_TO_ALERT = 40` — alerts below this are silently dropped.

#### Created — `.gitignore`
- **Why:** Prevent generated files and sensitive data from being committed.
- **Ignores:** `__pycache__/`, `*.pyc`, `venv/`, `data/logs.sqlite`, `data/alerts.json`, `.env`, `*.gguf`, `*.bin`, `.idea/`, `.vscode/`, `Thumbs.db`, etc.

#### Created — `README.md`
- **Why:** Setup and run instructions for judges and all three teammates.
- **Contents:** Architecture diagram, team responsibility table, prerequisites (Ollama install + `ollama pull llama3.2:1b`), per-component setup steps, three-terminal run instructions, demo flow, full database schema reference, agent reasoning flow diagram, detection rules table, smoke test commands, and troubleshooting table.

---

---

## [Session 2] — Expanded Threat Detection (5 New Rules)

**Trigger:** User approved adding attacks #4, #6, #7, #8, #10 from a suggested list of 7. Rejected #5 (Password Spray) and #9 (SQL Injection Probe).

### Actions Taken

#### Modified — `agent/rules_engine.py`
- **Why:** 3 rules was insufficient for a hackathon demo. Expanded to 8 total threat types covering all phases of an attack chain (entry → escalation → exfiltration → flood).

**Added to `BASELINE`:**
- `max_distinct_users_per_min: 8` — threshold for credential stuffing
- `account_takeover_min_failures: 3` — min prior failures before a success triggers takeover alert
- `account_takeover_window_seconds: 300` — lookback window for takeover correlation
- `max_data_requests_per_min: 20` — threshold for data exfiltration
- `path_traversal_min_attempts: 1` — even one traversal request is flagged
- `max_requests_per_min: 100` — threshold for DoS flood

**Added to `RULE_CONFIDENCE`:**
- `rule_credential_stuffing: 65`, `rule_many_distinct_users: 15` (bonus >15 users)
- `rule_account_takeover: 85` (highest base — success after failures is critical), `rule_high_failure_pre_success: 10`
- `rule_data_scraping: 60`, `rule_high_volume_scrape: 15` (bonus >2× threshold)
- `rule_path_traversal: 70`, `rule_encoded_traversal: 15` (bonus for URL-encoded variants)
- `rule_dos_flood: 55`, `rule_extreme_flood: 25` (bonus >3× threshold)

**Added constant `DATA_ENDPOINTS`:**
- List of data-serving endpoint names for the exfiltration rule.

**Added Rule 4 — `check_credential_stuffing()`:**
- Detects: same IP with `COUNT(DISTINCT username) > 8` failed logins in 60s.
- Key distinction from brute force: targets many different accounts, not one account many times.

**Added Rule 5 — `check_account_takeover()`:**
- Detects: IP with ≥3 failures in 5-min window that also has a successful login in the same window.
- Implementation: two-subquery JOIN in SQL — failure set JOINed to success set on IP.
- Highest base confidence (85) because a successful login after repeated failures is the most dangerous signal.

**Added Rule 6 — `check_data_exfiltration()`:**
- Detects: >20 successful (200 OK) GET requests to data-serving endpoints from same IP in 60s.
- Matches both exact endpoint names from `DATA_ENDPOINTS` and LIKE patterns for `/api/%`, `/data/%`, `/export/%`, `/download/%`, `/files/%`.

**Added Rule 7 — `check_path_traversal()`:**
- Detects: any request with directory traversal sequences in the endpoint URL.
- Patterns matched: `../`, `..\`, `%2e%2e%2f`, `%2e%2e/`, `..%2f`, `..%2F`, `%252e%252e` (double-encoded), `....//`.
- Bonus confidence if URL-encoded variants are used (indicates automated tooling).
- Minimum threshold = 1 (zero tolerance — a single hit fires the rule).

**Added Rule 8 — `check_dos_flood()`:**
- Detects: >100 total requests from same IP across any endpoint in 60s.
- Covers attacks that return 200 OK and slip past all other rules.
- Bonus if >3× threshold (clearly automated).

**Updated `run_all_rules()`:**
- Now calls all 8 rules.
- Ordered by descending base confidence so most severe alerts surface first in the console: Account Takeover (85) → Path Traversal (70) → Credential Stuffing (65) → Recon (60) → Data Exfiltration (60) → Brute Force (55) → Auth Scan (50) → DoS Flood (55).

**Updated `MITIGATIONS`:**
- Added entries for all 5 new threat types: Credential Stuffing, Account Takeover, Data Exfiltration, Path Traversal Attack, DoS Rate Flood.

#### Modified — `agent/main.py`
- **Why:** `_build_observation()` had hardcoded templates only for the original 3 threat types. New types would fall through to the generic fallback, producing low-quality LLM prompts.
- **What changed:** Added 5 new `if alert.threat_type == "..."` branches to `_build_observation()`:
  - **Credential Stuffing:** mentions distinct account count, total attempts, sample usernames.
  - **Account Takeover:** explicitly calls out the failure count, the successful login, and the compromised account name — making the LLM prompt as alarming and accurate as possible.
  - **Data Exfiltration:** mentions request volume, endpoint count, and specific endpoints hit.
  - **Path Traversal Attack:** mentions the traversal attempt count and the actual malicious URL strings.
  - **DoS Rate Flood:** mentions total request count, endpoint spread, and the rate threshold exceeded.

---

---

## Decisions Log (Non-Code)

| Decision | Rationale |
|---|---|
| No fine-tuning of LLM | Requires GPU + hours of training. We are inference-only. Pre-trained models already know all attack types. |
| `llama3.2:1b` as default model | Fastest on CPU (~5-15s/response). No dedicated GPU available. Sufficient for 1-3 sentence outputs. |
| SQLite over JSON for shared data | Safer concurrent access (WAL mode), faster queries for rule evaluation, single file for dashboard to read. |
| Alerts written to same `logs.sqlite` | Simplifies dashboard — one file to read. Agent writes to `alerts` table only; backend writes to `logs` table only. Clear ownership. |
| 5-minute alert cooldown | Prevents alert spam when agent polls every 5s. Same threat from same IP re-alerts after 5 minutes if still active. |
| `MIN_CONFIDENCE_TO_ALERT = 40` | Drops very weak signals. All current rules have a base confidence ≥ 50 so this is a safety net for future low-confidence rules. |
| Rules ordered highest-confidence-first in `run_all_rules()` | Most critical threats (Account Takeover, Path Traversal) surface at the top of the console output first. |
| Rejected Password Spray (#5) | User decision. Similar detection surface to Credential Stuffing; adds complexity without enough demo differentiation. |
| Rejected SQL Injection (#9) | User decision. Requires Teammate 1 to log full URL including query params — coordination dependency at risk during hackathon. |
| Rejected Groq / Gemini cloud API | Sending live incident data (IPs, usernames, attack evidence) to a third-party server violates the core privacy principle. May breach data residency laws. Directly contradicts the "How can you trust AI?" answer the project was designed to give. |
| Rejected Colab inference via ngrok | Running LLM inference on Colab and tunneling prompts to it is functionally identical to a cloud API — live log data leaves the machine. Same privacy violation as Groq/Gemini. |
| Rejected fine-tuning on Colab | Fine-tuning is privacy-safe (only static datasets leave the machine) but not worth the time cost (3-4 hours on Colab T4). The pre-trained model already knows all 8 attack types from internet pre-training. Output quality difference for 2-3 sentence summaries is marginal. |
| Ollama confirmed as final LLM strategy | Runs entirely on localhost:11434. No data ever leaves the machine. Works on any laptop with Ollama installed. To run on the integration teammate's laptop: install Ollama, run `ollama pull llama3.2:1b`, run `ollama serve`. Zero code changes needed. |
| `llama3.2:3b` noted as optional upgrade | If the integration laptop has 4+ GB free RAM, `llama3.2:3b` gives noticeably better output quality while remaining fully local and CPU-viable. Not a required change — `llama3.2:1b` is the safe default. |
| `llama3.1:8b` confirmed as final model | Integration teammate has 16 GB RAM and an NVIDIA RTX 4060 (8 GB VRAM). Model uses ~4.7 GB VRAM, fits with ~3 GB to spare. Ollama detects CUDA automatically — no config needed. Response time drops from 20-40s (CPU estimate) to ~1-3s on GPU. |
| `num_predict` raised from 150 → 220 | CPU-era concession removed. GPU is fast enough that limiting output length to save time is no longer necessary. Allows 3-4 polished sentences instead of 2-3 clipped ones. |
| `num_ctx` raised from 1024 → 2048 | CPU-era concession removed. Full context window available on GPU without speed penalty. |
| `REQUEST_TIMEOUT` lowered from 90s → 30s | GPU responses arrive in 1-3s. 90s was a generous CPU fallback. 30s is still comfortable headroom while failing fast if something goes wrong. |

---

---

## [Session 5] — Python 3.11 / 3.13 Cross-Version Compatibility

**Trigger:** User confirmed they use Python 3.11; both other teammates use Python 3.13. All teammates create a venv before running. Codebase must work identically on both versions.

### Investigation Results

A grep across all three agent files was run to identify version-specific patterns before making any changes.

| Pattern checked | Finding |
|---|---|
| `datetime.utcnow()` | **Found** in `rules_engine.py` line 153 — deprecated since Python 3.12, raises `DeprecationWarning` on 3.13 |
| `from typing import List, Dict` | Found in both files — soft-deprecated since 3.9 but **not removed in 3.13**, zero runtime warnings, left unchanged |
| `pydantic` in `requirements.txt` | **Found** — never imported anywhere in agent code, carries unnecessary C-extension build risk on fresh 3.13 environments |
| All other stdlib usage (`sqlite3`, `json`, `os`, `sys`, `time`, `dataclasses`) | Fully stable across 3.9 – 3.13, no action needed |

### Actions Taken

#### Modified — `agent/rules_engine.py`
- **What changed:** Line 48 import changed from `from datetime import datetime` → `from datetime import datetime, timezone`. Line 153 default factory changed from `datetime.utcnow().isoformat()` → `datetime.now(timezone.utc).isoformat()`.
- **Why:** `datetime.utcnow()` was deprecated in Python 3.12 and emits `DeprecationWarning` on Python 3.13. Since the agent creates a new `ThreatAlert` on every detection (every 5 seconds in the polling loop), this warning would spam the console continuously on the teammates' 3.13 machines. The replacement `datetime.now(timezone.utc)` is the officially recommended equivalent and works identically on Python 3.9 through 3.13.

#### Modified — `agent/requirements.txt`
- **What changed:** Removed `pydantic>=2.0.0`.
- **Why:** Pydantic was added as a placeholder dependency but is never imported anywhere in `main.py`, `rules_engine.py`, or `llm_client.py`. The agent uses Python's built-in `dataclasses.dataclass` for `ThreatAlert` instead. Pydantic 2.x includes compiled C extensions (`pydantic-core`) that occasionally fail to build on fresh Python 3.13 environments before binary wheels are published for that version. Removing it eliminates a silent install-time risk with zero functional impact.

#### Modified — `agent/main.py`
- **What changed:** Added a Python version guard block immediately after the module docstring, before all other imports. Checks `sys.version_info < (3, 9)` and exits with a clear human-readable message if the check fails.
- **Why:** Provides an explicit, actionable error message if someone accidentally runs the agent under an old Python installation (e.g., system Python 2.7 or 3.8 on older machines) rather than a cryptic `SyntaxError` or `ImportError` deep in the code. Tested range is Python 3.11 (agent author) and Python 3.13 (teammates). Minimum is set to 3.9 as a conservative floor — all language features used in the codebase are available from 3.9 onward.

### What was NOT changed and why

| Item | Reason left unchanged |
|---|---|
| `from typing import List, Dict, Any` in both files | Soft-deprecated since 3.9 but produces zero runtime warnings on any version including 3.13. Not removed until at least Python 3.14+. Updating all 20+ type annotations would be a large diff with no functional benefit during an 18-hour hackathon. |
| `datetime.now()` in `main.py` `_log()` function | Uses local time (no UTC), which is correct for console output. Not the same as `utcnow()` and carries no deprecation. |

---

---

## [Session 6] — Timezone Strategy (UTC Storage → IST Display)

**Trigger:** User confirmed the hackathon is in India and judges are Indian. Question raised: should timestamps be stored and displayed in IST, or keep UTC?

### Decision

**Store UTC everywhere. Convert to IST only at the Streamlit display layer.**

This is the industry standard approach, not a workaround. Reasons:

| Reason | Detail |
|---|---|
| SQLite `datetime('now')` is UTC | All rule queries (`datetime('now', '-60 seconds')` etc.) compare UTC to UTC. Storing IST in the DB would silently break every time-window query in the rules engine. |
| India has no DST | IST is a fixed UTC+5:30 offset — no edge cases, no ambiguity. The conversion is always exactly +5h 30m. |
| Console logs are already correct | `_log()` in `main.py` uses `datetime.now()` (system local time). If the machine running the agent has its system clock set to IST, console output already shows IST automatically. |
| Single responsibility | The DB and agent are data layers — they should not know or care about display timezones. The dashboard is the only thing judges see. |

### Actions Taken

**No changes to `agent/` or `backend/`.** Zero modifications required.

#### For Teammate 3 (Dashboard) — required snippet

Every timestamp read from SQLite must be converted before display:

```python
import pandas as pd

# When reading from the alerts or logs table:
df["timestamp"] = (
    pd.to_datetime(df["timestamp"], utc=True)       # parse stored string as UTC
      .dt.tz_convert("Asia/Kolkata")                # convert to IST (UTC+5:30)
      .dt.strftime("%d %b %Y, %I:%M:%S %p IST")    # e.g. 15 Jul 2025, 02:30:45 PM IST
)
```

**Rules for Teammate 3:**
1. Every timestamp column coming out of SQLite is UTC — always run `.tz_convert("Asia/Kolkata")` before rendering it on screen.
2. Never write IST timestamps back into the DB — the DB is write-only for the backend (logs table) and agent (alerts table).

---

---

## [Session 7] — Testing Infrastructure

**Trigger:** User requested two testing guides: one for solo testing without any teammate code, and one for final integration testing after all three components are built.

### Actions Taken

#### Created — `tests/mock_logs.py`
- **Why:** The agent reads from `data/logs.sqlite` which is normally populated by Teammate 1's backend. Since the backend doesn't exist yet, the agent has nothing to detect during solo development. This script replaces the backend for testing purposes by directly inserting realistic fake log rows.
- **What it contains:**
  - `get_conn()` — creates `data/logs.sqlite` and both tables (`logs`, `alerts`) if they don't exist yet. The agent can run immediately after this without needing any backend code.
  - One `inject_*` function per attack type (8 total). Each function inserts enough rows to cross that rule's exact detection threshold, using a unique attacker IP per scenario so all 8 can be active simultaneously.
  - `clean_db()` — wipes all rows from `logs` and `alerts` tables (keeps table structure). Used to reset between test runs.
  - Interactive menu — prompts the user to pick a scenario by number. Also supports `--all`, `--clean`, and `--scenario <name>` flags for non-interactive use.
  - All injected timestamps use `datetime.now(timezone.utc)` so they fall within the agent's 60-second detection windows immediately.
- **Mock attacker IPs used:** `10.10.10.1` through `10.10.10.8` — one per scenario, none in the `trusted_ips` list, so the `rule_untrusted_ip` confidence bonus fires for every scenario.

#### Created — `TESTING.md`
- **Why:** Provides a step-by-step test plan so the agent can be validated independently before integration, and again after integration in a structured way with clear pass/fail criteria.
- **Structure:**

  **Part 1 — Solo Testing (6 tests):**
  | Test | Purpose |
  |---|---|
  | Test 0 — LLM Smoke Test | Confirm Ollama is running and `llama3.1:8b` responds before touching agent code |
  | Test 1 — Single Attack | Full end-to-end pipeline for Brute Force only — confirms DB write, agent detection, LLM enrichment, alert persistence |
  | Test 2 — All 8 Attacks | All 8 rules fire in a single run; expected output table lists all 8 alerts |
  | Test 3 — Cooldown | Re-inject same scenario, verify no duplicate alert is created within 5 minutes |
  | Test 4 — Ollama Offline | Stop Ollama; verify agent still detects and saves alerts with `[LLM Offline]` placeholders |
  | Test 5 — No Database | Rename DB file; verify agent waits gracefully and resumes when DB is restored |

  **Part 2 — Full Integration Testing (5 test groups):**
  | Test | Purpose |
  |---|---|
  | Pre-flight checklist | GPU confirmed via `ollama ps`, all three components start cleanly |
  | Test A — Backend → Agent | Backend writes logs the agent can detect (manual curl/Python script provided) |
  | Test B — Agent → Dashboard | Dashboard displays alerts with IST timestamps |
  | Tests C-1 through C-5 | Live Requestly attack scenarios: Brute Force, Recon, Account Takeover, Path Traversal, DoS Flood |
  | Test D — Data Integrity | SQL query verifying no empty `llm_hypothesis`/`llm_report` fields |
  | Test E — Stress Test | All 8 mock scenarios + live traffic simultaneously; checks for crashes and duplicates |

- **Also includes:** Common integration issues table mapping 8 specific failure symptoms to their root causes and fixes (e.g. backend logging `user` instead of `username`, backend URL-decoding paths before logging, IST conversion missing on dashboard).

---

---

## [Session 6] — Timezone Strategy (UTC Storage → IST Display)

**Trigger:** User confirmed the hackathon is in India and judges are Indian. Question raised: should timestamps be stored and displayed in IST, or keep UTC?

### Decision

**Store UTC everywhere. Convert to IST only at the Streamlit display layer.**

This is the industry standard approach, not a workaround. Reasons:

| Reason | Detail |
|---|---|
| SQLite `datetime('now')` is UTC | All rule queries (`datetime('now', '-60 seconds')` etc.) compare UTC to UTC. Storing IST in the DB would silently break every time-window query in the rules engine. |
| India has no DST | IST is a fixed UTC+5:30 offset — no edge cases, no ambiguity. The conversion is always exactly +5h 30m. |
| Console logs are already correct | `_log()` in `main.py` uses `datetime.now()` (system local time). If the machine running the agent has its system clock set to IST, console output already shows IST automatically. |
| Single responsibility | The DB and agent are data layers — they should not know or care about display timezones. The dashboard is the only thing judges see. |

### Actions Taken

**No changes to `agent/` or `backend/`.** Zero modifications required.

#### For Teammate 3 (Dashboard) — required snippet

Every timestamp read from SQLite must be converted before display:

```python
import pandas as pd

# When reading from the alerts or logs table:
df["timestamp"] = (
    pd.to_datetime(df["timestamp"], utc=True)       # parse stored string as UTC
      .dt.tz_convert("Asia/Kolkata")                # convert to IST (UTC+5:30)
      .dt.strftime("%d %b %Y, %I:%M:%S %p IST")    # e.g. 15 Jul 2025, 02:30:45 PM IST
)
```

**Rules for Teammate 3:**
1. Every timestamp column coming out of SQLite is UTC — always run `.tz_convert("Asia/Kolkata")` before rendering it on screen.
2. Never write IST timestamps back into the DB — the DB is write-only for the backend (logs table) and agent (alerts table).

---

---

## [Session 8] — Agent & LLM Complete Technical Documentation

**Trigger:** User requested a comprehensive, detailed document covering how the agent works, every function, the full workflow, where outputs are stored, and how the LLM integration works — a complete technical recap of everything built.

### Actions Taken

#### Created — `AGENT_DOCUMENTATION.md`

A 1,985-line, 68,700-character technical reference document covering the entire agent and LLM system. Structured into 13 sections.

| Section | Content |
|---|---|
| 1. What the Agent Is | High-level explanation of the agent's dual responsibility: deterministic detection (no AI) and LLM-powered explanation (AI for text only) |
| 2. File Structure | Role of each file: `main.py` (conductor), `rules_engine.py` (detection brain), `llm_client.py` (LLM integration layer), `requirements.txt` |
| 3. Big Picture Data Flow | End-to-end ASCII diagram tracing one attacker request from browser through backend → logs.sqlite → agent → Ollama → alerts.sqlite → dashboard → judges |
| 4. Agent Reasoning Loop | Maps each of the 5 SOC analyst steps (Observe, Hypothesize, Investigate, Decide, Explain) to the exact function and file that implements it, and whether AI is involved |
| 5. rules_engine.py | Full documentation of: BASELINE thresholds, RESTRICTED_PATHS, DATA_ENDPOINTS, RULE_CONFIDENCE weights, ThreatAlert dataclass (every field explained), _clamp(), _risk_from_confidence(), _already_alerted() (duplicate suppression), all 8 detection rules with their exact SQL queries and bonus conditions, run_all_rules() ordering rationale, MITIGATIONS dict and get_mitigation() |
| 6. llm_client.py | What Ollama is and how it works locally, all configuration constants explained (temperature, num_predict, num_ctx, timeout), _query_ollama() request/response format with exact JSON bodies, all error handling fallback strings, check_ollama_health() flow, generate_hypothesis() with exact system and user prompts and example output, generate_incident_report() with exact prompts and example output, what is and is not stored (Ollama stores nothing — it is stateless) |
| 7. main.py | _startup_checks() three-step validation, Python version guard, _get_connection() WAL mode explained, _ensure_alerts_table() idempotency, _save_alert_initial() Phase 1 explained (why detection is saved before LLM), _update_alert_llm() Phase 2 explained, _build_observation() all 8 templates, _enrich_with_llm() flow including hypothesis passed into report, _run_agent_cycle() full 10-step sequence, main() infinite loop error handling, _log() and _print_alert_banner() ANSI colour codes |
| 8. The Database | Full schema of both tables with every column explained (type, example value, purpose), two-phase write sequence timeline |
| 9. Confidence Score System | Additive scoring explained with two worked examples (Brute Force scoring to 90, Path Traversal scoring to 95), risk level thresholds, MIN_CONFIDENCE_TO_ALERT filter |
| 10. The LLM Boundary | Explicit table of what the rules engine does vs what the LLM does and does not do — directly answers "How can you trust AI?" |
| 11. Full Walk-Through | Minute-by-minute, function-by-function trace of one complete Brute Force attack from attacker request through detection, both LLM calls, two-phase DB save, and final dashboard display — including exact SQL results, exact HTTP request/response bodies, and console output |
| 12. Error Handling | Every failure mode documented: Ollama offline, database missing, database locked, LLM timeout, unexpected cycle exception, Python version too old — with exact error message text and what the agent does in each case |
| 13. Integration With Teammates | Exact column names and value formats Teammate 1 must write to the logs table, two critical rules (log successes, do not URL-decode paths), recommended Streamlit query snippet for Teammate 3 with IST conversion and JSON parsing, three-process architecture diagram |