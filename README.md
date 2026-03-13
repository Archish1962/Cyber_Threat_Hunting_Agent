# 🛡️ AI-Driven Autonomous Cyber Threat Hunting Agent

A real-time Security Operations Centre (SOC) simulation built for the HackNocturn hackathon.
The system monitors a live "victim" web application, applies deterministic rules to detect 8 distinct attack types, uses a local LLM to generate human-readable incident reports, and streams everything to an interactive Streamlit dashboard.

---

## Architecture

```text
Attacker (Requestly browser extension)
         │
         ▼
 Victim App  ─── FastAPI (backend/api.py)
         │
         ▼
 data/logs.sqlite   ◄── written by backend
         │
         ▼
 Threat Hunting Agent (agent/main.py)
   ├── Rule Engine  (agent/rules_engine.py)   ← 100 % deterministic
   └── LLM Client   (agent/llm_client.py)     ← Ollama llama3.1:8b
         │
         ▼
 data/logs.sqlite   ◄── alerts table written by agent
         │
         ▼
 Streamlit Dashboard (dashboard/app.py)       ← auto-refresh every 3 s
```

**Key design principle:** The AI makes *zero* security decisions.
All detection, scoring, and mitigation logic lives in the deterministic rule engine.
The LLM only translates rule output into polished SOC-report prose.

---

## Detected Threat Types

| # | Threat Type | Trigger |
|---|-------------|---------|
| 1 | **Brute Force Attack** | > 5 failed logins / min, same IP |
| 2 | **Endpoint Reconnaissance** | > 3 restricted-path hits / min |
| 3 | **Unauthorized Access Scan** | > 6 HTTP 401/403 responses / min |
| 4 | **Credential Stuffing** | > 8 distinct usernames failing / min |
| 5 | **Account Takeover** | failures → successful login, same IP, 5 min window |
| 6 | **Data Exfiltration** | > 20 successful GETs to data endpoints / min |
| 7 | **Path Traversal Attack** | any `../` or URL-encoded traversal in request path |
| 8 | **DoS Rate Flood** | > 100 total requests / min from one IP |

---

## Project Structure

```text
cyber-threat-hunting-agent/
│
├── backend/
│   ├── api.py          FastAPI victim-app (login, admin, data endpoints + catch-all)
│   ├── db.py           SQLite helpers (init_db, get_connection)
│   ├── logger.py       log_event() — writes every request to the DB
│   └── main.py         Entry point: init DB + start uvicorn
│
├── agent/
│   ├── main.py         Core loop: Observe → Hypothesize → Investigate → Decide → Explain
│   ├── rules_engine.py All 8 detection rules + ThreatAlert dataclass + mitigations
│   └── llm_client.py   Ollama integration (generate_hypothesis, generate_incident_report)
│
├── dashboard/
│   └── app.py          Streamlit SOC watch view (auto-refreshes via @st.fragment)
│
├── data/
│   ├── logs.sqlite     Shared SQLite database (created at first run)
│   └── schema.sql      Table definitions for logs + alerts
│
├── mock_generator.py   Standalone traffic + alert simulator (no backend/agent needed)
├── pyproject.toml      Python dependencies (managed with uv)
└── README.md           This file
```

---

## Prerequisites

| Tool | Version | Notes |
|------|---------|-------|
| Python | 3.13+ | |
| [uv](https://docs.astral.sh/uv/) | latest | dependency management |
| [Ollama](https://ollama.com) | latest | local LLM runtime |
| llama3.1:8b | — | `ollama pull llama3.1:8b` |

> **GPU note:** `llama3.1:8b` runs at ~1–3 s/response on an NVIDIA RTX 4060 (8 GB VRAM).
> On CPU it takes 20–40 s but the agent degrades gracefully — detection still works instantly.

---

## Setup

```bash
# 1. Clone the repository
git clone <repo-url>
cd cyber-threat-hunting-agent

# 2. Install dependencies with uv
uv sync

# 3. Pull the LLM model (one-time download, ~4.7 GB)
ollama pull llama3.1:8b

# 4. Make sure Ollama is running
ollama serve
```

---

## Running the Full Stack

Open **three separate terminals** from the project root.

### Terminal 1 — Backend (Victim App)

```bash
uv run python -m backend.main
```

The FastAPI server starts at `http://localhost:8000`.
Interactive API docs: `http://localhost:8000/docs`

### Terminal 2 — Threat Hunting Agent

```bash
uv run python agent/main.py
```

The agent polls the database every 5 seconds.
Detections are printed to the console with colour-coded banners and written back to `data/logs.sqlite`.

### Terminal 3 — Dashboard

```bash
uv run streamlit run dashboard/app.py
```

Dashboard opens at `http://localhost:8501`.
It auto-refreshes every 3 seconds via Streamlit's `@st.fragment`.

---

## Demo Workflow (Hackathon Presentation)

1. Start all three components above.
2. Open the Victim App (`http://localhost:8000`) and the Dashboard (`http://localhost:8501`) side by side.
3. **Teammate / Attacker** activates Requestly rules in their browser to simulate attacks:

   | Attack | Requestly Action |
   |--------|-----------------|
   | Brute Force | Loop-fire `POST /login` with wrong passwords |
   | Recon | Rapid-fire `GET /admin`, `/config`, `/internal`, `/.env` |
   | Data Exfiltration | Loop-fire `GET /api/users`, `/export`, `/download` |

4. Watch the Dashboard detect each attack in real time, assign a risk level and confidence score, and display the LLM-generated incident report.

---

## Developing Without a Full Stack (Mock Generator)

The `mock_generator.py` writes realistic attack traffic and pre-built alerts directly into `data/logs.sqlite` so you can build and test the dashboard or agent independently.

```bash
# Continuous mode — fire attacks on a schedule (Ctrl-C to stop)
uv run python mock_generator.py

# Fire all 8 attack scenarios once then exit
uv run python mock_generator.py --once

# Wipe all data from the DB (use between judge demo runs)
uv run python mock_generator.py --reset
```

The "Reset Demo Data" button in the dashboard sidebar does the same thing as `--reset` at the click of a button.

---

## Configuration

### Agent thresholds (`agent/rules_engine.py → BASELINE`)

```python
BASELINE = {
    "max_failed_logins_per_min":    5,    # Brute Force trigger
    "max_restricted_hits_per_min":  3,    # Recon trigger
    "max_401_403_per_min":          6,    # Auth Scan trigger
    "max_distinct_users_per_min":   8,    # Credential Stuffing trigger
    "account_takeover_min_failures":3,    # Account Takeover: failures before success counts
    "max_data_requests_per_min":   20,    # Data Exfiltration trigger
    "path_traversal_min_attempts":  1,    # Path Traversal: any single hit fires
    "max_requests_per_min":       100,    # DoS Flood trigger
    "alert_cooldown_seconds":     300,    # suppress re-alerts for 5 min per (IP, threat)
}
```

### Agent polling interval (`agent/main.py`)

```python
POLL_INTERVAL_SECONDS   = 5   # how often to query the DB
MIN_CONFIDENCE_TO_ALERT = 40  # drop alerts below this threshold
```

### LLM model (`agent/llm_client.py`)

```python
MODEL_NAME = "llama3.1:8b"   # change to any model available in your Ollama instance
```

---

## Answering "How Can You Trust AI?"

This is a common judge question for AI-powered security tools. Our answer:

> **The AI makes zero security decisions.**
>
> Every detection, every confidence score, every mitigation recommendation is produced by the deterministic rule engine using explicit thresholds and verifiable SQL queries.
>
> The LLM's only job is to read those pre-calculated facts and format them into a readable paragraph for the dashboard — the same way a human analyst would write up a report after reviewing the logs.
>
> If Ollama goes offline, the agent continues detecting and alerting perfectly; it simply shows empty LLM fields in the UI.

---

## Dependencies

| Package | Purpose |
|---------|---------|
| `fastapi` | Victim web application |
| `uvicorn` | ASGI server for FastAPI |
| `streamlit` | SOC Watch View dashboard |
| `altair` | Timeline and attack-distribution charts |
| `pandas` | DataFrame queries for the dashboard |
| `requests` | HTTP calls from the agent to Ollama |
| `sqlite3` | Built-in — shared data layer |

---

## Team Roles

| Role | Owns | Files |
|------|------|-------|
| Backend | Victim App + Event Logging | `backend/` |
| Agent | Rule Engine + LLM Integration | `agent/` |
| Dashboard | SOC Watch View | `dashboard/` |

**Data layer contract:**
- `backend/` **writes** `logs` table only.
- `agent/` **reads** `logs`, **writes** `alerts`.
- `dashboard/` **reads** both — never writes.