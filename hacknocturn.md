Below is the updated system workflow documentation, redesigned to fit the 18-hour hackathon constraint and address structural flaws. It incorporates the "Victim App" concept, clarifies the teammate-driven Requestly attack workflow, replaces the in-memory queue with persistent local storage, and introduces an LLM strictly for explainability to counter the "How can you trust AI?" question.

---

# AI-Driven Autonomous Cyber Threat Hunting Agent

## Updated System Workflow Documentation

---

# 1. System Overview

This project builds a **Cyber Threat Hunting System** that simulates the reasoning workflow of a **Security Operations Center (SOC) analyst**.

To ensure reliability within an 18-hour hackathon while maintaining trust in the system's decisions, the architecture is split into two phases:
1. **Deterministic Detection:** A **rule-driven reasoning agent** that observes anomalous activity, forms hypotheses, and assigns confidence scores based on explicit logic.
2. **AI-Driven Explainability:** A fast LLM (e.g., Groq, Gemini) that reads the triggered rules and logs to generate a human-readable incident report. This directly answers the "How can you trust AI?" question: the AI isn't a black box making wild guesses; it is simply explaining deterministic, verifiable rules.

The system integrates three major components:

1. **Backend API (Victim App) + Requestly Attack Setup**
2. **Threat Hunting Agent (Rule Engine + LLM Reporter)**
3. **Interactive Read-Only Web Dashboard**

Together they form a near real-time monitoring and reporting pipeline.

---

# 2. High-Level Architecture

```text
Attacker (Teammate's Browser)
       │
       │ (network requests manipulated by Requestly)
       ▼
Victim Application (FastAPI)
(End-User App + Event Logging)
       │
       ▼
Local Log Database
(SQLite / JSON Log File)
       │
       ▼
Threat Hunting Agent
(Rule-Based Detection → LLM Incident Reporter)
       │
       ▼
Dashboard API / Polling Mechanism
       │
       ▼
Streamlit Web Dashboard (SOC Watch View)
```

---

# 3. Core System Components

The system consists of three primary subsystems.

---

# 3.1 Backend API & Victim Application

The backend serves a dual purpose: it hosts a simple "Victim Application" (e.g., a dummy login page or data portal) and acts as the **central event collection and logging system**.

### Responsibilities:
1. Serve the dummy Victim App endpoints.
2. Receive incoming traffic.
3. Generate structured security logs and persist them to a local file or database.

---

## 3.1.1 Purpose of Requestly (Attacker Setup)

During the demo, **one teammate acts as the Attacker**. Instead of writing complex scripts, they use the **Requestly browser extension** to manipulate their browser traffic directed at the Victim App.

This provides a highly visual, easy-to-explain attack simulation without relying on the judges to participate or building complex red-team infrastructure.

Examples of traffic manipulation:
• Modifying headers to bypass controls
• Looping requests to simulate brute force
• Altering payloads to simulate data exfiltration

---

## 3.1.2 Example Requestly Attack Scenarios

### Brute Force Simulation
The teammate configures Requestly to repeatedly duplicate and fire login requests:
```http
POST /login
```
Resulting backend logs (persisted to SQLite/JSON):
```csv
timestamp,event_type,user,ip,status
10:01,login_attempt,admin,192.168.1.4,fail
10:01,login_attempt,admin,192.168.1.4,fail
10:01,login_attempt,admin,192.168.1.4,fail
```

### Endpoint Reconnaissance
Requestly is configured to rewrite a single click into multiple requests:
```http
GET /admin
GET /config
GET /internal
```

---

## 3.1.3 Event Storage (The Data Layer)
To ensure the separate processes (FastAPI backend, Agent, and Streamlit) can communicate seamlessly without complex inter-process management, events are stored persistently.

Every request is written to a local SQLite database (`logs.db`) or a master JSON file (`events.json`). The Threat Agent and Dashboard will continuously poll this file.

---

# 3.2 Threat Hunting Agent (Built by [Your Role])

The Threat Hunting Agent simulates how a human SOC analyst investigates suspicious activity. 

It operates in a reasoning loop:
```text
Observe (Rules) → Hypothesize (Ollama LLM) → Investigate (Rules) → Decide (Rules) → Explain (LLM Formatter)
```

---

## 3.2.1 Agent Initialization
When the system starts, it loads a baseline configuration and a set of deterministic rules.

```python
BASELINE = {
    "max_login_attempts_per_min": 5,
    "max_restricted_access_per_min": 3,
    "trusted_ips": ["10.0.0.1"]
}
```

---

## 3.2.2 Observation & Hypothesis Modules (Rule + LLM Enhanced) (Built by [Your Role])
The agent continuously polls the log database for suspicious behavioral signals.

**Step 1: Observation (Rule-Based)**
The agent uses hardcoded rules to spot anomalies.
**Example Rule: Brute Force**
```python
if failed_login_count > BASELINE["max_login_attempts_per_min"] AND same_ip:
    observation = "High volume of failed logins from single IP."
```

**Step 2: Hypothesize (Ollama Local LLM)**
Instead of just guessing, the agent passes the raw observation to the local Ollama LLM to generate a situational hypothesis. 

**Prompt to Ollama:**
_"Observation: 45 failed logins from IP 192.168.1.4 in 60 seconds targeting the 'admin' account. What is the most likely attack scenario?"_

**Ollama Hypothesis:**
_"This behavior strongly indicates a credential brute-force or dictionary attack targeting a privileged account."_

This adds a layer of dynamic, human-like reasoning to the strict rules, making the agent much smarter without risking data leaks to the cloud.

---

## 3.2.3 Investigation & Decision Modules
The agent correlates events to finalize the decision. 
If a hypothesis reaches a high confidence score, it is flagged as an active threat.

```text
Threat Type: Brute Force Attack
Risk Level: High
Triggered Rules: [rule_high_login_failure, rule_unknown_ip]
```

---

## 3.2.4 LLM-Powered Incident Reporting (Formatting Only) (Built by [Your Role])

To earn the "AI-driven" title while answering the question **"How can you trust AI?"**, the system uses an LLM (whether local like Ollama or cloud-based) strictly to make the final output look "prettier." 

Here is the exact boundary:
**Everything related to sensing, detecting, reasoning, and generating mitigation suggestions is done by our Agent WITHOUT any AI assistance.** The Agent uses hardcoded rules to figure out exactly what is happening and what to do about it. 

We only hand those pre-calculated findings and mitigations to the LLM to format them into a nice, human-readable paragraph for the dashboard.

**Example Process:**
1. **Agent Output (Deterministic):** Threat=Brute Force, IP=192.168.1.4, Action=Block IP & Reset Password.
2. **LLM Output (Formatting Only):** "The system detected a credential brute-force attack from 192.168.1.4. We suggest temporarily banning this IP at the firewall level and enforcing an immediate password reset."

**Why this works:** The judges can trust our system because the actual security decisions (Investigate & Decide) are based on hard math and rules. We use the local LLM to generate the Hypothesis, and a formatting LLM to build the final UI text. This demonstrates a hybrid AI approach: using LLMs where they excel (reasoning and language) while keeping the core detection safe and deterministic.

---

# 3.3 Dashboard (Streamlit Interface)

The dashboard provides a **read-only visual interface** representing the SOC Watch View. 
It does not trigger attacks (that is the teammate's job via Requestly). It simply polls the local log database (`st.rerun()` or auto-refresh) to display live data.

## 3.3.1 Dashboard Layout
```text
System Status Panel (Live Traffic Feed)
Threat Detection Output (Rule Engine Decisions)
AI Incident Report (LLM Generated Summaries)
Mitigation Recommendations
```

## 3.3.2 Threat Visualization
When an attack is detected, the UI updates dynamically:

```text
[LIVE TRAFFIC]
10:01:22 - 401 Unauthorized - POST /login (192.168.1.4)
10:01:23 - 401 Unauthorized - POST /login (192.168.1.4)

[DETECTION ENGINE (DETERMINISTIC)]
Threat: Brute Force
Confidence: 85%
Triggered: rule_high_login_failure

[AI SOC ANALYST REPORT]
The system detected a credential brute-force attack...
Mitigation: Block IP 192.168.1.4
```

---

# 4. Data Pipeline

```text
Teammate uses Requestly
       ↓
Backend API (Victim App)
       ↓
Local Log DB (SQLite/JSON)
       ↓
Threat Agent (Rule Eval)
       ↓
LLM API (Incident Summary Writer)
       ↓
Streamlit Dashboard (Auto-refresh loop)
```

---

# 5. Environment Setup

Required dependencies:
```text
Python 3.10+
pandas
fastapi
uvicorn
streamlit
sqlite3 (built-in) or json (built-in)
groq / openai / google-generativeai (for LLM API)
```

---

# 6. System Execution

Start the Victim App & Logger:
```bash
uvicorn backend.api:app --reload
```

Start the Streamlit SOC Dashboard:
```bash
streamlit run dashboard/app.py
```

Demo Workflow:
1. Open Victim App (e.g., `http://localhost:8000`)
2. Open Dashboard (`http://localhost:8501`)
3. **Teammate turns on Requestly rules in their browser**
4. Watch the Dashboard catch the logs, evaluate the rules, and generate the AI report in real-time.

---

# 7. Project Summary

This system demonstrates a reliable, verifiable **AI-assisted cyber threat hunting agent** capable of:
• Collecting logs from targeted applications via Requestly-simulated attacks.
• Using our own deterministic rule agent to handle 100% of the detection, reasoning, and mitigation logic **(Built by [Your Role])**.
• Leveraging a local or cloud LLM for hypothesis generation and formatting to translate our agent's raw rule outputs into pretty, human-readable SOC incident reports **(Integrated by [Your Role])**.
• Visualizing the entire attack chain and defense reasoning in a near real-time Streamlit dashboard.

The architecture is explicitly designed to be built in 18 hours by decoupling the App, the Agent, and the UI, allowing maximum parallel development.
