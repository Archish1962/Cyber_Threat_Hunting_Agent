# Project Structure Outline: Cyber Threat Hunting Agent

This specific folder structure separates concerns perfectly so all 3 team members can work simultaneously in their assigned domains without causing merge conflicts or breaking the code integration.

---

## The Directory Layout

```text
cyber-detection-agent/
│
├── backend/                   # ➔ Teammate 1 (Backend & Attack Simulation)
│   ├── api.py                 # FastAPI victim application endpoints (/login, /admin)
│   ├── logger.py              # Logic to intercept requests and write to the database
│   └── requirements.txt       # Dependencies: fastapi, uvicorn
│
├── agent/                     # ➔ You (Agent Builder & LLM Integration)
│   ├── main.py                # The core loop: Observe -> Hypothesize -> Investigate -> Decide -> Explain
│   ├── rules_engine.py        # The deterministic math rules (e.g., BRUTE_FORCE flags)
│   ├── llm_client.py          # The integration script for Ollama (or Groq/Gemini)
│   └── requirements.txt       # Dependencies: requests, pydantic
│
├── dashboard/                 # ➔ Teammate 3 (UI & Visualization)
│   ├── app.py                 # Streamlit UI script (the SOC Watch View)
│   ├── components.py          # Helper functions for UI cards or layout (optional)
│   └── requirements.txt       # Dependencies: streamlit, pandas
│
├── data/                      # ➔ Shared Data Layer (The Integration Point)
│   ├── logs.sqlite            # The persistent SQLite database (or logs.json)
│   └── schema.sql             # (Optional) Table structures for the logs
│
├── .gitignore                 # Files to ignore (e.g., standard python cache, virtual envs)
└── README.md                  # Project setup instructions for the judges
```

---

## 3 Rules for Collaborative Work:

1. **The `data/` folder is sacred:**
   *   **Teammate 1 (Backend)** is the *only* one who WRITES to `data/logs.sqlite`.
   *   **You (Agent)** READ from `data/logs.sqlite` to find anomalies, and WRITE your final JSON output (Threat, Confidence, LLM Report) either back into a new `alerts` table in that database, or to a separate `data/alerts.json` file.
   *   **Teammate 3 (Dashboard)** *only* READS from the `data/` folder to put everything on the screen. 

2. **Virtual Environments:**
   *   Everyone should create their own Python Virtual Environment (`venv`) at the root of the project to isolate dependencies. If you haven't decided this yet, simply running `python -m venv venv` and `venv\Scripts\activate` will save you hours of dependency headaches on presentation day.

3. **Running the Flow during Development:**
   *   You each run your own component in separate terminal windows:
       *   **Terminal 1:** `cd backend && uvicorn api:app --reload`
       *   **Terminal 2:** `cd agent && python main.py`
       *   **Terminal 3:** `cd dashboard && streamlit run app.py`
