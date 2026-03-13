"""
main.py — Cyber Threat Hunting Agent Core Loop
================================================
This is the entry point for the agent. Run it with:
    python main.py

The agent executes a continuous reasoning loop modeled after how a real
SOC analyst thinks:

    Observe   → Poll the log database for raw event signals.
    Hypothesize → Ask the local Ollama LLM to name the likely attack scenario.
    Investigate → Run deterministic rules to measure severity and confidence.
    Decide    → If confidence is above threshold, promote it to a confirmed alert.
    Explain   → Ask the LLM to format the findings into a human-readable report.

The security decisions (Investigate + Decide) are 100% rule-based.
The LLM is used only in Hypothesize and Explain — it adds language, not logic.

Output:
  - Console: live status lines showing detections in real time.
  - data/logs.sqlite (alerts table): persisted alerts read by the dashboard.
"""

import sys

# ---------------------------------------------------------------------------
# Python version guard — must be checked before any other imports
# ---------------------------------------------------------------------------
if sys.version_info < (3, 9):
    print(
        f"\n[ERROR] Python 3.9+ is required. You are running {sys.version}.\n"
        "        Please upgrade Python or activate the correct virtual environment.\n"
        "        Tested on: Python 3.11 and Python 3.13\n"
    )
    sys.exit(1)

import json
import os
import sqlite3
import time
from datetime import datetime
from typing import List

# ---------------------------------------------------------------------------
# Path setup — allow running from the repo root OR from agent/
# ---------------------------------------------------------------------------
_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT_DIR = os.path.dirname(_THIS_DIR)

# The shared SQLite database written by the backend, read/written by us.
DB_PATH = os.path.join(_ROOT_DIR, "data", "logs.sqlite")

# Schema file — used to initialise the alerts table if it doesn't exist yet.
SCHEMA_PATH = os.path.join(_ROOT_DIR, "data", "schema.sql")

# ---------------------------------------------------------------------------
# Import our own modules (rules engine + LLM client)
# ---------------------------------------------------------------------------
sys.path.insert(0, _THIS_DIR)  # make sure local imports work regardless of cwd

from llm_client import (  # noqa: E402
    check_ollama_health,
    generate_hypothesis,
    generate_incident_report,
)
from rules_engine import ThreatAlert, get_mitigation, run_all_rules  # noqa: E402

# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------
POLL_INTERVAL_SECONDS = 5  # how often to query the DB for new threats
MIN_CONFIDENCE_TO_ALERT = 40  # alerts below this confidence are silently dropped
STARTUP_WAIT_SECONDS = 2  # brief pause between startup checks


# ─────────────────────────────────────────────────────────────────────────────
# Database helpers
# ─────────────────────────────────────────────────────────────────────────────


def _get_connection() -> sqlite3.Connection:
    """
    Open (and return) a SQLite connection with a 5-second busy-timeout so the
    agent doesn't crash if the backend is writing at the same instant.
    """
    conn = sqlite3.connect(DB_PATH, timeout=5)
    conn.row_factory = sqlite3.Row
    # Enable WAL mode for safe concurrent reads while the backend writes.
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn


def _ensure_alerts_table(conn: sqlite3.Connection) -> None:
    """
    Create the alerts table if it doesn't already exist.
    We only create alerts — the logs table is the backend's responsibility.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id              INTEGER  PRIMARY KEY AUTOINCREMENT,
            timestamp       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S', 'now')),
            threat_type     TEXT     NOT NULL,
            risk_level      TEXT     NOT NULL,
            confidence      INTEGER  NOT NULL,
            source_ip       TEXT     NOT NULL,
            triggered_rules TEXT,
            details         TEXT,
            llm_hypothesis  TEXT,
            llm_report      TEXT
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_ip_type "
        "ON alerts (source_ip, threat_type, timestamp);"
    )
    conn.commit()


def _save_alert_initial(conn: sqlite3.Connection, alert: ThreatAlert) -> int:  # noqa: E501
    """
    Phase 1 — Insert the detection result immediately with empty LLM fields.

    This lets the dashboard show the threat (type, risk level, confidence,
    triggered rules) the instant the rules engine fires — without waiting
    20-40 s for llama3.1:8b to finish generating text.

    Returns the SQLite row ID so Phase 2 can UPDATE the same row.
    """
    cursor = conn.execute(
        """
        INSERT INTO alerts
            (timestamp, threat_type, risk_level, confidence, source_ip,
             triggered_rules, details, llm_hypothesis, llm_report)
        VALUES (?, ?, ?, ?, ?, ?, ?, '', '')
        """,
        (
            alert.timestamp,
            alert.threat_type,
            alert.risk_level,
            alert.confidence,
            alert.source_ip,
            json.dumps(alert.triggered_rules),
            json.dumps(alert.details),
        ),
    )
    conn.commit()
    # lastrowid is None only when no row was inserted (INSERT OR IGNORE skipped
    # the row). That cannot happen here — we always INSERT. The fallback to 0
    # satisfies the type-checker without changing runtime behaviour.
    return cursor.lastrowid if cursor.lastrowid is not None else 0


def _update_alert_llm(
    conn: sqlite3.Connection, row_id: int, alert: ThreatAlert
) -> None:
    """
    Phase 2 — Fill in the LLM fields once Ollama has finished responding.

    Called after _enrich_with_llm() returns.  Updates the row that was
    already written by _save_alert_initial(), so the dashboard record
    goes from empty LLM fields → populated LLM fields in-place.
    """
    conn.execute(
        """
        UPDATE alerts
        SET llm_hypothesis = ?,
            llm_report     = ?
        WHERE id = ?
        """,
        (alert.llm_hypothesis, alert.llm_report, row_id),
    )
    conn.commit()


# ─────────────────────────────────────────────────────────────────────────────
# LLM enrichment
# ─────────────────────────────────────────────────────────────────────────────


def _build_observation(alert: ThreatAlert) -> str:
    """
    Construct a plain-English observation sentence from a ThreatAlert.
    This becomes the prompt for the Hypothesize step.
    """
    d = alert.details
    if alert.threat_type == "Brute Force Attack":
        return (
            f"{d.get('failed_attempts', '?')} failed login attempts from IP {alert.source_ip} "
            f"in {d.get('window_seconds', 60)} seconds "
            f"targeting account(s): {d.get('targeted_accounts', 'unknown')}."
        )
    if alert.threat_type == "Endpoint Reconnaissance":
        return (
            f"IP {alert.source_ip} hit {d.get('unique_paths', '?')} restricted endpoints "
            f"({d.get('paths_hit', 'various')}) "
            f"{d.get('total_hits', '?')} times in {d.get('window_seconds', 60)} seconds."
        )
    if alert.threat_type == "Unauthorized Access Scan":
        return (
            f"IP {alert.source_ip} received {d.get('auth_failures', '?')} "
            f"HTTP {d.get('status_codes', '401/403')} responses in "
            f"{d.get('window_seconds', 60)} seconds across endpoints: "
            f"{d.get('endpoints_hit', 'various')}."
        )
    if alert.threat_type == "Credential Stuffing":
        return (
            f"IP {alert.source_ip} attempted logins against "
            f"{d.get('distinct_usernames_tried', '?')} different user accounts "
            f"({d.get('total_attempts', '?')} total attempts) in "
            f"{d.get('window_seconds', 60)} seconds — "
            f"sample accounts targeted: {d.get('sample_usernames', 'unknown')}."
        )
    if alert.threat_type == "Account Takeover":
        return (
            f"IP {alert.source_ip} had {d.get('failures_before_success', '?')} "
            f"failed login attempts followed by a SUCCESSFUL login to account "
            f"'{d.get('compromised_account', 'unknown')}' "
            f"within a {d.get('window_seconds', 300)} second window."
        )
    if alert.threat_type == "Data Exfiltration":
        return (
            f"IP {alert.source_ip} made {d.get('total_requests', '?')} successful "
            f"GET requests to {d.get('unique_endpoints', '?')} data-serving endpoints "
            f"({d.get('endpoints_hit', 'various')}) "
            f"in {d.get('window_seconds', 60)} seconds."
        )
    if alert.threat_type == "Path Traversal Attack":
        return (
            f"IP {alert.source_ip} sent {d.get('attempts', '?')} request(s) containing "
            f"directory traversal sequences (../ or URL-encoded variants) "
            f"in the URL path: {d.get('endpoints_used', 'unknown')}."
        )
    if alert.threat_type == "DoS Rate Flood":
        return (
            f"IP {alert.source_ip} sent {d.get('total_requests', '?')} total requests "
            f"across {d.get('unique_endpoints', '?')} endpoints "
            f"in {d.get('window_seconds', 60)} seconds — "
            f"far exceeding the threshold of {d.get('threshold', '?')} requests/min."
        )
    # Generic fallback
    return (
        f"Suspicious activity detected from IP {alert.source_ip}. "
        f"Threat type: {alert.threat_type}. Details: {json.dumps(d)}."
    )


def _enrich_with_llm(alert: ThreatAlert) -> ThreatAlert:
    """
    Hypothesize + Explain steps.

    1. Generate a hypothesis (what kind of attack is this?).
    2. Generate an incident report (formatted summary for the dashboard).

    If Ollama is offline, placeholders are used and the agent continues normally.
    """
    observation = _build_observation(alert)

    # ── Step: Hypothesize ───────────────────────────────────────────────────
    _log(
        "info",
        f"  ↳ Hypothesizing via LLM for {alert.threat_type} from {alert.source_ip}...",
    )
    alert.llm_hypothesis = generate_hypothesis(observation)

    # ── Step: Explain ────────────────────────────────────────────────────────
    _log("info", "  ↳ Generating incident report...")
    mitigation = get_mitigation(alert.threat_type)
    alert.llm_report = generate_incident_report(
        threat_type=alert.threat_type,
        source_ip=alert.source_ip,
        details=alert.details,
        mitigation=mitigation,
        hypothesis=alert.llm_hypothesis,
    )

    return alert


# ─────────────────────────────────────────────────────────────────────────────
# Console output helpers
# ─────────────────────────────────────────────────────────────────────────────

# ANSI colour codes — safe on most terminals; fall back to plain text on Windows
# cmd prompt if colours break, but Windows Terminal / VSCode handles them fine.
_COLOURS = {
    "CRITICAL": "\033[91m",  # bright red
    "HIGH": "\033[33m",  # yellow
    "MEDIUM": "\033[36m",  # cyan
    "LOW": "\033[37m",  # white
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
}


def _log(level: str, message: str) -> None:
    """
    Print a timestamped, coloured log line to stdout.
    level: "info" | "warn" | "alert" | "error"
    """
    now = datetime.now().strftime("%H:%M:%S")
    prefix = {
        "info": f"[{now}] [INFO ]",
        "warn": f"[{now}] [WARN ]",
        "alert": f"[{now}] [ALERT]",
        "error": f"[{now}] [ERROR]",
        "ok": f"[{now}] [  OK ]",
    }.get(level, f"[{now}] [LOG  ]")

    colour = {
        "warn": "\033[33m",
        "alert": "\033[91m",
        "error": "\033[31m",
        "ok": "\033[32m",
    }.get(level, "")
    reset = _COLOURS["reset"]
    print(f"{colour}{prefix} {message}{reset}", flush=True)


def _print_alert_banner(alert: ThreatAlert) -> None:
    """Print a visible banner block for a confirmed threat."""
    c = _COLOURS.get(alert.risk_level, "")
    r = _COLOURS["reset"]
    b = _COLOURS["bold"]
    d = _COLOURS["dim"]
    sep = "─" * 60

    print(f"\n{c}{b}{sep}{r}")
    print(f"{c}{b}  ⚠  THREAT DETECTED{r}")
    print(f"{c}{sep}{r}")
    print(f"  Threat Type   : {b}{alert.threat_type}{r}")
    print(f"  Risk Level    : {c}{b}{alert.risk_level}{r}")
    print(f"  Confidence    : {alert.confidence}%")
    print(f"  Source IP     : {alert.source_ip}")
    print(f"  Rules Fired   : {', '.join(alert.triggered_rules)}")
    print(f"  Evidence      : {json.dumps(alert.details)}")
    if alert.llm_hypothesis:
        print(f"\n  {b}AI Hypothesis :{r}")
        print(f"  {d}{alert.llm_hypothesis}{r}")
    if alert.llm_report:
        print(f"\n  {b}Incident Report:{r}")
        print(f"  {d}{alert.llm_report}{r}")
    print(f"  Mitigation    : {get_mitigation(alert.threat_type)}")
    print(f"{c}{sep}{r}\n")


# ─────────────────────────────────────────────────────────────────────────────
# Startup checks
# ─────────────────────────────────────────────────────────────────────────────


def _startup_checks() -> bool:
    """
    Validate the environment before entering the main loop.
    Returns True if safe to proceed, False if a fatal condition is found.
    """
    print()
    print("=" * 60)
    print("  Cyber Threat Hunting Agent — Starting Up")
    print("=" * 60)

    all_ok = True

    # 1. Check that the data directory exists
    data_dir = os.path.join(_ROOT_DIR, "data")
    if not os.path.isdir(data_dir):
        _log("warn", f"data/ directory not found at {data_dir}. Creating it...")
        os.makedirs(data_dir, exist_ok=True)

    # 2. Check Ollama health
    health = check_ollama_health()
    if health["status"] == "ok":
        _log("ok", health["message"])
    elif health["status"] == "warning":
        _log("warn", health["message"])
        _log("warn", "Agent will run but LLM output will be unavailable.")
    else:
        _log("error", health["message"])
        _log("warn", "Agent will continue in RULES-ONLY mode (no LLM output).")
        all_ok = False  # non-fatal — agent still works; False signals LLM is down

    # 3. Check for the database (wait up to 30 s for backend to create it)
    if not os.path.exists(DB_PATH):
        _log("warn", f"Database not found at {DB_PATH}.")
        _log(
            "warn",
            "Waiting for backend to create it (start backend/api.py if not running).",
        )
        for i in range(6):  # wait up to 30 seconds
            time.sleep(STARTUP_WAIT_SECONDS)
            if os.path.exists(DB_PATH):
                _log("ok", "Database found!")
                break
            _log("info", f"  Still waiting... ({(i + 1) * STARTUP_WAIT_SECONDS}s)")
        else:
            _log(
                "warn", "Database still not found. Will keep retrying in the main loop."
            )

    print()
    # Return all_ok so callers know whether the LLM is available.
    # The main loop always runs regardless — the DB handler is self-healing.
    return all_ok


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────


def _run_agent_cycle() -> list:
    """
    One full Observe → Investigate → Decide cycle.
    Opens and closes the DB connection each cycle to prevent stale reads.
    Returns the list of confirmed, LLM-enriched alerts written this cycle.
    """
    conn = _get_connection()
    try:
        # Ensure the alerts table exists (idempotent)
        _ensure_alerts_table(conn)

        # ── Step 1: Observe + Investigate ───────────────────────────────────
        # run_all_rules queries the logs table and applies every rule.
        # run_all_rules returns List[ThreatAlert].  We avoid re-annotating with
        # the imported ThreatAlert here to prevent Pyright flagging an
        # invariant-list mismatch when sys.path causes two copies of
        # rules_engine to be registered under different module names.
        candidates = run_all_rules(conn)

        # ── Step 2: Decide ───────────────────────────────────────────────────
        # Filter out low-confidence candidates that don't meet our threshold.
        confirmed = [a for a in candidates if a.confidence >= MIN_CONFIDENCE_TO_ALERT]  # type: ignore[union-attr]

        if not confirmed:
            return []

        saved: List[ThreatAlert] = []
        for alert in confirmed:
            # ── Step 3: Persist detection immediately (LLM fields empty) ────
            # Dashboard can display the threat the instant rules fire.
            # llama3.1:8b takes 20-40 s per call — we never block the UI on it.
            row_id = _save_alert_initial(conn, alert)
            _log(
                "alert",
                f"Detection saved → {alert.risk_level} | {alert.threat_type} | "
                f"IP: {alert.source_ip} | Confidence: {alert.confidence}%",
            )

            # ── Step 4: Hypothesize + Explain (LLM) ─────────────────────────
            # Runs AFTER the DB write so the dashboard is never blocked.
            alert = _enrich_with_llm(alert)

            # ── Step 5: Update the same row with LLM output ──────────────────
            _update_alert_llm(conn, row_id, alert)
            _log("info", f"  ↳ LLM report written for alert id={row_id}")

            saved.append(alert)

        return saved

    finally:
        conn.close()


def main() -> None:  # noqa: C901
    """
    Entry point. Runs startup checks then enters the infinite polling loop.
    Press Ctrl+C to stop gracefully.
    """
    _startup_checks()

    _log(
        "info",
        f"Polling every {POLL_INTERVAL_SECONDS}s  |  Min confidence: {MIN_CONFIDENCE_TO_ALERT}%",
    )
    _log("info", f"Database path: {DB_PATH}")
    _log("info", "Press Ctrl+C to stop.\n")

    cycle = 0
    try:
        while True:
            cycle += 1
            try:
                if not os.path.exists(DB_PATH):
                    _log(
                        "warn",
                        f"Database missing at {DB_PATH} — waiting for backend...",
                    )
                    time.sleep(POLL_INTERVAL_SECONDS)
                    continue

                alerts = _run_agent_cycle()

                if alerts:
                    for alert in alerts:
                        _print_alert_banner(alert)
                else:
                    # Quiet heartbeat every 12 cycles (~60s) to show the agent is alive
                    if cycle % 12 == 0:
                        _log("info", "No new threats detected. Agent is watching...")

            except sqlite3.OperationalError as e:
                # DB might be locked for a split second while backend is writing
                _log("warn", f"DB temporarily unavailable ({e}). Retrying...")
            except Exception as e:
                _log("error", f"Unexpected error in agent cycle: {e}")
                import traceback

                traceback.print_exc()

            time.sleep(POLL_INTERVAL_SECONDS)

    except KeyboardInterrupt:
        print()
        _log("info", "Agent stopped by user (Ctrl+C). Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
