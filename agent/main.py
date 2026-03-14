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
from concurrent.futures import ThreadPoolExecutor
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

# ---------------------------------------------------------------------------
# LLM thread pool
# ---------------------------------------------------------------------------
# The fundamental reason LLM output was never appearing was that all Ollama
# calls were made SYNCHRONOUSLY inside _run_agent_cycle().  With llama3.1:8b
# taking 20–40 s per call and 2 calls per attack type × 8 attack types, the
# detection loop was blocked for up to 10 minutes per cycle.  During that
# time, every log written by the mock generator or real backend went outside
# the 60-second rule window, so subsequent cycles detected nothing and Ollama
# was never called again.
#
# Fix: a single-worker ThreadPoolExecutor runs all LLM work in the background.
# The detection loop saves the alert to the DB immediately (empty LLM fields),
# dispatches a task to the pool, and returns to polling within milliseconds.
# The worker thread opens its own DB connection, calls Ollama, and does a
# targeted UPDATE on the alert row when the response arrives.
#
# max_workers=1 serialises Ollama calls so the GPU/CPU is never flooded.
_LLM_EXECUTOR = ThreadPoolExecutor(max_workers=1, thread_name_prefix="llm-worker")


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
            llm_report      TEXT,
            llm_cache_used  INTEGER  NOT NULL DEFAULT 0
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_alerts_ip_type "
        "ON alerts (source_ip, threat_type, timestamp);"
    )
    # Add llm_cache_used to any existing alerts table that predates this column.
    # ALTER TABLE is a no-op if the column already exists (caught and ignored).
    try:
        conn.execute(
            "ALTER TABLE alerts ADD COLUMN llm_cache_used INTEGER NOT NULL DEFAULT 0"
        )
    except Exception:
        pass  # column already exists — expected on all runs after the first
    conn.commit()


def _ensure_blocked_ips_table(conn: sqlite3.Connection) -> None:
    """
    Create the blocked_ips table if it doesn't already exist.

    This table is the shared contract for active IP blocking:
      - Agent WRITES a new row whenever a HIGH/CRITICAL threat is confirmed.
      - Backend middleware READS it on every request to decide whether to 403.
      - Dashboard READS and WRITES it (unblock button sets status='unblocked').

    status values:
      'blocked'   → backend middleware will reject requests from this IP.
      'unblocked' → analyst cleared the block; row kept for audit history.
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            id            INTEGER  PRIMARY KEY AUTOINCREMENT,
            ip            TEXT     NOT NULL,
            reason        TEXT,               -- e.g. "Brute Force Attack (confidence: 91%)"
            risk_level    TEXT,               -- 'HIGH' or 'CRITICAL'
            blocked_at    TEXT     NOT NULL,  -- UTC ISO datetime
            status        TEXT     NOT NULL DEFAULT 'blocked',
            unblocked_at  TEXT                -- NULL while active; set when analyst unblocks
        );
        """
    )
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_blocked_ips_ip_status "
        "ON blocked_ips (ip, status);"
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
    Also persists llm_cache_used so the dashboard can show whether the
    response came from the in-memory cache or a live Ollama call.
    """
    conn.execute(
        """
        UPDATE alerts
        SET llm_hypothesis = ?,
            llm_report     = ?,
            llm_cache_used = ?
        WHERE id = ?
        """,
        (
            alert.llm_hypothesis,
            alert.llm_report,
            1 if alert.llm_cache_used else 0,
            row_id,
        ),
    )
    conn.commit()


def _block_ip(conn: sqlite3.Connection, alert: ThreatAlert) -> None:
    """
    Write the attacker's IP to the blocked_ips table when the confirmed
    threat is HIGH or CRITICAL risk.

    The backend middleware reads this table on every incoming request and
    returns HTTP 403 immediately if the IP has an active 'blocked' entry.

    Guards:
      - Only acts on HIGH / CRITICAL alerts (MEDIUM and LOW are not blocked
        automatically — they need human review first).
      - Skips if the IP already has an active 'blocked' row so a single
        attack that fires multiple rules doesn't create duplicate entries.
    """
    if alert.risk_level not in ("HIGH", "CRITICAL"):
        return

    # Check for an existing active block to avoid duplicate rows
    cur = conn.execute(
        "SELECT 1 FROM blocked_ips WHERE ip = ? AND status = 'blocked' LIMIT 1",
        (alert.source_ip,),
    )
    if cur.fetchone() is not None:
        _log(
            "info",
            f"  ↳ IP {alert.source_ip} already blocked — skipping duplicate entry.",
        )
        return

    conn.execute(
        """
        INSERT INTO blocked_ips (ip, reason, risk_level, blocked_at, status)
        VALUES (?, ?, ?, ?, 'blocked')
        """,
        (
            alert.source_ip,
            f"{alert.threat_type} (confidence: {alert.confidence}%)",
            alert.risk_level,
            alert.timestamp,
        ),
    )
    conn.commit()
    _log(
        "alert",
        f"  ↳ IP {alert.source_ip} BLOCKED → {alert.risk_level} | {alert.threat_type}",
    )


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

    1. Build a plain-English observation from the alert's details dict using
       the threat-type-specific _build_observation() helper.
    2. Generate a hypothesis — the LLM explains what the attacker is doing
       and why it is dangerous, informed by both the observation and the
       confirmed threat type.
    3. Generate an incident report — the LLM formats all evidence (observation,
       hypothesis, raw details, mitigation) into a polished SOC paragraph.
       The observation is now explicitly forwarded so each of the 8 attack
       categories produces a correctly-contextualised report.

    If Ollama is offline, placeholder strings are stored and the agent
    continues operating in rules-only mode — detection is unaffected.
    """
    observation = _build_observation(alert)

    # ── Step: Hypothesize ───────────────────────────────────────────────────
    # Cache key: (threat_type, source_ip, "hyp") — each unique (attack-type, IP)
    # pair gets its own targeted hypothesis, so multiple different threat types
    # firing from the same IP in the same cycle each get the correct response.
    hyp_text, hyp_cached = generate_hypothesis(
        observation,
        threat_type=alert.threat_type,
        source_ip=alert.source_ip,
    )
    alert.llm_hypothesis = hyp_text
    if hyp_cached:
        _log(
            "info",
            f"  ↳ [CACHE HIT] Hypothesis ({alert.threat_type} / {alert.source_ip}) "
            f"served from cache — Ollama call skipped",
        )
    else:
        _log(
            "info",
            f"  ↳ [LIVE CALL] Ollama generated hypothesis  »  {alert.threat_type} "
            f"from {alert.source_ip}",
        )

    # ── Step: Explain ────────────────────────────────────────────────────────
    # The observation string is forwarded alongside the raw details dict so
    # the LLM has a clear narrative starting point specific to this attack type.
    mitigation = get_mitigation(alert.threat_type)
    rep_text, rep_cached = generate_incident_report(
        threat_type=alert.threat_type,
        source_ip=alert.source_ip,
        details=alert.details,
        mitigation=mitigation,
        hypothesis=alert.llm_hypothesis,
        observation=observation,
    )
    alert.llm_report = rep_text
    if rep_cached:
        _log(
            "info",
            f"  ↳ [CACHE HIT] Incident report ({alert.threat_type} / {alert.source_ip}) "
            f"served from cache — Ollama call skipped",
        )
    else:
        _log(
            "info",
            f"  ↳ [LIVE CALL] Ollama generated incident report  »  {alert.threat_type}",
        )

    # Mark the alert so the dashboard can display the live-vs-cached badge.
    # True when EITHER the hypothesis OR the report came from the cache.
    alert.llm_cache_used = hyp_cached or rep_cached

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


def _llm_worker(alert: ThreatAlert, row_id: int) -> None:
    """
    Background thread task — called by _LLM_EXECUTOR after detection.

    Opens its own DB connection (required: SQLite connections are not
    thread-safe across threads), calls Ollama for hypothesis + report,
    then does a targeted UPDATE on the alert row.

    If Ollama is offline or times out the error string is stored as-is
    so the dashboard always shows something (never silently empty).
    """
    try:
        enriched = _enrich_with_llm(alert)
        # Each worker thread needs its own connection — never share across threads
        conn = _get_connection()
        try:
            _update_alert_llm(conn, row_id, enriched)
        finally:
            conn.close()
        _log(
            "ok",
            f"[LLM] id={row_id} | {enriched.threat_type} | {enriched.source_ip}"
            f"{'  [CACHED]' if enriched.llm_cache_used else '  [LIVE]'}",
        )
    except Exception as exc:
        _log("error", f"[LLM] Worker failed for alert id={row_id}: {exc}")
        import traceback

        traceback.print_exc()


def _run_agent_cycle() -> list:
    """
    One full Observe → Investigate → Decide cycle.

    IMPORTANT — why this function must return in milliseconds
    ---------------------------------------------------------
    Previously, Ollama calls were made SYNCHRONOUSLY here.  With
    llama3.1:8b taking 20–40 s per call and 2 calls per alert × up to
    8 alerts per cycle, the loop could be blocked for 10+ minutes.
    During that time every log written by the mock or real backend went
    outside the 60-second rule window, so subsequent cycles detected
    nothing and the LLM was effectively never called again.

    Fix: detection + DB save happen here (fast, <1 s).  LLM work is
    dispatched to _LLM_EXECUTOR (a single-worker ThreadPoolExecutor)
    which runs _llm_worker in the background.  The worker opens its own
    DB connection, calls Ollama, and UPDATEs the row when done.  The
    dashboard auto-refreshes every 3 s so the LLM fields appear as soon
    as Ollama responds — typically 20–40 s after detection.
    """
    conn = _get_connection()
    try:
        # Ensure all agent-owned tables exist (both calls are idempotent)
        _ensure_alerts_table(conn)
        _ensure_blocked_ips_table(conn)

        # ── Step 1: Observe + Investigate ───────────────────────────────────
        candidates = run_all_rules(conn)

        # ── Step 2: Decide ───────────────────────────────────────────────────
        confirmed = [a for a in candidates if a.confidence >= MIN_CONFIDENCE_TO_ALERT]  # type: ignore[union-attr]

        if not confirmed:
            return []

        dispatched: List[ThreatAlert] = []
        for alert in confirmed:
            # ── Step 3: Persist detection immediately (LLM fields empty) ────
            # The dashboard shows the threat card the instant the rule fires.
            row_id = _save_alert_initial(conn, alert)
            _log(
                "alert",
                f"Detection saved → {alert.risk_level} | {alert.threat_type} | "
                f"IP: {alert.source_ip} | Confidence: {alert.confidence}%",
            )

            # ── Step 3b: Block IP immediately for HIGH / CRITICAL threats ────
            _block_ip(conn, alert)

            # ── Step 4: Dispatch LLM work to background thread ───────────────
            # _llm_worker opens its own connection, calls Ollama (hypothesis +
            # report), and UPDATEs the row.  This call returns immediately —
            # the detection loop is never blocked by Ollama response time.
            _LLM_EXECUTOR.submit(_llm_worker, alert, row_id)
            _log(
                "info",
                f"  ↳ LLM enrichment queued for id={row_id} "
                f"({alert.threat_type} / {alert.source_ip})",
            )

            dispatched.append(alert)

        return dispatched

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
                        # Banner is printed immediately after detection.
                        # LLM fields are empty here — they are filled in by the
                        # background worker and will appear on the dashboard
                        # automatically once Ollama responds (20–40 s later).
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
        _log("info", "Shutting down — waiting for queued LLM tasks to finish...")
        # cancel_futures=False: let any already-running Ollama call complete so
        # its alert row gets updated rather than staying with empty LLM fields.
        _LLM_EXECUTOR.shutdown(wait=True, cancel_futures=False)
        _log("info", "Agent stopped. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
