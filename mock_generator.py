"""
mock_generator.py  (project root)
----------------------------------
Simulates all 8 attack scenarios by writing realistic attack LOGS to
data/logs.sqlite so the real agent can detect them, call Ollama, and write
alerts with genuine LLM output.

WHY write_alert() is NOT called from the simulate functions
------------------------------------------------------------
Earlier versions called write_alert() inside every simulate_* function,
which wrote rows directly into the alerts table with hardcoded placeholder
LLM strings.  This caused two compounding bugs:

  1. The agent's _already_alerted() Tier-3 cooldown (300 s) reads the alerts
     table.  The mock-written alerts made _already_alerted() return True for
     every attack type → the agent skipped detection entirely → Ollama was
     never called → real LLM output never appeared on the dashboard.

  2. The hardcoded placeholder text was displayed instead of actual Ollama
     hypothesis / incident reports, making the LLM integration appear broken.

The correct separation of concerns:
  mock_generator.py → writes attack LOGS only  (data layer: logs table)
  agent/main.py     → detects those logs, calls Ollama, writes ALERTS
  dashboard/app.py  → reads logs + alerts, renders everything

The write_alert() helper is kept at the bottom of this file for standalone
testing use cases (e.g. dashboard layout checks without the agent running),
but it is never called automatically by the simulate functions.

status semantics (must match backend/api.py post last-commit)
--------------------------------------------------------------
  "success"  → HTTP 200, request succeeded
  "fail"     → HTTP 401, login credential failure
  "blocked"  → HTTP 403, IP is on the blocked_ips list (middleware fired)
  "denied"   → HTTP 403/404, restricted endpoint hit by a non-blocked IP

Scenarios simulated
  1. Brute Force Attack          – >5 failed logins, same IP, same account
  2. Endpoint Reconnaissance     – probing 3+ restricted paths
  3. Unauthorized Access Scan    – flood of 401/403 across any endpoint
  4. Credential Stuffing         – >8 distinct usernames failing, same IP
  5. Account Takeover            – failures then a successful login
  6. Data Exfiltration           – >20 successful GETs to data endpoints
  7. Path Traversal Attack       – ../ and URL-encoded variants in endpoint
  8. DoS Rate Flood              – >100 total requests in 60 seconds

Usage:
    python mock_generator.py            # continuous loop (Ctrl-C to stop)
    python mock_generator.py --once     # fire one round of every attack then exit
    python mock_generator.py --reset    # wipe DB and exit
"""

import argparse
import json
import os
import random
import sqlite3
import sys
import time
from datetime import datetime, timezone

# ── Shared DB path ─────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "data", "logs.sqlite")
SCHEMA_PATH = os.path.join(BASE_DIR, "data", "schema.sql")


# ── Schema / DB init ───────────────────────────────────────────────────────────


def init_db(reset: bool = False) -> None:
    """
    Initialise the database from data/schema.sql.
    If reset=True, wipe all rows from logs and alerts first.
    """
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    if os.path.exists(SCHEMA_PATH):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            schema_sql = f.read()
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(schema_sql)
        conn.commit()
        conn.close()
        print(f"[db] Schema applied from {SCHEMA_PATH}")
    else:
        # Fallback: create minimal tables without the schema file
        conn = sqlite3.connect(DB_PATH)
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id          INTEGER  PRIMARY KEY AUTOINCREMENT,
                timestamp   DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
                event_type  TEXT     NOT NULL,
                method      TEXT,
                endpoint    TEXT,
                username    TEXT,
                ip          TEXT     NOT NULL,
                status_code INTEGER,
                status      TEXT
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER  PRIMARY KEY AUTOINCREMENT,
                timestamp       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%d %H:%M:%S','now')),
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
        conn.commit()
        conn.close()
        print("[db] Fallback schema applied (schema.sql not found).")

    if reset:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM logs")
        conn.execute("DELETE FROM alerts")
        try:
            conn.execute("DELETE FROM blocked_ips")
        except Exception:
            pass  # table may not exist yet
        conn.commit()
        conn.close()
        print("[db] All rows cleared (reset requested).")


# ── Low-level write helpers ────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def write_log(
    event_type: str,
    method: str,
    endpoint: str,
    ip: str,
    status_code: int,
    status: str,
    username: str | None = None,
) -> None:
    """Insert a single row into the logs table."""
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO logs
            (timestamp, event_type, method, endpoint, username, ip, status_code, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (_now(), event_type, method, endpoint, username, ip, status_code, status),
    )
    conn.commit()
    conn.close()


# ── Normal (benign) traffic ───────────────────────────────────────────────────

_NORMAL_USERS = ["alice", "bob", "carol", "dave", "eve", "frank"]
_NORMAL_ENDPOINTS = ["/", "/profile", "/dashboard", "/api/data", "/login"]
_NORMAL_IPS = ["10.0.0.1", "10.0.0.2", "10.0.0.5", "172.16.0.8", "192.168.0.50"]


def simulate_normal_traffic(n: int = 3) -> None:
    for _ in range(n):
        method = random.choice(["GET", "POST"])
        endpoint = random.choice(_NORMAL_ENDPOINTS)
        ip = random.choice(_NORMAL_IPS)
        user = random.choice(_NORMAL_USERS)
        outcome = random.choices(["success", "fail"], weights=[90, 10])[0]
        code = 200 if outcome == "success" else 401
        event_type = "login_attempt" if endpoint == "/login" else "page_access"
        write_log(
            event_type=event_type,
            method=method,
            endpoint=endpoint,
            ip=ip,
            status_code=code,
            status=outcome,
            username=user if endpoint == "/login" else None,
        )


# ── Attack simulators ─────────────────────────────────────────────────────────
# Each function writes ONLY to the logs table.
# The agent reads these logs, applies the 8 detection rules, calls Ollama,
# and writes the resulting alerts (with real LLM output) to the alerts table.
# ─────────────────────────────────────────────────────────────────────────────


def simulate_brute_force(attacker_ip: str = "192.168.1.4") -> None:
    """
    Rule 1: Brute Force Attack
    Fire > max_failed_logins_per_min (5) failed logins against 'admin' from one IP.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Brute Force          -> {attacker_ip}")
    count = random.randint(12, 20)
    for _ in range(count):
        write_log(
            event_type="login_attempt",
            method="POST",
            endpoint="/login",
            ip=attacker_ip,
            status_code=401,
            status="fail",
            username="admin",
        )
        time.sleep(0.05)


def simulate_recon(attacker_ip: str = "10.5.0.22") -> None:
    """
    Rule 2: Endpoint Reconnaissance
    Probe > max_restricted_hits_per_min (3) restricted paths.

    status="denied": non-blocked IP hitting a restricted endpoint returns 403.
    This matches backend/api.py semantics (status="denied" for restricted paths,
    status="blocked" only when the blocked_ips middleware fires).
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Endpoint Recon       -> {attacker_ip}")
    restricted = [
        "/admin",
        "/config",
        "/internal",
        "/.env",
        "/api/keys",
        "/settings",
        "/env",
    ]
    paths_hit = random.sample(restricted, k=random.randint(4, len(restricted)))
    for ep in paths_hit:
        write_log(
            event_type="page_access",
            method="GET",
            endpoint=ep,
            ip=attacker_ip,
            status_code=403,
            status="denied",  # restricted endpoint hit by a non-blocked IP
        )
        time.sleep(0.1)


def simulate_auth_scan(attacker_ip: str = "172.16.5.99") -> None:
    """
    Rule 3: Unauthorized Access Scan
    Fire > max_401_403_per_min (6) auth failures across various endpoints.

    status="denied" for 403 (restricted endpoint), status="fail" for 401
    (login credential failure).  Matches backend/api.py semantics.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Unauthorized Scan    -> {attacker_ip}")
    endpoints = [
        "/admin",
        "/api/users",
        "/config",
        "/login",
        "/internal",
        "/api/keys",
        "/dashboard",
        "/settings",
        "/backup",
        "/export",
    ]
    count = random.randint(10, 18)
    for _ in range(count):
        ep = random.choice(endpoints)
        code = random.choice([401, 403])
        # 403 = restricted endpoint (denied), 401 = login failure (fail)
        status = "denied" if code == 403 else "fail"
        write_log(
            event_type="page_access",
            method=random.choice(["GET", "POST"]),
            endpoint=ep,
            ip=attacker_ip,
            status_code=code,
            status=status,
        )
        time.sleep(0.06)


def simulate_credential_stuffing(attacker_ip: str = "45.33.32.156") -> None:
    """
    Rule 4: Credential Stuffing
    Try > max_distinct_users_per_min (8) DISTINCT usernames from one IP.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Credential Stuffing  -> {attacker_ip}")
    usernames = [
        "john.doe",
        "jane.smith",
        "mike_jones",
        "sarah_k",
        "testuser",
        "admin2",
        "support",
        "helpdesk",
        "operator",
        "sysadmin",
        "webmaster",
        "deploy",
        "devops",
        "noreply",
    ]
    count = random.randint(10, len(usernames))
    targets = usernames[:count]
    for uname in targets:
        write_log(
            event_type="login_attempt",
            method="POST",
            endpoint="/login",
            ip=attacker_ip,
            status_code=401,
            status="fail",
            username=uname,
        )
        time.sleep(0.04)


def simulate_account_takeover(attacker_ip: str = "198.51.100.14") -> None:
    """
    Rule 5: Account Takeover
    Several failures then a successful login from the same IP.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Account Takeover     -> {attacker_ip}")
    failure_count = random.randint(8, 15)
    for _ in range(failure_count):
        write_log(
            event_type="login_attempt",
            method="POST",
            endpoint="/login",
            ip=attacker_ip,
            status_code=401,
            status="fail",
            username="alice",
        )
        time.sleep(0.05)

    # The attacker "guesses" the correct password
    write_log(
        event_type="login_attempt",
        method="POST",
        endpoint="/login",
        ip=attacker_ip,
        status_code=200,
        status="success",
        username="alice",
    )


def simulate_data_exfiltration(attacker_ip: str = "203.0.113.9") -> None:
    """
    Rule 6: Data Exfiltration
    High volume of successful GETs to data-serving endpoints.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Data Exfiltration    -> {attacker_ip}")
    data_endpoints = [
        "/api/users",
        "/api/data",
        "/export",
        "/api/export",
        "/download",
        "/reports",
        "/backup",
        "/files",
        "/dump",
    ]
    count = random.randint(25, 40)
    for _ in range(count):
        ep = random.choice(data_endpoints)
        write_log(
            event_type="api_call",
            method="GET",
            endpoint=ep,
            ip=attacker_ip,
            status_code=200,
            status="success",
        )
        time.sleep(0.04)


def simulate_path_traversal(attacker_ip: str = "185.220.101.34") -> None:
    """
    Rule 7: Path Traversal Attack
    Requests containing ../ or URL-encoded equivalents.

    status="denied": these requests hit the catch-all handler (404) or a
    restricted path (403) — in both cases no blocked_ips entry exists yet,
    so the correct status is "denied" not "blocked".
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] Path Traversal       -> {attacker_ip}")
    traversal_payloads = [
        "/../../../etc/passwd",
        "/..%2f..%2f..%2fetc%2fshadow",
        "/%2e%2e%2f%2e%2e%2fwindows%2fsystem32",
        "/../config/.env",
        "/....//....//etc/passwd",
        "/%252e%252e%252fetc%252fpasswd",
        "/../admin/secrets.txt",
    ]
    attempts = random.randint(3, len(traversal_payloads))
    payloads_used = random.sample(traversal_payloads, k=attempts)
    for payload in payloads_used:
        write_log(
            event_type="page_access",
            method="GET",
            endpoint=payload,
            ip=attacker_ip,
            status_code=404,
            status="denied",  # catch-all 404 — not a blocked-IP hit
        )
        time.sleep(0.08)


def simulate_dos_flood(attacker_ip: str = "104.21.45.60") -> None:
    """
    Rule 8: DoS Rate Flood
    Extreme total request volume (> max_requests_per_min = 100).

    status="denied" for non-200 responses (restricted endpoint or 404).
    status="success" for 200 responses.
    Writes ONLY to logs — agent detects and generates the alert + LLM output.
    """
    print(f"  [MOCK] DoS Rate Flood       -> {attacker_ip}")
    all_endpoints = ["/", "/login", "/api/data", "/profile", "/admin", "/config"]
    count = random.randint(120, 160)
    for _ in range(count):
        ep = random.choice(all_endpoints)
        code = random.choice([200, 403, 404])
        # 200 = success, anything else = denied (restricted endpoint or not found)
        status = "success" if code == 200 else "denied"
        write_log(
            event_type="page_access",
            method="GET",
            endpoint=ep,
            ip=attacker_ip,
            status_code=code,
            status=status,
        )
        time.sleep(0.01)


# ── Scenario registry ──────────────────────────────────────────────────────────

# Each entry: (function, attacker_ip, cycle_period)
# cycle_period = "fire every N cycles in continuous mode"
_SCENARIOS = [
    (simulate_brute_force, "192.168.1.4", 8),
    (simulate_recon, "10.5.0.22", 11),
    (simulate_auth_scan, "172.16.5.99", 13),
    (simulate_credential_stuffing, "45.33.32.156", 17),
    (simulate_account_takeover, "198.51.100.14", 22),
    (simulate_data_exfiltration, "203.0.113.9", 27),
    (simulate_path_traversal, "185.220.101.34", 19),
    (simulate_dos_flood, "104.21.45.60", 31),
]


def run_all_attacks_once() -> None:
    """Fire every attack scenario exactly once (useful for quick testing)."""
    print("\n[mock] Running all 8 attack scenarios once...\n")
    for fn, ip, _ in _SCENARIOS:
        fn(ip)
        time.sleep(0.3)
    print("\n[mock] All scenarios complete.")
    print(
        "[mock] Start (or wait for) agent/main.py to detect these logs and call Ollama."
    )


# ── Standalone alert writer (kept for direct dashboard layout testing ONLY) ───
# Do NOT call this from the simulate functions — it bypasses the agent and
# poisons the cooldown table, preventing real LLM output from being generated.


def write_alert(
    threat_type: str,
    risk_level: str,
    confidence: int,
    source_ip: str,
    triggered_rules: list,
    details: dict,
    llm_hypothesis: str = "",
    llm_report: str = "",
) -> None:
    """
    Insert a single row directly into the alerts table.

    WARNING: Only use this for isolated dashboard layout tests where the agent
    is NOT running.  If the agent is running alongside, this call will make
    _already_alerted() return True for the matching (threat_type, source_ip)
    pair and suppress the agent's real detection for 300 seconds, meaning
    Ollama never gets called and no real LLM output is generated.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        """
        INSERT INTO alerts
            (timestamp, threat_type, risk_level, confidence, source_ip,
             triggered_rules, details, llm_hypothesis, llm_report)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            _now(),
            threat_type,
            risk_level,
            confidence,
            source_ip,
            json.dumps(triggered_rules),
            json.dumps(details),
            llm_hypothesis,
            llm_report,
        ),
    )
    conn.commit()
    conn.close()


# ── Main ───────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Cyber Threat Hunting Agent — Mock Data Generator"
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="Fire all 8 attack scenarios once then exit.",
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Wipe all data from the DB then exit.",
    )
    args = parser.parse_args()

    init_db(reset=args.reset)

    if args.reset:
        print("[mock] Database reset complete. Exiting.")
        sys.exit(0)

    if args.once:
        run_all_attacks_once()
        sys.exit(0)

    print(f"[mock] Continuous mode started -> writing to {DB_PATH}")
    print("[mock] Press Ctrl+C to stop.\n")

    cycle = 0
    try:
        while True:
            cycle += 1

            # Steady stream of background traffic every cycle
            simulate_normal_traffic(n=random.randint(2, 5))

            # Check each scenario's trigger period
            for fn, ip, period in _SCENARIOS:
                if cycle % period == 0:
                    fn(ip)

            if cycle % 10 == 0:
                print(f"[mock] Cycle {cycle} complete — {_now()}")

            time.sleep(2)

    except KeyboardInterrupt:
        print(f"\n[mock] Stopped at cycle {cycle}. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
