"""
mock_generator.py  (project root)
----------------------------------
Simulates all 8 attack scenarios against the REAL logs/alerts schema
(data/schema.sql).  Use this to develop and test the dashboard or agent
without needing the full backend + agent stack running.

Scenarios simulated
  1. Brute Force Attack          – >5 failed logins, same IP, same account
  2. Endpoint Reconnaissance     – probing 3+ restricted paths
  3. Unauthorized Access Scan    – flood of 401/403 across any endpoint
  4. Credential Stuffing         – >8 distinct usernames failing, same IP
  5. Account Takeover            – failures then a successful login
  6. Data Exfiltration           – >20 successful GETs to data endpoints
  7. Path Traversal Attack        – ../ and URL-encoded variants in endpoint
  8. DoS Rate Flood              – >100 total requests in 60 seconds

Usage:
    python mock_generator.py            # continuous loop (Ctrl-C to stop)
    python mock_generator.py --once     # fire one round of every attack then exit
    python mock_generator.py --reset    # wipe DB and exit

The file writes ONLY to data/logs.sqlite using the canonical schema.
Delete or ignore this file before the final demo once teammates are live.
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
                llm_report      TEXT
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
    """Insert a single row into the alerts table."""
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


def simulate_brute_force(attacker_ip: str = "192.168.1.4") -> None:
    """
    Rule 1: Brute Force Attack
    Fire > max_failed_logins_per_min (5) failed logins against 'admin' from one IP.
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

    write_alert(
        threat_type="Brute Force Attack",
        risk_level="HIGH",
        confidence=90,
        source_ip=attacker_ip,
        triggered_rules=[
            "rule_high_login_failure",
            "rule_single_ip_brute",
            "rule_untrusted_ip",
        ],
        details={
            "failed_attempts": count,
            "window_seconds": 60,
            "threshold": 5,
            "targeted_accounts": "admin",
        },
        llm_hypothesis=(
            "This pattern strongly indicates a credential brute-force attack targeting "
            "a privileged administrative account using automated tooling."
        ),
        llm_report=(
            f"A brute-force credential attack was detected from IP {attacker_ip}. "
            f"The source made {count} consecutive failed login attempts against the 'admin' "
            "account within a 60-second window, far exceeding the threshold of 5 attempts/min. "
            "Recommended action: block IP at the firewall immediately and force a password reset."
        ),
    )


def simulate_recon(attacker_ip: str = "10.5.0.22") -> None:
    """
    Rule 2: Endpoint Reconnaissance
    Probe > max_restricted_hits_per_min (3) restricted paths.
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
            status="blocked",
        )
        time.sleep(0.1)

    write_alert(
        threat_type="Endpoint Reconnaissance",
        risk_level="HIGH",
        confidence=90,
        source_ip=attacker_ip,
        triggered_rules=[
            "rule_restricted_recon",
            "rule_multi_path_recon",
            "rule_untrusted_ip",
        ],
        details={
            "total_hits": len(paths_hit),
            "unique_paths": len(paths_hit),
            "paths_hit": ",".join(paths_hit),
            "window_seconds": 60,
            "threshold": 3,
        },
        llm_hypothesis=(
            "The systematic probing of multiple restricted endpoints suggests automated "
            "directory enumeration, likely the first reconnaissance phase of a targeted attack."
        ),
        llm_report=(
            f"Endpoint reconnaissance was detected from IP {attacker_ip}. "
            f"The source probed {len(paths_hit)} restricted paths "
            f"({', '.join(paths_hit[:3])}...) in rapid succession — "
            "consistent with automated directory scanning tools such as gobuster or dirb. "
            "Recommended: rate-limit this IP and review access controls on all admin paths."
        ),
    )


def simulate_auth_scan(attacker_ip: str = "172.16.5.99") -> None:
    """
    Rule 3: Unauthorized Access Scan
    Fire > max_401_403_per_min (6) auth failures across various endpoints.
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
        status = "blocked" if code == 403 else "fail"
        write_log(
            event_type="page_access",
            method=random.choice(["GET", "POST"]),
            endpoint=ep,
            ip=attacker_ip,
            status_code=code,
            status=status,
        )
        time.sleep(0.06)

    write_alert(
        threat_type="Unauthorized Access Scan",
        risk_level="MEDIUM",
        confidence=70,
        source_ip=attacker_ip,
        triggered_rules=["rule_auth_scan", "rule_untrusted_ip"],
        details={
            "auth_failures": count,
            "status_codes": "401,403",
            "endpoints_hit": ",".join(set(endpoints[:6])),
            "window_seconds": 60,
            "threshold": 6,
        },
        llm_hypothesis=(
            "Repeated HTTP 401/403 responses across diverse endpoints indicate systematic "
            "probing for weakly-protected or misconfigured routes."
        ),
        llm_report=(
            f"An unauthorized access scan was detected from IP {attacker_ip}. "
            f"The source accumulated {count} HTTP 401/403 responses across multiple "
            "application endpoints in under 60 seconds, indicating automated probing. "
            "Recommended: block source IP at the reverse proxy and audit endpoint auth middleware."
        ),
    )


def simulate_credential_stuffing(attacker_ip: str = "45.33.32.156") -> None:
    """
    Rule 4: Credential Stuffing
    Try > max_distinct_users_per_min (8) DISTINCT usernames from one IP.
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

    write_alert(
        threat_type="Credential Stuffing",
        risk_level="HIGH",
        confidence=90,
        source_ip=attacker_ip,
        triggered_rules=[
            "rule_credential_stuffing",
            "rule_many_distinct_users",
            "rule_untrusted_ip",
        ],
        details={
            "distinct_usernames_tried": count,
            "total_attempts": count,
            "sample_usernames": ",".join(targets[:6]),
            "window_seconds": 60,
            "threshold": 8,
        },
        llm_hypothesis=(
            "The high number of distinct usernames attempted from a single IP is consistent "
            "with an automated credential-stuffing attack using a leaked password database."
        ),
        llm_report=(
            f"A credential stuffing attack was detected from IP {attacker_ip}. "
            f"The attacker attempted login against {count} distinct user accounts "
            f"(including {', '.join(targets[:3])}) in under 60 seconds — "
            "a clear sign of automated credential list enumeration. "
            "Recommended: block IP, force resets on targeted accounts, and add CAPTCHA to /login."
        ),
    )


def simulate_account_takeover(attacker_ip: str = "198.51.100.14") -> None:
    """
    Rule 5: Account Takeover
    Several failures then a successful login from the same IP.
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

    write_alert(
        threat_type="Account Takeover",
        risk_level="CRITICAL",
        confidence=95,
        source_ip=attacker_ip,
        triggered_rules=[
            "rule_account_takeover",
            "rule_high_failure_pre_success",
            "rule_untrusted_ip",
        ],
        details={
            "failures_before_success": failure_count,
            "compromised_account": "alice",
            "window_seconds": 300,
            "min_failures_threshold": 3,
        },
        llm_hypothesis=(
            "Multiple failed login attempts followed by a successful authentication "
            "strongly indicates a successful account takeover — the attacker found a valid credential."
        ),
        llm_report=(
            f"A critical account takeover event was detected from IP {attacker_ip}. "
            f"After {failure_count} failed login attempts, the attacker successfully "
            "authenticated as user 'alice'. All active sessions for this account must be "
            "terminated immediately and the account owner notified. "
            "Recommended: block IP, revoke sessions, force password reset, and audit post-login activity."
        ),
    )


def simulate_data_exfiltration(attacker_ip: str = "203.0.113.9") -> None:
    """
    Rule 6: Data Exfiltration
    High volume of successful GETs to data-serving endpoints.
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
    endpoints_used: list[str] = []
    for _ in range(count):
        ep = random.choice(data_endpoints)
        endpoints_used.append(ep)
        write_log(
            event_type="api_call",
            method="GET",
            endpoint=ep,
            ip=attacker_ip,
            status_code=200,
            status="success",
        )
        time.sleep(0.04)

    unique_eps = list(set(endpoints_used))
    write_alert(
        threat_type="Data Exfiltration",
        risk_level="CRITICAL",
        confidence=85,
        source_ip=attacker_ip,
        triggered_rules=[
            "rule_data_scraping",
            "rule_high_volume_scrape",
            "rule_untrusted_ip",
        ],
        details={
            "total_requests": count,
            "unique_endpoints": len(unique_eps),
            "endpoints_hit": ",".join(unique_eps),
            "window_seconds": 60,
            "threshold": 20,
        },
        llm_hypothesis=(
            "High-volume automated GET requests targeting data-serving endpoints indicate "
            "deliberate bulk data theft or systematic API scraping."
        ),
        llm_report=(
            f"A data exfiltration event was detected from IP {attacker_ip}. "
            f"The source made {count} successful GET requests to {len(unique_eps)} data-serving "
            f"endpoints ({', '.join(unique_eps[:3])}...) within 60 seconds. "
            "Recommended: block IP immediately, revoke API tokens, audit all accessed records, "
            "and enforce rate-limiting on data endpoints."
        ),
    )


def simulate_path_traversal(attacker_ip: str = "185.220.101.34") -> None:
    """
    Rule 7: Path Traversal Attack
    Requests containing ../ or URL-encoded equivalents.
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
            status="blocked",
        )
        time.sleep(0.08)

    has_encoding = any("%" in p.lower() for p in payloads_used)
    rules = ["rule_path_traversal", "rule_untrusted_ip"]
    if has_encoding:
        rules.insert(1, "rule_encoded_traversal")

    write_alert(
        threat_type="Path Traversal Attack",
        risk_level="HIGH",
        confidence=95 if has_encoding else 80,
        source_ip=attacker_ip,
        triggered_rules=rules,
        details={
            "attempts": attempts,
            "endpoints_used": "|".join(payloads_used),
            "window_seconds": 300,
        },
        llm_hypothesis=(
            "Directory traversal sequences in the request URL indicate an automated exploit "
            "attempting to read arbitrary files from the server file system."
        ),
        llm_report=(
            f"A path traversal attack was detected from IP {attacker_ip}. "
            f"The attacker sent {attempts} requests containing directory traversal sequences "
            "(including URL-encoded variants), attempting to escape the web root and access "
            "sensitive server files such as /etc/passwd or .env. "
            "Recommended: block IP, sanitize path inputs, and audit server file-system access logs."
        ),
    )


def simulate_dos_flood(attacker_ip: str = "104.21.45.60") -> None:
    """
    Rule 8: DoS Rate Flood
    Extreme total request volume (> max_requests_per_min = 100).
    """
    print(f"  [MOCK] DoS Rate Flood       -> {attacker_ip}")
    all_endpoints = ["/", "/login", "/api/data", "/profile", "/admin", "/config"]
    count = random.randint(120, 160)
    for _ in range(count):
        ep = random.choice(all_endpoints)
        code = random.choice([200, 403, 404])
        status = "success" if code == 200 else "blocked"
        write_log(
            event_type="page_access",
            method="GET",
            endpoint=ep,
            ip=attacker_ip,
            status_code=code,
            status=status,
        )
        time.sleep(0.01)

    write_alert(
        threat_type="DoS Rate Flood",
        risk_level="HIGH",
        confidence=80,
        source_ip=attacker_ip,
        triggered_rules=["rule_dos_flood", "rule_extreme_flood", "rule_untrusted_ip"],
        details={
            "total_requests": count,
            "unique_endpoints": len(all_endpoints),
            "window_seconds": 60,
            "threshold": 100,
        },
        llm_hypothesis=(
            "Extreme request volume from a single IP in under one minute is consistent "
            "with an automated Denial-of-Service flood or aggressive vulnerability scanner."
        ),
        llm_report=(
            f"A DoS rate flood was detected from IP {attacker_ip}. "
            f"The source sent {count} requests in under 60 seconds across "
            f"{len(all_endpoints)} endpoints — {count - 100} requests above the threshold. "
            "Recommended: activate rate-limiting at the WAF/reverse-proxy, apply a temporary IP ban, "
            "and monitor for escalation into a targeted attack."
        ),
    )


# ── Scenario registry ──────────────────────────────────────────────────────────

# Each entry: (function, attacker_ip, cycle_period)
# cycle_period = "fire every N cycles"
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
