"""
rules_engine.py — Deterministic Threat Detection Rules
=======================================================
This module contains ALL detection logic. It is 100% rule-based math with zero AI.
The LLM is only called AFTER this module has already made its decision.

Detected threat types (8 total):
  1.  Brute Force Attack          — many failed logins, same IP, same account(s)
  2.  Endpoint Reconnaissance     — probing restricted admin/config paths
  3.  Unauthorized Access Scan    — flood of 401/403 responses across any endpoints
  4.  Credential Stuffing         — many DISTINCT usernames failing from same IP
  5.  Account Takeover            — prior failures from an IP that then succeeds
  6.  Data Exfiltration           — high-volume successful GETs to data endpoints
  7.  Path Traversal Attack       — ../ or URL-encoded variants in the endpoint URL
  8.  DoS Rate Flood              — extreme total request volume from a single IP

Expected SQLite schema  (data/logs.sqlite)
------------------------------------------
CREATE TABLE logs (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type   TEXT NOT NULL,   -- 'login_attempt', 'page_access', 'api_call'
    method       TEXT,            -- 'GET', 'POST', 'PUT', 'DELETE'
    endpoint     TEXT,            -- '/login', '/admin', '/config'
    username     TEXT,            -- username if applicable (NULL for anonymous)
    ip           TEXT NOT NULL,   -- source IP address
    status_code  INTEGER,         -- HTTP status code (200, 401, 403, 500)
    status       TEXT             -- 'success', 'fail', 'blocked'
);

CREATE TABLE alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_type     TEXT NOT NULL,
    risk_level      TEXT NOT NULL,
    confidence      INTEGER NOT NULL,
    source_ip       TEXT NOT NULL,
    triggered_rules TEXT,   -- JSON list of rule names
    details         TEXT,   -- JSON object with supporting evidence
    llm_hypothesis  TEXT,
    llm_report      TEXT
);
"""

import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List

# ---------------------------------------------------------------------------
# Baseline thresholds — tweak these to adjust sensitivity for the demo
# ---------------------------------------------------------------------------
BASELINE: Dict[str, Any] = {
    # Rule 1 — Brute Force
    "max_failed_logins_per_min": 5,
    # Rule 2 — Endpoint Reconnaissance
    "max_restricted_hits_per_min": 3,
    # Rule 3 — Unauthorized Access Scan
    "max_401_403_per_min": 6,
    # Rule 4 — Credential Stuffing
    "max_distinct_users_per_min": 8,
    # Rule 5 — Account Takeover
    "account_takeover_min_failures": 3,  # failures required before a success counts
    "account_takeover_window_seconds": 300,  # look back 5 minutes
    # Rule 6 — Data Exfiltration
    "max_data_requests_per_min": 20,
    # Rule 7 — Path Traversal (threshold = 1: any single hit is flagged)
    "path_traversal_min_attempts": 1,
    # Rule 8 — DoS Rate Flood
    "max_requests_per_min": 100,
    # Shared
    "alert_cooldown_seconds": 300,  # suppress re-alerts for 5 minutes
    "trusted_ips": ["10.0.0.1", "127.0.0.1"],
}

# Paths that should not be accessed by regular users
RESTRICTED_PATHS: List[str] = [
    "/admin",
    "/config",
    "/internal",
    "/dashboard",
    "/api/keys",
    "/env",
    "/.env",
    "/settings",
]

# Endpoints that serve user data — high volume hits here suggest exfiltration
DATA_ENDPOINTS: List[str] = [
    "/api/users",
    "/api/user",
    "/users",
    "/user",
    "/export",
    "/download",
    "/data",
    "/api/data",
    "/files",
    "/reports",
    "/backup",
    "/api/export",
    "/dump",
]

# ---------------------------------------------------------------------------
# Confidence weights per rule hit
# The base rule sets the floor; bonus rules stack on top.
# ---------------------------------------------------------------------------
RULE_CONFIDENCE: Dict[str, int] = {
    # Brute Force
    "rule_high_login_failure": 55,
    "rule_single_ip_brute": 25,  # bonus: 90%+ of login attempts are fails
    # Endpoint Recon
    "rule_restricted_recon": 60,
    "rule_multi_path_recon": 20,  # bonus: 3+ distinct restricted paths
    # Auth Scan
    "rule_auth_scan": 50,
    "rule_rapid_auth_failures": 20,  # bonus: count >= 3x threshold
    # Credential Stuffing
    "rule_credential_stuffing": 65,
    "rule_many_distinct_users": 15,  # bonus: >15 distinct users targeted
    # Account Takeover
    "rule_account_takeover": 85,  # high base — success after failures is serious
    "rule_high_failure_pre_success": 10,  # bonus: >=10 failures before the success
    # Data Exfiltration
    "rule_data_scraping": 60,
    "rule_high_volume_scrape": 15,  # bonus: >2x threshold in one minute
    # Path Traversal
    "rule_path_traversal": 70,
    "rule_encoded_traversal": 15,  # bonus: uses URL encoding (more sophisticated)
    # DoS Flood
    "rule_dos_flood": 55,
    "rule_extreme_flood": 25,  # bonus: >3x threshold
    # Shared bonus
    "rule_untrusted_ip": 10,
}


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------
@dataclass
class ThreatAlert:
    """A fully-evaluated threat decision produced by the rules engine."""

    threat_type: str
    risk_level: str  # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    confidence: int  # 0–100
    triggered_rules: List[str]
    source_ip: str
    details: Dict[str, Any]
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    llm_hypothesis: str = ""  # filled in by llm_client after detection
    llm_report: str = ""  # filled in by llm_client after detection
    llm_cache_used: bool = False  # True if LLM response(s) came from in-memory cache

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "threat_type": self.threat_type,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "triggered_rules": self.triggered_rules,
            "details": self.details,
            "llm_hypothesis": self.llm_hypothesis,
            "llm_report": self.llm_report,
            "llm_cache_used": self.llm_cache_used,
        }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _clamp(value: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, value))


def _risk_from_confidence(confidence: int) -> str:
    if confidence >= 80:
        return "CRITICAL"
    if confidence >= 60:
        return "HIGH"
    if confidence >= 40:
        return "MEDIUM"
    return "LOW"


def _already_alerted(
    conn: sqlite3.Connection, threat_type: str, source_ip: str
) -> bool:
    """
    Return True if this (threat_type, source_ip) pair was already alerted within
    the cooldown window.  Prevents alert storms when the agent polls every 5s.
    """
    cooldown = BASELINE["alert_cooldown_seconds"]
    cur = conn.execute(
        """
        SELECT COUNT(*) FROM alerts
        WHERE threat_type = ?
          AND source_ip   = ?
          AND timestamp  >= datetime('now', ? || ' seconds')
        """,
        (threat_type, source_ip, f"-{cooldown}"),
    )
    row = cur.fetchone()
    return row is not None and row[0] > 0


# ---------------------------------------------------------------------------
# Rule 1 — Brute Force Login Attack
# ---------------------------------------------------------------------------
def check_brute_force(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    Many failed logins from the same IP targeting the same account(s).
    Threshold: > max_failed_logins_per_min failures in 60 seconds.
    """
    threshold = BASELINE["max_failed_logins_per_min"]

    cur = conn.execute(
        """
        SELECT ip,
               COUNT(*)                        AS cnt,
               GROUP_CONCAT(DISTINCT username) AS targeted_users
        FROM logs
        WHERE event_type = 'login_attempt'
          AND status     = 'fail'
          AND timestamp >= datetime('now', '-60 seconds')
        GROUP BY ip
        HAVING cnt > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, count, users in rows:
        if _already_alerted(conn, "Brute Force Attack", ip):
            continue

        triggered = ["rule_high_login_failure"]
        confidence = RULE_CONFIDENCE["rule_high_login_failure"]

        # Bonus: almost all activity from this IP is failed logins (concentration)
        total_cur = conn.execute(
            """
            SELECT COUNT(*) FROM logs
            WHERE event_type = 'login_attempt'
              AND timestamp >= datetime('now', '-60 seconds')
              AND ip = ?
            """,
            (ip,),
        )
        total_row = total_cur.fetchone()
        total_for_ip = total_row[0] if total_row else count
        if total_for_ip > 0 and (count / total_for_ip) >= 0.9:
            triggered.append("rule_single_ip_brute")
            confidence += RULE_CONFIDENCE["rule_single_ip_brute"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Brute Force Attack",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "failed_attempts": count,
                    "window_seconds": 60,
                    "threshold": threshold,
                    "targeted_accounts": users or "unknown",
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 2 — Endpoint Reconnaissance
# ---------------------------------------------------------------------------
def check_recon(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP probes multiple restricted admin/config paths.
    Threshold: > max_restricted_hits_per_min hits in 60 seconds.
    """
    threshold = BASELINE["max_restricted_hits_per_min"]
    path_list = ", ".join(f"'{p}'" for p in RESTRICTED_PATHS)

    cur = conn.execute(
        f"""
        SELECT ip,
               COUNT(*)                        AS total_hits,
               COUNT(DISTINCT endpoint)        AS unique_paths,
               GROUP_CONCAT(DISTINCT endpoint) AS paths_hit
        FROM logs
        WHERE endpoint IN ({path_list})
          AND timestamp >= datetime('now', '-60 seconds')
        GROUP BY ip
        HAVING total_hits > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, total_hits, unique_paths, paths_hit in rows:
        if _already_alerted(conn, "Endpoint Reconnaissance", ip):
            continue

        triggered = ["rule_restricted_recon"]
        confidence = RULE_CONFIDENCE["rule_restricted_recon"]

        if unique_paths >= 3:
            triggered.append("rule_multi_path_recon")
            confidence += RULE_CONFIDENCE["rule_multi_path_recon"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Endpoint Reconnaissance",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "total_hits": total_hits,
                    "unique_paths": unique_paths,
                    "paths_hit": paths_hit or "",
                    "window_seconds": 60,
                    "threshold": threshold,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 3 — Unauthorized Access Scan
# ---------------------------------------------------------------------------
def check_auth_scan(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP accumulates many HTTP 401/403 responses — indicates probing for
    weakly-protected endpoints across the application.
    Threshold: > max_401_403_per_min in 60 seconds.
    """
    threshold = BASELINE["max_401_403_per_min"]

    cur = conn.execute(
        """
        SELECT ip,
               COUNT(*)                        AS cnt,
               GROUP_CONCAT(DISTINCT status_code) AS codes,
               GROUP_CONCAT(DISTINCT endpoint)    AS endpoints
        FROM logs
        WHERE status_code IN (401, 403)
          AND timestamp >= datetime('now', '-60 seconds')
        GROUP BY ip
        HAVING cnt > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, count, codes, endpoints in rows:
        if _already_alerted(conn, "Unauthorized Access Scan", ip):
            continue

        triggered = ["rule_auth_scan"]
        confidence = RULE_CONFIDENCE["rule_auth_scan"]

        if count >= threshold * 3:
            triggered.append("rule_rapid_auth_failures")
            confidence += RULE_CONFIDENCE["rule_rapid_auth_failures"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Unauthorized Access Scan",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "auth_failures": count,
                    "status_codes": codes or "401/403",
                    "endpoints_hit": endpoints or "various",
                    "window_seconds": 60,
                    "threshold": threshold,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 4 — Credential Stuffing
# ---------------------------------------------------------------------------
def check_credential_stuffing(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP tries many DISTINCT usernames with failed logins — indicating an
    automated attack using a leaked credentials list rather than targeting
    one account (which brute force would catch instead).

    Key difference from brute force:
      Brute Force   → many attempts, FEW distinct usernames (1-2 accounts)
      Cred Stuffing → many attempts, MANY distinct usernames (>8 accounts)

    Threshold: > max_distinct_users_per_min distinct failing usernames in 60 seconds.
    """
    threshold = BASELINE["max_distinct_users_per_min"]

    cur = conn.execute(
        """
        SELECT ip,
               COUNT(DISTINCT username)        AS distinct_users,
               COUNT(*)                        AS total_attempts,
               GROUP_CONCAT(DISTINCT username) AS usernames_tried
        FROM logs
        WHERE event_type = 'login_attempt'
          AND status     = 'fail'
          AND username   IS NOT NULL
          AND timestamp >= datetime('now', '-60 seconds')
        GROUP BY ip
        HAVING distinct_users > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, distinct_users, total_attempts, usernames_tried in rows:
        if _already_alerted(conn, "Credential Stuffing", ip):
            continue

        triggered = ["rule_credential_stuffing"]
        confidence = RULE_CONFIDENCE["rule_credential_stuffing"]

        # Bonus: large-scale stuffing (>15 accounts)
        if distinct_users > 15:
            triggered.append("rule_many_distinct_users")
            confidence += RULE_CONFIDENCE["rule_many_distinct_users"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Credential Stuffing",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "distinct_usernames_tried": distinct_users,
                    "total_attempts": total_attempts,
                    "sample_usernames": (usernames_tried or "")[:200],
                    "window_seconds": 60,
                    "threshold": threshold,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 5 — Account Takeover Detection
# ---------------------------------------------------------------------------
def check_account_takeover(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP that accumulated multiple login failures then achieves a SUCCESSFUL
    login within the same lookback window.  This is the most dangerous signal —
    it means the attacker found a working credential.

    Logic (two-step JOIN):
      Step A: find IPs with >= account_takeover_min_failures failed logins
              in the last account_takeover_window_seconds seconds.
      Step B: find IPs with at least one successful login in the same window.
      Match:  any IP present in BOTH sets = likely account takeover.
    """
    min_failures = BASELINE["account_takeover_min_failures"]
    window_s = BASELINE["account_takeover_window_seconds"]
    window_str = f"-{window_s} seconds"

    cur = conn.execute(
        """
        SELECT f.ip,
               f.failure_count,
               s.compromised_account
        FROM (
            SELECT ip,
                   COUNT(*) AS failure_count
            FROM logs
            WHERE event_type = 'login_attempt'
              AND status     = 'fail'
              AND timestamp >= datetime('now', ?)
            GROUP BY ip
            HAVING failure_count >= ?
        ) f
        JOIN (
            SELECT ip,
                   GROUP_CONCAT(DISTINCT username) AS compromised_account
            FROM logs
            WHERE event_type = 'login_attempt'
              AND status     = 'success'
              AND timestamp >= datetime('now', ?)
            GROUP BY ip
        ) s ON f.ip = s.ip
        """,
        (window_str, min_failures, window_str),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, failure_count, compromised_account in rows:
        if _already_alerted(conn, "Account Takeover", ip):
            continue

        triggered = ["rule_account_takeover"]
        confidence = RULE_CONFIDENCE["rule_account_takeover"]

        # Bonus: many failures before success (stronger evidence of automation)
        if failure_count >= 10:
            triggered.append("rule_high_failure_pre_success")
            confidence += RULE_CONFIDENCE["rule_high_failure_pre_success"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Account Takeover",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "failures_before_success": failure_count,
                    "compromised_account": compromised_account or "unknown",
                    "window_seconds": window_s,
                    "min_failures_threshold": min_failures,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 6 — Data Exfiltration / Scraping
# ---------------------------------------------------------------------------
def check_data_exfiltration(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP fires a high volume of successful GET requests to data-serving
    endpoints, indicating automated scraping or bulk data theft.

    Matches exact endpoint names in DATA_ENDPOINTS and also any endpoint
    under common data-serving path prefixes (/api/, /data/, /export/, /download/).

    Threshold: > max_data_requests_per_min successful GETs in 60 seconds.
    """
    threshold = BASELINE["max_data_requests_per_min"]
    exact_list = ", ".join(f"'{p}'" for p in DATA_ENDPOINTS)

    cur = conn.execute(
        f"""
        SELECT ip,
               COUNT(*)                        AS total_requests,
               COUNT(DISTINCT endpoint)        AS unique_endpoints,
               GROUP_CONCAT(DISTINCT endpoint) AS endpoints_hit
        FROM logs
        WHERE (
                endpoint IN ({exact_list})
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
        HAVING total_requests > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, total_requests, unique_endpoints, endpoints_hit in rows:
        if _already_alerted(conn, "Data Exfiltration", ip):
            continue

        triggered = ["rule_data_scraping"]
        confidence = RULE_CONFIDENCE["rule_data_scraping"]

        # Bonus: very high volume (>2× threshold)
        if total_requests >= threshold * 2:
            triggered.append("rule_high_volume_scrape")
            confidence += RULE_CONFIDENCE["rule_high_volume_scrape"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Data Exfiltration",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "total_requests": total_requests,
                    "unique_endpoints": unique_endpoints,
                    "endpoints_hit": endpoints_hit or "various",
                    "window_seconds": 60,
                    "threshold": threshold,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 7 — Path Traversal Attack
# ---------------------------------------------------------------------------
def check_path_traversal(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    Requests containing directory traversal sequences in the endpoint URL.
    Even a SINGLE hit is suspicious — no volume threshold needed.

    Patterns detected:
      ../          basic traversal
      ..\\         Windows-style
      %2e%2e%2f    fully URL-encoded
      %2e%2e/      partially encoded
      ..%2f        partially encoded (lowercase)
      ..%2F        partially encoded (uppercase)
      %252e        double-encoded (bypass attempt — more sophisticated)
      ....//       duplicated-dot bypass
    """
    min_attempts = BASELINE["path_traversal_min_attempts"]

    cur = conn.execute(
        r"""
        SELECT ip,
               COUNT(*)                   AS attempts,
               GROUP_CONCAT(endpoint, '|') AS endpoints_used
        FROM logs
        WHERE (
               endpoint LIKE '%../%'
            OR endpoint LIKE '%..\\%'
            OR endpoint LIKE '%2e%2e%2f%'
            OR endpoint LIKE '%2e%2e/%'
            OR endpoint LIKE '%..%2f%'
            OR endpoint LIKE '%..%2F%'
            OR endpoint LIKE '%252e%252e%'
            OR endpoint LIKE '%..../%'
            OR endpoint LIKE '%....\\%'
        )
          AND timestamp >= datetime('now', '-300 seconds')
        GROUP BY ip
        HAVING attempts >= ?
        """,
        (min_attempts,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, attempts, endpoints_used in rows:
        if _already_alerted(conn, "Path Traversal Attack", ip):
            continue

        triggered = ["rule_path_traversal"]
        confidence = RULE_CONFIDENCE["rule_path_traversal"]

        # Bonus: uses URL encoding — suggests automated tool or deliberate evasion
        raw_endpoints = endpoints_used or ""
        if (
            "%2e" in raw_endpoints.lower()
            or "%252e" in raw_endpoints.lower()
            or "%2f" in raw_endpoints.lower()
        ):
            triggered.append("rule_encoded_traversal")
            confidence += RULE_CONFIDENCE["rule_encoded_traversal"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="Path Traversal Attack",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "attempts": attempts,
                    "endpoints_used": raw_endpoints[:300],  # cap length for DB storage
                    "window_seconds": 300,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Rule 8 — Denial of Service (Rate Flood)
# ---------------------------------------------------------------------------
def check_dos_flood(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    An IP sends an extreme volume of requests (any endpoint, any status) within
    one minute — indicative of a DoS flood, stress-testing, or automated scanner.

    This catches attacks that slip past all other rules because they are returning
    200 OK on every request (e.g., scraping public pages, or flooding a cached endpoint).

    Threshold: > max_requests_per_min total requests in 60 seconds.
    """
    threshold = BASELINE["max_requests_per_min"]

    cur = conn.execute(
        """
        SELECT ip,
               COUNT(*)                AS total_requests,
               COUNT(DISTINCT endpoint) AS unique_endpoints
        FROM logs
        WHERE timestamp >= datetime('now', '-60 seconds')
        GROUP BY ip
        HAVING total_requests > ?
        """,
        (threshold,),
    )
    rows = cur.fetchall()

    alerts: List[ThreatAlert] = []
    for ip, total_requests, unique_endpoints in rows:
        if _already_alerted(conn, "DoS Rate Flood", ip):
            continue

        triggered = ["rule_dos_flood"]
        confidence = RULE_CONFIDENCE["rule_dos_flood"]

        # Bonus: extreme volume (>3× threshold = clearly automated)
        if total_requests >= threshold * 3:
            triggered.append("rule_extreme_flood")
            confidence += RULE_CONFIDENCE["rule_extreme_flood"]

        if ip not in BASELINE["trusted_ips"]:
            triggered.append("rule_untrusted_ip")
            confidence += RULE_CONFIDENCE["rule_untrusted_ip"]

        confidence = _clamp(confidence)
        alerts.append(
            ThreatAlert(
                threat_type="DoS Rate Flood",
                risk_level=_risk_from_confidence(confidence),
                confidence=confidence,
                triggered_rules=triggered,
                source_ip=ip,
                details={
                    "total_requests": total_requests,
                    "unique_endpoints": unique_endpoints,
                    "window_seconds": 60,
                    "threshold": threshold,
                },
            )
        )

    return alerts


# ---------------------------------------------------------------------------
# Public API — run all 8 rules in one call
# ---------------------------------------------------------------------------
def run_all_rules(conn: sqlite3.Connection) -> List[ThreatAlert]:
    """
    Execute every rule against the current log database state.
    Returns a list of ThreatAlert objects ready for LLM enrichment.
    Order matters: roughly most-severe to least, so the agent console
    surfaces the biggest threats first.
    """
    alerts: List[ThreatAlert] = []
    alerts.extend(check_account_takeover(conn))  # Rule 5 — highest base confidence (85)
    alerts.extend(check_path_traversal(conn))  # Rule 7 — single-hit trigger (70+)
    alerts.extend(check_credential_stuffing(conn))  # Rule 4 — (65+)
    alerts.extend(check_recon(conn))  # Rule 2 — (60+)
    alerts.extend(check_data_exfiltration(conn))  # Rule 6 — (60+)
    alerts.extend(check_brute_force(conn))  # Rule 1 — (55+)
    alerts.extend(check_auth_scan(conn))  # Rule 3 — (50+)
    alerts.extend(check_dos_flood(conn))  # Rule 8 — (55+)
    return alerts


# ---------------------------------------------------------------------------
# Mitigation lookup — deterministic, no AI involved
# ---------------------------------------------------------------------------
MITIGATIONS: Dict[str, str] = {
    "Brute Force Attack": (
        "Immediately block source IP at the firewall. "
        "Lock the targeted account(s) and force a password reset. "
        "Enable MFA if not already active."
    ),
    "Endpoint Reconnaissance": (
        "Rate-limit or temporarily block the source IP. "
        "Review access-control rules on all restricted endpoints. "
        "Enable IP-based allow-listing for admin paths."
    ),
    "Unauthorized Access Scan": (
        "Block source IP at the reverse-proxy level. "
        "Audit endpoint authentication middleware for gaps. "
        "Check for recently exposed credentials or tokens."
    ),
    "Credential Stuffing": (
        "Block source IP immediately. "
        "Force password resets for all accounts in the targeted username list. "
        "Implement CAPTCHA or rate-limiting on the login endpoint. "
        "Enable breach-password detection (e.g., HaveIBeenPwned API)."
    ),
    "Account Takeover": (
        "CRITICAL: Immediately terminate all active sessions for the compromised account. "
        "Force a password reset and notify the account owner. "
        "Block the source IP. "
        "Audit all actions the account performed after the successful login."
    ),
    "Data Exfiltration": (
        "Block source IP immediately and revoke any API tokens it used. "
        "Audit all data accessed in the session window. "
        "Implement rate-limiting and authentication on all data-serving endpoints. "
        "Review data-access logs to determine scope of the breach."
    ),
    "Path Traversal Attack": (
        "Block source IP immediately. "
        "Patch the affected endpoint to sanitize and validate all path inputs. "
        "Audit server file-system access logs for any files that may have been read. "
        "Rotate any secrets or keys stored in files accessible from the web root."
    ),
    "DoS Rate Flood": (
        "Activate rate-limiting rules at the reverse-proxy or WAF level for the source IP. "
        "Consider a temporary IP ban at the firewall. "
        "Scale up server resources or enable a CDN/DDoS mitigation service if attack persists. "
        "Investigate whether this is reconnaissance before a targeted attack."
    ),
}


def get_mitigation(threat_type: str) -> str:
    """Return the deterministic mitigation string for a given threat type."""
    return MITIGATIONS.get(
        threat_type, "Investigate the source IP and review recent logs."
    )
