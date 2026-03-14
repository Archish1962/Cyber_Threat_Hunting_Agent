"""
dashboard/app.py  (v2)
----------------------
SOC Watch View — Streamlit Dashboard
Polls data/logs.sqlite (written by Backend + Agent teammates).
Your only deliverable. Zero coupling to their code.

Improvements over v1:
  - @st.fragment(run_every=3) replaces time.sleep(3)+st.rerun() → no thread blocking, no full-page flash
  - try/except on every DB call → graceful degradation if schema changes
  - get_stats() now counts "fail", "403", "blocked" as failures (v1 only counted "fail")
  - safe_html() escapes all LLM/agent text before injecting into HTML → no XSS / display corruption
  - System status banner: NOMINAL / MEDIUM / HIGH / CRITICAL
  - Events timeline chart (altair, 30-second buckets)
  - Attack type distribution chart (altair, horizontal bars)
  - Top attacking IPs panel
  - Sidebar reset button to wipe DB between demo runs
"""

import html as html_lib
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

import altair as alt
import pandas as pd
import streamlit as st

# ── IST timezone (UTC+5:30) ───────────────────────────────────────────────────
IST = timezone(timedelta(hours=5, minutes=30), "IST")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "data", "logs.sqlite")

# ── Page config (runs once, outside the fragment) ─────────────────────────────
st.set_page_config(
    page_title="SOC Threat Hunter",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Global CSS ────────────────────────────────────────────────────────────────
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #050a0e;
    color: #c9d1d9;
}
.block-container { padding: 1rem 2rem 2rem 2rem !important; }

/* Collapse the header to zero height instead of display:none so the
   sidebar toggle button (collapsedControl) stays in the DOM and can
   be re-styled as a floating button. display:none would remove the
   toggle entirely, leaving no way to reopen a closed sidebar. */
[data-testid="stHeader"] {
    height: 0px !important;
    min-height: 0px !important;
    padding: 0 !important;
    background: transparent !important;
    border: none !important;
    overflow: visible !important;
}
[data-testid="stToolbar"] { display: none !important; }

/* Sidebar toggle button — floats in the top-left corner when the sidebar
   is collapsed, styled to match the dashboard's dark cyber theme.
   When the sidebar is open, the sidebar's own close arrow is visible
   inside the sidebar panel, so this rule only matters when collapsed. */
[data-testid="collapsedControl"] {
    position: fixed !important;
    top: 8px !important;
    left: 8px !important;
    z-index: 99999 !important;
    background: rgba(13, 17, 23, 0.92) !important;
    border: 1px solid #00ffe7 !important;
    border-radius: 4px !important;
    padding: 2px 6px !important;
    display: flex !important;
    align-items: center !important;
    justify-content: center !important;
    cursor: pointer !important;
    transition: background 0.2s ease !important;
}
[data-testid="collapsedControl"]:hover {
    background: rgba(0, 255, 231, 0.12) !important;
}
[data-testid="collapsedControl"] svg {
    fill: #00ffe7 !important;
}

/* ── Header ── */
.soc-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 0.6rem 1.2rem;
    background: linear-gradient(90deg, #0d1117 60%, #091a2a);
    border-bottom: 1px solid #00ffe7;
    margin-bottom: 0.8rem; border-radius: 4px;
}
.soc-title    { font-size: 1.4rem; font-weight: 700; color: #00ffe7; letter-spacing: 2px; }
.soc-subtitle { font-size: 0.75rem; color: #8b949e; letter-spacing: 1px; }
.soc-clock    { font-family: 'Share Tech Mono', monospace; font-size: 1rem; color: #00ffe7; }

/* ── Status banner ── */
.status-banner {
    padding: 0.45rem 1.2rem; border-radius: 4px; margin-bottom: 0.8rem;
    font-family: 'Share Tech Mono', monospace; font-size: 0.78rem;
    letter-spacing: 2px; text-align: center; font-weight: 700;
}
.status-nominal  { background: rgba(63,185,80,0.08);  border: 1px solid rgba(63,185,80,0.35);  color: #3fb950; }
.status-medium   { background: rgba(88,166,255,0.08); border: 1px solid rgba(88,166,255,0.35); color: #58a6ff; }
.status-high     { background: rgba(210,153,34,0.12); border: 1px solid rgba(210,153,34,0.45); color: #d29922; }
.status-critical {
    background: rgba(248,81,73,0.12); border: 1px solid rgba(248,81,73,0.5);
    color: #f85149; animation: pulse-red 1.6s ease-in-out infinite;
}
@keyframes pulse-red {
    0%,100% { box-shadow: 0 0 0px rgba(248,81,73,0); }
    50%      { box-shadow: 0 0 12px rgba(248,81,73,0.4); }
}

/* ── KPI metric cards ── */
.metric-card {
    background: #0d1117; border: 1px solid #21262d;
    border-radius: 6px; padding: 1rem 1.2rem;
    text-align: center; position: relative; overflow: hidden;
}
.metric-card::before { content:''; position:absolute; top:0; left:0; right:0; height:2px; }
.metric-card.green::before  { background: #3fb950; }
.metric-card.yellow::before { background: #d29922; }
.metric-card.red::before    { background: #f85149; }
.metric-card.blue::before   { background: #58a6ff; }
.metric-value { font-family:'Share Tech Mono',monospace; font-size:2.2rem; font-weight:700; }
.metric-label { font-size:0.7rem; letter-spacing:1.5px; color:#8b949e; text-transform:uppercase; margin-top:2px; }
.green .metric-value  { color: #3fb950; }
.yellow .metric-value { color: #d29922; }
.red .metric-value    { color: #f85149; }
.blue .metric-value   { color: #58a6ff; }

/* ── Section headers ── */
.section-head {
    font-size:0.65rem; letter-spacing:3px; text-transform:uppercase;
    color:#8b949e; border-bottom:1px solid #21262d; padding-bottom:4px; margin-bottom:0.6rem;
}

/* ── Live traffic feed ── */
.feed-row {
    font-family:'Share Tech Mono',monospace; font-size:0.72rem;
    padding:3px 8px; border-radius:3px; margin-bottom:2px; line-height:1.6;
}
.feed-row.fail    { background:rgba(248,81,73,0.08);  color:#f85149; }
.feed-row.success { background:rgba(63,185,80,0.06);  color:#3fb950; }
.feed-row.blocked { background:rgba(210,153,34,0.08); color:#d29922; }
.feed-row.normal  { color:#8b949e; }
.feed-container   { max-height:300px; overflow-y:auto; scrollbar-width:thin; scrollbar-color:#21262d transparent; }

/* ── Threat cards ── */
.threat-card {
    background:#0d1117; border:1px solid #21262d; border-left:3px solid;
    border-radius:4px; padding:0.8rem 1rem; margin-bottom:0.6rem;
}
.threat-card.Critical { border-left-color:#f85149; }
.threat-card.High     { border-left-color:#d29922; }
.threat-card.Medium   { border-left-color:#58a6ff; }
.threat-card.Low      { border-left-color:#3fb950; }
.threat-type { font-size:0.9rem; font-weight:700; letter-spacing:1px; }
.threat-meta { font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#8b949e; margin:4px 0; }

/* ── Badges ── */
.badge { display:inline-block; padding:1px 8px; border-radius:20px; font-size:0.6rem; font-weight:700; letter-spacing:1px; margin-right:4px; }
.badge-Critical { background:rgba(248,81,73,0.2);  color:#f85149; }
.badge-High     { background:rgba(210,153,34,0.2); color:#d29922; }
.badge-Medium   { background:rgba(88,166,255,0.2); color:#58a6ff; }
.badge-Low      { background:rgba(63,185,80,0.2);  color:#3fb950; }

/* ── Confidence bar ── */
.conf-bar-bg   { background:#21262d; border-radius:3px; height:4px; margin:6px 0; width:100%; }
.conf-bar-fill { height:4px; border-radius:3px; }

/* ── LLM report & mitigation ── */
.llm-label  { font-size:0.6rem; letter-spacing:2px; color:#00ffe7; text-transform:uppercase; margin-bottom:4px; margin-top:6px; }
.llm-report { background:#080d12; border:1px solid #1c2128; border-radius:4px; padding:0.6rem 0.8rem; font-size:0.78rem; color:#c9d1d9; margin-top:0.3rem; line-height:1.6; }
.mitigation { background:rgba(63,185,80,0.06); border:1px solid rgba(63,185,80,0.2); border-radius:4px; padding:0.5rem 0.8rem; font-size:0.75rem; color:#3fb950; margin-top:0.4rem; }
.rule-tag   { display:inline-block; background:#161b22; border:1px solid #30363d; color:#8b949e; font-family:'Share Tech Mono',monospace; font-size:0.6rem; padding:1px 6px; border-radius:3px; margin-right:3px; margin-bottom:3px; }



/* ── Bottom analytics tabs ── */
.stTabs [data-baseweb="tab-list"] {
    background-color: transparent;
    border-bottom: 1px solid #21262d;
    gap: 0;
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.62rem;
    letter-spacing: 2px;
    color: #8b949e;
    background-color: transparent;
    border: none;
    padding: 0.4rem 1rem;
    text-transform: uppercase;
}
.stTabs [aria-selected="true"] {
    color: #00ffe7 !important;
    border-bottom: 2px solid #00ffe7 !important;
    background-color: transparent !important;
}
.stTabs [data-baseweb="tab-panel"] {
    padding: 0.6rem 0;
    background-color: transparent;
}
.stTabs [data-baseweb="tab-highlight"] { background-color: transparent !important; }

/* ── Misc ── */
.empty-state { text-align:center; color:#3d444d; font-size:0.8rem; padding:2rem; letter-spacing:2px; }
.db-warning  { background:rgba(248,81,73,0.1); border:1px solid rgba(248,81,73,0.3); border-radius:6px; padding:1.2rem; color:#f85149; font-family:'Share Tech Mono',monospace; font-size:0.8rem; text-align:center; }

/* ── Blocked IPs tab ── */
.blocked-header { font-size:0.65rem; letter-spacing:2px; color:#f85149; text-transform:uppercase; margin-bottom:0.5rem; }
.sidebar-summary-box { background:#0d1117; border:1px solid #21262d; border-radius:4px; padding:0.6rem 0.8rem; margin-bottom:0.5rem; font-size:0.72rem; color:#8b949e; }

/* ── LLM call-source badges (live vs cached) ── */
.llm-live-badge {
    font-family:'Share Tech Mono',monospace; font-size:0.6rem; letter-spacing:1.5px;
    color:#f85149; background:rgba(248,81,73,0.08); border:1px solid rgba(248,81,73,0.3);
    border-radius:3px; padding:3px 8px; margin:6px 0 4px 0; display:inline-block;
}
.llm-cache-badge {
    font-family:'Share Tech Mono',monospace; font-size:0.6rem; letter-spacing:1.5px;
    color:#3fb950; background:rgba(63,185,80,0.08); border:1px solid rgba(63,185,80,0.3);
    border-radius:3px; padding:3px 8px; margin:6px 0 4px 0; display:inline-block;
}
</style>
""",
    unsafe_allow_html=True,
)


# ── Sidebar ───────────────────────────────────────────────────────────────────
# Session state for the two-step log-cleanup confirmation in the tab
if "confirm_cleanup_logs" not in st.session_state:
    st.session_state.confirm_cleanup_logs = False

with st.sidebar:
    st.markdown("### ⚙ DASHBOARD CONTROLS")
    st.markdown("---")
    st.caption(f"DB path:\n`{DB_PATH}`")
    st.caption("Dashboard auto-refreshes every **3 seconds** via `@st.fragment`.")


# ── DB helpers ────────────────────────────────────────────────────────────────
def db_ok() -> bool:
    return os.path.exists(DB_PATH)


def get_events(limit: int = 80) -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM logs ORDER BY id DESC LIMIT ?", conn, params=[limit]
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def get_threats(limit: int = 20) -> pd.DataFrame:
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", conn, params=[limit]
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def get_top_ips() -> pd.DataFrame:
    """Aggregate event counts and failure counts per source IP."""
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            """
            SELECT
                ip                                                          AS "IP Address",
                COUNT(*)                                                    AS "Total Events",
                SUM(CASE WHEN status IN ('fail','403','blocked') THEN 1
                         ELSE 0 END)                                        AS "Failed Requests"
            FROM   logs
            GROUP  BY ip
            ORDER  BY "Total Events" DESC
            LIMIT  10
            """,
            conn,
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def get_blocked_ips() -> pd.DataFrame:
    """
    Return all rows from blocked_ips ordered by most recently blocked first.
    Returns an empty DataFrame if the table doesn't exist yet (agent hasn't
    run its first cycle) — dashboard degrades gracefully.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM blocked_ips ORDER BY blocked_at DESC",
            conn,
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def get_timeline_data() -> pd.DataFrame:
    """
    Returns event counts grouped into 30-second time buckets,
    pulling the most recent 300 events so the chart covers the live window.
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT timestamp, status FROM logs ORDER BY id DESC LIMIT 300", conn
        )
        conn.close()
        if df.empty:
            return pd.DataFrame()
        df["ts"] = pd.to_datetime(df["timestamp"], utc=True, errors="coerce")
        df = df.dropna(subset=["ts"]).sort_values("ts")
        df["bucket"] = df["ts"].dt.floor("30s")
        timeline = df.groupby("bucket").size().reset_index()
        timeline.columns = pd.Index(["bucket", "Events"])
        timeline["bucket"] = timeline["bucket"].dt.strftime("%H:%M:%S")
        return timeline
    except Exception:
        return pd.DataFrame()


# ── Pure helpers ──────────────────────────────────────────────────────────────
def get_stats(events_df: pd.DataFrame, threats_df: pd.DataFrame):
    total = len(events_df)
    # v1 only counted "fail" — now we count 403 and blocked too
    fails = (
        int(events_df["status"].isin(["fail", "403", "blocked"]).sum()) if total else 0
    )
    active_threats = (
        int(threats_df["risk_level"].isin(["HIGH", "CRITICAL"]).sum())
        if len(threats_df)
        else 0
    )
    flagged_ips = int(threats_df["source_ip"].nunique()) if len(threats_df) else 0
    return total, fails, active_threats, flagged_ips


def fmt_time(ts_str: str) -> str:
    try:
        raw = str(ts_str).replace("Z", "+00:00")
        dt = datetime.fromisoformat(raw)
        # Timestamps from the DB have no tzinfo (SQLite 'now' is UTC).
        # Timestamps written by the agent carry an explicit UTC offset.
        # In both cases treat the value as UTC then convert to IST.
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(IST).strftime("%H:%M:%S")
    except Exception:
        return str(ts_str)[:8]


def conf_color(c: int) -> str:
    if c >= 85:
        return "#f85149"
    if c >= 65:
        return "#d29922"
    return "#58a6ff"


def safe_html(text) -> str:
    """Escape any LLM / agent-generated text before embedding in raw HTML."""
    return html_lib.escape(str(text)) if text else ""


# ── Mitigation lookup (mirrors rules_engine.MITIGATIONS — no AI involved) ────
MITIGATIONS: dict[str, str] = {
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
        "Implement CAPTCHA or rate-limiting on the login endpoint."
    ),
    "Account Takeover": (
        "CRITICAL: Immediately terminate all active sessions for the compromised account. "
        "Force a password reset and notify the account owner. "
        "Block the source IP and audit all actions performed after the successful login."
    ),
    "Data Exfiltration": (
        "Block source IP immediately and revoke any API tokens it used. "
        "Audit all data accessed in the session window. "
        "Implement rate-limiting and authentication on all data-serving endpoints."
    ),
    "Path Traversal Attack": (
        "Block source IP immediately. "
        "Patch the affected endpoint to sanitize and validate all path inputs. "
        "Rotate any secrets or keys stored in files accessible from the web root."
    ),
    "DoS Rate Flood": (
        "Activate rate-limiting rules at the reverse-proxy or WAF level. "
        "Consider a temporary IP ban at the firewall. "
        "Scale up server resources or enable a CDN/DDoS mitigation service if the attack persists."
    ),
}


# ── Altair dark-theme config (shared by all charts) ──────────────────────────
# NOTE: plain dict — do NOT use alt.AxisConfig() here because spreading its
# __dict__ passes internal Altair keys (_args, _kwds …) that fail schema validation.
# Annotated as dict[str, Any] so Pyright doesn't complain about the **-spread
# into configure_axis(), which has very granular per-parameter type signatures.
_CHART_CFG: dict[str, Any] = dict(
    background="transparent",
    height=180,
)
_AXIS_KWARGS: dict[str, Any] = dict(
    labelColor="#8b949e",
    titleColor="#8b949e",
    gridColor="#21262d",
    domainColor="#30363d",
    tickColor="#30363d",
    labelFontSize=10,
)


# ── Fragment: entire live dashboard re-renders every 3 s ──────────────────────
@st.fragment(run_every=3)
def live_dashboard():
    # ── Live clock ────────────────────────────────────────────────────────────
    now_str = datetime.now(IST).strftime("%Y-%m-%d  %H:%M:%S IST")
    st.markdown(
        f"""
    <div class="soc-header">
      <div>
        <div class="soc-title">🛡 SOC THREAT HUNTER</div>
        <div class="soc-subtitle">AI-DRIVEN AUTONOMOUS CYBER THREAT HUNTING AGENT</div>
      </div>
      <div class="soc-clock">{now_str}</div>
    </div>
    """,
        unsafe_allow_html=True,
    )

    # ── No-DB guard ───────────────────────────────────────────────────────────
    if not db_ok():
        st.markdown(
            f"""
        <div class="db-warning">
          ⚠ &nbsp; Database not found at: <b>{safe_html(DB_PATH)}</b><br><br>
          Run <b>python mock_generator.py</b> from the project root to simulate traffic,<br>
          or wait for the backend teammate to start the FastAPI server.
        </div>
        """,
            unsafe_allow_html=True,
        )
        return  # fragment will retry automatically on next 3s tick

    # ── Load data ─────────────────────────────────────────────────────────────
    events_df = get_events()
    threats_df = get_threats()
    total, fails, active_threats, flagged_ips = get_stats(events_df, threats_df)

    # ── Status banner ─────────────────────────────────────────────────────────
    # risk_level is stored uppercase by the real agent ("HIGH", "CRITICAL", etc.)
    risk_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not threats_df.empty:
        max_risk_val = (
            threats_df["risk_level"]
            .map(lambda x: risk_order.get(str(x).upper(), 0))
            .max()
        )
    else:
        max_risk_val = 0

    if max_risk_val >= 4:
        banner_cls = "status-critical"
        banner_text = "⛔  CRITICAL THREAT ACTIVE — IMMEDIATE CONTAINMENT REQUIRED"
    elif max_risk_val >= 3:
        banner_cls = "status-high"
        banner_text = "⚠  HIGH THREAT DETECTED — REVIEW INCIDENT REPORTS NOW"
    elif max_risk_val >= 2:
        banner_cls = "status-medium"
        banner_text = "⚡  MEDIUM THREAT DETECTED — MONITOR & INVESTIGATE"
    elif max_risk_val == 1:
        banner_cls = "status-nominal"
        banner_text = "✅  LOW-LEVEL ACTIVITY — SYSTEM NOMINAL"
    else:
        banner_cls = "status-nominal"
        banner_text = "✅  SYSTEM NOMINAL — NO ACTIVE THREATS DETECTED"

    st.markdown(
        f'<div class="status-banner {banner_cls}">{banner_text}</div>',
        unsafe_allow_html=True,
    )

    # ── KPI metric cards ──────────────────────────────────────────────────────
    c1, c2, c3, c4 = st.columns(4)
    for col, cls, val, label in [
        (c1, "blue", total, "EVENTS CAPTURED"),
        (c2, "red", fails, "FAILED REQUESTS"),
        (c3, "yellow", active_threats, "ACTIVE THREATS"),
        (c4, "green", flagged_ips, "FLAGGED IPs"),
    ]:
        col.markdown(
            f"""
        <div class="metric-card {cls}">
          <div class="metric-value">{val}</div>
          <div class="metric-label">{label}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

    st.markdown("<br>", unsafe_allow_html=True)

    # ── Main two-column layout ─────────────────────────────────────────────────
    left, right = st.columns([1, 1.35], gap="medium")

    # ────────────────────────────── LEFT COLUMN ───────────────────────────────
    with left:
        # Live traffic feed
        st.markdown(
            '<div class="section-head">◈ LIVE TRAFFIC FEED</div>',
            unsafe_allow_html=True,
        )
        if events_df.empty:
            st.markdown(
                '<div class="empty-state">AWAITING TRAFFIC...</div>',
                unsafe_allow_html=True,
            )
        else:
            rows_html = ""
            for _, row in events_df.head(40).iterrows():
                ts = fmt_time(str(row.get("timestamp") or ""))
                ip = safe_html(row.get("ip", "?"))
                ep = safe_html(row.get("endpoint", "?"))
                met = safe_html(row.get("method", "?"))
                sta = safe_html(row.get("status", "?"))
                # logs table uses 'username'; mock used 'user' — handle both
                usr = safe_html(row.get("username") or row.get("user") or "?")
                css = (
                    "fail"
                    if sta == "fail"
                    else "success"
                    if sta == "success"
                    else "blocked"
                    if sta in ("blocked", "403", "403")
                    else "normal"
                )
                rows_html += (
                    f'<div class="feed-row {css}">'
                    f"{ts}  {met:<4}  {ep:<22} {usr:<10} {ip:<16} [{sta.upper()}]"
                    f"</div>"
                )
            st.markdown(
                f'<div class="feed-container">{rows_html}</div>', unsafe_allow_html=True
            )

        st.markdown("<br>", unsafe_allow_html=True)

        # Endpoint hit count
        st.markdown(
            '<div class="section-head">◈ ENDPOINT HIT COUNT</div>',
            unsafe_allow_html=True,
        )
        if not events_df.empty and "endpoint" in events_df.columns:
            ep_counts = events_df["endpoint"].value_counts().head(8).reset_index()
            ep_counts.columns = ["Endpoint", "Hits"]
            st.dataframe(
                ep_counts,
                width="stretch",
                hide_index=True,
                column_config={
                    "Endpoint": st.column_config.TextColumn("Endpoint"),
                    "Hits": st.column_config.ProgressColumn(
                        "Hits",
                        min_value=0,
                        max_value=int(ep_counts["Hits"].max())
                        if not ep_counts.empty
                        else 1,
                    ),
                },
            )
        else:
            st.markdown(
                '<div class="empty-state">NO ENDPOINT DATA YET</div>',
                unsafe_allow_html=True,
            )

    # ────────────────────────────── RIGHT COLUMN ──────────────────────────────
    with right:
        st.markdown(
            '<div class="section-head">◈ DETECTION ENGINE  ·  AI SOC ANALYST REPORTS</div>',
            unsafe_allow_html=True,
        )

        if threats_df.empty:
            st.markdown(
                '<div class="empty-state">NO THREATS DETECTED YET</div>',
                unsafe_allow_html=True,
            )
        else:
            # st.container(height=...) is Streamlit's native scrollable box —
            # far more reliable than a CSS max-height trick on a single markdown blob.
            with st.container(height=530, border=False):
                for _, t in threats_df.iterrows():
                    # risk_level is uppercase from the real agent ("HIGH", "CRITICAL")
                    # capitalize() converts "HIGH"→"High" for CSS class matching
                    risk_raw = str(t.get("risk_level", "LOW")).upper()
                    risk = risk_raw.capitalize()  # "HIGH" → "High" for CSS/badges
                    conf = int(t.get("confidence") or 50)
                    ttype = safe_html(t.get("threat_type", "Unknown"))
                    ip = safe_html(t.get("source_ip", "?"))
                    # real agent uses 'timestamp'; mock used 'detected_at' — handle both
                    ts = fmt_time(str(t.get("timestamp") or t.get("detected_at") or ""))
                    # mitigation is no longer stored in the row — look it up from threat_type
                    raw_ttype = str(t.get("threat_type", ""))
                    mit = safe_html(
                        MITIGATIONS.get(
                            raw_ttype,
                            "Investigate the source IP and review recent logs.",
                        )
                    )
                    llm = safe_html(t.get("llm_report", ""))
                    hypothesis = safe_html(t.get("llm_hypothesis", ""))
                    cache_used = int(t.get("llm_cache_used") or 0)

                    # Parse triggered_rules safely
                    raw_rules = t.get("triggered_rules", "[]") or "[]"
                    try:
                        rules = json.loads(raw_rules)
                    except (json.JSONDecodeError, TypeError):
                        rules = []

                    rule_tags = "".join(
                        f'<span class="rule-tag">{safe_html(r)}</span>' for r in rules
                    )
                    conf_bar = (
                        f'<div class="conf-bar-bg">'
                        f'<div class="conf-bar-fill" style="width:{conf}%;background:{conf_color(conf)}"></div>'
                        f"</div>"
                    )
                    badge = f'<span class="badge badge-{risk}">{risk_raw}</span>'

                    # LLM source badge — shown whenever LLM text is present
                    if llm or hypothesis:
                        if cache_used:
                            llm_status_block = (
                                '<div class="llm-cache-badge">'
                                "⚡ CACHED RESPONSE — Attack pattern already seen within last 5 min"
                                " · Ollama call skipped, 0 new API tokens used"
                                "</div>"
                            )
                        else:
                            llm_status_block = (
                                '<div class="llm-live-badge">'
                                "🔴 LIVE LLM CALL — Ollama analysed this threat in real-time"
                                "</div>"
                            )
                    else:
                        llm_status_block = ""

                    hyp_block = (
                        f'<div class="llm-label">◈ AI HYPOTHESIS</div>'
                        f'<div class="llm-report" style="border-color:#1c3a2a;color:#8b949e;font-style:italic">{hypothesis}</div>'
                        if hypothesis
                        else ""
                    )

                    llm_block = (
                        f'<div class="llm-label">◉ AI SOC ANALYST REPORT</div>'
                        f'<div class="llm-report">{llm}</div>'
                        if llm
                        else ""
                    )

                    mit_block = (
                        f'<div class="mitigation">⬡ MITIGATION: {mit}</div>'
                        if mit
                        else ""
                    )

                    st.markdown(
                        f'<div class="threat-card {risk}">'
                        f'<div class="threat-type">{badge} {ttype.upper()}</div>'
                        f'<div class="threat-meta">⏱ {ts} &nbsp;|&nbsp; ⚡ {ip} &nbsp;|&nbsp; CONFIDENCE {conf}%</div>'
                        f"{conf_bar}"
                        f'<div style="margin:4px 0">{rule_tags}</div>'
                        f"{llm_status_block}"
                        f"{hyp_block}"
                        f"{llm_block}"
                        f"{mit_block}"
                        f"</div>",
                        unsafe_allow_html=True,
                    )

    # ── Bottom analytics tabs (replaces 3-column row to avoid page over-scroll) ─
    st.markdown("---")
    tab1, tab2, tab3, tab4, tab5 = st.tabs(
        [
            "◈  EVENTS TIMELINE",
            "◈  ATTACK TYPES",
            "◈  TOP ATTACKING IPs",
            "◈  BLOCKED IPs",
            "◈  LOG CLEANUP",
        ]
    )

    # ── Tab 1: Events Timeline ────────────────────────────────────────────────
    with tab1:
        tl = get_timeline_data()
        if tl.empty:
            st.markdown(
                '<div class="empty-state">AWAITING DATA...</div>',
                unsafe_allow_html=True,
            )
        else:
            chart = (
                alt.Chart(tl)
                .mark_bar(
                    color="#00ffe7",
                    opacity=0.75,
                    cornerRadiusTopLeft=2,
                    cornerRadiusTopRight=2,
                )
                .encode(
                    x=alt.X(
                        "bucket:N", axis=alt.Axis(title="Time (UTC)", labelAngle=-40)
                    ),
                    y=alt.Y("Events:Q", axis=alt.Axis(title="Event Count")),
                    tooltip=["bucket:N", "Events:Q"],
                )
                .properties(**_CHART_CFG)
                .configure_axis(**_AXIS_KWARGS)
                .configure_view(stroke="transparent")
            )
            st.altair_chart(chart, width="stretch")

    # ── Tab 2: Attack Type Distribution ───────────────────────────────────────
    with tab2:
        if threats_df.empty or "threat_type" not in threats_df.columns:
            st.markdown(
                '<div class="empty-state">NO THREAT DATA</div>', unsafe_allow_html=True
            )
        else:
            type_counts = threats_df["threat_type"].value_counts().reset_index()
            type_counts.columns = ["Threat Type", "Count"]

            color_map = {
                "Brute Force": "#f85149",
                "Data Exfiltration": "#d29922",
                "Reconnaissance": "#58a6ff",
            }
            type_counts["color"] = type_counts["Threat Type"].map(
                lambda x: color_map.get(str(x), "#8b949e")
            )

            bar_chart = (
                alt.Chart(type_counts)
                .mark_bar(cornerRadiusTopRight=2, cornerRadiusBottomRight=2)
                .encode(
                    y=alt.Y("Threat Type:N", sort="-x", axis=alt.Axis(title=None)),
                    x=alt.X("Count:Q", axis=alt.Axis(title="Count")),
                    color=alt.Color("color:N", scale=None, legend=None),
                    tooltip=["Threat Type:N", "Count:Q"],
                )
                .properties(**_CHART_CFG)
                .configure_axis(**_AXIS_KWARGS)
                .configure_view(stroke="transparent")
            )
            st.altair_chart(bar_chart, width="stretch")

    # ── Tab 3: Top Attacking IPs ──────────────────────────────────────────────
    with tab3:
        ip_df = get_top_ips()
        if ip_df.empty:
            st.markdown(
                '<div class="empty-state">NO IP DATA</div>', unsafe_allow_html=True
            )
        else:
            max_events = int(ip_df["Total Events"].max()) if not ip_df.empty else 1
            st.dataframe(
                ip_df,
                width="stretch",
                hide_index=True,
                height=220,
                column_config={
                    "IP Address": st.column_config.TextColumn("IP Address"),
                    "Total Events": st.column_config.ProgressColumn(
                        "Total Events", min_value=0, max_value=max_events
                    ),
                    "Failed Requests": st.column_config.NumberColumn(
                        "Failed Req.", format="%d"
                    ),
                },
            )

    # ── Tab 4: Blocked IPs ────────────────────────────────────────────────────
    with tab4:
        blocked_df = get_blocked_ips()
        if blocked_df.empty:
            st.markdown(
                '<div class="empty-state">NO BLOCKED IPs — AGENT HAS NOT BLOCKED ANY IPs YET</div>',
                unsafe_allow_html=True,
            )
        else:
            n_blocked = (
                int((blocked_df["status"] == "blocked").sum())
                if "status" in blocked_df.columns
                else 0
            )
            n_unblocked = (
                int((blocked_df["status"] == "unblocked").sum())
                if "status" in blocked_df.columns
                else 0
            )
            st.markdown(
                f'<div class="blocked-header">'
                f"⛔ {n_blocked} ACTIVE BLOCK(S) &nbsp;·&nbsp; ✓ {n_unblocked} CLEARED"
                f"</div>",
                unsafe_allow_html=True,
            )
            for _, brow in blocked_df.iterrows():
                b_ip = safe_html(brow.get("ip", "?"))
                b_reason = safe_html(brow.get("reason", "—"))
                b_risk = safe_html(str(brow.get("risk_level", "—")).upper())
                b_time = fmt_time(str(brow.get("blocked_at") or ""))
                b_status = str(brow.get("status", "blocked")).lower()
                b_row_id = int(brow.get("id") or 0)
                b_cleared = brow.get("unblocked_at")

                risk_col = "#f85149" if b_risk == "CRITICAL" else "#d29922"
                stat_col = "#f85149" if b_status == "blocked" else "#3fb950"
                stat_label = "⛔ BLOCKED" if b_status == "blocked" else "✓ UNBLOCKED"
                cleared_str = (
                    f" &nbsp;|&nbsp; ✓ Cleared: {fmt_time(str(b_cleared))}"
                    if b_cleared
                    else ""
                )

                col_info, col_btn = st.columns([4, 1])
                with col_info:
                    st.markdown(
                        f'<div style="background:#0d1117;border:1px solid #21262d;'
                        f"border-left:3px solid {risk_col};border-radius:4px;"
                        f'padding:0.55rem 0.8rem;margin-bottom:4px;">'
                        f"<span style=\"font-family:'Share Tech Mono',monospace;"
                        f"font-size:0.85rem;font-weight:700;color:{risk_col};"
                        f'">{b_ip}</span>'
                        f'&nbsp;&nbsp;<span style="font-size:0.6rem;font-weight:700;'
                        f"color:{stat_col};background:rgba(0,0,0,0.3);"
                        f'padding:1px 7px;border-radius:10px;">{stat_label}</span>'
                        f'<div style="font-size:0.67rem;color:#8b949e;margin-top:3px;'
                        f"font-family:'Share Tech Mono',monospace;\">"
                        f"⚡ {b_reason} &nbsp;|&nbsp; ⏱ {b_time}{cleared_str}"
                        f"</div></div>",
                        unsafe_allow_html=True,
                    )
                with col_btn:
                    if b_status == "blocked":
                        if st.button(
                            "Unblock",
                            key=f"unblock_{b_row_id}",
                            type="secondary",
                            use_container_width=True,
                        ):
                            try:
                                _uc = sqlite3.connect(DB_PATH)
                                _uc.execute(
                                    "UPDATE blocked_ips "
                                    "SET status = 'unblocked', "
                                    "    unblocked_at = datetime('now') "
                                    "WHERE id = ?",
                                    (b_row_id,),
                                )
                                _uc.commit()
                                _uc.close()
                            except Exception as _ue:
                                st.error(f"Unblock failed: {_ue}")
                    else:
                        st.caption("Cleared")

    # ── Tab 5: Log Cleanup ────────────────────────────────────────────────────
    with tab5:
        st.markdown(
            '<div class="section-head">◈ LOG CLEANUP — ELIGIBLE: LOGS OLDER THAN 15 MINUTES</div>',
            unsafe_allow_html=True,
        )

        if not db_ok():
            st.markdown(
                '<div class="empty-state">DATABASE NOT FOUND</div>',
                unsafe_allow_html=True,
            )
        else:
            try:
                _cl = sqlite3.connect(DB_PATH)

                _eligible = int(
                    pd.read_sql_query(
                        "SELECT COUNT(*) AS n FROM logs "
                        "WHERE timestamp < datetime('now', '-15 minutes')",
                        _cl,
                    ).iloc[0]["n"]
                )
                _recent = int(
                    pd.read_sql_query(
                        "SELECT COUNT(*) AS n FROM logs "
                        "WHERE timestamp >= datetime('now', '-15 minutes')",
                        _cl,
                    ).iloc[0]["n"]
                )
                _total_logs = _eligible + _recent
                _alert_count = int(
                    pd.read_sql_query("SELECT COUNT(*) AS n FROM alerts", _cl).iloc[0][
                        "n"
                    ]
                )
                _oldest_eligible = (
                    pd.read_sql_query(
                        "SELECT MIN(timestamp) AS t FROM logs "
                        "WHERE timestamp < datetime('now', '-15 minutes')",
                        _cl,
                    ).iloc[0]["t"]
                    or "—"
                )
                _breakdown = pd.read_sql_query(
                    "SELECT event_type, COUNT(*) AS cnt FROM logs "
                    "WHERE timestamp < datetime('now', '-15 minutes') "
                    "GROUP BY event_type ORDER BY cnt DESC",
                    _cl,
                )
                _cl.close()

                # ── Stats row ─────────────────────────────────────────────────
                cs1, cs2, cs3, cs4 = st.columns(4)
                for _col, _cls, _val, _lbl in [
                    (cs1, "blue", _total_logs, "TOTAL LOGS"),
                    (cs2, "red", _eligible, "ELIGIBLE (>15M)"),
                    (cs3, "green", _recent, "RECENT (<15M, KEPT)"),
                    (cs4, "yellow", _alert_count, "ALERTS PRESERVED"),
                ]:
                    _col.markdown(
                        f'<div class="metric-card {_cls}">'
                        f'<div class="metric-value">{_val}</div>'
                        f'<div class="metric-label">{_lbl}</div>'
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                st.markdown("<br>", unsafe_allow_html=True)

                if _eligible == 0:
                    st.markdown(
                        '<div class="empty-state">✅ &nbsp; NO LOGS OLDER THAN 15 MINUTES — NOTHING TO DELETE</div>',
                        unsafe_allow_html=True,
                    )
                    st.session_state.confirm_cleanup_logs = False
                else:
                    # ── Breakdown table ───────────────────────────────────────
                    st.markdown(
                        '<div class="section-head">BREAKDOWN OF ELIGIBLE LOGS BY TYPE</div>',
                        unsafe_allow_html=True,
                    )
                    if not _breakdown.empty:
                        for _, _br in _breakdown.iterrows():
                            pct = int(_br["cnt"] / _eligible * 100) if _eligible else 0
                            st.markdown(
                                f'<div style="display:flex;align-items:center;'
                                f'gap:0.6rem;margin-bottom:4px;">'
                                f"<span style=\"font-family:'Share Tech Mono',monospace;"
                                f'font-size:0.7rem;color:#8b949e;width:160px;">'
                                f"{safe_html(str(_br['event_type']))}</span>"
                                f'<div style="flex:1;background:#21262d;border-radius:3px;height:6px;">'
                                f'<div style="width:{pct}%;background:#f85149;'
                                f'height:6px;border-radius:3px;"></div></div>'
                                f"<span style=\"font-family:'Share Tech Mono',monospace;"
                                f'font-size:0.7rem;color:#f85149;width:50px;text-align:right;">'
                                f"{int(_br['cnt'])}</span>"
                                f"</div>",
                                unsafe_allow_html=True,
                            )

                    st.markdown(
                        f'<div class="sidebar-summary-box" style="margin-top:0.6rem;">'
                        f"📅 Oldest eligible log: <b>{str(_oldest_eligible)[:19]}</b><br>"
                        f"🛡 <b>{_recent}</b> recent log(s) will be <b>kept</b>. "
                        f"&nbsp;&nbsp;🔒 All <b>{_alert_count}</b> alert(s) are always preserved."
                        f"</div>",
                        unsafe_allow_html=True,
                    )

                    st.markdown("<br>", unsafe_allow_html=True)

                    # ── Two-step confirmation ─────────────────────────────────
                    if not st.session_state.confirm_cleanup_logs:
                        if st.button(
                            f"🗑  Delete {_eligible} Log(s) Older Than 15 Minutes",
                            type="secondary",
                            use_container_width=True,
                            help="Only logs older than 15 minutes are deleted. Recent logs and all alerts are preserved.",
                        ):
                            st.session_state.confirm_cleanup_logs = True
                            st.rerun()
                    else:
                        st.warning(
                            f"⚠ This will permanently delete **{_eligible}** log entr{'y' if _eligible == 1 else 'ies'} "
                            f"older than 15 minutes. **{_recent}** recent log(s) and all **{_alert_count}** alert(s) will be kept."
                        )
                        _cc1, _cc2 = st.columns(2)
                        with _cc1:
                            if st.button(
                                "✓ Confirm Delete",
                                type="primary",
                                use_container_width=True,
                            ):
                                try:
                                    _dc = sqlite3.connect(DB_PATH)
                                    _dc.execute(
                                        "DELETE FROM logs "
                                        "WHERE timestamp < datetime('now', '-15 minutes')"
                                    )
                                    _deleted = _dc.total_changes
                                    _dc.commit()
                                    _dc.close()
                                    st.session_state.confirm_cleanup_logs = False
                                    st.success(
                                        f"✓ {_deleted} log(s) deleted. Recent logs and alerts intact."
                                    )
                                except Exception as _de:
                                    st.error(f"Delete failed: {_de}")
                        with _cc2:
                            if st.button("✗ Cancel", use_container_width=True):
                                st.session_state.confirm_cleanup_logs = False
                                st.rerun()

            except Exception as _ce:
                st.error(f"Could not load cleanup stats: {_ce}")
                st.session_state.confirm_cleanup_logs = False


# ── Entry point ───────────────────────────────────────────────────────────────
live_dashboard()
