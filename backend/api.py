from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from backend.db import get_connection, init_db
from backend.logger import log_event

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_ip(request: Request) -> str:
    """
    Extract the real client IP, checking simulation/proxy headers first.

    Priority order:
      1. X-Forwarded-For  — injected by Requestly to simulate different attacker
                            IPs. The leftmost value is the original client IP.
      2. X-Real-IP        — set by nginx / HAProxy in production deployments.
      3. request.client.host — actual TCP connection IP (local machine / LAN).
      4. "unknown"        — final fallback if none of the above are available.

    This ordering means Requestly can set X-Forwarded-For to any IP address
    (e.g. "45.33.32.156") and every layer below — log_event(), the SQLite DB,
    the rules engine, and the Streamlit dashboard — will treat that value as
    the real source IP, enabling fully distributed attack simulation from a
    single machine.
    """
    # 1. X-Forwarded-For — Requestly injects this for distributed attack simulation
    xff = request.headers.get("X-Forwarded-For", "").strip()
    if xff:
        # Take the leftmost (original client) entry; ignore any proxy chain IPs
        candidate = xff.split(",")[0].strip()
        if candidate:
            return candidate

    # 2. X-Real-IP — nginx / HAProxy style single-value header
    xri = request.headers.get("X-Real-IP", "").strip()
    if xri:
        return xri

    # 3. Actual TCP connection IP (fallback for direct requests without headers)
    if request.client is not None:
        return request.client.host

    # 4. Nothing available
    return "unknown"


# ---------------------------------------------------------------------------
# Lifespan – runs init_db() once when the server starts
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()  # ensure schema exists before the first request
    yield  # app is running
    # (shutdown logic goes here if needed)


def _is_ip_blocked(ip: str) -> bool:
    """
    Check whether the given IP address has an active block entry in the
    blocked_ips table.  Returns False on any DB error (fail-open) so a
    missing or locked database never hard-stops incoming traffic.
    """
    try:
        conn = get_connection()
        cur = conn.execute(
            "SELECT 1 FROM blocked_ips WHERE ip = ? AND status = 'blocked' LIMIT 1",
            (ip,),
        )
        blocked = cur.fetchone() is not None
        conn.close()
        return blocked
    except Exception:
        # Table may not exist yet if the agent hasn't run its first cycle.
        # Fail-open: never block traffic due to a DB lookup error.
        return False


app = FastAPI(
    title="Cyber Threat Hunting – Victim App",
    description=(
        "A deliberately exposed dummy application used as the attack target "
        "during the hackathon demo.  All requests are logged to data/logs.sqlite "
        "so the Threat Hunting Agent can analyse them in real time."
    ),
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# IP Block Middleware
# Runs before every route handler. Checks the blocked_ips table written by
# the agent. If the source IP is blocked, the connection is killed with a
# 403 Forbidden immediately — the route handler never executes.
#
# Skipped for /health so the health-check endpoint never adds DB overhead
# and never gets accidentally blocked during a demo.
# ---------------------------------------------------------------------------


@app.middleware("http")
async def block_ip_middleware(request: Request, call_next):
    # Health check bypass — never block, never add DB overhead
    if request.url.path == "/health":
        return await call_next(request)

    ip = _get_ip(request)
    if _is_ip_blocked(ip):
        # Log the blocked request so it appears in the SOC events feed.
        # Without this the dashboard goes dark for a blocked IP — every
        # request after the block is silently dropped and never written
        # to the DB, making it look like the attack stopped.
        try:
            log_event(
                event_type="page_access",
                method=request.method,
                endpoint=str(request.url.path) or "/",
                username=None,
                ip=ip,
                status_code=403,
                status="blocked",
            )
        except Exception:
            pass  # never let a logging failure break the middleware response
        return JSONResponse(
            status_code=403,
            content={
                "blocked": True,
                "message": (
                    f"IP {ip} has been blocked by the autonomous threat hunting agent. "
                    "Contact your SOC team to request an unblock."
                ),
            },
        )

    return await call_next(request)


# ---------------------------------------------------------------------------
# Root
# ---------------------------------------------------------------------------


@app.get("/")
def root():
    return {"message": "Cyber Threat Detection Victim API Running"}


# ---------------------------------------------------------------------------
# Auth endpoints  (triggers: Brute Force, Credential Stuffing, Account Takeover)
# ---------------------------------------------------------------------------

# Hard-coded "valid" credentials for the demo so an Account Takeover can be
# demonstrated by eventually guessing the right password.
_VALID_CREDENTIALS: dict[str, str] = {
    "admin": "supersecret",
    "root": "toor",
    "alice": "alice123",
    "bob": "bobpass",
}


@app.post("/login")
async def login(request: Request):
    """
    Primary authentication endpoint.
    Accepts JSON body: {"username": "...", "password": "..."}
    Returns 200 on success, 401 on failure.
    Logs every attempt so the agent can spot brute-force / credential-stuffing.
    """
    ip = _get_ip(request)

    try:
        data = await request.json()
    except Exception:
        data = {}

    username: str = str(data.get("username", "unknown"))
    password: Optional[str] = data.get("password")

    # Determine outcome
    expected = _VALID_CREDENTIALS.get(username)
    if expected is not None and password == expected:
        status_code = 200
        status = "success"
    else:
        status_code = 401
        status = "fail"

    log_event(
        event_type="login_attempt",
        method="POST",
        endpoint="/login",
        username=username,
        ip=ip,
        status_code=status_code,
        status=status,
    )

    if status == "success":
        return JSONResponse(
            status_code=200,
            content={"message": f"Welcome, {username}!", "token": "demo-jwt-token"},
        )
    return JSONResponse(status_code=401, content={"message": "Invalid credentials"})


@app.post("/api/auth/login")
async def api_auth_login(request: Request):
    """Alternate login path — some scanners hit both /login and /api/auth/login."""
    ip = _get_ip(request)

    try:
        data = await request.json()
    except Exception:
        data = {}

    username: str = str(data.get("username", "unknown"))
    password: Optional[str] = data.get("password")

    expected = _VALID_CREDENTIALS.get(username)
    if expected is not None and password == expected:
        status_code, status = 200, "success"
    else:
        status_code, status = 401, "fail"

    log_event(
        event_type="login_attempt",
        method="POST",
        endpoint="/api/auth/login",
        username=username,
        ip=ip,
        status_code=status_code,
        status=status,
    )

    if status == "success":
        return JSONResponse(
            status_code=200, content={"message": f"Authenticated as {username}"}
        )
    return JSONResponse(status_code=401, content={"message": "Unauthorized"})


# ---------------------------------------------------------------------------
# Restricted admin / config endpoints
# (triggers: Endpoint Reconnaissance, Unauthorized Access Scan)
# ---------------------------------------------------------------------------


@app.get("/admin")
async def admin(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/admin",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Admin access denied"})


@app.get("/config")
async def config(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/config",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Forbidden"})


@app.get("/internal")
async def internal(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/internal",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Forbidden"})


@app.get("/dashboard")
async def dashboard_admin(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/dashboard",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(
        status_code=403, content={"message": "Dashboard access restricted"}
    )


@app.get("/settings")
async def settings(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/settings",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Settings access denied"})


@app.get("/env")
async def env_file(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/env",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Forbidden"})


@app.get("/.env")
async def dot_env(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/.env",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Forbidden"})


@app.get("/api/keys")
async def api_keys(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/api/keys",
        username=None,
        ip=ip,
        status_code=403,
        status="blocked",
    )
    return JSONResponse(status_code=403, content={"message": "Forbidden"})


# ---------------------------------------------------------------------------
# Data-serving endpoints
# (triggers: Data Exfiltration rule — high-volume successful GETs)
# ---------------------------------------------------------------------------

_MOCK_USERS = [
    {"id": i, "username": f"user_{i}", "email": f"user_{i}@example.com"}
    for i in range(1, 11)
]


@app.get("/api/users")
async def list_users(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/api/users",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"users": _MOCK_USERS, "total": len(_MOCK_USERS)}


@app.get("/api/user/{user_id}")
async def get_user(user_id: int, request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint=f"/api/user/{user_id}",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {
        "id": user_id,
        "username": f"user_{user_id}",
        "email": f"user_{user_id}@example.com",
    }


@app.get("/api/data")
async def get_data(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/api/data",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"records": [{"id": i, "value": f"record_{i}"} for i in range(1, 21)]}


@app.get("/data")
async def data(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/data",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"data": "Sensitive business data payload"}


@app.get("/export")
async def export_data(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/export",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"export": "Full data export", "rows": 1000}


@app.get("/api/export")
async def api_export(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/api/export",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"export": "API data export payload", "format": "json"}


@app.get("/download")
async def download(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/download",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"file": "sensitive_report.csv", "size_bytes": 204800}


@app.get("/reports")
async def reports(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/reports",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"reports": [{"id": i, "title": f"Report {i}"} for i in range(1, 6)]}


@app.get("/backup")
async def backup(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/backup",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"backup": "Database backup snapshot", "timestamp": "2024-01-01T00:00:00Z"}


@app.get("/files")
async def files(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/files",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"files": ["passwords.txt", "config.yaml", "private_key.pem"]}


@app.get("/dump")
async def dump(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="api_call",
        method="GET",
        endpoint="/dump",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"dump": "Full database dump payload"}


# ---------------------------------------------------------------------------
# General-purpose API endpoints (normal benign traffic)
# ---------------------------------------------------------------------------


@app.get("/profile")
async def profile(request: Request):
    ip = _get_ip(request)
    log_event(
        event_type="page_access",
        method="GET",
        endpoint="/profile",
        username=None,
        ip=ip,
        status_code=200,
        status="success",
    )
    return {"message": "User profile page"}


@app.get("/health")
async def health(request: Request):
    """Health-check endpoint — not logged (reduces noise in the demo DB)."""
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Catch-all for path traversal attempts
# (triggers: Path Traversal Attack rule — ../ patterns in endpoint URL)
# ---------------------------------------------------------------------------


@app.api_route(
    "/{full_path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
)
async def catch_all(full_path: str, request: Request):
    """
    Catch-all route — logs any request that doesn't match a real endpoint.
    This captures directory-traversal probes (../../etc/passwd) and random
    scanner hits so the rules engine can detect them.
    """
    ip = _get_ip(request)
    endpoint = f"/{full_path}"

    log_event(
        event_type="page_access",
        method=request.method,
        endpoint=endpoint,
        username=None,
        ip=ip,
        status_code=404,
        status="blocked",
    )
    return JSONResponse(status_code=404, content={"message": "Not found"})
