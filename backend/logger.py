from backend.db import get_connection


def log_event(event_type, method, endpoint, username, ip, status_code, status):
    """Insert a single log row into the logs table."""

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO logs
        (event_type, method, endpoint, username, ip, status_code, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        event_type,
        method,
        endpoint,
        username,
        ip,
        status_code,
        status
    ))

    conn.commit()
    conn.close()