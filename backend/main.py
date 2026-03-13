"""
Cyber Threat Hunting Agent – Backend Entry Point
=================================================
Run with:   python main.py
This initialises the shared SQLite database (data/logs.sqlite) from the
schema definition (data/schema.sql) and then starts the FastAPI victim-app
server via Uvicorn.
"""

import uvicorn

from backend.db import init_db


def main():
    # 1. Ensure the database schema is up-to-date
    init_db()

    # 2. Launch the FastAPI application
    uvicorn.run(
        "backend.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
    )


if __name__ == "__main__":
    main()
