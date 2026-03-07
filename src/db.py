"""
VantaOps — Database layer (PostgreSQL)

Shared module used by the Slack bot, poller, and remediation engine.
"""

import os
import psycopg2
import psycopg2.extras

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://vantaops:vantaops@localhost:5432/vantaops",
)


def get_db():
    """Get a PostgreSQL connection with dict-like row access."""
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn


def dict_cursor(conn):
    """Return a cursor that yields dict-like rows."""
    return conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)


def init_db():
    """Create tables if they don't exist."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS vanta_tasks (
            task_id         TEXT PRIMARY KEY,
            title           TEXT NOT NULL,
            description     TEXT,
            due_date        TEXT,
            framework       TEXT,
            resource_id     TEXT,
            resource_type   TEXT,
            account_id      TEXT,
            region          TEXT,
            remediation_type TEXT,
            status          TEXT DEFAULT 'pending',
            notified_at     TEXT,
            remediated_at   TEXT,
            remediated_by   TEXT,
            slack_ts        TEXT,
            raw_json        TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id              SERIAL PRIMARY KEY,
            timestamp       TEXT NOT NULL,
            task_id         TEXT,
            action          TEXT NOT NULL,
            account_id      TEXT,
            region          TEXT,
            command         TEXT,
            output          TEXT,
            exit_code       INTEGER,
            approved_by     TEXT,
            approved_at     TEXT,
            verification    TEXT
        );

        CREATE TABLE IF NOT EXISTS poller_state (
            key     TEXT PRIMARY KEY,
            value   TEXT
        );

        CREATE TABLE IF NOT EXISTS knowledge_base (
            id              SERIAL PRIMARY KEY,
            created_at      TEXT NOT NULL,
            task_id         TEXT,
            remediation_type TEXT,
            problem         TEXT NOT NULL,
            solution        TEXT,
            pitfalls        TEXT,
            tags            TEXT,
            source          TEXT DEFAULT 'slack'
        );
    """)
    conn.commit()
    cur.close()
    conn.close()
