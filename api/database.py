"""
TransWAF - Async SQLite Database Layer
Stores all classified requests for history, analytics, and audit.
"""

import aiosqlite
from pathlib import Path
from datetime import datetime
from typing import Optional
from loguru import logger

DB_PATH = Path(__file__).parent.parent / "transwaf.db"


async def init_db():
    """Create database tables if they don't exist."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                label       TEXT NOT NULL,
                label_display TEXT NOT NULL,
                confidence  REAL NOT NULL,
                action      TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                latency_ms  REAL NOT NULL,
                normalized_text TEXT,
                all_scores  TEXT
            )
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON requests(timestamp);
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_action ON requests(action);
        """)
        await db.execute("""
            CREATE INDEX IF NOT EXISTS idx_label ON requests(label);
        """)
        await db.commit()
    logger.info(f"Database initialized at {DB_PATH}")


async def insert_request(result: dict) -> int:
    """Insert a classification result into the database."""
    import json
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO requests
                (timestamp, label, label_display, confidence, action,
                 threat_level, latency_ms, normalized_text, all_scores)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.utcnow().isoformat() + "Z",
                result.get("label", "unknown"),
                result.get("label_display", "Unknown"),
                result.get("confidence", 0.0),
                result.get("action", "ALLOW"),
                result.get("threat_level", "NONE"),
                result.get("latency_ms", 0.0),
                result.get("normalized_text", "")[:1000],
                json.dumps(result.get("all_scores", {})),
            ),
        )
        await db.commit()
        return cursor.lastrowid


async def get_stats() -> dict:
    """Compute aggregated statistics from request history."""
    async with aiosqlite.connect(DB_PATH) as db:
        # Total counts
        cursor = await db.execute("SELECT COUNT(*) FROM requests")
        total = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM requests WHERE action='BLOCK'")
        blocked = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM requests WHERE action='FLAG'")
        flagged = (await cursor.fetchone())[0]

        cursor = await db.execute("SELECT COUNT(*) FROM requests WHERE action='ALLOW'")
        allowed = (await cursor.fetchone())[0]

        # Per-label breakdown
        cursor = await db.execute(
            "SELECT label, COUNT(*) as cnt FROM requests GROUP BY label ORDER BY cnt DESC"
        )
        rows = await cursor.fetchall()
        attack_breakdown = {row[0]: row[1] for row in rows}

        # Average latency
        cursor = await db.execute("SELECT AVG(latency_ms) FROM requests")
        avg_lat = (await cursor.fetchone())[0] or 0.0

    return {
        "total_requests": total,
        "blocked": blocked,
        "flagged": flagged,
        "allowed": allowed,
        "attack_breakdown": attack_breakdown,
        "avg_latency_ms": round(avg_lat, 2),
    }


async def get_history(page: int = 1, page_size: int = 50, action_filter: Optional[str] = None) -> dict:
    """Fetch paginated request history."""
    offset = (page - 1) * page_size

    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        if action_filter:
            count_cursor = await db.execute(
                "SELECT COUNT(*) FROM requests WHERE action=?", (action_filter,)
            )
            total = (await count_cursor.fetchone())[0]
            cursor = await db.execute(
                "SELECT * FROM requests WHERE action=? ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (action_filter, page_size, offset),
            )
        else:
            count_cursor = await db.execute("SELECT COUNT(*) FROM requests")
            total = (await count_cursor.fetchone())[0]
            cursor = await db.execute(
                "SELECT * FROM requests ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                (page_size, offset),
            )

        rows = await cursor.fetchall()
        items = [dict(row) for row in rows]

    return {"items": items, "total": total, "page": page, "page_size": page_size}
