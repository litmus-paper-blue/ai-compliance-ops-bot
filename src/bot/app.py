"""
VantaOps — Slack Bot (Bolt for Python, Socket Mode)

Handles interactive notifications, approval buttons, and remediation
triggers from Slack. Runs as a standalone service alongside OpenClaw.
"""

import os
import sys
import re
import json
import hashlib
import logging
import subprocess
from difflib import SequenceMatcher
from datetime import datetime, timezone
from typing import Optional

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from db import get_db, dict_cursor, init_db
from llm import LLMRouter
from vanta_client import VantaClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

SLACK_BOT_TOKEN = os.environ["SLACK_BOT_TOKEN"]
SLACK_APP_TOKEN = os.environ["SLACK_APP_TOKEN"]  # xapp-... token for Socket Mode
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")

SCRIPTS_DIR = os.environ.get("VANTAOPS_SCRIPTS_DIR", "/app/src/scripts")

# Allowed Slack user IDs who can approve remediations
ALLOWED_APPROVERS = os.environ.get(
    "VANTAOPS_APPROVERS", ""
).split(",")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("vantaops-slack")

# ---------------------------------------------------------------------------
# App Setup
# ---------------------------------------------------------------------------

app = App(token=SLACK_BOT_TOKEN)
llm = None    # initialized after db in main()
vanta = None  # initialized after db in main()
live_resource_lookup_enabled = True

SYSTEM_PROMPT = """You are VantaOps, an AI-powered Vanta compliance remediation assistant.

Your job is to help users understand and fix AWS compliance findings flagged by Vanta.
You cover: CloudWatch, S3, security groups, SSM patching, CloudTrail/Config, RDS, DynamoDB, EKS, GuardDuty, Inspector, ACM, VPC flow logs, and more.

When a user asks about a specific task or finding:
1. Reference the exact task from the database context (title, due date, type, account, region).
2. Explain *what* the finding means and *why* it matters for compliance.
3. Explain *how* to fix it step by step. Be specific — mention the exact AWS CLI commands or console steps.
4. If the task is auto-remediable, tell the user they can click "View Plan & Remediate" on the Slack notification, or use `/vantaops task <id>` to see details.
5. If the user says "yes", "proceed", "fix it", "remediate" — guide them to the Slack notification button or provide the `/vantaops task <id>` command. Don't lose context.

When a user asks a follow-up or says "yes":
- Remember what you were just discussing. The conversation history is provided — use it.
- Don't start fresh or ask "what would you like help with?" — continue the thread.

Rules:
- Be concise. Use Slack-friendly formatting (*bold*, `code`, bullet points).
- Never fabricate task IDs, AWS resource IDs, or compliance details — only reference what's in the database context.
- If you have relevant lessons from past remediations (provided in context), reference them.
- If you don't know something, say so and suggest checking Vanta or AWS directly.
- Remediation execution requires explicit approval via the Slack button — you cannot execute AWS commands directly.
- IAM policy changes are always manual — flag these and explain why.
"""


def _extract_lookahead_days(message: str) -> int:
    """Extract a day-range from the user's message, default 7."""
    # Match patterns like "10 days", "in 12 days", "due 30 days", "next 14 days"
    m = re.search(r'(\d+)\s*days?', message.lower())
    if m:
        return min(int(m.group(1)), 365)
    # Match specific dates like "March 14" or "2026-03-19"
    # Calculate days from now to that date
    date_patterns = [
        (r'(\w+)\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s*(\d{4}))?', '%B %d %Y'),
        (r'(\d{4})-(\d{2})-(\d{2})', None),
    ]
    for pattern, fmt in date_patterns:
        match = re.search(pattern, message)
        if match:
            try:
                if fmt:
                    month_str, day_str = match.group(1), match.group(2)
                    year_str = match.group(3) or str(datetime.now(timezone.utc).year)
                    target = datetime.strptime(f"{month_str} {day_str} {year_str}", fmt)
                    target = target.replace(tzinfo=timezone.utc)
                else:
                    target = datetime(int(match.group(1)), int(match.group(2)), int(match.group(3)), tzinfo=timezone.utc)
                days = (target - datetime.now(timezone.utc)).days
                if days > 0:
                    return min(days, 365)
            except (ValueError, TypeError):
                pass
    return 7


def _extract_specific_date_iso(message: str) -> Optional[str]:
    """Extract a specific date from user text as YYYY-MM-DD, if present."""
    now_utc = datetime.now(timezone.utc)
    text = message.strip()

    # ISO format: 2026-03-19
    iso_match = re.search(r"\b(\d{4})-(\d{2})-(\d{2})\b", text)
    if iso_match:
        try:
            dt = datetime(
                int(iso_match.group(1)),
                int(iso_match.group(2)),
                int(iso_match.group(3)),
                tzinfo=timezone.utc,
            )
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return None

    # Month name format: March 19 or March 19, 2026
    month_match = re.search(
        r"\b([A-Za-z]+)\s+(\d{1,2})(?:st|nd|rd|th)?(?:,?\s*(\d{4}))?\b",
        text,
    )
    if month_match:
        month_str = month_match.group(1)
        day_str = month_match.group(2)
        year_str = month_match.group(3) or str(now_utc.year)
        try:
            dt = datetime.strptime(f"{month_str} {day_str} {year_str}", "%B %d %Y")
            dt = dt.replace(tzinfo=timezone.utc)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            return None

    return None


def _build_exact_due_date_response(user_message: str) -> Optional[str]:
    """Return a direct DB answer for exact-date due queries, when applicable."""
    message_lower = user_message.lower()
    asks_due_date = any(token in message_lower for token in ("due", "task", "tasks", "test", "tests"))
    if not asks_due_date:
        return None

    target_date = _extract_specific_date_iso(user_message)
    if not target_date:
        return None

    conn = get_db()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT task_id, title, remediation_type, due_date "
            "FROM vanta_tasks WHERE due_date LIKE %s "
            "AND status NOT IN ('remediated', 'rejected') "
            "ORDER BY due_date ASC LIMIT 50",
            (f"{target_date}%",),
        )
        tasks = cur.fetchall()

        if not tasks:
            return (
                f"There are no open tasks due on **{target_date}** "
                f"in the current database snapshot."
            )

        lines = [f"Open tasks due on **{target_date}** ({len(tasks)} total):"]
        for t in tasks[:20]:
            lines.append(
                f"• `{t['task_id']}` — {t['title'][:90]} "
                f"({t['remediation_type']}, due {t['due_date'][:10]})"
            )
        if len(tasks) > 20:
            lines.append(f"_...and {len(tasks) - 20} more._")
        return "\n".join(lines)
    finally:
        cur.close()
        conn.close()


def _build_assignment_response(user_message: str) -> Optional[str]:
    """Return a direct DB answer for assignment/owner questions."""
    message_lower = user_message.lower()
    if not any(token in message_lower for token in ("assigned", "owner", "who is", "assignee")):
        return None

    cve_match = re.search(r"\b(cve-\d{4}-\d{4,})\b", message_lower)
    if not cve_match:
        return None

    cve_id = cve_match.group(1).upper()
    conn = get_db()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT task_id, title, owner, due_date, account_id, remediation_type "
            "FROM vanta_tasks WHERE LOWER(title) LIKE LOWER(%s) "
            "AND status NOT IN ('remediated', 'rejected') "
            "ORDER BY due_date ASC LIMIT 1",
            (f"%{cve_id}%",),
        )
        task = cur.fetchone()
        if not task:
            return f"I couldn't find an open task matching **{cve_id}** in the database."

        owner = (task.get("owner") or "").strip()
        if owner:
            return (
                f"**{cve_id}** is currently assigned to **{owner}** "
                f"(task `{task['task_id']}`, due {task['due_date'][:10] if task.get('due_date') else '?'})."
            )

        # CVE subtasks are often unassigned while the parent vulnerability test has an owner.
        due_prefix = (task.get("due_date") or "")[:10]
        cur.execute(
            "SELECT task_id, title, owner "
            "FROM vanta_tasks "
            "WHERE owner IS NOT NULL AND TRIM(owner) <> '' "
            "AND status NOT IN ('remediated', 'rejected') "
            "AND remediation_type = %s "
            "AND COALESCE(account_id, '') = COALESCE(%s, '') "
            "AND due_date LIKE %s "
            "ORDER BY CASE "
            "  WHEN LOWER(title) LIKE '%%vulnerabilities identified in packages are addressed%%' THEN 0 "
            "  ELSE 1 "
            "END, due_date ASC LIMIT 1",
            (
                task.get("remediation_type") or "",
                task.get("account_id"),
                f"{due_prefix}%",
            ),
        )
        parent = cur.fetchone()
        if parent:
            return (
                f"**{cve_id}** subtask `{task['task_id']}` is unassigned, but the related parent finding "
                f"appears owned by **{parent['owner']}** (`{parent['task_id']}`)."
            )

        return (
            f"**{cve_id}** is currently unassigned "
            f"(task `{task['task_id']}`, due {task['due_date'][:10] if task.get('due_date') else '?'})."
        )
    finally:
        cur.close()
        conn.close()


def _build_owner_list_response(user_message: str) -> Optional[str]:
    """Return a direct DB list of known owners for 'list users' style questions."""
    message_lower = user_message.lower()
    wants_user_list = (
        ("list" in message_lower and ("users" in message_lower or "owners" in message_lower))
        or ("who can" in message_lower and "assigned" in message_lower)
        or ("do you have a list of users" in message_lower)
    )
    if not wants_user_list:
        return None

    conn = get_db()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT owner AS person FROM vanta_tasks "
            "WHERE owner IS NOT NULL AND TRIM(owner) <> '' "
            "UNION "
            "SELECT owner_name AS person FROM person_security_tasks "
            "WHERE owner_name IS NOT NULL AND TRIM(owner_name) <> '' "
            "ORDER BY person ASC LIMIT 150"
        )
        rows = cur.fetchall()
        if not rows:
            return "I don't have any task owners in the database yet. Run a fresh poll to sync assignment data."

        owners = [r["person"] for r in rows if r.get("person")]
        lines = [f"I can see {len(owners)} known task owner(s) from synced tasks:"]
        lines.extend([f"• {owner}" for owner in owners[:30]])
        if len(owners) > 30:
            lines.append(f"_...and {len(owners) - 30} more._")
        lines.append("")
        lines.append("_Note: this is task owner data from synced Vanta findings, not a full company directory._")
        return "\n".join(lines)
    finally:
        cur.close()
        conn.close()


def _extract_owner_candidate(user_message: str) -> Optional[str]:
    """Extract a likely owner name from natural language owner-task questions."""
    text = user_message.strip()
    text = re.sub(r"^/vantaops\s+", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return None

    patterns = [
        r"(?:belong(?:s)?\s+t+o|assigned to|owned by|for)\s+([A-Za-z][A-Za-z .'\-]{1,80})\??$",
        r"^what about\s+([A-Za-z][A-Za-z .'\-]{1,80})\??$",
    ]
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip(" ?")

    return None


def _normalize_owner_name(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", (value or "").lower()).strip()


def _resolve_owner_via_alias(cur, candidate: str) -> Optional[str]:
    normalized = _normalize_owner_name(candidate)
    if not normalized:
        return None
    cur.execute(
        "SELECT canonical_name FROM owner_aliases WHERE alias_normalized = %s LIMIT 1",
        (normalized,),
    )
    row = cur.fetchone()
    return row.get("canonical_name") if row else None


def _upsert_owner_alias(cur, alias: str, canonical_name: str, source: str = "owner-query"):
    alias_norm = _normalize_owner_name(alias)
    if not alias_norm or not canonical_name:
        return
    now_iso = datetime.now(timezone.utc).isoformat()
    cur.execute(
        "INSERT INTO owner_aliases (alias_normalized, alias, canonical_name, confidence, source, last_seen_at) "
        "VALUES (%s, %s, %s, %s, %s, %s) "
        "ON CONFLICT(alias_normalized) DO UPDATE SET "
        "canonical_name = EXCLUDED.canonical_name, "
        "confidence = GREATEST(owner_aliases.confidence, EXCLUDED.confidence), "
        "source = EXCLUDED.source, "
        "last_seen_at = EXCLUDED.last_seen_at",
        (alias_norm, alias, canonical_name, 0.85, source, now_iso),
    )


def _best_owner_match(candidate: str, owners: list[str]) -> Optional[str]:
    """Find the closest owner name using exact, substring, then fuzzy matching."""
    if not owners:
        return None
    normalized = candidate.strip().lower()
    if not normalized:
        return None

    for owner in owners:
        if owner.lower() == normalized:
            return owner

    contains_matches = [o for o in owners if normalized in o.lower()]
    if contains_matches:
        return sorted(contains_matches, key=lambda o: (len(o), o.lower()))[0]

    reverse_contains = [o for o in owners if o.lower() in normalized]
    if reverse_contains:
        return sorted(reverse_contains, key=lambda o: (len(o), o.lower()))[0]

    scored = sorted(
        ((SequenceMatcher(None, normalized, owner.lower()).ratio(), owner) for owner in owners),
        reverse=True,
    )
    if scored and scored[0][0] >= 0.72:
        return scored[0][1]
    return None


def _find_related_parent_owner(cur, task: dict) -> tuple[Optional[str], Optional[str]]:
    """Infer owner from a related parent finding when the task row has no owner."""
    cur.execute(
        "SELECT p.task_id, p.owner "
        "FROM task_links l "
        "JOIN vanta_tasks p ON p.task_id = l.parent_task_id "
        "WHERE l.child_task_id = %s "
        "AND l.link_type = 'parent_finding' "
        "AND p.owner IS NOT NULL AND TRIM(p.owner) <> '' "
        "AND p.status NOT IN ('remediated', 'rejected') "
        "ORDER BY l.confidence DESC LIMIT 1",
        (task.get("task_id", ""),),
    )
    linked_parent = cur.fetchone()
    if linked_parent:
        owner = (linked_parent.get("owner") or "").strip()
        if owner:
            return owner, linked_parent.get("task_id")

    due_prefix = (task.get("due_date") or "")[:10]
    if not due_prefix:
        return None, None

    cur.execute(
        "SELECT task_id, owner "
        "FROM vanta_tasks "
        "WHERE owner IS NOT NULL AND TRIM(owner) <> '' "
        "AND status NOT IN ('remediated', 'rejected') "
        "AND COALESCE(account_id, '') = COALESCE(%s, '') "
        "AND due_date LIKE %s "
        "AND task_id <> %s "
        "ORDER BY CASE "
        "  WHEN LOWER(title) LIKE '%%vulnerabilities identified in packages are addressed%%' THEN 0 "
        "  ELSE 1 "
        "END, due_date ASC LIMIT 1",
        (
            task.get("account_id"),
            f"{due_prefix}%",
            task.get("task_id", ""),
        ),
    )
    parent = cur.fetchone()
    if not parent:
        return None, None
    owner = (parent.get("owner") or "").strip()
    parent_task_id = parent.get("task_id")
    if not owner:
        return None, None
    return owner, parent_task_id


def _build_task_owner_verification_response(user_message: str) -> Optional[str]:
    """Handle statements/questions like '<task_id> belongs to <owner>' deterministically."""
    text = user_message.strip()
    if not re.search(r"\b([a-f0-9]{16,})\b", text.lower()):
        return None
    if not (
        re.search(r"\bbelong(?:s)?\s+t+o\b", text.lower())
        or any(phrase in text.lower() for phrase in ("assigned to", "owned by"))
    ):
        return None

    task_id_match = re.search(r"\b([a-f0-9]{16,})\b", text.lower())
    claimed_owner = _extract_owner_candidate(text)
    if not task_id_match or not claimed_owner:
        return None
    task_id_fragment = task_id_match.group(1)

    conn = get_db()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT * FROM vanta_tasks WHERE task_id LIKE %s LIMIT 1",
            (f"%{task_id_fragment}%",),
        )
        task = cur.fetchone()
        if not task:
            return f"I couldn't find task `{task_id_fragment}` in the database."

        direct_owner = (task.get("owner") or "").strip()
        related_owner, parent_task_id = (None, None)
        if not direct_owner:
            related_owner, parent_task_id = _find_related_parent_owner(cur, task)

        effective_owner = direct_owner or related_owner
        if not effective_owner:
            return (
                f"Task `{task['task_id']}` currently has no owner on the task row, and I couldn't infer a parent owner yet."
            )

        is_match = _best_owner_match(claimed_owner, [effective_owner]) is not None
        if is_match and parent_task_id and not direct_owner:
            return (
                f"Yes — task `{task['task_id']}` appears linked to **{effective_owner}** via parent finding "
                f"`{parent_task_id}`."
            )
        if is_match:
            return f"Yes — task `{task['task_id']}` is owned by **{effective_owner}**."

        return (
            f"Task `{task['task_id']}` currently resolves to owner **{effective_owner}** "
            f"(claimed: **{claimed_owner}**)."
        )
    finally:
        cur.close()
        conn.close()


def _build_owner_tasks_response(user_message: str) -> Optional[str]:
    """Return direct DB results for 'what tasks belong to <owner>' questions."""
    message_lower = user_message.lower()
    if re.search(r"\bcve-\d{4}-\d{4,}\b", message_lower):
        return None

    asks_owner_tasks = (
        bool(re.search(r"\bbelong(?:s)?\s+t+o\b", message_lower))
        or any(phrase in message_lower for phrase in ("assigned to", "owned by", "what about"))
    )
    if not asks_owner_tasks:
        return None

    owner_candidate = _extract_owner_candidate(user_message)
    if not owner_candidate:
        return None

    conn = get_db()
    cur = dict_cursor(conn)
    try:
        cur.execute(
            "SELECT owner AS person FROM vanta_tasks "
            "WHERE owner IS NOT NULL AND TRIM(owner) <> '' "
            "UNION "
            "SELECT owner_name AS person FROM person_security_tasks "
            "WHERE owner_name IS NOT NULL AND TRIM(owner_name) <> '' "
            "ORDER BY person ASC"
        )
        owner_rows = cur.fetchall()
        known_owners = [r["person"] for r in owner_rows if r.get("person")]
        matched_owner = _best_owner_match(owner_candidate, known_owners)
        if not matched_owner:
            matched_owner = _resolve_owner_via_alias(cur, owner_candidate)
        if matched_owner:
            _upsert_owner_alias(cur, owner_candidate, matched_owner)

        owner_pattern = f"%{owner_candidate.strip().lower()}%"
        matched_pattern = f"%{matched_owner.lower()}%" if matched_owner else None

        # 1) Direct owner-column matches.
        if matched_owner:
            cur.execute(
                "SELECT task_id, title, remediation_type, due_date, status, owner "
                "FROM vanta_tasks "
                "WHERE (LOWER(owner) LIKE %s OR LOWER(owner) LIKE %s) "
                "AND status NOT IN ('remediated', 'rejected') "
                "ORDER BY due_date ASC LIMIT 40",
                (matched_pattern, owner_pattern),
            )
        else:
            cur.execute(
                "SELECT task_id, title, remediation_type, due_date, status, owner "
                "FROM vanta_tasks "
                "WHERE LOWER(owner) LIKE %s "
                "AND status NOT IN ('remediated', 'rejected') "
                "ORDER BY due_date ASC LIMIT 40",
                (owner_pattern,),
            )
        direct_tasks = cur.fetchall()

        # 2) Fallback: owner appears in raw payload, not normalized owner column.
        cur.execute(
            "SELECT task_id, title, remediation_type, due_date, status, owner "
            "FROM vanta_tasks "
            "WHERE LOWER(COALESCE(raw_json, '')) LIKE %s "
            "AND status NOT IN ('remediated', 'rejected') "
            "ORDER BY due_date ASC LIMIT 40",
            (owner_pattern,),
        )
        raw_owner_tasks = cur.fetchall()

        # 3) Include unowned CVE subtasks linked to owner-matching parent findings.
        cur.execute(
            "SELECT DISTINCT t.task_id, t.title, t.remediation_type, t.due_date, t.status, t.owner "
            "FROM vanta_tasks t "
            "JOIN vanta_tasks p ON COALESCE(t.account_id, '') = COALESCE(p.account_id, '') "
            "  AND SUBSTRING(COALESCE(t.due_date, '') FROM 1 FOR 10) = SUBSTRING(COALESCE(p.due_date, '') FROM 1 FOR 10) "
            "WHERE (LOWER(t.title) LIKE '%%cve-%%' OR LOWER(COALESCE(t.description, '')) LIKE '%%cve-%%') "
            "  AND (t.owner IS NULL OR TRIM(t.owner) = '') "
            "  AND p.status NOT IN ('remediated', 'rejected') "
            "  AND (LOWER(COALESCE(p.owner, '')) LIKE %s OR LOWER(COALESCE(p.raw_json, '')) LIKE %s) "
            "  AND p.title <> t.title "
            "ORDER BY t.due_date ASC LIMIT 40",
            (owner_pattern, owner_pattern),
        )
        linked_cve_tasks = cur.fetchall()

        # Deduplicate rows while preserving order.
        merged = []
        seen = set()
        for row in [*direct_tasks, *raw_owner_tasks, *linked_cve_tasks]:
            tid = row.get("task_id")
            if tid and tid not in seen:
                seen.add(tid)
                merged.append(row)

        display_owner = matched_owner or owner_candidate
        # Personnel/security task coverage (completed/open) like Vanta in-app AI answers.
        if matched_owner:
            cur.execute(
                "SELECT person_task_id, task_title, task_category, status, due_date, completed_at "
                "FROM person_security_tasks "
                "WHERE LOWER(owner_name) LIKE %s "
                "ORDER BY CASE WHEN status = 'completed' THEN 1 ELSE 0 END, due_date ASC, task_title ASC "
                "LIMIT 80",
                (matched_pattern,),
            )
        else:
            cur.execute(
                "SELECT person_task_id, task_title, task_category, status, due_date, completed_at "
                "FROM person_security_tasks "
                "WHERE LOWER(owner_name) LIKE %s "
                "ORDER BY CASE WHEN status = 'completed' THEN 1 ELSE 0 END, due_date ASC, task_title ASC "
                "LIMIT 80",
                (owner_pattern,),
            )
        person_tasks = cur.fetchall()
        open_person = [p for p in person_tasks if (p.get("status") or "").lower() != "completed"]
        done_person = [p for p in person_tasks if (p.get("status") or "").lower() == "completed"]

        if not merged and not person_tasks:
            conn.commit()
            return f"I couldn't find tasks assigned to **{display_owner}** in the current database snapshot."

        lines = []
        if merged:
            lines.append(f"Open remediation tasks for **{display_owner}** ({len(merged)} found):")
        else:
            lines.append(f"Open remediation tasks for **{display_owner}**: none found.")

        for t in merged[:30]:
            due_str = t["due_date"][:10] if t.get("due_date") else "?"
            owner_str = t.get("owner") or "unassigned (linked via parent finding)"
            lines.append(
                f"• `{t['task_id']}` — {t['title'][:85]} "
                f"({t['remediation_type']}, due {due_str}, owner: {owner_str})"
            )
        if len(merged) > 30:
            lines.append(f"_...and {len(merged) - 30} more._")

        lines.append("")
        lines.append(
            f"Personnel/security tasks for **{display_owner}**: "
            f"{len(open_person)} open, {len(done_person)} completed."
        )
        for p in open_person[:12]:
            due_str = p["due_date"][:10] if p.get("due_date") else "?"
            lines.append(f"• OPEN — {p['task_title'][:90]} ({p.get('task_category') or 'security'}, due {due_str})")
        if not open_person and done_person:
            lines.append("• No open personnel tasks.")

        if done_person:
            lines.append("")
            lines.append("Recently completed personnel tasks:")
            for p in done_person[:8]:
                completed = p["completed_at"][:10] if p.get("completed_at") else "recently"
                lines.append(f"• DONE — {p['task_title'][:90]} (completed {completed})")

        conn.commit()
        return "\n".join(lines)
    finally:
        cur.close()
        conn.close()


def _build_task_resource_response(user_message: str, history: list) -> Optional[str]:
    """Return exact resource metadata for task/resource questions without LLM inference."""
    message_lower = user_message.lower()
    asks_resource = (
        "resource" in message_lower
        or ("aws" in message_lower and ("involved" in message_lower or "where" in message_lower))
    )
    if not asks_resource:
        return None

    task = detect_specific_task(user_message, history)
    if not task:
        return None

    resource_id = task.get("resource_id") or "N/A"
    resource_type = task.get("resource_type") or "N/A"
    account_id = task.get("account_id") or "N/A"
    region = task.get("region") or "N/A"
    inferred_resource_type = resource_type
    if resource_type.upper() == "COMMON":
        text = " ".join(
            [
                str(task.get("title", "")),
                str(task.get("description", "")),
                str(task.get("raw_json", "")),
            ]
        ).lower()
        if any(token in text for token in ("ecr", "aws container", "inspector", "container vulnerab")):
            inferred_resource_type = "AWS_ECR"

    lines = [
        f"The AWS metadata recorded for task `{task['task_id']}` is:",
        f"• Resource ID: `{resource_id}`",
        f"• Resource Type: `{inferred_resource_type}`",
        f"• Account: `{account_id}`",
        f"• Region: `{region}`",
    ]

    if resource_type.upper() == "COMMON":
        lines.append(
            "_Note: Vanta stored this row as `COMMON`; type above is inferred from finding content._"
        )

    return "\n".join(lines)


def get_context_for_llm(user_message: str) -> str:
    """Pull relevant context from the database for the LLM."""
    from datetime import timedelta
    context_parts = []
    conn = get_db()
    cur = dict_cursor(conn)

    lookahead = _extract_lookahead_days(user_message)
    now_utc = datetime.now(timezone.utc)
    lookahead_cutoff = (now_utc + timedelta(days=lookahead)).isoformat()
    now_iso = now_utc.isoformat()

    context_parts.append(f"Current date/time: {now_utc.strftime('%Y-%m-%d %H:%M UTC')}")

    # Overall counts
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE status IN ('pending', 'notified')"
    )
    pending = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE status = 'remediated'"
    )
    remediated = cur.fetchone()["c"]

    # Tasks due in the lookahead window
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE due_date >= %s AND due_date <= %s "
        "AND status NOT IN ('remediated', 'rejected')",
        (now_iso, lookahead_cutoff),
    )
    due_soon = cur.fetchone()["c"]

    # Overdue tasks (due before now, not resolved)
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE due_date < %s "
        "AND status NOT IN ('remediated', 'rejected')",
        (now_iso,),
    )
    overdue = cur.fetchone()["c"]

    context_parts.append(
        f"Task summary: {pending} pending, {remediated} remediated, "
        f"{due_soon} due in next {lookahead} days, {overdue} overdue."
    )

    # Tasks due in lookahead window (up to 20)
    cur.execute(
        "SELECT task_id, title, status, remediation_type, severity, owner, account_id, region, due_date "
        "FROM vanta_tasks WHERE due_date >= %s AND due_date <= %s "
        "AND status NOT IN ('remediated', 'rejected') "
        "ORDER BY due_date ASC LIMIT 20",
        (now_iso, lookahead_cutoff),
    )
    tasks = cur.fetchall()
    if tasks:
        lines = [f"Tasks due in next {lookahead} days:"]
        for t in tasks:
            owner_str = f", owner: {t['owner']}" if t.get('owner') else ""
            severity_str = f", severity: {t['severity']}" if t.get('severity') else ""
            lines.append(
                f"  - [{t['status']}] {t['title']} (id: {t['task_id']}, type: {t['remediation_type']}{severity_str}, "
                f"account: {t['account_id'] or '?'}, due: {t['due_date'][:10] if t['due_date'] else '?'}{owner_str})"
            )
        context_parts.append("\n".join(lines))

    # Overdue tasks (up to 10)
    cur.execute(
        "SELECT task_id, title, status, remediation_type, severity, owner, account_id, region, due_date "
        "FROM vanta_tasks WHERE due_date < %s "
        "AND status NOT IN ('remediated', 'rejected') "
        "ORDER BY due_date DESC LIMIT 10",
        (now_iso,),
    )
    overdue_tasks = cur.fetchall()
    if overdue_tasks:
        lines = ["Overdue tasks:"]
        for t in overdue_tasks:
            owner_str = f", owner: {t['owner']}" if t.get('owner') else ""
            severity_str = f", severity: {t['severity']}" if t.get('severity') else ""
            lines.append(
                f"  - [{t['status']}] {t['title']} (id: {t['task_id']}, type: {t['remediation_type']}{severity_str}, "
                f"account: {t['account_id'] or '?'}, due: {t['due_date'][:10] if t['due_date'] else '?'}{owner_str})"
            )
        context_parts.append("\n".join(lines))

    # Relevant lessons from knowledge base
    cur.execute(
        "SELECT problem, solution, pitfalls, remediation_type "
        "FROM knowledge_base ORDER BY created_at DESC LIMIT 10"
    )
    lessons = cur.fetchall()
    if lessons:
        lines = ["Lessons from past remediations:"]
        for l in lessons:
            entry = f"  - [{l['remediation_type']}] Problem: {l['problem']}"
            if l['solution']:
                entry += f" | Solution: {l['solution']}"
            if l['pitfalls']:
                entry += f" | Pitfalls: {l['pitfalls']}"
            lines.append(entry)
        context_parts.append("\n".join(lines))

    cur.close()
    conn.close()
    return "\n\n".join(context_parts)


def save_lesson(task_id: str, remediation_type: str, problem: str,
                solution: str = "", pitfalls: str = "", source: str = "slack"):
    """Save a lesson learned to the knowledge base."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO knowledge_base
            (created_at, task_id, remediation_type, problem, solution, pitfalls, tags, source)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    """, (
        datetime.now(timezone.utc).isoformat(),
        task_id, remediation_type, problem, solution, pitfalls,
        remediation_type, source,
    ))
    conn.commit()
    cur.close()
    conn.close()
    log.info(f"Saved lesson for task {task_id}: {problem[:80]}")


def get_thread_history(channel_id: str, thread_ts: str, limit: int = 10) -> list:
    """Fetch recent conversation history from a Slack thread."""
    if not channel_id or not thread_ts:
        return []

    try:
        result = app.client.conversations_replies(
            channel=channel_id,
            ts=thread_ts,
            limit=limit + 1,  # include parent
        )
        messages = result.get("messages", [])

        history = []
        for msg in messages:
            # Skip the very last message (it's the current one we're responding to)
            if msg.get("ts") == thread_ts and len(messages) == 1:
                break

            text = msg.get("text", "").strip()
            if not text:
                continue

            # Strip bot mentions
            text = re.sub(r"<@[A-Z0-9]+>\s*", "", text).strip()

            if msg.get("bot_id"):
                history.append({"role": "assistant", "content": text})
            else:
                history.append({"role": "user", "content": text})

        return history
    except Exception as e:
        log.warning(f"Could not fetch thread history: {e}")
        return []


def detect_specific_task(user_message: str, history: list = None) -> Optional[dict]:
    """Detect if the user is asking about a specific task. Returns full task row or None."""
    conn = get_db()
    cur = dict_cursor(conn)

    # 1. Check for task ID in message (hex strings 8+ chars)
    id_match = re.search(r'\b([a-f0-9]{8,})\b', user_message.lower())
    if id_match:
        cur.execute("SELECT * FROM vanta_tasks WHERE task_id LIKE %s LIMIT 1",
                     (f"%{id_match.group(1)}%",))
        task = cur.fetchone()
        if task:
            cur.close(); conn.close()
            return task

    # 2. Search by keywords in title
    words = [w for w in re.findall(r'[a-zA-Z]{3,}', user_message.lower())
             if w not in {'the', 'what', 'about', 'show', 'tell', 'how', 'can', 'this',
                          'that', 'with', 'from', 'for', 'and', 'are', 'task', 'test',
                          'closest', 'date', 'due', 'fix', 'remediate', 'yes', 'help',
                          'more', 'explain', 'details', 'please', 'could', 'would'}]
    if words:
        pattern = '%' + '%'.join(words[:3]) + '%'
        cur.execute(
            "SELECT * FROM vanta_tasks WHERE LOWER(title) LIKE LOWER(%s) "
            "ORDER BY due_date ASC LIMIT 1", (pattern,))
        task = cur.fetchone()
        if task:
            cur.close(); conn.close()
            return task

    # 3. Check thread history for previously mentioned task IDs
    if history:
        for msg in reversed(history):
            if msg.get("role") != "assistant":
                continue
            tid = re.search(r'\b([a-f0-9]{8,})\b', msg.get("content", "").lower())
            if tid:
                cur.execute("SELECT * FROM vanta_tasks WHERE task_id LIKE %s LIMIT 1",
                             (f"%{tid.group(1)}%",))
                task = cur.fetchone()
                if task:
                    cur.close(); conn.close()
                    return task
            # Also try matching task title fragments from bot's previous reply
            title_match = re.search(r'\*([^*]{10,})\*', msg.get("content", ""))
            if title_match:
                cur.execute(
                    "SELECT * FROM vanta_tasks WHERE LOWER(title) LIKE LOWER(%s) LIMIT 1",
                    (f"%{title_match.group(1)[:50]}%",))
                task = cur.fetchone()
                if task:
                    cur.close(); conn.close()
                    return task

    cur.close(); conn.close()
    return None


def get_task_detail_context(task: dict, max_chars: int = 3000) -> str:
    """Build detailed LLM context for a specific task."""
    parts = [f"DETAILED TASK INFO (user is asking about this):"]
    for field in ['task_id', 'title', 'description', 'framework', 'due_date', 'status',
                  'remediation_type', 'severity', 'owner', 'account_id',
                  'region', 'resource_id', 'resource_type',
                  'remediated_at', 'remediated_by']:
        val = task.get(field)
        if val:
            parts.append(f"  {field}: {val}")

    if task.get('raw_json'):
        try:
            raw = json.loads(task['raw_json'])
            known = {'task_id', 'title', 'description', 'due_date', 'framework',
                     'remediation_type', 'resource_id', 'resource_type',
                     'account_id', 'region', 'severity', 'owner'}
            extra = {k: v for k, v in raw.items() if k not in known and v}
            if extra:
                extra_text = json.dumps(extra, indent=2, default=str)
                if len(extra_text) > max_chars:
                    extra_text = extra_text[:max_chars] + "\n...(truncated)"
                parts.append(f"  Additional data:\n{extra_text}")
        except (json.JSONDecodeError, TypeError):
            pass

    return "\n".join(parts)


def get_live_resource_context(resource_type: str, resource_id: str) -> str:
    """Fetch live resource details from Vanta API if configured."""
    global live_resource_lookup_enabled

    if not vanta or not vanta.is_configured() or not live_resource_lookup_enabled:
        return ""

    # Generic bucket types are often not readable from /v1/resources for scoped tokens.
    if not resource_type or resource_type.upper() == "COMMON":
        return ""

    try:
        resources = vanta.get_resources(resource_type=resource_type)
        match = next((r for r in resources
                      if r.get("id") == resource_id
                      or r.get("externalId") == resource_id), None)
        if match:
            text = json.dumps(match, indent=2, default=str)
            if len(text) > 2000:
                text = text[:2000] + "\n...(truncated)"
            return f"Live Vanta resource data:\n{text}"
    except Exception as e:
        status_code = getattr(getattr(e, "response", None), "status_code", None)
        if status_code == 403:
            live_resource_lookup_enabled = False
            log.info("Live Vanta resource lookup disabled after 403 forbidden response.")
            return ""
        log.warning(f"Failed to fetch live Vanta resource: {e}")
    return ""


def ask_llm(user_message: str, channel_id: str = "", thread_ts: str = "") -> str:
    """Send a message to the LLM with database context, task detail, and conversation history."""
    if not llm:
        return "LLM not configured. Set ANTHROPIC_API_KEY or GOOGLE_API_KEY."

    # For exact date queries, answer directly from DB to avoid LLM ambiguity.
    exact_due_date_response = _build_exact_due_date_response(user_message)
    if exact_due_date_response:
        return exact_due_date_response

    # Build history early so we can resolve follow-up questions deterministically.
    history = get_thread_history(channel_id, thread_ts)

    # For assignment questions, answer directly from DB.
    assignment_response = _build_assignment_response(user_message)
    if assignment_response:
        return assignment_response

    # For explicit ownership assertions/questions on a specific task id.
    owner_verification_response = _build_task_owner_verification_response(user_message)
    if owner_verification_response:
        return owner_verification_response

    # For "list users/owners" questions, return distinct known owners from DB.
    owner_list_response = _build_owner_list_response(user_message)
    if owner_list_response:
        return owner_list_response

    # For owner-task questions, return direct DB-backed task lists.
    owner_tasks_response = _build_owner_tasks_response(user_message)
    if owner_tasks_response:
        return owner_tasks_response

    # For resource questions, answer directly from DB and avoid speculative mapping.
    resource_response = _build_task_resource_response(user_message, history)
    if resource_response:
        return resource_response

    context = get_context_for_llm(user_message)

    # Detect if user is asking about a specific task
    specific_task = detect_specific_task(user_message, history)
    if specific_task:
        context += "\n\n--- SPECIFIC TASK DETAIL ---\n" + get_task_detail_context(specific_task)
        # Try live Vanta data if we have a resource type
        if specific_task.get('resource_type') and specific_task.get('resource_id'):
            live = get_live_resource_context(specific_task['resource_type'], specific_task['resource_id'])
            if live:
                context += "\n\n--- LIVE VANTA DATA ---\n" + live

    system = SYSTEM_PROMPT + "\n\n--- DATABASE CONTEXT ---\n" + context

    if history:
        if history[-1].get("role") == "user" and history[-1].get("content") == user_message:
            messages = history
        else:
            messages = history + [{"role": "user", "content": user_message}]
    else:
        messages = [{"role": "user", "content": user_message}]

    return llm.chat(messages, system=system)


def is_authorized(user_id: str) -> bool:
    """Check if a Slack user is authorized to approve remediations."""
    if not ALLOWED_APPROVERS or ALLOWED_APPROVERS == [""]:
        return True
    return user_id in ALLOWED_APPROVERS


def run_script(script: str, args: list) -> dict:
    """Run a VantaOps Python script and return the result."""
    cmd = [sys.executable, os.path.join(SCRIPTS_DIR, script)] + args
    log.info(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=300,
        env={**os.environ},
    )
    return {
        "stdout": proc.stdout,
        "stderr": proc.stderr,
        "exit_code": proc.returncode,
    }


def post_bot_response(client, channel: str, thread_ts: str, response_text: str):
    """Post bot response with lightweight feedback buttons for learning."""
    text = (response_text or "").strip() or "No response generated."
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:12]
    response_id = f"resp-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{digest}"
    excerpt = text[:200]
    value_up = json.dumps({"response_id": response_id, "feedback": "up", "excerpt": excerpt})
    value_down = json.dumps({"response_id": response_id, "feedback": "down", "excerpt": excerpt})
    if len(text) > 2800:
        client.chat_postMessage(channel=channel, thread_ts=thread_ts, text=text)
        return

    client.chat_postMessage(
        channel=channel,
        thread_ts=thread_ts,
        text=text,
        blocks=[
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "👍 Correct"},
                        "action_id": "vantaops_feedback_up",
                        "value": value_up,
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "👎 Incorrect"},
                        "action_id": "vantaops_feedback_down",
                        "value": value_down,
                    },
                ],
            },
        ],
    )


# ---------------------------------------------------------------------------
# Action Handlers
# ---------------------------------------------------------------------------

@app.action("vantaops_feedback_up")
@app.action("vantaops_feedback_down")
def handle_feedback(ack, body, client):
    """Capture user feedback on bot responses."""
    ack()
    user_id = body.get("user", {}).get("id", "")
    channel_id = body.get("channel", {}).get("id", "")
    message_ts = body.get("message", {}).get("ts", "")

    try:
        value = json.loads(body["actions"][0]["value"])
    except Exception:
        return

    feedback = value.get("feedback", "")
    response_id = value.get("response_id", "")
    excerpt = value.get("excerpt", "")
    if feedback not in ("up", "down") or not response_id:
        return

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO response_feedback (response_id, channel_id, thread_ts, user_id, feedback, message_excerpt, created_at) "
        "VALUES (%s, %s, %s, %s, %s, %s, %s)",
        (
            response_id,
            channel_id,
            message_ts,
            user_id,
            feedback,
            excerpt,
            datetime.now(timezone.utc).isoformat(),
        ),
    )
    conn.commit()
    cur.close()
    conn.close()

    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text="Thanks for the feedback — I'll use it to improve future answers.",
    )


@app.action("vantaops_remediate")
def handle_remediate(ack, body, client):
    """Handle the 'View Plan & Remediate' button click."""
    ack()

    user_id = body["user"]["id"]
    user_name = body["user"].get("username", user_id)
    channel_id = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    if not is_authorized(user_id):
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"⛔ <@{user_id}> is not authorized to approve remediations.",
        )
        return

    # Parse task info from button value
    try:
        value = json.loads(body["actions"][0]["value"])
        task_id = value["task_id"]
        remediation_type = value["remediation_type"]
    except (json.JSONDecodeError, KeyError) as e:
        log.error(f"Invalid button value: {e}")
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text="❌ Error: Could not parse task information.",
        )
        return

    # Step 1: Generate the remediation plan
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=f"⏳ Generating remediation plan for `{task_id}`...",
    )

    result = run_script("aws_remediate.py", ["plan", "--task-id", task_id])

    if result["exit_code"] != 0:
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"❌ Plan generation failed:\n```{result['stderr'][:1000]}```",
        )
        return

    plan_output = result["stdout"]

    # Step 2: Show the plan and ask for final approval
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        blocks=[
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"```{plan_output[:2900]}```",
                },
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Approve & Execute"},
                        "style": "primary",
                        "action_id": "vantaops_approve_execute",
                        "value": json.dumps({
                            "task_id": task_id,
                            "approved_by": user_name,
                        }),
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Confirm Execution"},
                            "text": {
                                "type": "mrkdwn",
                                "text": (
                                    "This will execute the AWS commands shown above. "
                                    "Are you sure you want to proceed?"
                                ),
                            },
                            "confirm": {"type": "plain_text", "text": "Execute"},
                            "deny": {"type": "plain_text", "text": "Cancel"},
                        },
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ Reject"},
                        "style": "danger",
                        "action_id": "vantaops_reject",
                        "value": task_id,
                    },
                ],
            },
        ],
        text=f"Remediation plan for {task_id}",  # fallback
    )


@app.action("vantaops_approve_execute")
def handle_approve_execute(ack, body, client):
    """Handle the final 'Approve & Execute' button after viewing the plan."""
    ack()

    user_id = body["user"]["id"]
    user_name = body["user"].get("username", user_id)
    channel_id = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    if not is_authorized(user_id):
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"⛔ <@{user_id}> is not authorized to approve remediations.",
        )
        return

    try:
        value = json.loads(body["actions"][0]["value"])
        task_id = value["task_id"]
    except (json.JSONDecodeError, KeyError):
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text="❌ Error: Could not parse approval information.",
        )
        return

    # Execute the remediation
    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=(
            f"✅ Approved by <@{user_id}> at "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"⏳ Executing remediation..."
        ),
    )

    result = run_script("aws_remediate.py", [
        "execute",
        "--task-id", task_id,
        "--approved-by", user_name,
    ])

    # Post execution results
    output = result["stdout"] if result["stdout"] else result["stderr"]
    status = "✅ Remediation complete" if result["exit_code"] == 0 else "❌ Remediation failed"

    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=f"{status}\n```{output[:2900]}```",
    )

    # Run verification if execution succeeded
    if result["exit_code"] == 0:
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text="⏳ Running verification...",
        )

        verify_result = run_script("aws_remediate.py", [
            "verify", "--task-id", task_id,
        ])

        verify_output = verify_result["stdout"] or verify_result["stderr"]
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"```{verify_output[:2900]}```",
        )


@app.action("vantaops_reject")
def handle_reject(ack, body, client):
    """Handle remediation rejection."""
    ack()

    user_id = body["user"]["id"]
    task_id = body["actions"][0]["value"]
    channel_id = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=f"❌ Remediation for `{task_id}` rejected by <@{user_id}>.",
    )

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vanta_tasks SET status = 'rejected' WHERE task_id = %s",
        (task_id,),
    )
    conn.commit()
    cur.close()
    conn.close()


@app.action("vantaops_details")
def handle_details(ack, body, client):
    """Handle the 'View Details' button — show full task info."""
    ack()

    task_id = body["actions"][0]["value"]
    channel_id = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    conn = get_db()
    cur = dict_cursor(conn)
    cur.execute(
        "SELECT * FROM vanta_tasks WHERE task_id = %s", (task_id,)
    )
    task = cur.fetchone()
    cur.close()
    conn.close()

    if not task:
        client.chat_postMessage(
            channel=channel_id,
            thread_ts=message_ts,
            text=f"Task `{task_id}` not found in database.",
        )
        return

    details = (
        f"*Task ID:* `{task['task_id']}`\n"
        f"*Title:* {task['title']}\n"
        f"*Description:* {task['description'] or 'N/A'}\n"
        f"*Framework:* {task['framework'] or 'N/A'}\n"
        f"*Due Date:* {task['due_date']}\n"
        f"*Account:* {task['account_id'] or 'N/A'}\n"
        f"*Region:* {task['region'] or 'N/A'}\n"
        f"*Resource:* `{task['resource_id'] or 'N/A'}`\n"
        f"*Resource Type:* {task['resource_type'] or 'N/A'}\n"
        f"*Remediation Type:* {task['remediation_type']}\n"
        f"*Status:* {task['status']}\n"
        f"*Last Notified:* {task['notified_at'] or 'Never'}\n"
        f"*Remediated At:* {task['remediated_at'] or 'N/A'}\n"
        f"*Remediated By:* {task['remediated_by'] or 'N/A'}"
    )

    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=details,
    )


@app.action("vantaops_snooze")
def handle_snooze(ack, body, client):
    """Handle the 'Snooze' button — suppress notifications for 24h."""
    ack()

    user_id = body["user"]["id"]
    task_id = body["actions"][0]["value"]
    channel_id = body["channel"]["id"]
    message_ts = body["message"]["ts"]

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "UPDATE vanta_tasks SET notified_at = %s, status = 'snoozed' WHERE task_id = %s",
        (datetime.now(timezone.utc).isoformat(), task_id),
    )
    conn.commit()
    cur.close()
    conn.close()

    client.chat_postMessage(
        channel=channel_id,
        thread_ts=message_ts,
        text=f"⏭️ Snoozed by <@{user_id}>. Will re-notify in 24 hours.",
    )


# ---------------------------------------------------------------------------
# Slash Commands
# ---------------------------------------------------------------------------

@app.command("/vantaops")
def handle_vantaops_command(ack, body, client, respond):
    """Handle /vantaops slash command for on-demand actions."""
    ack()

    text = body.get("text", "").strip()
    user_id = body["user_id"]

    if not text or text == "help":
        respond(
            "📋 *VantaOps Commands:*\n"
            "• `/vantaops status` — Show current task summary\n"
            "• `/vantaops poll` — Trigger a manual Vanta poll\n"
            "• `/vantaops due <days>` — Show tasks due in N days (e.g. `/vantaops due 10`)\n"
            "• `/vantaops audit` — Show recent remediation audit log\n"
            "• `/vantaops task <id>` — Show details for a specific task"
        )
        return

    if text == "status":
        from datetime import timedelta
        conn = get_db()
        cur = dict_cursor(conn)
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        seven_days = (now_utc + timedelta(days=7)).isoformat()

        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE status IN ('pending', 'notified')"
        )
        pending = cur.fetchone()["c"]
        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE status = 'remediated'"
        )
        remediated = cur.fetchone()["c"]
        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE status = 'snoozed'"
        )
        snoozed = cur.fetchone()["c"]
        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE due_date >= %s AND due_date <= %s "
            "AND status NOT IN ('remediated', 'rejected')",
            (now_iso, seven_days),
        )
        due_soon = cur.fetchone()["c"]
        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE due_date < %s "
            "AND status NOT IN ('remediated', 'rejected')",
            (now_iso,),
        )
        overdue = cur.fetchone()["c"]
        cur.close()
        conn.close()

        respond(
            f"📊 *VantaOps Status* ({now_utc.strftime('%Y-%m-%d %H:%M UTC')}):\n"
            f"• Due in next 7 days: {due_soon}\n"
            f"• Overdue: {overdue}\n"
            f"• Total pending: {pending}\n"
            f"• Remediated: {remediated}\n"
            f"• Snoozed: {snoozed}"
        )

    elif text == "poll":
        respond("⏳ Triggering manual Vanta poll...")
        result = run_script("vanta_poller.py", [])
        respond(f"```{result['stdout'][:2900]}```")

    elif text == "audit":
        conn = get_db()
        cur = dict_cursor(conn)
        cur.execute(
            "SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 10"
        )
        logs = cur.fetchall()
        cur.close()
        conn.close()

        if not logs:
            respond("No audit logs yet.")
            return

        entries = []
        for log_entry in logs:
            status = "✅" if log_entry["exit_code"] == 0 else "❌"
            entries.append(
                f"{status} `{log_entry['timestamp'][:19]}` — "
                f"{log_entry['action']} "
                f"(by {log_entry['approved_by'] or 'system'})"
            )
        respond("📋 *Recent Audit Log:*\n" + "\n".join(entries))

    elif text.startswith("task "):
        task_id = text[5:].strip()
        conn = get_db()
        cur = dict_cursor(conn)
        cur.execute(
            "SELECT * FROM vanta_tasks WHERE task_id = %s", (task_id,)
        )
        task = cur.fetchone()
        cur.close()
        conn.close()

        if task:
            respond(
                f"*{task['title']}*\n"
                f"Status: {task['status']} | Type: {task['remediation_type']}\n"
                f"Account: {task['account_id']} | Region: {task['region']}\n"
                f"Due: {task['due_date']}"
            )
        else:
            respond(f"Task `{task_id}` not found.")

    elif text.startswith("due"):
        from datetime import timedelta
        # Parse days from "due 10" or "due 12 days"
        m = re.search(r'(\d+)', text)
        days = int(m.group(1)) if m else 7

        conn = get_db()
        cur = dict_cursor(conn)
        now_utc = datetime.now(timezone.utc)
        now_iso = now_utc.isoformat()
        cutoff = (now_utc + timedelta(days=days)).isoformat()

        cur.execute(
            "SELECT task_id, title, status, remediation_type, account_id, region, due_date "
            "FROM vanta_tasks WHERE due_date >= %s AND due_date <= %s "
            "AND status NOT IN ('remediated', 'rejected') "
            "ORDER BY due_date ASC LIMIT 30",
            (now_iso, cutoff),
        )
        tasks = cur.fetchall()

        cur.execute(
            "SELECT COUNT(*) as c FROM vanta_tasks WHERE due_date >= %s AND due_date <= %s "
            "AND status NOT IN ('remediated', 'rejected')",
            (now_iso, cutoff),
        )
        total = cur.fetchone()["c"]
        cur.close()
        conn.close()

        if not tasks:
            respond(f"✅ No tasks due in the next {days} days.")
        else:
            lines = [f"📋 *Tasks due in next {days} days* ({total} total):"]
            for t in tasks:
                due_str = t['due_date'][:10] if t['due_date'] else '?'
                resource_hint = f", resource {t['resource_id'][:16]}" if t.get('resource_id') else ""
                lines.append(
                    f"• `{t['task_id']}` — {t['title'][:80]} "
                    f"({t['remediation_type']}, due {due_str}{resource_hint})"
                )
            if total > 30:
                lines.append(f"_...and {total - 30} more. Use `/vantaops task <id>` for details._")
            respond("\n".join(lines))

    else:
        # Route unknown commands through the LLM for natural language handling
        response = ask_llm(f"/vantaops {text}")
        respond(response)


# ---------------------------------------------------------------------------
# Event Handlers
# ---------------------------------------------------------------------------

@app.event("app_mention")
def handle_mention(event, client):
    """Handle @VantaOps mentions in channels — route through LLM."""
    channel = event["channel"]
    thread_ts = event.get("ts", "")
    # Strip the bot mention from the text
    text = event.get("text", "")
    # Remove <@BOTID> prefix
    text = re.sub(r"<@[A-Z0-9]+>\s*", "", text).strip()

    if not text:
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="👋 I'm VantaOps! Ask me about your compliance tasks or use `/vantaops help`.",
        )
        return

    response = ask_llm(text, channel_id=channel, thread_ts=thread_ts)
    post_bot_response(client, channel=channel, thread_ts=thread_ts, response_text=response)


@app.event("message")
def handle_dm(event, client, logger):
    """Handle DMs — route through LLM for natural language conversation."""
    # Only handle DMs (channel type "im"), skip bot messages
    if event.get("channel_type") != "im":
        return
    if event.get("bot_id") or event.get("subtype"):
        return

    text = event.get("text", "").strip()
    channel = event["channel"]
    thread_ts = event.get("thread_ts", event.get("ts", ""))

    if not text:
        return

    # Check for "remember" / "lesson" commands
    if text.lower().startswith("remember:") or text.lower().startswith("lesson:"):
        lesson_text = text.split(":", 1)[1].strip()
        save_lesson(
            task_id="manual",
            remediation_type="general",
            problem=lesson_text,
            source="slack-dm",
        )
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="✅ Got it — I've saved that to my knowledge base.",
        )
        return

    response = ask_llm(text, channel_id=channel, thread_ts=thread_ts)
    post_bot_response(client, channel=channel, thread_ts=thread_ts, response_text=response)


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Starting VantaOps Slack bot (Socket Mode)...")
    init_db()
    log.info("Database initialized.")
    llm = LLMRouter()
    vanta = VantaClient(
        os.environ.get("VANTA_CLIENT_ID", ""),
        os.environ.get("VANTA_CLIENT_SECRET", ""),
    )
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
