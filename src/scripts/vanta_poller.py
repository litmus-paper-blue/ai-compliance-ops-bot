"""
VantaOps — Vanta Compliance Task Poller

Polls the Vanta API for tasks and failing tests due within 5 days.
Sends interactive notifications to Slack and returns summaries for OpenClaw.
"""

import os
import sys
import json
import time
import logging
import argparse
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests

from db import get_db, dict_cursor, init_db
from vanta_client import VantaClient

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VANTA_CLIENT_ID = os.environ.get("VANTA_CLIENT_ID", "")
VANTA_CLIENT_SECRET = os.environ.get("VANTA_CLIENT_SECRET", "")

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN", "")
SLACK_CHANNEL_ID = os.environ.get("SLACK_CHANNEL_ID", "")

LOOKAHEAD_DAYS = int(os.environ.get("VANTAOPS_LOOKAHEAD_DAYS", "5"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("vanta-poller")


# ---------------------------------------------------------------------------
# Task Classification
# ---------------------------------------------------------------------------

# Map Vanta test/vulnerability descriptions to remediation types
REMEDIATION_PATTERNS = {
    "cloudwatch": [
        "alarm", "monitoring", "metric", "cloudwatch",
        "health check", "5xx", "4xx", "latency",
    ],
    "s3": [
        "s3", "bucket", "encryption", "versioning",
        "public access", "logging",
    ],
    "security-group": [
        "security group", "ingress", "egress", "firewall",
        "open port", "0.0.0.0",
    ],
    "ssm-patch": [
        "patch", "update", "cve", "vulnerability",
        "package", "outdated", "eol",
    ],
    "logging": [
        "cloudtrail", "aws config", "flow log", "access log",
    ],
}


def classify_remediation_type(title: str, description: str = "") -> str:
    """Classify a Vanta finding into a remediation type."""
    text = f"{title} {description}".lower()
    for rtype, keywords in REMEDIATION_PATTERNS.items():
        if any(kw in text for kw in keywords):
            return rtype
    return "manual"


def extract_owner(finding: dict) -> str:
    """Extract a human-readable owner/assignee from a Vanta finding."""
    candidate_paths = [
        ("owner", "displayName"),
        ("owner", "email"),
        ("owner", "name"),
        ("assignee", "displayName"),
        ("assignee", "email"),
        ("assignee", "name"),
    ]
    for parent, child in candidate_paths:
        block = finding.get(parent, {})
        if isinstance(block, dict):
            value = block.get(child)
            if isinstance(value, str) and value.strip():
                return value.strip()

    # Some payloads expose assignment as top-level strings.
    for key in ("ownerEmail", "ownerName", "assignedTo", "assigneeEmail"):
        value = finding.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    remediation_info = finding.get("remediationStatusInfo", {})
    if isinstance(remediation_info, dict):
        for key in ("owner", "assignee", "assignedTo"):
            value = remediation_info.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()

    return ""


def _infer_resource_type(finding: dict, default_type: str) -> str:
    """Infer a more useful resource type when Vanta provides a generic value."""
    if default_type and default_type.upper() != "COMMON":
        return default_type

    text_parts = [
        str(finding.get("name", "")),
        str(finding.get("title", "")),
        str(finding.get("description", "")),
        str(finding.get("failureDescription", "")),
        str(finding.get("packageIdentifier", "")),
        str(finding.get("targetId", "")),
    ]
    integration = finding.get("integration", {}) or {}
    text_parts.extend(
        [
            str(integration.get("name", "")),
            str(integration.get("provider", "")),
            str(integration.get("type", "")),
        ]
    )
    text = " ".join(text_parts).lower()

    # Most common case in this repo: AWS container/package vulnerabilities from ECR scans.
    if any(token in text for token in ("ecr", "aws container", "inspector", "container vulnerab")):
        return "AWS_ECR"
    if "ec2" in text:
        return "AWS_EC2"
    if "s3" in text:
        return "AWS_S3"

    return default_type or "COMMON"


def _select_resource_id(finding: dict, resource: dict) -> str:
    """Pick the most actionable resource identifier from Vanta fields."""
    target_id = finding.get("targetId", "")
    package_identifier = finding.get("packageIdentifier", "")
    external_id = resource.get("externalId", "")
    internal_id = resource.get("id", "")

    # Prefer explicit target identifiers from vulnerability results
    # (e.g., awsbot1_ecr1 from AWS container findings).
    for value in (target_id, package_identifier, external_id, internal_id):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def extract_aws_context(finding: dict) -> dict:
    """Extract AWS account, region, and resource info from a Vanta finding."""
    # Vanta structures vary — this handles common patterns
    resource = finding.get("resource", {}) or {}
    integration = finding.get("integration", {}) or {}

    # Vulnerabilities use flat fields like targetId, integrationId
    resource_id = _select_resource_id(finding, resource)
    resource_type = (
        resource.get("resourceType", "")
        or finding.get("vulnerabilityType", "")
    )
    resource_type = _infer_resource_type(finding, resource_type)
    account_id = (
        integration.get("accountId", "")
        or resource.get("accountId", "")
        or finding.get("integrationId", "")
        or _extract_account_from_arn(resource.get("arn", ""))
    )
    region = (
        resource.get("region", "")
        or _extract_region_from_arn(resource.get("arn", ""))
        or "us-east-1"
    )

    return {
        "resource_id": resource_id,
        "resource_type": resource_type,
        "account_id": account_id,
        "region": region,
    }


def infer_and_store_task_links(cur, tasks: list) -> int:
    """Infer parent/child links (e.g., package-vuln parent -> CVE child) and persist."""
    now_iso = datetime.now(timezone.utc).isoformat()
    parents = [
        t for t in tasks
        if "vulnerabilities identified in packages are addressed" in (t.get("title") or "").lower()
    ]
    if not parents:
        return 0

    link_count = 0
    for child in tasks:
        child_title = (child.get("title") or "").lower()
        child_desc = (child.get("description") or "").lower()
        is_cve = "cve-" in child_title or "cve-" in child_desc
        if not is_cve:
            continue

        for parent in parents:
            same_account = (parent.get("account_id") or "") == (child.get("account_id") or "")
            same_type = (parent.get("remediation_type") or "") == (child.get("remediation_type") or "")
            same_due_day = (parent.get("due_date") or "")[:10] and (parent.get("due_date") or "")[:10] == (child.get("due_date") or "")[:10]
            if not (same_account and same_type and same_due_day):
                continue

            cur.execute(
                "INSERT INTO task_links (parent_task_id, child_task_id, link_type, confidence, source, created_at) "
                "VALUES (%s, %s, %s, %s, %s, %s) "
                "ON CONFLICT(parent_task_id, child_task_id, link_type) DO UPDATE SET "
                "confidence = EXCLUDED.confidence, source = EXCLUDED.source, created_at = EXCLUDED.created_at",
                (
                    parent.get("task_id"),
                    child.get("task_id"),
                    "parent_finding",
                    0.90,
                    "poller",
                    now_iso,
                ),
            )
            link_count += 1
            break

    return link_count


def _extract_account_from_arn(arn: str) -> str:
    """Pull AWS account ID from an ARN."""
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 else ""


def _extract_region_from_arn(arn: str) -> str:
    """Pull region from an ARN."""
    parts = arn.split(":")
    return parts[3] if len(parts) > 3 else ""


# ---------------------------------------------------------------------------
# Slack Notification
# ---------------------------------------------------------------------------

def send_slack_notification(task: dict) -> Optional[str]:
    """Send an interactive Slack message for a Vanta task. Returns message ts."""
    if not SLACK_BOT_TOKEN or not SLACK_CHANNEL_ID:
        log.warning("Slack not configured — skipping notification.")
        return None

    # Urgency emoji
    due = datetime.fromisoformat(task["due_date"].replace("Z", "+00:00"))
    now = datetime.now(timezone.utc)
    days_left = (due - now).days

    if days_left < 0:
        urgency = "🔴 OVERDUE"
        urgency_color = "#dc3545"
    elif days_left <= 2:
        urgency = "🟡 Due Soon"
        urgency_color = "#ffc107"
    else:
        urgency = "🟢 Upcoming"
        urgency_color = "#28a745"

    is_auto = task["remediation_type"] != "manual"
    remediation_label = (
        f"Auto-remediable (`{task['remediation_type']}`)" if is_auto
        else "Manual review required"
    )

    blocks = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{urgency} — Vanta Compliance Task",
            },
        },
        {
            "type": "section",
            "fields": [
                {"type": "mrkdwn", "text": f"*Task:*\n{task['title']}"},
                {"type": "mrkdwn", "text": f"*Due:*\n{task['due_date'][:10]} ({days_left}d)"},
                {"type": "mrkdwn", "text": f"*Account:*\n{task.get('account_id', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Region:*\n{task.get('region', 'N/A')}"},
                {"type": "mrkdwn", "text": f"*Resource:*\n`{task.get('resource_id', 'N/A')}`"},
                {"type": "mrkdwn", "text": f"*Remediation:*\n{remediation_label}"},
            ],
        },
    ]

    if task.get("description"):
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*Details:*\n{task['description'][:500]}",
            },
        })

    # Action buttons — only show Remediate if auto-remediable
    actions = []
    if is_auto:
        actions.append({
            "type": "button",
            "text": {"type": "plain_text", "text": "🔧 View Plan & Remediate"},
            "style": "primary",
            "action_id": "vantaops_remediate",
            "value": json.dumps({
                "task_id": task["task_id"],
                "remediation_type": task["remediation_type"],
            }),
        })

    actions.extend([
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "📋 View Details"},
            "action_id": "vantaops_details",
            "value": task["task_id"],
        },
        {
            "type": "button",
            "text": {"type": "plain_text", "text": "⏭️ Snooze"},
            "action_id": "vantaops_snooze",
            "value": task["task_id"],
        },
    ])

    blocks.append({"type": "actions", "elements": actions})

    # Send to Slack
    resp = requests.post(
        "https://slack.com/api/chat.postMessage",
        headers={
            "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
            "Content-Type": "application/json",
        },
        json={
            "channel": SLACK_CHANNEL_ID,
            "blocks": blocks,
            "text": f"{urgency} — {task['title']}",  # fallback
        },
        timeout=15,
    )

    if resp.ok and resp.json().get("ok"):
        ts = resp.json()["ts"]
        log.info(f"Slack notification sent for task {task['task_id']} (ts={ts})")
        return ts
    else:
        log.error(f"Slack API error: {resp.text}")
        return None


# ---------------------------------------------------------------------------
# Dashboard Summary (stdout for OpenClaw)
# ---------------------------------------------------------------------------

def format_dashboard_summary(tasks: list) -> str:
    """Format a summary showing only tasks due in the next 7 days.
    Overdue tasks are stored in DB but not shown unless explicitly requested."""
    ALERT_WINDOW_DAYS = int(os.environ.get("VANTAOPS_ALERT_WINDOW_DAYS", "7"))
    now = datetime.now(timezone.utc)
    alert_cutoff = now + timedelta(days=ALERT_WINDOW_DAYS)

    overdue_count = 0
    due_soon = []   # within 2 days
    upcoming = []   # 3-7 days

    for t in tasks:
        try:
            due = datetime.fromisoformat(t["due_date"].replace("Z", "+00:00"))
        except (ValueError, TypeError):
            continue
        days_left = (due - now).days

        if days_left < 0:
            overdue_count += 1
            continue  # don't list overdue individually

        if due > alert_cutoff:
            continue  # outside the alert window

        entry = f"  - {t['title'][:80]} — due {t['due_date'][:10]} ({days_left}d)"

        if days_left <= 2:
            due_soon.append(entry)
        else:
            upcoming.append(entry)

    auto_count = sum(1 for t in tasks if t["remediation_type"] != "manual")
    manual_count = len(tasks) - auto_count
    active_count = len(due_soon) + len(upcoming)

    lines = [
        f"📋 Vanta Compliance Summary — {now.strftime('%B %d, %Y')}",
        "",
    ]

    if due_soon:
        lines.append(f"🟡 Due within 2 days ({len(due_soon)}):")
        lines.extend(due_soon)
        lines.append("")

    if upcoming:
        lines.append(f"🟢 Due within {ALERT_WINDOW_DAYS} days ({len(upcoming)}):")
        lines.extend(upcoming)
        lines.append("")

    if not due_soon and not upcoming:
        lines.append(f"✅ No tasks due in the next {ALERT_WINDOW_DAYS} days.")
        lines.append("")

    lines.append(f"Total synced: {len(tasks)} | Due soon: {active_count} | Overdue: {overdue_count}")
    lines.append(f"Auto-remediable: {auto_count} | Manual: {manual_count}")
    lines.append("")
    lines.append("Use `/vantaops due <days>` to query a custom range or ask me in natural language.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main Poller Logic
# ---------------------------------------------------------------------------

def poll_and_notify(conn, client: VantaClient) -> str:
    """Main polling loop: fetch from Vanta, classify, notify, return summary."""
    cur = dict_cursor(conn)

    # 1. Fetch failing tests and approaching vulnerabilities
    failing_tests = client.get_failing_tests()
    vulnerabilities = client.get_vulnerabilities(sla_days=LOOKAHEAD_DAYS)
    person_security_tasks = client.get_person_security_tasks()

    log.info(
        f"Fetched {len(failing_tests)} failing tests, {len(vulnerabilities)} vulnerabilities, "
        f"{len(person_security_tasks)} personnel tasks from Vanta."
    )

    # 2. Normalize into a common task format
    tasks = []

    for test in failing_tests:
        task_id = test.get("id", "")
        title = test.get("name", test.get("title", "Unnamed test"))
        description = test.get("description", test.get("failureDescription", ""))
        # Vanta tests use remediationStatusInfo or don't have explicit SLA dates.
        # For failing tests, derive a deadline: remediation target or default 14 days from flip.
        remediation_info = test.get("remediationStatusInfo", {}) or {}
        due_date = remediation_info.get("remediateByDate", "")
        if not due_date:
            # Fallback: use latestFlipDate + LOOKAHEAD_DAYS * 3 as synthetic deadline
            flip_date = test.get("latestFlipDate", "")
            if flip_date:
                try:
                    flip_dt = datetime.fromisoformat(flip_date.replace("Z", "+00:00"))
                    synthetic_due = flip_dt + timedelta(days=30)
                    due_date = synthetic_due.isoformat()
                except (ValueError, TypeError):
                    pass
        if not due_date:
            due_date = None

        framework = test.get("category", test.get("framework", {}).get("name", ""))
        aws_ctx = extract_aws_context(test)
        rtype = classify_remediation_type(title, description)

        owner = extract_owner(test)

        tasks.append({
            "task_id": task_id,
            "title": title,
            "description": description,
            "due_date": due_date,
            "framework": framework,
            "remediation_type": rtype,
            "severity": test.get("status", ""),
            "owner": owner,
            **aws_ctx,
        })

    for vuln in vulnerabilities:
        task_id = vuln.get("id", "")
        title = vuln.get("name", vuln.get("title", "Unnamed vulnerability"))
        description = vuln.get("description", "")
        due_date = vuln.get("remediateByDate", vuln.get("slaDeadline", ""))
        if not due_date:
            continue

        aws_ctx = extract_aws_context(vuln)
        rtype = classify_remediation_type(title, description)

        tasks.append({
            "task_id": task_id,
            "title": title,
            "description": description,
            "due_date": due_date,
            "framework": vuln.get("framework", {}).get("name", ""),
            "remediation_type": rtype,
            "severity": vuln.get("severity", ""),
            "owner": extract_owner(vuln),
            **aws_ctx,
        })

    linked = infer_and_store_task_links(cur, tasks)
    if linked:
        log.info(f"Inferred and stored {linked} task links.")

    # 2b. Sync personnel/security tasks for smarter owner queries
    now_iso = datetime.now(timezone.utc).isoformat()
    for ptask in person_security_tasks:
        cur.execute("""
            INSERT INTO person_security_tasks
                (person_task_id, owner_name, owner_email, task_title, task_category,
                 status, due_date, completed_at, synced_at, raw_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT(person_task_id) DO UPDATE SET
                owner_name = EXCLUDED.owner_name,
                owner_email = EXCLUDED.owner_email,
                task_title = EXCLUDED.task_title,
                task_category = EXCLUDED.task_category,
                status = EXCLUDED.status,
                due_date = COALESCE(EXCLUDED.due_date, person_security_tasks.due_date),
                completed_at = COALESCE(EXCLUDED.completed_at, person_security_tasks.completed_at),
                synced_at = EXCLUDED.synced_at,
                raw_json = EXCLUDED.raw_json
        """, (
            ptask.get("person_task_id", ""),
            ptask.get("owner_name", ""),
            ptask.get("owner_email", ""),
            ptask.get("task_title", ""),
            ptask.get("task_category", ""),
            ptask.get("status", "open"),
            ptask.get("due_date", ""),
            ptask.get("completed_at", ""),
            now_iso,
            json.dumps(ptask.get("raw_json", {})),
        ))

    # 3. Deduplicate — skip tasks already notified in the last 24h
    new_tasks = []
    for task in tasks:
        cur.execute(
            "SELECT notified_at FROM vanta_tasks WHERE task_id = %s",
            (task["task_id"],),
        )
        row = cur.fetchone()

        if row and row["notified_at"]:
            last_notified = datetime.fromisoformat(row["notified_at"])
            if (datetime.now(timezone.utc) - last_notified).total_seconds() < 86400:
                log.info(f"Skipping {task['task_id']} — notified within 24h.")
                continue

        new_tasks.append(task)

    log.info(f"Total tasks found: {len(tasks)}, new to notify: {len(new_tasks)}")

    # 4. Store ALL tasks in DB; only send individual Slack alerts for tasks due within 7 days
    ALERT_WINDOW_DAYS = int(os.environ.get("VANTAOPS_ALERT_WINDOW_DAYS", "7"))
    alert_cutoff = datetime.now(timezone.utc) + timedelta(days=ALERT_WINDOW_DAYS)
    alerted_count = 0

    # Sort by due date (most urgent first)
    new_tasks.sort(key=lambda t: t.get("due_date") or "9999")

    for task in new_tasks:
        now_iso = datetime.now(timezone.utc).isoformat()

        # Only send individual Slack alerts for tasks due between now and the alert window
        # (skip old/past-due tasks from 2024 etc. — they're stored in DB for historical queries)
        slack_ts = None
        now_dt = datetime.now(timezone.utc)
        due_date = task.get("due_date")
        if due_date:
            try:
                task_due = datetime.fromisoformat(due_date.replace("Z", "+00:00"))
                if now_dt <= task_due <= alert_cutoff:
                    slack_ts = send_slack_notification(task)
                    alerted_count += 1
            except (ValueError, TypeError, AttributeError):
                pass

        # Upsert into database (always)
        cur.execute("""
            INSERT INTO vanta_tasks
                (task_id, title, description, due_date, framework,
                 resource_id, resource_type, account_id, region,
                 remediation_type, severity, owner, status, notified_at, slack_ts, raw_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'notified', %s, %s, %s)
            ON CONFLICT(task_id) DO UPDATE SET
                title = EXCLUDED.title,
                description = EXCLUDED.description,
                due_date = COALESCE(EXCLUDED.due_date, vanta_tasks.due_date),
                framework = EXCLUDED.framework,
                resource_id = EXCLUDED.resource_id,
                resource_type = EXCLUDED.resource_type,
                account_id = EXCLUDED.account_id,
                region = EXCLUDED.region,
                remediation_type = EXCLUDED.remediation_type,
                notified_at = EXCLUDED.notified_at,
                slack_ts = COALESCE(EXCLUDED.slack_ts, vanta_tasks.slack_ts),
                severity = COALESCE(EXCLUDED.severity, vanta_tasks.severity),
                owner = COALESCE(EXCLUDED.owner, vanta_tasks.owner),
                raw_json = EXCLUDED.raw_json,
                status = CASE
                    WHEN vanta_tasks.status = 'remediated' THEN 'remediated'
                    ELSE 'notified'
                END
        """, (
            task["task_id"], task["title"], task["description"],
            task["due_date"], task["framework"],
            task.get("resource_id"), task.get("resource_type"),
            task.get("account_id"), task.get("region"),
            task["remediation_type"], task.get("severity", ""),
            task.get("owner", ""), now_iso, slack_ts,
            json.dumps(task),
        ))

    conn.commit()
    cur.close()

    log.info(f"Stored {len(new_tasks)} tasks in DB, sent {alerted_count} Slack alerts (due within {ALERT_WINDOW_DAYS}d)")

    # 5. Return summary
    summary = format_dashboard_summary(tasks if tasks else new_tasks)
    return summary


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="VantaOps Poller")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Fetch and classify tasks but don't send Slack notifications",
    )
    args = parser.parse_args()

    # Validate required env vars
    missing = []
    if not VANTA_CLIENT_ID:
        missing.append("VANTA_CLIENT_ID")
    if not VANTA_CLIENT_SECRET:
        missing.append("VANTA_CLIENT_SECRET")
    if missing:
        log.error(f"Missing required environment variables: {', '.join(missing)}")
        sys.exit(1)

    if not SLACK_BOT_TOKEN and not args.dry_run:
        log.warning("SLACK_BOT_TOKEN not set — Slack notifications will be skipped.")

    # Initialize
    init_db()
    conn = get_db()
    client = VantaClient(VANTA_CLIENT_ID, VANTA_CLIENT_SECRET)

    # Poll and notify
    try:
        summary = poll_and_notify(conn, client)
        print(summary)
    except requests.exceptions.HTTPError as e:
        log.error(f"Vanta API error: {e}")
        log.error(f"Response: {e.response.text if e.response else 'No response'}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
