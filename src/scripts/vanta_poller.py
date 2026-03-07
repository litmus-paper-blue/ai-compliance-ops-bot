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

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

VANTA_API_BASE = "https://api.vanta.com"
VANTA_AUTH_URL = f"{VANTA_API_BASE}/oauth/token"
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
# Vanta API Client
# ---------------------------------------------------------------------------

class VantaClient:
    """Minimal Vanta REST API client using OAuth2 client credentials."""

    def __init__(self, client_id: str, client_secret: str):
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._token_expiry: float = 0

    def _authenticate(self) -> str:
        """Obtain or refresh an OAuth2 access token."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        log.info("Authenticating with Vanta API...")
        resp = requests.post(
            VANTA_AUTH_URL,
            json={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "scope": "vanta-api.all:read",
            },
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
        self._token = data["access_token"]
        # Expire 5 min early to be safe
        self._token_expiry = time.time() + data.get("expires_in", 3600) - 300
        log.info("Authenticated successfully.")
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._authenticate()}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    def _get_paginated(self, endpoint: str, params: dict = None) -> list:
        """Fetch all pages from a paginated Vanta endpoint."""
        results = []
        params = params or {}
        params.setdefault("pageSize", 100)
        cursor = None

        while True:
            if cursor:
                params["pageCursor"] = cursor
            resp = requests.get(
                f"{VANTA_API_BASE}{endpoint}",
                headers=self._headers(),
                params=params,
                timeout=30,
            )
            resp.raise_for_status()
            body = resp.json()

            data = body.get("results", {}).get("data", [])
            results.extend(data)

            page_info = body.get("results", {}).get("pageInfo", {})
            if page_info.get("hasNextPage") and page_info.get("endCursor"):
                cursor = page_info["endCursor"]
            else:
                break

        return results

    def get_failing_tests(self) -> list:
        """Fetch tests that are currently failing."""
        log.info("Fetching failing tests from Vanta...")
        # The Vanta API allows filtering tests by status
        tests = self._get_paginated(
            "/v1/tests",
            params={"filter[status]": "FAILING"},
        )
        log.info(f"Found {len(tests)} failing tests.")
        return tests

    def get_vulnerabilities(self, sla_days: int = 5) -> list:
        """Fetch vulnerabilities with SLA approaching within N days."""
        log.info(f"Fetching vulnerabilities with SLA within {sla_days} days...")
        cutoff = (datetime.now(timezone.utc) + timedelta(days=sla_days)).isoformat()
        vulns = self._get_paginated(
            "/v1/vulnerabilities",
            params={"filter[slaDeadlineBefore]": cutoff},
        )
        log.info(f"Found {len(vulns)} vulnerabilities approaching SLA.")
        return vulns

    def get_resources(self, resource_type: str = None) -> list:
        """Fetch monitored resources, optionally filtered by type."""
        log.info(f"Fetching resources (type={resource_type})...")
        params = {}
        if resource_type:
            params["filter[resourceType]"] = resource_type
        return self._get_paginated("/v1/resources", params=params)


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


def extract_aws_context(finding: dict) -> dict:
    """Extract AWS account, region, and resource info from a Vanta finding."""
    # Vanta structures vary — this handles common patterns
    resource = finding.get("resource", {})
    integration = finding.get("integration", {})

    return {
        "resource_id": resource.get("id", resource.get("externalId", "")),
        "resource_type": resource.get("resourceType", ""),
        "account_id": (
            integration.get("accountId", "")
            or resource.get("accountId", "")
            or _extract_account_from_arn(resource.get("arn", ""))
        ),
        "region": (
            resource.get("region", "")
            or _extract_region_from_arn(resource.get("arn", ""))
            or "us-east-1"
        ),
    }


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
    """Format a summary string for the OpenClaw dashboard."""
    now = datetime.now(timezone.utc)
    overdue = []
    due_soon = []  # within 2 days
    upcoming = []  # 3-5 days

    for t in tasks:
        due = datetime.fromisoformat(t["due_date"].replace("Z", "+00:00"))
        days_left = (due - now).days
        entry = f"  - {t['title']} ({t.get('account_id', '?')}, {t.get('region', '?')}) — due {t['due_date'][:10]}"

        if days_left < 0:
            overdue.append(entry)
        elif days_left <= 2:
            due_soon.append(entry)
        else:
            upcoming.append(entry)

    auto_count = sum(1 for t in tasks if t["remediation_type"] != "manual")
    manual_count = len(tasks) - auto_count

    lines = [
        f"📋 Vanta Compliance Summary — {now.strftime('%B %d, %Y')}",
        "",
    ]

    if overdue:
        lines.append(f"🔴 Overdue ({len(overdue)}):")
        lines.extend(overdue)
        lines.append("")

    if due_soon:
        lines.append(f"🟡 Due within 2 days ({len(due_soon)}):")
        lines.extend(due_soon)
        lines.append("")

    if upcoming:
        lines.append(f"🟢 Due within 5 days ({len(upcoming)}):")
        lines.extend(upcoming)
        lines.append("")

    if not tasks:
        lines.append("✅ No tasks due in the next 5 days. Looking good!")
        lines.append("")

    lines.append(f"Auto-remediable: {auto_count} | Manual: {manual_count}")
    lines.append("")
    lines.append("Reply with a task ID or click 'Remediate' in Slack to fix.")

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

    # 2. Normalize into a common task format
    tasks = []

    for test in failing_tests:
        task_id = test.get("id", "")
        title = test.get("title", test.get("name", "Unnamed test"))
        description = test.get("description", "")
        due_date = test.get("remediationSlaDeadline", "")
        if not due_date:
            continue

        framework = test.get("framework", {}).get("name", "")
        aws_ctx = extract_aws_context(test)
        rtype = classify_remediation_type(title, description)

        tasks.append({
            "task_id": task_id,
            "title": title,
            "description": description,
            "due_date": due_date,
            "framework": framework,
            "remediation_type": rtype,
            **aws_ctx,
        })

    for vuln in vulnerabilities:
        task_id = vuln.get("id", "")
        title = vuln.get("title", vuln.get("name", "Unnamed vulnerability"))
        description = vuln.get("description", "")
        due_date = vuln.get("slaDeadline", "")
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
            **aws_ctx,
        })

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

    # 4. Store and notify
    for task in new_tasks:
        now_iso = datetime.now(timezone.utc).isoformat()

        # Send Slack notification
        slack_ts = send_slack_notification(task)

        # Upsert into database
        cur.execute("""
            INSERT INTO vanta_tasks
                (task_id, title, description, due_date, framework,
                 resource_id, resource_type, account_id, region,
                 remediation_type, status, notified_at, slack_ts, raw_json)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'notified', %s, %s, %s)
            ON CONFLICT(task_id) DO UPDATE SET
                notified_at = EXCLUDED.notified_at,
                slack_ts = EXCLUDED.slack_ts,
                status = CASE
                    WHEN vanta_tasks.status = 'remediated' THEN 'remediated'
                    ELSE 'notified'
                END
        """, (
            task["task_id"], task["title"], task["description"],
            task["due_date"], task["framework"],
            task.get("resource_id"), task.get("resource_type"),
            task.get("account_id"), task.get("region"),
            task["remediation_type"], now_iso, slack_ts,
            json.dumps(task),
        ))

    conn.commit()
    cur.close()

    # 5. Return summary for OpenClaw dashboard
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
