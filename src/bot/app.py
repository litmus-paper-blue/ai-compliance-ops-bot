"""
VantaOps — Slack Bot (Bolt for Python, Socket Mode)

Handles interactive notifications, approval buttons, and remediation
triggers from Slack. Runs as a standalone service alongside OpenClaw.
"""

import os
import sys
import json
import logging
import subprocess
from datetime import datetime, timezone

from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler

from db import get_db, dict_cursor, init_db
from llm import LLMRouter

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
llm = None  # initialized after db in main()

SYSTEM_PROMPT = """You are VantaOps, an AI-powered Vanta compliance remediation assistant.

Your job is to help users understand and fix AWS compliance findings flagged by Vanta.
You focus on: CloudWatch alarms, S3 bucket security, security groups, SSM patching, and CloudTrail/Config logging.

Rules:
- Be concise. Use Slack-friendly formatting (*bold*, `code`, bullet points).
- When discussing remediation, always mention that execution requires explicit approval.
- Never fabricate task IDs, AWS resource IDs, or compliance details — only reference what's in the database.
- If you have relevant lessons from past remediations (provided in context), reference them.
- If you don't know something, say so and suggest checking Vanta or AWS directly.
- You are NOT allowed to execute AWS commands directly — only the remediation engine does that with user approval.
"""


def get_context_for_llm(user_message: str) -> str:
    """Pull relevant context from the database for the LLM."""
    context_parts = []
    conn = get_db()
    cur = dict_cursor(conn)

    # Current task summary
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE status IN ('pending', 'notified')"
    )
    pending = cur.fetchone()["c"]
    cur.execute(
        "SELECT COUNT(*) as c FROM vanta_tasks WHERE status = 'remediated'"
    )
    remediated = cur.fetchone()["c"]
    context_parts.append(
        f"Current state: {pending} pending tasks, {remediated} remediated."
    )

    # Recent tasks (up to 5)
    cur.execute(
        "SELECT task_id, title, status, remediation_type, account_id, region, due_date "
        "FROM vanta_tasks ORDER BY due_date ASC LIMIT 5"
    )
    tasks = cur.fetchall()
    if tasks:
        lines = ["Recent tasks:"]
        for t in tasks:
            lines.append(
                f"  - [{t['status']}] {t['title']} (type: {t['remediation_type']}, "
                f"account: {t['account_id'] or '?'}, due: {t['due_date'] or '?'})"
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


def ask_llm(user_message: str, channel_id: str = "", thread_ts: str = "") -> str:
    """Send a message to the LLM with database context."""
    if not llm:
        return "LLM not configured. Set ANTHROPIC_API_KEY or GOOGLE_API_KEY."

    context = get_context_for_llm(user_message)
    system = SYSTEM_PROMPT + "\n\n--- DATABASE CONTEXT ---\n" + context

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


# ---------------------------------------------------------------------------
# Action Handlers
# ---------------------------------------------------------------------------

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
            "• `/vantaops audit` — Show recent remediation audit log\n"
            "• `/vantaops task <id>` — Show details for a specific task"
        )
        return

    if text == "status":
        conn = get_db()
        cur = dict_cursor(conn)
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
        cur.close()
        conn.close()

        respond(
            f"📊 *VantaOps Status:*\n"
            f"• Pending/Notified: {pending}\n"
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

    else:
        respond(f"Unknown command: `{text}`. Try `/vantaops help`.")


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
    import re
    text = re.sub(r"<@[A-Z0-9]+>\s*", "", text).strip()

    if not text:
        client.chat_postMessage(
            channel=channel,
            thread_ts=thread_ts,
            text="👋 I'm VantaOps! Ask me about your compliance tasks or use `/vantaops help`.",
        )
        return

    response = ask_llm(text, channel_id=channel, thread_ts=thread_ts)
    client.chat_postMessage(
        channel=channel,
        thread_ts=thread_ts,
        text=response,
    )


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
    client.chat_postMessage(
        channel=channel,
        thread_ts=thread_ts,
        text=response,
    )


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Starting VantaOps Slack bot (Socket Mode)...")
    init_db()
    log.info("Database initialized.")
    llm = LLMRouter()
    handler = SocketModeHandler(app, SLACK_APP_TOKEN)
    handler.start()
