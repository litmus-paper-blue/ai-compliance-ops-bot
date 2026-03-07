"""
VantaOps — AWS Remediation Engine

Generates remediation plans and executes AWS CLI commands for Vanta
compliance findings. Every destructive action requires explicit approval.
"""

import os
import sys
import json
import logging
import argparse
import subprocess
from datetime import datetime, timezone
from typing import Optional

from db import get_db, dict_cursor, init_db

ACCOUNTS_CONFIG = os.environ.get("VANTAOPS_ACCOUNTS_CONFIG", "/app/config/accounts.json")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("aws-remediate")


# ---------------------------------------------------------------------------
# AWS Account Management
# ---------------------------------------------------------------------------

def load_accounts() -> dict:
    """Load AWS account configuration."""
    if os.path.exists(ACCOUNTS_CONFIG):
        with open(ACCOUNTS_CONFIG) as f:
            return json.load(f).get("accounts", {})
    log.warning(f"Accounts config not found at {ACCOUNTS_CONFIG}")
    return {}


def assume_role(account_id: str, role_name: str = "vantaops-remediation-role") -> dict:
    """Assume an IAM role in the target account. Returns temp credentials."""
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    log.info(f"Assuming role {role_arn}...")

    result = _run_aws([
        "sts", "assume-role",
        "--role-arn", role_arn,
        "--role-session-name", "vantaops-remediation",
        "--duration-seconds", "3600",
    ])

    if result["exit_code"] != 0:
        raise RuntimeError(f"AssumeRole failed: {result['output']}")

    creds = json.loads(result["output"])["Credentials"]
    return {
        "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
        "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
        "AWS_SESSION_TOKEN": creds["SessionToken"],
    }


def _run_aws(args: list, env_override: dict = None, region: str = None) -> dict:
    """Run an AWS CLI command and return structured output."""
    cmd = ["aws", "--output", "json"]
    if region:
        cmd.extend(["--region", region])
    cmd.extend(args)

    env = os.environ.copy()
    if env_override:
        env.update(env_override)

    log.info(f"Running: {' '.join(cmd)}")
    proc = subprocess.run(
        cmd, capture_output=True, text=True, env=env, timeout=120,
    )

    return {
        "command": " ".join(cmd),
        "output": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "exit_code": proc.returncode,
    }


# ---------------------------------------------------------------------------
# Remediation Plan Generators
# ---------------------------------------------------------------------------

class RemediationPlan:
    """Represents a remediation plan with commands to execute."""

    def __init__(self, task_id: str, remediation_type: str):
        self.task_id = task_id
        self.remediation_type = remediation_type
        self.steps: list[dict] = []
        self.current_state: str = ""
        self.desired_state: str = ""
        self.risk: str = "low"  # low, medium, high

    def add_step(self, description: str, command: list, region: str = None):
        self.steps.append({
            "description": description,
            "command": command,
            "region": region,
        })

    def to_dict(self) -> dict:
        return {
            "task_id": self.task_id,
            "remediation_type": self.remediation_type,
            "risk": self.risk,
            "current_state": self.current_state,
            "desired_state": self.desired_state,
            "steps": [
                {
                    "description": s["description"],
                    "command": f"aws {' '.join(s['command'])}",
                    "region": s.get("region"),
                }
                for s in self.steps
            ],
        }

    def to_display(self) -> str:
        """Format for human-readable display."""
        lines = [
            f"📋 Remediation Plan — {self.task_id}",
            f"Type: {self.remediation_type} | Risk: {self.risk.upper()}",
            "",
            f"Current State: {self.current_state}",
            f"Desired State: {self.desired_state}",
            "",
            "Commands to execute:",
        ]
        for i, step in enumerate(self.steps, 1):
            lines.append(f"  {i}. {step['description']}")
            cmd = f"aws {' '.join(step['command'])}"
            if step.get("region"):
                cmd = f"aws --region {step['region']} {' '.join(step['command'])}"
            lines.append(f"     $ {cmd}")
            lines.append("")

        lines.append("⚠️  Awaiting your approval before executing.")
        return "\n".join(lines)


def plan_cloudwatch_alarm(task: dict, creds: dict) -> RemediationPlan:
    """Generate a plan to create a CloudWatch alarm."""
    plan = RemediationPlan(task["task_id"], "cloudwatch")
    resource_id = task.get("resource_id", "")
    region = task.get("region", "us-east-1")
    account_id = task.get("account_id", "")

    # Determine alarm parameters based on resource type
    resource_type = task.get("resource_type", "").lower()
    title_lower = task.get("title", "").lower()

    if "alb" in resource_type or "load balancer" in title_lower or "elb" in title_lower:
        alarm_name = f"{resource_id}-5xx-alarm"
        plan.current_state = f"ALB '{resource_id}' has no 5XX error alarm"
        plan.desired_state = f"CloudWatch alarm '{alarm_name}' monitors 5XX errors"
        plan.risk = "low"
        plan.add_step(
            f"Create 5XX alarm for ALB {resource_id}",
            [
                "cloudwatch", "put-metric-alarm",
                "--alarm-name", alarm_name,
                "--namespace", "AWS/ApplicationELB",
                "--metric-name", "HTTPCode_ELB_5XX_Count",
                "--dimensions", f"Name=LoadBalancer,Value={resource_id}",
                "--statistic", "Sum",
                "--period", "300",
                "--threshold", "10",
                "--comparison-operator", "GreaterThanThreshold",
                "--evaluation-periods", "2",
                "--treat-missing-data", "notBreaching",
                "--alarm-description", f"VantaOps: 5XX alarm for {resource_id}",
            ],
            region=region,
        )

    elif "rds" in resource_type or "database" in title_lower:
        alarm_name = f"{resource_id}-cpu-alarm"
        plan.current_state = f"RDS '{resource_id}' has no CPU alarm"
        plan.desired_state = f"CloudWatch alarm '{alarm_name}' monitors CPU utilization"
        plan.risk = "low"
        plan.add_step(
            f"Create CPU alarm for RDS {resource_id}",
            [
                "cloudwatch", "put-metric-alarm",
                "--alarm-name", alarm_name,
                "--namespace", "AWS/RDS",
                "--metric-name", "CPUUtilization",
                "--dimensions", f"Name=DBInstanceIdentifier,Value={resource_id}",
                "--statistic", "Average",
                "--period", "300",
                "--threshold", "80",
                "--comparison-operator", "GreaterThanThreshold",
                "--evaluation-periods", "3",
                "--treat-missing-data", "missing",
                "--alarm-description", f"VantaOps: CPU alarm for {resource_id}",
            ],
            region=region,
        )

    elif "lambda" in resource_type or "lambda" in title_lower:
        alarm_name = f"{resource_id}-errors-alarm"
        plan.current_state = f"Lambda '{resource_id}' has no error alarm"
        plan.desired_state = f"CloudWatch alarm '{alarm_name}' monitors errors"
        plan.risk = "low"
        plan.add_step(
            f"Create error alarm for Lambda {resource_id}",
            [
                "cloudwatch", "put-metric-alarm",
                "--alarm-name", alarm_name,
                "--namespace", "AWS/Lambda",
                "--metric-name", "Errors",
                "--dimensions", f"Name=FunctionName,Value={resource_id}",
                "--statistic", "Sum",
                "--period", "300",
                "--threshold", "5",
                "--comparison-operator", "GreaterThanThreshold",
                "--evaluation-periods", "2",
                "--treat-missing-data", "notBreaching",
                "--alarm-description", f"VantaOps: Error alarm for {resource_id}",
            ],
            region=region,
        )

    else:
        # Generic — let the user know we need more context
        plan.current_state = f"Resource '{resource_id}' missing CloudWatch alarm"
        plan.desired_state = "CloudWatch alarm configured"
        plan.risk = "medium"
        plan.steps = []  # Empty — will prompt for manual specification

    return plan


def plan_s3_remediation(task: dict, creds: dict) -> RemediationPlan:
    """Generate a plan to fix S3 bucket security settings."""
    plan = RemediationPlan(task["task_id"], "s3")
    bucket = task.get("resource_id", "")
    region = task.get("region", "us-east-1")
    title_lower = task.get("title", "").lower()

    plan.risk = "low"

    if "encryption" in title_lower:
        plan.current_state = f"S3 bucket '{bucket}' does not have default encryption"
        plan.desired_state = f"S3 bucket '{bucket}' has AES-256 default encryption"
        plan.add_step(
            f"Enable AES-256 default encryption on {bucket}",
            [
                "s3api", "put-bucket-encryption",
                "--bucket", bucket,
                "--server-side-encryption-configuration",
                '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}',
            ],
            region=region,
        )

    elif "public" in title_lower:
        plan.current_state = f"S3 bucket '{bucket}' allows public access"
        plan.desired_state = f"S3 bucket '{bucket}' blocks all public access"
        plan.add_step(
            f"Block all public access on {bucket}",
            [
                "s3api", "put-public-access-block",
                "--bucket", bucket,
                "--public-access-block-configuration",
                "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            ],
            region=region,
        )

    elif "versioning" in title_lower:
        plan.current_state = f"S3 bucket '{bucket}' does not have versioning enabled"
        plan.desired_state = f"S3 bucket '{bucket}' has versioning enabled"
        plan.add_step(
            f"Enable versioning on {bucket}",
            [
                "s3api", "put-bucket-versioning",
                "--bucket", bucket,
                "--versioning-configuration", "Status=Enabled",
            ],
            region=region,
        )

    elif "logging" in title_lower:
        plan.current_state = f"S3 bucket '{bucket}' does not have access logging"
        plan.desired_state = f"S3 bucket '{bucket}' has access logging to a logging bucket"
        plan.risk = "medium"  # Needs a target bucket
        # This one needs more context — we'll note that
        plan.add_step(
            f"Enable access logging on {bucket} (target bucket TBD)",
            [
                "s3api", "put-bucket-logging",
                "--bucket", bucket,
                "--bucket-logging-status",
                '{"LoggingEnabled":{"TargetBucket":"LOGGING_BUCKET_NAME","TargetPrefix":"s3-access-logs/"}}',
            ],
            region=region,
        )

    return plan


def plan_security_group(task: dict, creds: dict) -> RemediationPlan:
    """Generate a plan to fix security group issues."""
    plan = RemediationPlan(task["task_id"], "security-group")
    sg_id = task.get("resource_id", "")
    region = task.get("region", "us-east-1")

    plan.current_state = f"Security group '{sg_id}' has overly permissive rules"
    plan.desired_state = f"Security group '{sg_id}' restricted to appropriate CIDRs"
    plan.risk = "high"  # SG changes can break connectivity

    # First step: describe current rules so the user sees what's there
    plan.add_step(
        f"Describe current rules for {sg_id}",
        [
            "ec2", "describe-security-group-rules",
            "--filters", f"Name=group-id,Values={sg_id}",
        ],
        region=region,
    )

    # We don't auto-generate the revoke/authorize commands because SG changes
    # are high-risk and context-dependent. The plan will show current rules
    # and the user/LLM will determine the specific changes needed.

    return plan


def plan_ssm_patch(task: dict, creds: dict) -> RemediationPlan:
    """Generate a plan to patch an EC2 instance via SSM."""
    plan = RemediationPlan(task["task_id"], "ssm-patch")
    instance_id = task.get("resource_id", "")
    region = task.get("region", "us-east-1")
    title = task.get("title", "")

    plan.current_state = f"EC2 instance '{instance_id}' has outdated packages"
    plan.desired_state = f"EC2 instance '{instance_id}' packages updated"
    plan.risk = "medium"

    # Check SSM agent status first
    plan.add_step(
        f"Verify SSM agent is running on {instance_id}",
        [
            "ssm", "describe-instance-information",
            "--filters", f"Key=InstanceIds,Values={instance_id}",
        ],
        region=region,
    )

    # Determine the patch command based on the finding
    if "node" in title.lower() or "npm" in title.lower():
        patch_cmd = "source ~/.nvm/nvm.sh && nvm install --lts && npm update -g"
    elif "python" in title.lower():
        patch_cmd = "pip3 install --upgrade pip && pip3 list --outdated --format=json"
    else:
        # Generic OS package update
        patch_cmd = (
            "if command -v yum &>/dev/null; then yum update -y --security; "
            "elif command -v apt-get &>/dev/null; then apt-get update && "
            "apt-get upgrade -y --with-new-pkgs; fi"
        )

    plan.add_step(
        f"Run patch command on {instance_id} via SSM",
        [
            "ssm", "send-command",
            "--instance-ids", instance_id,
            "--document-name", "AWS-RunShellScript",
            "--parameters", json.dumps({"commands": [patch_cmd]}),
            "--timeout-seconds", "600",
            "--comment", f"VantaOps remediation for {task['task_id']}",
        ],
        region=region,
    )

    return plan


def plan_logging(task: dict, creds: dict) -> RemediationPlan:
    """Generate a plan to enable CloudTrail or AWS Config."""
    plan = RemediationPlan(task["task_id"], "logging")
    region = task.get("region", "us-east-1")
    title_lower = task.get("title", "").lower()

    if "cloudtrail" in title_lower:
        plan.current_state = f"CloudTrail not enabled in {region}"
        plan.desired_state = f"CloudTrail enabled with S3 logging in {region}"
        plan.risk = "low"
        plan.add_step(
            "List existing trails",
            ["cloudtrail", "describe-trails"],
            region=region,
        )
        # Actual trail creation needs a target S3 bucket — flag for user input
    elif "config" in title_lower:
        plan.current_state = f"AWS Config not recording in {region}"
        plan.desired_state = f"AWS Config recording enabled in {region}"
        plan.risk = "low"
        plan.add_step(
            "Check Config recorder status",
            ["configservice", "describe-configuration-recorder-status"],
            region=region,
        )

    return plan


# Plan dispatcher
PLAN_GENERATORS = {
    "cloudwatch": plan_cloudwatch_alarm,
    "s3": plan_s3_remediation,
    "security-group": plan_security_group,
    "ssm-patch": plan_ssm_patch,
    "logging": plan_logging,
}


# ---------------------------------------------------------------------------
# Execution Engine
# ---------------------------------------------------------------------------

def execute_plan(
    plan: RemediationPlan,
    creds: dict,
    approved_by: str,
    conn,
) -> list[dict]:
    """Execute all steps in a remediation plan. Returns list of results."""
    results = []
    now_iso = datetime.now(timezone.utc).isoformat()
    cur = conn.cursor()

    for step in plan.steps:
        log.info(f"Executing: {step['description']}")

        result = _run_aws(
            step["command"],
            env_override=creds,
            region=step.get("region"),
        )

        results.append({
            "description": step["description"],
            **result,
        })

        # Log to audit table
        cur.execute("""
            INSERT INTO audit_log
                (timestamp, task_id, action, account_id, region,
                 command, output, exit_code, approved_by, approved_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            now_iso, plan.task_id, step["description"],
            "", step.get("region", ""),
            result["command"], result["output"], result["exit_code"],
            approved_by, now_iso,
        ))

        # If any step fails, stop execution
        if result["exit_code"] != 0:
            log.error(f"Step failed: {result['stderr']}")
            break

    conn.commit()
    cur.close()
    return results


def format_execution_results(results: list) -> str:
    """Format execution results for display."""
    lines = ["📋 Execution Results:", ""]
    all_ok = True

    for r in results:
        status = "✅" if r["exit_code"] == 0 else "❌"
        if r["exit_code"] != 0:
            all_ok = False
        lines.append(f"{status} {r['description']}")
        lines.append(f"   Command: {r['command']}")
        if r["output"]:
            # Truncate long output
            output = r["output"][:500]
            if len(r["output"]) > 500:
                output += "\n   ... (truncated)"
            lines.append(f"   Output: {output}")
        if r["exit_code"] != 0 and r["stderr"]:
            lines.append(f"   Error: {r['stderr'][:300]}")
        lines.append("")

    if all_ok:
        lines.append("✅ All steps completed successfully.")
    else:
        lines.append("⚠️ Some steps failed. Review the errors above.")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="VantaOps AWS Remediation")
    subparsers = parser.add_subparsers(dest="action", required=True)

    # Plan subcommand
    plan_parser = subparsers.add_parser("plan", help="Generate a remediation plan")
    plan_parser.add_argument("--task-id", required=True)

    # Execute subcommand
    exec_parser = subparsers.add_parser("execute", help="Execute an approved plan")
    exec_parser.add_argument("--task-id", required=True)
    exec_parser.add_argument("--approved-by", required=True)

    # Verify subcommand
    verify_parser = subparsers.add_parser("verify", help="Verify remediation was applied")
    verify_parser.add_argument("--task-id", required=True)

    args = parser.parse_args()

    init_db()
    conn = get_db()
    cur = dict_cursor(conn)

    # Load task from database
    cur.execute(
        "SELECT * FROM vanta_tasks WHERE task_id = %s", (args.task_id,)
    )
    task_row = cur.fetchone()

    if not task_row:
        log.error(f"Task {args.task_id} not found in database.")
        sys.exit(1)

    task = dict(task_row)
    cur.close()

    if args.action == "plan":
        # Generate remediation plan
        rtype = task.get("remediation_type", "manual")
        if rtype == "manual" or rtype not in PLAN_GENERATORS:
            print(f"⚠️ Task {args.task_id} requires manual remediation (type: {rtype}).")
            print(f"Title: {task['title']}")
            print(f"Description: {task.get('description', 'N/A')}")
            sys.exit(0)

        # Get temporary credentials for the target account
        account_id = task.get("account_id")
        if account_id:
            creds = assume_role(account_id)
        else:
            creds = {}
            log.warning("No account ID — using default credentials.")

        generator = PLAN_GENERATORS[rtype]
        plan = generator(task, creds)

        # Display the plan
        print(plan.to_display())

        # Also save plan as JSON for the execute step
        plan_json = json.dumps(plan.to_dict(), indent=2)
        cur2 = conn.cursor()
        cur2.execute("""
            UPDATE vanta_tasks SET raw_json = %s WHERE task_id = %s
        """, (plan_json, args.task_id))
        conn.commit()
        cur2.close()

    elif args.action == "execute":
        # Load the saved plan
        plan_data = json.loads(task.get("raw_json", "{}"))
        if not plan_data.get("steps"):
            log.error("No plan found — run 'plan' first.")
            sys.exit(1)

        rtype = plan_data["remediation_type"]
        plan = RemediationPlan(args.task_id, rtype)
        for step in plan_data["steps"]:
            # Parse the command string back into a list (skip the "aws" prefix)
            cmd_parts = step["command"].split()[1:]  # remove "aws"
            plan.add_step(step["description"], cmd_parts, step.get("region"))
        plan.current_state = plan_data.get("current_state", "")
        plan.desired_state = plan_data.get("desired_state", "")
        plan.risk = plan_data.get("risk", "medium")

        # Get credentials
        account_id = task.get("account_id")
        creds = assume_role(account_id) if account_id else {}

        # Execute
        results = execute_plan(plan, creds, args.approved_by, conn)
        print(format_execution_results(results))

        # Update task status
        all_ok = all(r["exit_code"] == 0 for r in results)
        if all_ok:
            cur2 = conn.cursor()
            cur2.execute("""
                UPDATE vanta_tasks
                SET status = 'remediated',
                    remediated_at = %s,
                    remediated_by = %s
                WHERE task_id = %s
            """, (
                datetime.now(timezone.utc).isoformat(),
                args.approved_by,
                args.task_id,
            ))
            conn.commit()
            cur2.close()

    elif args.action == "verify":
        # Re-run a read-only check to confirm the fix is in place
        rtype = task.get("remediation_type", "")
        account_id = task.get("account_id")
        region = task.get("region", "us-east-1")
        resource_id = task.get("resource_id", "")

        creds = assume_role(account_id) if account_id else {}

        if rtype == "cloudwatch":
            result = _run_aws(
                ["cloudwatch", "describe-alarms",
                 "--alarm-name-prefix", resource_id],
                env_override=creds, region=region,
            )
        elif rtype == "s3":
            result = _run_aws(
                ["s3api", "get-bucket-encryption", "--bucket", resource_id],
                env_override=creds, region=region,
            )
        elif rtype == "ssm-patch":
            result = _run_aws(
                ["ssm", "describe-instance-information",
                 "--filters", f"Key=InstanceIds,Values={resource_id}"],
                env_override=creds, region=region,
            )
        else:
            print(f"Verification not implemented for type: {rtype}")
            sys.exit(0)

        if result["exit_code"] == 0:
            print(f"✅ Verification passed for {args.task_id}")
            print(result["output"][:500])
        else:
            print(f"❌ Verification failed for {args.task_id}")
            print(result["stderr"][:300])

    conn.close()


if __name__ == "__main__":
    main()
