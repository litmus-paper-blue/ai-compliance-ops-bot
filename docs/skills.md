---
name: ai-compliance-ops-bot-skills
description: >
  OpenClaw skill reference for Vanta polling and AWS remediation workflows.
---

# Skills Reference

## Vanta Poller

Poll Vanta for tasks due in the next 5 days and notify Slack.

```bash
python3 /app/src/scripts/vanta_poller.py
```

What it does:
- Authenticates to Vanta using OAuth2 credentials
- Pulls failing tests and due-soon tasks
- Classifies remediation type and deduplicates notifications
- Posts actionable summaries to Slack

## AWS Remediation

Generate, approve, execute, and verify AWS remediations.

### 1) Generate plan

```bash
python3 /app/src/scripts/aws_remediate.py plan --task-id <TASK_ID>
```

### 2) Execute after explicit approval

```bash
python3 /app/src/scripts/aws_remediate.py execute --task-id <TASK_ID> --approved-by <USER>
```

### 3) Verify result

```bash
python3 /app/src/scripts/aws_remediate.py verify --task-id <TASK_ID>
```

Safety rules:
- Never execute without explicit human approval
- Never auto-modify IAM policies
- Never delete resources automatically
