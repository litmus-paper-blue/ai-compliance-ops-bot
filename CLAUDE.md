# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ComplianceOps** is an AI-powered compliance remediation bot that monitors AWS infrastructure for compliance drift via Vanta, alerts via Slack, proposes fixes, and waits for your approval before executing anything.

### Core Workflow
1. Polls Vanta API daily for failing compliance checks due within 5 days
2. Sends Slack notifications with interactive buttons
3. Plans AWS remediation steps using LLM (Claude Haiku as primary)
4. Shows the exact AWS commands before executing
5. Waits for explicit approval before running anything
6. Stores lessons from each remediation for future reference
7. Responds to natural language questions in Slack DMs and channels

## Architecture & Key Components

### Database Layer (`src/db.py`)
- **PostgreSQL** (never SQLite) for multi-connection concurrency
- `get_db()` returns a connection; always call `close_db(conn)` after use
- Tables: `vanta_tasks`, `audit_log`, `poller_state`, `knowledge_base`
- `dict_cursor(conn)` returns a cursor that yields dicts (not tuples)
- Schema auto-initializes on first connection via `init_db()`
- **SQL placeholders**: Use `%s` (not `?`); PostgreSQL syntax

### LLM Provider System (`src/llm.py`)
- Abstract `LLMProvider` base class with `chat()` and `is_configured()` methods
- **Provider priority**: Anthropic → Azure OpenAI → Google (tries each in order)
- `LLMRouter` automatically falls back if a provider fails or hits quota
- Configured via environment variables: `ANTHROPIC_API_KEY`, `AZURE_OPENAI_*`, `GOOGLE_API_KEY`
- Free-tier quotas can exhaust quickly (Google ~429 errors); Azure/Anthropic preferred

### Slack Bot (`src/bot/app.py`)
- **Slack Bolt** framework with **Socket Mode** (outbound-only, no public URL needed)
- Handles: slash commands (`/vantaops`), DMs, channel mentions (`@VantaOps`), interactive buttons
- Injects memory context from `knowledge_base` table before every LLM call
- DM prefix `remember:` saves lessons to knowledge base for future conversations
- Responds in natural language to questions about compliance, AWS, remediation

### Vanta Poller (`src/scripts/vanta_poller.py`)
- OAuth2 client authentication against Vanta API
- Fetches failing tests + vulnerabilities due within 5 days
- Keyword matching against `REMEDIATION_PATTERNS` dict to classify issue types
- Deduplicates against 24-hour notification window
- Sends Slack notifications with buttons: "View Plan & Remediate", "View Details", "Snooze"

### AWS Remediation (`src/scripts/aws_remediate.py`)
- Three subcommands: `plan` (generate steps), `execute` (run approved steps), `verify` (check status)
- `PLAN_GENERATORS` dict dispatches to type-specific functions: `plan_cloudwatch()`, `plan_s3()`, `plan_security_group()`, `plan_ssm_patch()`, `plan_logging()`
- Uses STS `AssumeRole` to scope AWS credentials to target accounts
- **Never deletes anything**, only creates/modifies/enables
- **Never touches IAM policies** — flagged as manual-only
- Logs all actions to `audit_log` table with approver info

### Docker Setup
- **Dockerfile.slack**: Builds Slack bot image; copies `src/`, sets `PYTHONPATH=/app:/app/src`, runs `python -m src.bot.app`
- **Dockerfile.openclaw**: Builds OpenClaw gateway image (optional, shares same database)
- **docker-compose.yml**: Postgres (Alpine) + Slack bot + optional OpenClaw; all use `DATABASE_URL=postgresql://vantaops:vantaops@postgres:5432/vantaops`

## Common Development Tasks

### Local Development (Docker Compose)
```bash
cp .env.example .env
# Fill in your API keys (at least SLACK_BOT_TOKEN, SLACK_APP_TOKEN, one LLM key)

docker compose up -d              # Start all services
docker compose logs -f slack-bot  # Watch bot logs
docker compose down               # Stop all services
```

### Testing the Slack Bot Only (without Vanta/AWS)
```bash
docker compose up -d postgres     # Start just the database
docker compose up -d slack-bot    # Start just the bot
# In Slack: /vantaops help or DM the bot "hello"
```

### Checking Bot Logs
```bash
docker compose logs -f slack-bot
# Look for: "Bolt app is running!" to confirm successful startup
# Look for: "All LLM providers failed" to debug provider issues
```

### Database Migrations
No explicit migration files needed. Use the pattern in `src/db.py`:
```python
cursor.execute("CREATE TABLE IF NOT EXISTS my_table (...)")
```
Tables are created automatically on startup. To add new tables, add them to `init_db()`.

### Database Inspection
```bash
docker compose exec postgres psql -U vantaops -d vantaops

# Inside psql:
\dt                           # List all tables
SELECT * FROM knowledge_base; # View stored lessons
SELECT * FROM audit_log;      # View action history
SELECT * FROM vanta_tasks;    # View task status
```

### Backup/Restore
```bash
# Backup
docker compose exec postgres pg_dump -U vantaops vantaops > backup.sql

# Restore
cat backup.sql | docker compose exec -T postgres psql -U vantaops vantaops
```

### Adding a New Remediation Type
1. Add keyword pattern to `REMEDIATION_PATTERNS` in `src/scripts/vanta_poller.py`
   ```python
   "my-issue-type": {"keywords": [...], "aws_service": "..."}
   ```
2. Create `plan_my_issue_type()` function in `src/scripts/aws_remediate.py`
3. Register it in `PLAN_GENERATORS` dict
4. Update IAM policy in `terraform/modules/vantaops-iam/main.tf` if new AWS permissions needed

## Environment Variables

**Slack (required)**:
- `SLACK_BOT_TOKEN` — Bot token starting with `xoxb-`
- `SLACK_APP_TOKEN` — App-level token starting with `xapp-` (for Socket Mode)
- `SLACK_CHANNEL_ID` — Channel ID where notifications post (e.g., `C0123456789`)

**LLM (at least one required)**:
- `ANTHROPIC_API_KEY` — Anthropic API key (`sk-ant-...`); highest quota
- `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, `AZURE_OPENAI_DEPLOYMENT` — Azure OpenAI
- `GOOGLE_API_KEY` — Google AI API key; free tier has low quota

**Database (required)**:
- `DATABASE_URL` — PostgreSQL connection string (default: `postgresql://vantaops:vantaops@postgres:5432/vantaops`)

**Optional**:
- `VANTA_CLIENT_ID`, `VANTA_CLIENT_SECRET` — For Vanta API polling
- `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` — For AWS remediation (must have AssumeRole permissions only)
- `VANTAOPS_APPROVERS` — Comma-separated Slack user IDs; empty = anyone can approve

## Important Patterns & Gotchas

### PYTHONPATH Handling
The environment variable `PYTHONPATH=/app:/app/src` is set in all Dockerfiles and docker-compose. This allows simple imports:
```python
from db import get_db, dict_cursor, init_db
from llm import LLMRouter
```
Do not modify imports or add `sys.path` manipulation — the environment handles resolution.

### LLM Fallback Behavior
If a provider fails (quota, network, invalid key), `LLMRouter.chat()` tries the next one automatically. Only configured providers (those with valid API keys) are attempted. If all fail, an exception is raised with details on which provider failed and why.

### Knowledge Base Context
Before every LLM call, the bot injects relevant lessons from the `knowledge_base` table based on keyword matching. This prevents repeating mistakes. Users can teach it with: `remember: <lesson>`

### Socket Mode Replicas
Slack Socket Mode allows **only 1 active connection per app token**. If deploying to Kubernetes, set `replicas: 1` in the deployment. Multiple replicas will fight over the connection and both will fail.

### No Public URL Needed
Socket Mode means the bot connects *outward* to Slack, not inbound. No public URL, no firewall rules, no reverse proxy needed. Safe for private networks.

### Approval Logging
Every remediation that executes logs the approver's Slack user ID in `audit_log`. If `VANTAOPS_APPROVERS` is set, only those users can click "Approve".

## Deployment

### Quick Start (Local)
```bash
docker compose up -d
```

### EC2
```bash
git clone <repo> && cd ai-compliance-ops-bot
cp .env.example .env
# Edit .env
docker compose up -d
```

### Kubernetes
```bash
kubectl create namespace complianceops
kubectl create secret generic complianceops-secrets --namespace complianceops \
  --from-literal=SLACK_BOT_TOKEN='xoxb-...' \
  --from-literal=SLACK_APP_TOKEN='xapp-...' \
  --from-literal=DATABASE_URL='postgresql://...' \
  --from-literal=ANTHROPIC_API_KEY='sk-ant-...'

docker build -f Dockerfile.slack -t complianceops-slack .
docker tag complianceops-slack <registry>/complianceops-slack:latest
docker push <registry>/complianceops-slack:latest

kubectl apply -f k8s/deployment.yaml
```

See `docs/deployment.md` for full instructions (RDS, backup/restore, systemd auto-start, etc.).

## Security

Before pushing to GitHub:
1. No hardcoded secrets in code (all use `os.environ.get()`)
2. `.env` is in `.gitignore` and won't be committed
3. Pre-commit hook blocks commits with patterns: `sk-ant-`, `xoxb-`, `xapp-`, `AKIA`, `password=`
4. All AWS credentials scoped to AssumeRole only (no direct write permissions)

See `docs/security/checklist.md` and `docs/release/ready-to-push.md` for full verification steps.

## Troubleshooting

**Bot doesn't respond in Slack**:
- Check Socket Mode is enabled in Slack app settings
- Verify `SLACK_APP_TOKEN` starts with `xapp-`
- Check subscribed to `app_mention`, `message.im` events
- Restart bot: `docker compose restart slack-bot`

**"All LLM providers failed"**:
- At least one API key must be set and valid
- Google free tier quota is very low (try Anthropic/Azure)
- Check logs: `docker compose logs slack-bot | grep -i "llm\|provider"`

**Database connection refused**:
- Postgres running? `docker compose ps postgres`
- Check `DATABASE_URL` — host is `postgres` in Docker, `localhost` if not using Compose
- Check volume: `docker volume ls | grep pg-data`

**Slash commands don't work**:
- Create `/vantaops` command in Slack app settings (Features > Slash Commands)
- Reinstall the app after adding the command

## File Structure

```
ai-compliance-ops-bot/
├── src/                           # Core application
│   ├── __init__.py
│   ├── bot/
│   │   ├── __init__.py
│   │   └── app.py                 # Slack bot entry point
│   ├── scripts/
│   │   ├── __init__.py
│   │   ├── vanta_poller.py        # Vanta polling & Slack notifications
│   │   └── aws_remediate.py       # AWS remediation planner & executor
│   ├── db.py                      # PostgreSQL connection layer
│   └── llm.py                     # LLM provider abstraction
│
├── config/                        # Configuration (not code)
│   ├── accounts.json              # AWS account mappings
│   └── openclaw.json              # OpenClaw skill definitions
│
├── docs/                          # Deployment & API docs
│   ├── deployment.md              # How to deploy (local, EC2, K8s)
│   ├── skills.md                  # OpenClaw skills reference
│   ├── security/checklist.md      # Pre-push security verification
│   ├── release/ready-to-push.md   # Final GitHub push checklist
│   └── architecture/              # Reorg and layout references
│       ├── reorganized.md
│       └── repo-structure.md
│
├── terraform/                     # IAM role definitions
│   └── modules/vantaops-iam/main.tf
│
├── Dockerfile.slack               # Slack bot image
├── Dockerfile.openclaw            # OpenClaw gateway image (optional)
├── docker-compose.yml             # Local dev orchestration
├── requirements.txt               # Python dependencies
│
├── .env.example                   # Environment template (copy to .env)
├── .gitignore                     # Git ignore rules
├── .githooks/pre-commit           # Secret-blocking pre-commit hook
│
├── README.md                      # User-friendly guide
├── CLAUDE.md                      # This file (for AI agents)
├── CONTRIBUTING.md                # Contribution guidelines
└── LICENSE                        # Open-source license
```

## Running Tests

Currently, there are no automated tests. When adding them:
- Use `pytest` for unit tests
- Place tests in `tests/` directory with same structure as `src/`
- Test database queries against a test PostgreSQL instance in CI
- Run via: `pytest tests/` or `docker compose exec slack-bot pytest`

## Dependencies

See `requirements.txt`. Key libraries:
- `slack-bolt` — Slack API framework with Socket Mode
- `psycopg2` — PostgreSQL driver
- `anthropic` — Anthropic API client
- `google-generativeai` — Google Gemini API client
- `azure-openai` — Azure OpenAI client
- `requests` — HTTP client for Vanta API
- `boto3` — AWS SDK for remediation

All pinned to specific versions for reproducibility.

## Additional Resources

- **Slack Socket Mode Docs**: https://slack.com/blog/engineering/socket-mode-available-in-beta
- **Slack Bolt Python Docs**: https://slack.dev/bolt-python/
- **PostgreSQL Docs**: https://www.postgresql.org/docs/
- **AWS STS AssumeRole**: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html
- **Anthropic API Docs**: https://docs.anthropic.com/
