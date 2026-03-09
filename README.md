# AI Compliance Ops Bot (VantaOps)

Your team's compliance co-pilot. VantaOps watches Vanta for failing compliance checks, pings you on Slack, and helps fix AWS issues — all with your approval, never on its own.

Talk to it like a person. It remembers what worked before and gets smarter over time.

## What it does

1. **Watches Vanta** — polls for failing compliance tests and vulnerabilities, stores everything in the database
2. **Pings you on Slack** — sends individual alerts for tasks due in the next 7 days, plus a summary of everything else
3. **Plans the fix** — generates the exact AWS commands needed (you see them before anything runs)
4. **Waits for your OK** — nothing executes without you clicking Approve
5. **Remembers what happened** — stores lessons from past fixes so it doesn't repeat mistakes

## Talk to it

VantaOps understands natural language. No need to memorize commands.

**In a channel:**
> @VantaOps what's overdue?
> @VantaOps show me all tests due in 10 days
> @VantaOps any vulnerabilities due by March 19th?
> @VantaOps how do I fix S3 encryption on the logs bucket?

**In a DM:**
> What tasks are due this week?
> Show me everything due in 14 days
> Walk me through fixing a security group issue

**Teach it something:**
> remember: when fixing S3 logging, the target bucket must exist first
> lesson: security group changes on prod ALBs need the platform team looped in

It saves these and brings them up next time a similar issue comes around.

## Quick commands

These still work for when you want something fast:

| Command | What it does |
|---------|-------------|
| `/vantaops status` | Summary with counts: due in 7 days, overdue, pending, remediated |
| `/vantaops poll` | Fetch from Vanta now — stores all tasks, alerts only what's due in 7 days |
| `/vantaops due <days>` | List tasks due in N days (e.g. `/vantaops due 10`, `/vantaops due 30`) |
| `/vantaops audit` | See the last 10 things VantaOps did |
| `/vantaops task <id>` | Full details on a specific task |

Any other text after `/vantaops` is treated as a natural language question — e.g. `/vantaops show me everything due in 12 days` works too.

## When a notification arrives

You'll see buttons:
- **View Plan & Remediate** — shows you the AWS commands, then asks for approval
- **View Details** — expands the full task info in a thread
- **Snooze** — hides it for 24 hours

## How it's built

```
You (Slack) ←→ Slack Bot (Python, Socket Mode)
                    ↕
              LLM (Claude Haiku / Gemini Flash — auto-fallback)
                    ↕
              PostgreSQL (tasks, audit log, knowledge base)
                    ↕
              Vanta API ←→ AWS Accounts (via AssumeRole)
```

- **Slack bot** — Python app using Slack Bolt in Socket Mode (no public URL needed)
- **LLM** — Azure OpenAI, Anthropic, and Google supported with automatic fallback. If one runs out of quota, it switches automatically
- **PostgreSQL** — stores tasks, audit logs, and the knowledge base (lessons learned)
- **Vanta API** — OAuth2 polling for failing tests and approaching vulnerabilities
- **AWS** — remediations run via AssumeRole into target accounts. The bot's own credentials can only assume roles, nothing else.
- **OpenClaw** — optional conversational dashboard (can be added later, shares the same database and knowledge base)

## Getting started

### What you need

- Docker & Docker Compose
- A Slack workspace where you're an admin
- At least one LLM API key (Azure OpenAI, Anthropic, or Google)
- Vanta API credentials (optional — needed for polling, not for testing the bot)
- AWS credentials (optional — needed for remediation, not for testing the bot)

### 1. Set up the Slack app

Go to [api.slack.com/apps](https://api.slack.com/apps) and create a new app from scratch.

Then configure these (in order):

1. **Socket Mode** — turn it on, create an app-level token with `connections:write` scope. Save the `xapp-...` token.
2. **OAuth & Permissions** — add bot scopes: `chat:write`, `commands`, `im:history`, `im:write`, `app_mentions:read`, `channels:history`
3. **Slash Commands** — create `/vantaops` with description "VantaOps compliance bot"
4. **Event Subscriptions** — turn on, subscribe to: `app_mention`, `message.im`
5. **Interactivity** — turn on (Socket Mode handles the URL)
6. **Install to Workspace** — authorize and copy the `xoxb-...` bot token
7. **Create a channel** (e.g. `#vantaops`) — grab the Channel ID from channel details

### 2. Configure

```bash
cp .env.example .env
```

Fill in your `.env`:

```
# Required for the bot to run
SLACK_BOT_TOKEN=xoxb-...
SLACK_APP_TOKEN=xapp-...
SLACK_CHANNEL_ID=C...

# At least one LLM provider
ANTHROPIC_API_KEY=sk-ant-...
AZURE_OPENAI_API_KEY=...
AZURE_OPENAI_ENDPOINT=https://...openai.azure.com
AZURE_OPENAI_DEPLOYMENT=gpt-4.1-mini
GOOGLE_API_KEY=...

# Database
DATABASE_URL=postgresql://vantaops:vantaops@localhost:5432/vantaops

# Optional (add when ready)
VANTA_CLIENT_ID=
VANTA_CLIENT_SECRET=
# Optional override if your tenant exposes personnel tasks on a custom endpoint
VANTAOPS_PERSON_SECURITY_ENDPOINT=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
```

### 3. Run

```bash
docker compose up -d
```

Or start services individually:
```bash
docker compose up -d postgres    # Start database first
docker compose up -d slack-bot   # Then the bot
```

### Run Vanta poll from Docker command

You can trigger a one-off Vanta poll directly from Docker Compose:

```bash
docker compose run --rm vanta-poller
```

Dry run (fetch + classify only, no Slack notifications):

```bash
docker compose run --rm vanta-poller python -m src.scripts.vanta_poller --dry-run
```

### 4. Test

In Slack:
- `/vantaops help` — see if commands work
- DM the bot: "hello" — see if the LLM responds
- `@VantaOps what's our compliance status?` — test channel mentions

## AWS setup (when you're ready)

Deploy the IAM role in each AWS account you want the bot to manage:

```bash
cd terraform/modules/vantaops-iam

terraform init
terraform apply \
  -var="trusted_principal=arn:aws:iam::AGENT_ACCOUNT:user/vantaops-agent" \
  -var="environment=dev"
```

The bot can fix these types of issues automatically:
- **CloudWatch** — missing alarms on ALBs, RDS, Lambda
- **S3** — encryption, public access, versioning, logging
- **Security Groups** — overly permissive rules (shows current rules, you decide the fix)
- **EC2 Patching** — OS and package updates via SSM
- **Logging** — CloudTrail and AWS Config enablement

## Vanta API setup (when you have admin access)

You need Vanta Admin to create API credentials:
1. Log into Vanta > **Settings > Developer Console**
2. Create a new app (type: "Manage Vanta")
3. Copy the Client ID and generate a Client Secret
4. Add both to your `.env`
5. Restart the bot and run `/vantaops poll` to sync

The poller fetches all failing tests and vulnerabilities from Vanta, stores them in the database for historical queries, and sends Slack alerts only for tasks due in the next 7 days (configurable via `VANTAOPS_ALERT_WINDOW_DAYS`).

If you're a Vanta Editor, ask an admin to create the credentials for you.

## Safety

- **Nothing runs without your approval.** Every AWS change needs an explicit button click.
- **It never deletes anything.** Only creates, modifies, or enables.
- **It never touches IAM policies.** Those are flagged as manual-only.
- **All actions are logged.** Every command, output, and who approved it.
- **No public URLs.** Socket Mode means no inbound firewall rules.
- **LLM fallback.** If one provider is down or out of quota, the next one takes over.

## Adding new fix types

1. Add keyword patterns to `REMEDIATION_PATTERNS` in `src/scripts/vanta_poller.py`
2. Add a `plan_*` function in `src/scripts/aws_remediate.py`
3. Register it in the `PLAN_GENERATORS` dict
4. Update the IAM policy in `terraform/modules/vantaops-iam/main.tf` if new AWS permissions are needed

## Teaching the bot

The more you use it, the smarter it gets. After a remediation (successful or not), the outcome is logged. You can also teach it directly:

- DM: `remember: always check if CloudTrail S3 bucket exists before enabling`
- DM: `lesson: prod security group changes need change management approval first`

These lessons show up as context in future conversations about similar issues.
