# VantaOps Development Journal

A detailed log of all development steps, decisions, errors, and fixes made while building the ComplianceOps bot. Written for future reference and blog/writeup use.

---

## Phase 1: Initial Setup & Vanta API Integration

### What We Built
- Slack bot using **Slack Bolt** with **Socket Mode** (no public URL needed)
- PostgreSQL database for task storage, audit logs, and knowledge base
- LLM Router with multi-provider fallback (Anthropic -> Azure OpenAI -> Google)
- Vanta API client with OAuth2 client credentials and pagination

### Errors & Fixes

**Vanta API field name mismatch**
- Expected: `title`, `slaDeadline`, `remediationSlaDeadline`
- Actual: `name`, `remediateByDate`, `remediationStatusInfo.remediateByDate`
- Fix: Added debug logging to dump raw API response keys, then updated all field mappings in `vanta_poller.py`
- Lesson: Always inspect raw API responses first — don't trust documentation blindly

**LLM provider quota exhaustion**
- Google free tier hit 429 errors almost immediately
- Fix: Set Azure OpenAI (gpt-4.1-mini) as primary provider, Google as last fallback
- Lesson: Free-tier LLM APIs are unreliable for production; budget for paid tier

---

## Phase 2: Notification Flood Problem

### The Problem
First poll fetched **184 failing tests** and **4,093 vulnerabilities** — all sent as individual Slack messages. Channel was completely flooded.

### Root Cause
No filtering logic — every item from Vanta API was posted to Slack regardless of urgency or age.

### Solution (Multi-layered)
1. **Alert window**: Only send Slack notifications for tasks due within 7 days (configurable via `VANTAOPS_ALERT_WINDOW_DAYS`)
2. **Store everything**: All tasks saved to PostgreSQL regardless of due date — queryable later
3. **Dashboard summary**: `/vantaops status` shows counts by category, not individual items
4. **Deduplication**: 24-hour notification window prevents re-alerting on same task

### Overdue Task Noise
- Summary was listing 127+ overdue items from 2024
- User decision: "It should not see overdue tests except outrightly requested for"
- Fix: `format_dashboard_summary()` shows overdue as a count only, not a list
- Users can explicitly request overdue details via `/vantaops due` or natural language

---

## Phase 3: Making the Bot Smarter

### Problem: Bot Had No Memory
Each message was a standalone LLM call. User said "yes" to approve something, bot replied "Hi! How can I assist you?" — complete context loss.

### Fix: Conversation History
- Added `get_thread_history()` — fetches last 10 messages from Slack thread via `conversations_replies` API
- Thread history passed to LLM as conversation context
- Bot now maintains continuity within a thread

### Problem: Bot Couldn't Explain Remediation Steps
User asked "how do I fix this?" and bot gave generic answers with no specifics about the actual task.

### Fix: Multi-Layer Context Enrichment
1. **Task detection** (`detect_specific_task()`): Finds relevant task by:
   - Task ID regex match in message
   - Keyword search against task titles in DB
   - Thread history carryforward (if earlier message referenced a task)
2. **DB context** (`get_task_detail_context()`): Pulls full task details from DB including raw JSON from Vanta
3. **Live Vanta data** (`get_live_resource_context()`): Fetches current resource state from Vanta API
4. **Rewritten system prompt**: Step-by-step remediation guidance, conversation continuity instructions

### Problem: No Owner or Severity Data
User asked "who is this assigned to?" — bot had no data.

### Fix
- Added `owner` and `severity` columns to `vanta_tasks` table
- Extract owner from `test.get("owner", {}).get("displayName", ...)` in Vanta response
- Schema migration via `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`

---

## Phase 4: Flexible Querying

### What We Added
- `/vantaops due <days>` — custom day-range queries (e.g., `/vantaops due 14`)
- Natural language date parsing in `_extract_lookahead_days()` — "show me tasks due in 10 days"
- Unknown `/vantaops` text now routes through LLM instead of returning an error

---

## Phase 5: Code Architecture Refactoring

### VantaClient Extraction
- Originally: Vanta API client was inline in `vanta_poller.py`
- Problem: Bot also needed Vanta API access for live resource lookups
- Fix: Extracted to shared `src/vanta_client.py`, imported by both poller and bot
- `VantaClient` class handles: OAuth2 auth, token refresh, pagination, all endpoints

### Redundant Imports Cleanup
- `import re` was duplicated 4 times inside functions despite being imported at module top
- Removed all 4 redundant local imports

---

## Phase 6: AWS IAM Scoping

### The Audit
- Ran `vanta_audit.py` to categorize all 184 failing tests by AWS service
- Services found: CloudWatch, S3, EC2/VPC, RDS, DynamoDB, EKS, ELB, GuardDuty, Inspector, ACM, SNS, SSM, CloudTrail/Config

### Terraform IAM Role (Complete Rewrite)
- Original: Generic broad permissions
- Rewritten: 15 specific IAM policies scoped to exactly what Vanta tests require
- **Safety rails**:
  - Explicit Deny on all IAM mutations (safety net)
  - All delete/revoke permissions removed (`cloudwatch:DeleteAlarms`, `acm:DeleteCertificate`, `ec2:RevokeSecurityGroup*`)
  - Bot can create/modify/enable but never delete

### SNS Topic Scoping
- Initially had a generic `sns_alert_topic_arn` variable that was declared but never used
- Split into two specific variables: `sns_cloudwatch_topic_arn` and `sns_guardduty_topic_arn`
- SNS policy scoped to only those two topic ARNs

---

## Phase 7: Terraform & CI/CD Setup

### S3 Backend for Terraform State
- Created `backend.tf` with S3 backend configuration
- Two backend configs:
  - `backend-test.hcl` — local dev with AWS profile `openbb_awsbot1`
  - `backend-ci.hcl` — CI with access keys passed via `-backend-config` flags

### Credential Model (Simplified)
- Started with 3 credential sets (TF provider, TF state, bot)
- Simplified to 2: AWS provider + bot share one set, TF state uses separate keys
- Rationale: bot remediation and Terraform both operate on same target account

### Errors
- **Wrong profile name**: `openbb-awsbot1` (hyphen) vs `openbb_awsbot1` (underscore) — caused terraform init failure
- **Wrong directory**: User ran `terraform plan` from `terraform/modules/vantaops-iam/` instead of `terraform/` — got prompted for variables that are defined in the root module
- **Unused variable warning**: `sns_alert_topic_arn` was declared but never referenced in any resource

### GitHub Actions Workflows
1. **`terraform.yml`**: Triggers on `terraform/` changes, runs plan on PR, apply on merge to main
2. **`deploy-bot.yml`**: Triggers on `src/` changes, builds Docker image, deploy steps templated (ECR, EC2, ECS, K8s options commented out for user to choose)

---

## Phase 8: Slack App Configuration Issues

### "Sending messages to this app has been turned off"
- Slack app settings needed: `message.im` event subscription enabled
- Bot OAuth scopes needed: `im:history`, `im:read`, `im:write`
- After adding, had to reinstall the app to the workspace

### Bot Mention Requirement
- User asked: "Do I have to tag the bot each time before it responds?"
- Answer: In channels yes (@mention), in DMs no — DMs go directly to the bot
- Bot handles both via `app_mention` event (channels) and `message` event with `im` channel type (DMs)

---

## Phase 9: Data Accuracy Debugging (Vanta vs Bot Mismatch)

### Trigger
User observed direct Vanta/MCP answers differed from bot output:
- Missing due tasks on exact dates (e.g., March 19)
- Duplicate-looking CVE list output
- Wrong/unhelpful owner answers ("unassigned")
- `COMMON` resource type with opaque IDs instead of actionable context

### Root Causes Found
1. **LLM-only answers for structured questions** (date/owner/resource) led to ambiguity.
2. **Poller upsert did not refresh core fields** (`title`, `description`, `due_date`, resource fields), leaving stale records.
3. **Failing tests without explicit due date were dropped**, so owner-bearing parent records could be lost.
4. **Resource extraction prioritized internal IDs** over actionable target IDs.
5. **Owner matching logic missed real-world phrasing/typos** ("belong too").

### Fixes Implemented
- Added deterministic DB-backed handlers in bot for:
  - Exact-date due queries
  - CVE assignment queries
  - Owner list queries
  - Task resource metadata queries
  - Owner-task queries with fuzzy matching and typo tolerance
- Improved parent-owner fallback for CVE subtasks:
  - If CVE row owner is empty, resolve owner from related parent finding.
- Updated poller upsert to refresh canonical task fields on conflict.
- Stopped dropping failing tests when due date is missing:
  - Keep row for context/ownership, skip alert if no due date.
- Improved resource extraction:
  - Prefer `targetId`/`packageIdentifier` over opaque internal IDs.
  - Infer practical type (e.g., `AWS_ECR`) when Vanta returns `COMMON`.
- Added guardrails for live Vanta resource lookup:
  - Skip `COMMON`
  - Auto-disable noisy lookup path after first `403`.

---

## Phase 10: Docker Poller & External Postgres Workflow

### What Was Added
- Added dedicated `vanta-poller` service to `docker-compose.yml` (one-off runner).
- Added README commands:
  - `docker compose run --rm vanta-poller`
  - dry-run variant with `--dry-run`.

### External Postgres Guidance
When DB is outside compose:
- Use `--no-deps` and pass external `DATABASE_URL`
- Reminder: inside container, `localhost` != host DB; use `host.docker.internal` or shared network alias.

---

## Phase 11: "Smarter Bot" Foundations (Context + Learning)

### Goal
Move from "single-table remediation assistant" toward "context-aware compliance assistant" with memory and feedback.

### New Data Model
- `person_security_tasks` table:
  - stores open/completed personnel/security tasks for richer owner context.
- `owner_aliases` table:
  - maps normalized aliases (`ogonna`) to canonical names (`Ogonna Nnamani`).
- `task_links` table:
  - parent/child links (e.g., package finding parent -> CVE child).
- `response_feedback` table:
  - stores per-response thumbs up/down feedback for iterative improvement.

### New Sync Logic
- `VantaClient.get_person_security_tasks()`:
  - tries tenant-accessible personnel/security endpoints.
  - handles shape differences and normalizes rows.
  - gracefully skips 403/404 endpoints.
- Poller now syncs `person_security_tasks` each run.
- Poller infers/stores task links in `task_links`.

### New Bot Learning/Context Logic
- Owner query now resolves across:
  - remediation tasks (`vanta_tasks`)
  - personnel tasks (`person_security_tasks`)
  - aliases (`owner_aliases`)
  - parent links (`task_links`)
- Added alias auto-learning:
  - successful user phrasing is stored as alias->canonical mapping.
- Added feedback capture:
  - bot messages in mentions/DM now include `👍 Correct` / `👎 Incorrect`
  - actions persist to `response_feedback`.

### Current Behavior Improvement
Owner question responses can now include:
- open remediation tasks
- personnel task summary (open/completed)
- recent completed personnel tasks

---

## Bottlenecks & Decisions Log

| Decision | Options Considered | Chosen | Why |
|---|---|---|---|
| Database | SQLite vs PostgreSQL | PostgreSQL | Multi-connection concurrency for bot + poller |
| Slack connectivity | HTTP webhook vs Socket Mode | Socket Mode | No public URL needed, works behind firewalls |
| LLM provider | Single vs multi-provider | Multi with fallback | Resilience against quota exhaustion |
| Alert strategy | All items vs windowed | 7-day window | Prevent notification flood |
| Vanta client location | Inline in poller vs shared module | Shared `vanta_client.py` | Both bot and poller need API access |
| IAM permissions | Broad vs audited | Audited from 184 real tests | Least-privilege principle |
| Delete permissions | Include vs exclude | Exclude entirely | Safety — bot should never destroy resources |
| TF state credentials | Same as provider vs separate | Separate | State bucket may live in different account |
| Overdue task display | Full list vs count only | Count only (unless requested) | Noise reduction |
| Structured question handling | LLM-only vs deterministic DB routing | Deterministic first | Eliminate hallucinations on date/owner/resource |
| Resource ID selection | Internal ID vs target/context ID | Target/context first | More actionable output for remediation |
| Owner resolution | Direct owner only vs multi-source + alias + link | Multi-source | Real Vanta payloads often split ownership across parent/child rows |
| Poller execution | Slack-only trigger vs Docker one-off service | Both | More operational control and easier debugging |
| Learning feedback | Passive logging vs explicit user feedback | Explicit thumbs feedback | Build measurable correction loop |

---

## File Change Log

| File | Change Type | Description |
|---|---|---|
| `src/bot/app.py` | Heavy modification | Conversation history, task detection, live Vanta fetching, flexible day queries, LLM routing for unknown commands, system prompt rewrite |
| `src/scripts/vanta_poller.py` | Heavy modification | Field name fixes, alert window filtering, owner/severity extraction, VantaClient import |
| `src/vanta_client.py` | New file | Extracted shared Vanta API client |
| `src/db.py` | Modified | Added owner/severity columns, ALTER TABLE migrations |
| `src/scripts/vanta_audit.py` | New file | Diagnostic script to audit all Vanta tests by AWS service |
| `docker-compose.yml` | Modified | Added one-off `vanta-poller` service runnable via compose command |
| `terraform/modules/vantaops-iam/main.tf` | Complete rewrite | 15 policies based on real Vanta audit, delete deny, IAM deny |
| `terraform/main.tf` | Modified | Provider config, SNS variables, backend reference |
| `terraform/backend.tf` | New file | S3 backend configuration |
| `terraform/backend-test.hcl` | New file | Local dev backend config |
| `terraform/backend-ci.hcl` | New file | CI backend config |
| `terraform/terraform.tfvars` | New file | Local variable values |
| `.github/workflows/terraform.yml` | New file | Terraform CI/CD pipeline |
| `.github/workflows/deploy-bot.yml` | New file | Bot build/deploy pipeline |
| `.gitignore` | Modified | Added terraform.tfvars, *.tfstate, .terraform/ |
| `README.md` | Modified | Updated commands, Azure OpenAI, alert window config |
| `docs/development-journal.md` | Modified | Added phase-by-phase narrative for debugging, smart context, and learning loop |

---

## Still TODO

- [ ] Rebuild/restart bot + poller images with latest changes:
  - `docker compose build slack-bot vanta-poller`
  - `docker compose up -d --force-recreate slack-bot`
- [ ] Run fresh poll to populate new tables and links:
  - `/vantaops poll` or `docker compose run --rm --no-deps vanta-poller`
- [ ] Verify personnel sync status in logs:
  - Look for `Fetched ... personnel tasks` OR expected `Skipping unavailable personnel endpoint ...`
- [ ] Validate owner query end-to-end with known sample:
  - `what tasks belong too ogonna?`
  - `69733f3dcc9acb0697b75208 this belongs to ogonna`
- [ ] Validate feedback loop:
  - Click `👍/👎` on a bot response and confirm row in `response_feedback`
- [ ] Validate alias learning:
  - Query with shorthand and full name; confirm improved matching
- [ ] Run `terraform init -reconfigure -backend-config=backend-test.hcl` from `terraform/` directory
- [ ] Run `terraform plan` to verify IAM changes
- [ ] Populate GitHub Actions secrets for CI/CD
- [ ] Test conversation continuity in Slack threads
- [ ] Test resource-context replies after new `targetId` extraction
- [ ] Add automated tests (pytest)
