# Repository Structure

Professional, clean organization for maintainability.

## Target Structure

```
ai-compliance-ops-bot/
├── README.md                        # Main documentation
├── LICENSE                          # MIT or your choice
├── CONTRIBUTING.md                  # How to contribute
├── CLAUDE.md                        # AI agent guidance
│
├── .env.example                     # Template (no secrets)
├── .gitignore                       # What not to commit
├── .githooks/
│   └── pre-commit                   # Hook to block secrets
│
├── requirements.txt                 # Python dependencies
├── docker-compose.yml               # Local dev environment
├── Dockerfile.slack                 # Slack bot image
├── Dockerfile.openclaw              # OpenClaw image (optional)
│
├── src/                             # Core application code
│   ├── __init__.py
│   ├── db.py                        # Database connection & schema
│   ├── llm.py                       # LLM provider abstraction
│   ├── bot/
│   │   ├── __init__.py
│   │   └── app.py                   # Slack bot (Bolt)
│   └── scripts/
│       ├── __init__.py
│       ├── vanta_poller.py          # Vanta API polling
│       └── aws_remediate.py         # AWS remediation engine
│
├── config/                          # Configuration files
│   ├── accounts.json                # AWS account mappings
│   └── openclaw.json                # OpenClaw config (optional)
│
├── docs/                            # Documentation
│   ├── deployment.md                # Deploy guide (local/EC2/K8s)
│   ├── skills.md                    # OpenClaw skills reference
│   ├── security/checklist.md        # Pre-push security verification
│   ├── release/ready-to-push.md     # Release readiness checklist
│   └── architecture/reorganized.md  # Reorganization notes
│
├── terraform/                       # Infrastructure as code
│   └── modules/
│       └── vantaops-iam/
│           └── main.tf              # IAM role for target accounts
│
└── .github/                         # GitHub-specific (optional)
    ├── workflows/
    │   ├── test.yml                 # Run tests on PR
    │   └── lint.yml                 # Linting check
    └── ISSUE_TEMPLATE/
        └── bug_report.md
```

## Optional Additions

- `.github/workflows/test.yml` — Run tests on PR
- `.github/workflows/lint.yml` — Python linting
- `docs/architecture.md` — Technical deep dive
- `tests/` — Unit tests (currently none)

---

**This structure is clean, professional, and ready for an open-source repo.**
