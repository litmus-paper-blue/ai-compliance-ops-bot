# Contributing to ComplianceOps

Thanks for wanting to contribute! Here's how to get started.

## Setup

```bash
git clone <repo>
cd ai-compliance-ops-bot
cp .env.example .env
# Fill in your .env with local test credentials (never commit this)

# Set up pre-commit hooks to prevent accidental secret commits
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit

# Install dependencies
pip install -r requirements.txt
```

## Code Style

- **Python**: Follow PEP 8. Use meaningful variable names.
- **Modules**: Keep functions focused and single-purpose.
- **Logging**: Use the `logging` module, not `print()`.
- **Comments**: Explain the "why", not the "what".

## Adding Features

1. **Branch**: Create a feature branch (`git checkout -b feature/my-feature`)
2. **Code**: Write your changes
3. **Test locally**: Run the bot with `docker build -f Dockerfile.slack -t complianceops-slack . && docker run --env-file .env --network host complianceops-slack`
4. **Commit**: Write clear, descriptive commit messages
5. **Push**: Push to your branch and open a PR

## Adding Remediation Types

To add a new AWS remediation:

1. Add patterns to `REMEDIATION_PATTERNS` in `src/scripts/vanta_poller.py`
2. Add a `plan_*` function in `src/scripts/aws_remediate.py`
3. Register it in `PLAN_GENERATORS` dict
4. Update IAM policy in `terraform/modules/vantaops-iam/main.tf`
5. Test the full flow locally

## Adding LLM Providers

To add a new LLM provider:

1. Create a class in `src/llm.py` extending `LLMProvider`
2. Implement `is_configured()` and `chat(messages, system="")`
3. Add it to `PROVIDER_CLASSES` (order = fallback priority)
4. Add env vars to `.env.example`
5. Test with `docker build` and `docker run`

## Security

- **Never commit secrets.** The pre-commit hook will block obvious ones.
- **Check your code.** If you add credential handling, make sure it uses `os.environ.get()`, not hardcoding.
- **Review third-party deps.** Before adding a new package, check its security record.

## Documentation

- Update `docs/` if you change how something works
- Update README.md if you change user-facing features
- Update CLAUDE.md if you change architecture or core modules

## Questions?

Open an issue or reach out to the maintainers.
