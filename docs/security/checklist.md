# Security Checklist Before Pushing to Public Repo

Use this checklist to ensure no secrets are accidentally committed.

## Pre-Push Verification

- [ ] `.env` file exists and is in `.gitignore` ✓ (verified)
- [ ] No `*.db` or `*.sqlite` files staged ✓ (verified)
- [ ] No hardcoded API keys in any `.py`, `.json`, or `.md` files ✓ (verified)
- [ ] All env vars reference `os.environ.get()` not hardcoded values ✓ (verified)
- [ ] `.DS_Store` and IDE files are ignored ✓ (verified)

## Before First Commit

```bash
# 1. Ensure pre-commit hooks are set up
git config core.hooksPath .githooks
chmod +x .githooks/pre-commit

# 2. Do a final check for secrets
git diff --cached | grep -iE "sk-ant-|xoxb-|xapp-|AKIA|password.*="
# Should return nothing

# 3. Review what's about to be committed
git status
git diff --cached
```

## Environment Variables Used in Code

All credentials are read from environment variables:
- `SLACK_BOT_TOKEN` -> `os.environ["SLACK_BOT_TOKEN"]`
- `SLACK_APP_TOKEN` -> `os.environ["SLACK_APP_TOKEN"]`
- `DATABASE_URL` -> `os.environ.get("DATABASE_URL", ...)`
- `ANTHROPIC_API_KEY` -> `os.environ.get("ANTHROPIC_API_KEY", "")`
- etc.

None are hardcoded. ✓

## Files That Are Safe

✓ `.py` files — all use `os.environ.get()`
✓ `.md` files — only contain placeholder examples like `sk-ant-...`
✓ `.tf` files — no credentials, only variable references
✓ `.json` config files — no secrets, only account IDs and regions

## Files That Must NOT Be Committed

✗ `.env` (in `.gitignore`)
✗ `*.db` (in `.gitignore`)
✗ `.claude/settings.local.json` (in `.gitignore`)
✗ Private SSH keys or certificates

## After You Push

1. **Rotate all credentials** — do this immediately after pushing the repo publicly, even though no secrets were committed. This is standard practice.
2. **Enable branch protection** — require reviews before merging to `main`
3. **Monitor commits** — watch for any accidental secrets in PRs

---

**You're good to push.** All sensitive data is properly isolated.
