# Deployment Guide

How to get VantaOps running — locally, on EC2, or on Kubernetes.

## Local (Docker Compose)

The fastest way to get started. Good for testing and development.

### Prerequisites
- Docker and Docker Compose installed
- A Slack app configured (see [README](../README.md#1-set-up-the-slack-app))
- At least one LLM API key

### Steps

```bash
# 1. Clone and configure
git clone <repo-url> && cd ai-compliance-ops-bot
cp .env.example .env
# Fill in your .env (see Environment Variables below)

# 2. Start everything
docker compose up -d
```

Or start services individually:
```bash
# Start Postgres first
docker compose up -d postgres

# Then start the Slack bot
docker compose up -d slack-bot
```

### Verify it works
- Check logs: `docker compose logs -f slack-bot`
- You should see: `Bolt app is running!`
- In Slack: `/vantaops help` or DM the bot "hello"

---

## EC2

Running VantaOps on a single EC2 instance with Docker Compose.

### Instance requirements
- **Type**: `t3.small` or larger (1 vCPU, 2GB RAM is plenty)
- **OS**: Amazon Linux 2023 or Ubuntu 22.04+
- **Storage**: 20GB gp3
- **Security group**: outbound only (no inbound needed — Socket Mode connects outward)

### Setup

```bash
# 1. Install Docker
sudo yum install -y docker   # Amazon Linux
sudo systemctl enable --now docker
sudo usermod -aG docker $USER

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 2. Clone the repo
git clone <repo-url> && cd ai-compliance-ops-bot

# 3. Configure
cp .env.example .env
# Edit .env with your credentials (vi .env)

# 4. Start everything
docker compose up -d

# 5. Check it's running
docker compose logs -f slack-bot
```

### Persistence
Postgres data lives in a Docker volume (`pg-data`). To back it up:
```bash
docker compose exec postgres pg_dump -U vantaops vantaops > backup.sql
```

To restore:
```bash
cat backup.sql | docker compose exec -T postgres psql -U vantaops vantaops
```

### Running as a systemd service
To auto-start on boot:

```bash
sudo tee /etc/systemd/system/ai-compliance-ops-bot.service > /dev/null <<EOF
[Unit]
Description=AI Compliance Ops Bot
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/ec2-user/ai-compliance-ops-bot
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now ai-compliance-ops-bot
```

### Using RDS instead of local Postgres
If you'd rather use a managed database:

1. Create an RDS PostgreSQL instance (db.t3.micro is fine for this)
2. Update `DATABASE_URL` in `.env`:
   ```
   DATABASE_URL=postgresql://vantaops:<password>@<rds-endpoint>:5432/vantaops
   ```
3. Remove the `postgres` service from `docker-compose.yml` (or just don't start it)
4. The bot creates tables automatically on startup

---

## Kubernetes

Deploying VantaOps to an existing Kubernetes cluster.

### Prerequisites
- A running cluster (EKS, AKS, GKE, or local kind/k3d)
- `kubectl` configured
- A PostgreSQL instance accessible from the cluster (RDS, Cloud SQL, or in-cluster)

### 1. Create the namespace and secret

```bash
kubectl create namespace complianceops

kubectl create secret generic complianceops-secrets \
  --namespace complianceops \
  --from-literal=SLACK_BOT_TOKEN='xoxb-...' \
  --from-literal=SLACK_APP_TOKEN='xapp-...' \
  --from-literal=SLACK_CHANNEL_ID='C...' \
  --from-literal=DATABASE_URL='postgresql://vantaops:password@postgres-host:5432/vantaops' \
  --from-literal=AZURE_OPENAI_API_KEY='...' \
  --from-literal=AZURE_OPENAI_ENDPOINT='https://...' \
  --from-literal=GOOGLE_API_KEY='...'
```

### 2. Build and push the image

```bash
# Build
docker build -f Dockerfile.slack -t complianceops-slack .

# Tag and push to your registry
docker tag complianceops-slack <registry>/complianceops-slack:latest
docker push <registry>/complianceops-slack:latest
```

### 3. Deploy

```yaml
# k8s/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: complianceops-slack
  namespace: complianceops
spec:
  replicas: 1  # Only 1 — Socket Mode doesn't support multiple connections
  selector:
    matchLabels:
      app: complianceops-slack
  template:
    metadata:
      labels:
        app: complianceops-slack
    spec:
      containers:
        - name: slack-bot
          image: <registry>/complianceops-slack:latest
          envFrom:
            - secretRef:
                name: complianceops-secrets
          env:
            - name: PYTHONPATH
              value: "/app:/app/src"
            - name: AZURE_OPENAI_DEPLOYMENT
              value: "gpt-4.1-mini"
            - name: AZURE_OPENAI_API_VERSION
              value: "2024-12-01-preview"
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
```

```bash
kubectl apply -f k8s/deployment.yaml
```

### 4. Verify

```bash
kubectl logs -f deployment/complianceops-slack -n complianceops
```

You should see `Bolt app is running!`.

### Important notes
- **Replicas must be 1.** Slack Socket Mode only allows one active connection per app token. Multiple replicas will fight over the connection.
- **No ingress needed.** Socket Mode connects outward — no inbound ports required.
- **Database must be reachable.** If using in-cluster Postgres, use the service DNS name. If using RDS, ensure the security group allows traffic from the cluster.

---

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SLACK_BOT_TOKEN` | Yes | Bot token (`xoxb-...`) from OAuth & Permissions |
| `SLACK_APP_TOKEN` | Yes | App-level token (`xapp-...`) for Socket Mode |
| `SLACK_CHANNEL_ID` | Yes | Channel ID where notifications are posted |
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `ANTHROPIC_API_KEY` | One LLM required | Anthropic API key (`sk-ant-...`) |
| `AZURE_OPENAI_API_KEY` | One LLM required | Azure OpenAI API key |
| `AZURE_OPENAI_ENDPOINT` | With Azure key | Azure OpenAI endpoint URL |
| `AZURE_OPENAI_DEPLOYMENT` | With Azure key | Deployment name (default: `gpt-4.1-mini`) |
| `AZURE_OPENAI_API_VERSION` | With Azure key | API version (default: `2024-12-01-preview`) |
| `GOOGLE_API_KEY` | One LLM required | Google AI API key |
| `VANTA_CLIENT_ID` | For polling | Vanta OAuth2 client ID |
| `VANTA_CLIENT_SECRET` | For polling | Vanta OAuth2 client secret |
| `AWS_ACCESS_KEY_ID` | For remediation | AWS credentials (AssumeRole only) |
| `AWS_SECRET_ACCESS_KEY` | For remediation | AWS credentials |
| `VANTAOPS_APPROVERS` | No | Comma-separated Slack user IDs who can approve. Empty = anyone. |

### LLM fallback order
The bot tries providers in this order: **Anthropic → Azure OpenAI → Google**. Only configured providers (those with API keys set) are used. If one fails, the next is tried automatically.

---

## Upgrading

```bash
# Pull latest code
git pull

# Rebuild the image
docker build -f Dockerfile.slack -t vantaops-slack .

# Restart the bot service
docker compose up -d --build slack-bot
```

Database migrations happen automatically — `init_db()` uses `CREATE TABLE IF NOT EXISTS` so new tables are added on startup without affecting existing data.

---

## Troubleshooting

**Bot starts but doesn't respond in Slack**
- Check that Socket Mode is enabled in your Slack app settings
- Verify `SLACK_APP_TOKEN` starts with `xapp-`
- Make sure you've subscribed to `app_mention` and `message.im` events
- Reinstall the app to your workspace after changing scopes

**"All LLM providers failed"**
- Check that at least one API key is set and valid
- Google free tier has very low quotas — consider a paid plan or use Anthropic/Azure
- Check the logs for specific error messages from each provider

**Database connection refused**
- Make sure Postgres is running: `docker compose ps postgres`
- Check `DATABASE_URL` in `.env` — host should be `localhost` for local, `postgres` for Docker Compose networking

**Slash commands not working**
- Create the `/vantaops` command in your Slack app settings (Features > Slash Commands)
- Reinstall the app after adding the command
