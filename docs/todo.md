# TODO

Next implementation milestone:

## 1) OpenClaw communication via Slack

- [ ] Define OpenClaw <-> Slack interaction model (DMs, channel mentions, command routing)
- [ ] Map Slack events/actions to OpenClaw workflows and skill execution
- [ ] Configure required Slack env vars and token scopes for OpenClaw service
- [ ] Add routing/dispatch logic so Slack requests reach OpenClaw cleanly
- [ ] Add audit logging for OpenClaw-triggered actions
- [ ] Validate end-to-end flow in Docker Compose (send message -> receive OpenClaw response)

## 2) OpenClaw Kubernetes deployment

- [ ] Add Kubernetes manifests for OpenClaw (`Deployment`, `Service`, `Secret` references)
- [ ] Add OpenClaw config mount strategy (`config/openclaw.json` via `ConfigMap` or image copy)
- [ ] Define readiness/liveness probes for OpenClaw gateway
- [ ] Set resource requests/limits and replica strategy
- [ ] Document namespace/secret/image build + deploy commands
- [ ] Validate in cluster: pod health, gateway health endpoint, Slack/OpenClaw round-trip

## Definition of done

- [ ] OpenClaw responds to Slack messages in target channels/DMs
- [ ] OpenClaw deployment is reproducible on Kubernetes from docs alone
- [ ] Rollback steps documented for failed deploys
