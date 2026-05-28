# secrets-bridge / agent

**Outbound-only execution agent for [Secrets Bridge](https://github.com/secrets-bridge).** Runs inside a target boundary (Kubernetes cluster, private VPC, customer account) and communicates ONLY outbound to the Control Plane API + the local secrets provider. **No inbound listener on a public network interface.**

## Status

| Issue | Step | Status |
|---|---|---|
| [#1](https://github.com/secrets-bridge/agent/issues/1) | Outbound client: identity + heartbeat | **this PR** |
| [#2](https://github.com/secrets-bridge/agent/issues/2) | Job claim/complete loop | open |

## Hard rules

| Invariant | How enforced |
|---|---|
| **No Postgres / Redis / any DB driver** | CI job `no-db-or-redis` greps `go.sum` for forbidden module paths and fails the build if any appear |
| **No inbound public listener** | Local probe + metrics server binds to `127.0.0.1` only (configurable but loopback by default) |
| **One credential — no on-disk identity state** | Pod restart re-reads the same K8s Secret; no PVC needed |

## How it works

```
admin → CP:    POST /api/v1/agents       → { id, agent_secret }
admin → K8s:   creates Secret with both fields
Pod start:     reads Secret (env vars OR file) → heartbeats forever
Pod restart:   same — reads same Secret, no state to persist
```

## Configuration

The agent reads its credential pair from **either** env vars **or** a mounted file. Env vars take precedence when set; this lets a chart use the cleaner env-var path for dev installations and the safer file mount for production.

| Env var | Flag | Default | Notes |
|---|---|---|---|
| `SB_CP_ENDPOINT` | `--cp-endpoint` | (required) | Control Plane API base URL |
| `SB_AGENT_ID` | — | (unset) | Agent UUID — env-var bootstrap |
| `SB_AGENT_SECRET` | — | (unset) | Agent long-lived secret — env-var bootstrap |
| `SB_IDENTITY_FILE` | `--identity-file` | `/etc/secrets-bridge/identity.json` | JSON `{agent_id, agent_secret}` — file bootstrap |
| `SB_LOCAL_ADDR` | `--local-addr` | `127.0.0.1:8090` | `/healthz` `/readyz` `/metrics` |
| `SB_HEARTBEAT_INTERVAL` | `--heartbeat-interval` | `30s` | |
| `SB_SHUTDOWN_GRACE` | `--shutdown-grace` | `15s` | |
| `LOG_LEVEL` | — | `info` | `debug`/`info`/`warn`/`error` |

**Priority:** if `SB_AGENT_ID` AND `SB_AGENT_SECRET` are both set, the env-var path wins. Otherwise the file at `SB_IDENTITY_FILE` is consulted.

## Helm patterns (for `secrets-bridge/charts` — Step 14)

### Mode A — env-var (clean, easier for dev)

```yaml
env:
  - name: SB_AGENT_ID
    valueFrom:
      secretKeyRef: { name: my-agent-secret, key: agent_id }
  - name: SB_AGENT_SECRET
    valueFrom:
      secretKeyRef: { name: my-agent-secret, key: agent_secret }
```

### Mode B — mounted file (K8s docs recommend for credentials)

```yaml
volumes:
  - name: identity
    secret:
      secretName: my-agent-secret
      items:
        - { key: identity.json, path: identity.json }
      defaultMode: 0400
volumeMounts:
  - { name: identity, mountPath: /etc/secrets-bridge, readOnly: true }
```

Both modes use the same K8s Secret. **No PVC** is needed in either case.

## Layout

```
cmd/agent/                main + config (the binary)
internal/
  client/                 typed CP HTTP client (Heartbeat)
  identity/               env-var-or-file credential loader
  local/                  loopback /healthz /readyz /metrics
  observability/          slog JSON logger
```

The agent imports only the stdlib + `github.com/prometheus/client_golang`. Once Step 8 (job loop) lands it will also import `github.com/secrets-bridge/core/providers` to execute provider operations.

## Local development

```bash
go build ./...
go vet ./...
go test -race -count=1 ./...
```

End-to-end against a running CP:

```bash
# 1. Bring up the CP (separate repo)
( cd ../api && docker compose up -d )

# 2. Mint an agent via the CP
MINT=$(curl -s -X POST -H 'Content-Type: application/json' \
  -d '{"name":"demo-agent","scope":{"cluster":"prod-eu"}}' \
  http://localhost:8080/api/v1/agents)
AGENT_ID=$(echo "$MINT" | jq -r '.id')
SECRET=$(echo "$MINT" | jq -r '.agent_secret')

# 3a. Run with env-var bootstrap
SB_CP_ENDPOINT=http://localhost:8080 \
SB_AGENT_ID=$AGENT_ID \
SB_AGENT_SECRET=$SECRET \
SB_HEARTBEAT_INTERVAL=2s \
go run ./cmd/agent

# 3b. OR with file bootstrap
echo "{\"agent_id\":\"$AGENT_ID\",\"agent_secret\":\"$SECRET\"}" \
  > /tmp/identity.json
SB_CP_ENDPOINT=http://localhost:8080 \
SB_IDENTITY_FILE=/tmp/identity.json \
SB_HEARTBEAT_INTERVAL=2s \
go run ./cmd/agent

# 4. Watch the agent's last_seen_at tick on the CP side
watch -n 1 'curl -s http://localhost:8080/api/v1/agents | jq'
```

## Container

```bash
docker build -t secrets-bridge-agent:dev .
```

Multi-stage build on `golang:1.25-alpine` → `distroless/static:nonroot`. No shell, no package manager.
