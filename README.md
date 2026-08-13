<p align="center">
  <a href="https://github.com/secrets-bridge"><img src="https://raw.githubusercontent.com/secrets-bridge/.github/main/profile/logo.svg" alt="Secrets Bridge" width="520" /></a>
</p>

<p align="center">
  <b>The brain behind your secrets.</b><br/>
  Unified secrets control plane for cloud-native teams.<br/>
  <a href="https://secrets-bridge.io">secrets-bridge.io</a> · <a href="https://github.com/secrets-bridge">all repos</a>
</p>

---
# secrets-bridge / agent

**Outbound-only execution agent for [Secrets Bridge](https://github.com/secrets-bridge).** Runs inside a target boundary (Kubernetes cluster, private VPC, customer account) and communicates ONLY outbound to the Control Plane API + the local secrets provider. **No inbound listener on a public network interface.**

## Status

| Issue | Step | Status |
|---|---|---|
| [#1](https://github.com/secrets-bridge/agent/issues/1) | Outbound client: identity + heartbeat | ✅ merged |
| [#2](https://github.com/secrets-bridge/agent/issues/2) | Job claim/complete loop | ✅ merged |
| [#5](https://github.com/secrets-bridge/agent/pull/5) | `PatchExecutor` + router (Piece 4b) | ✅ merged |
| [#6](https://github.com/secrets-bridge/agent/pull/6) | Vault resolver + `ResolverByType` (Piece 4c) | ✅ merged |
| [#7](https://github.com/secrets-bridge/agent/pull/7) | AWS Secrets Manager resolver (Piece 4d) | ✅ merged |
| [#8](https://github.com/secrets-bridge/agent/pull/8) | `DiscoverExecutor` + native tag preservation (Piece 6b) | ✅ merged |
| [#9](https://github.com/secrets-bridge/agent/pull/9) | `ReadExecutor` — selective fetch + per-key wrap (Piece 5b) | ✅ merged |
| [#10](https://github.com/secrets-bridge/agent/pull/10) | Transit security hardening (Piece 7 — TLS validation + CA pinning) | ✅ merged |
| [#11](https://github.com/secrets-bridge/agent/pull/11) | Wire-envelope encryption (Piece 8b — X25519 + KMS DEK) | ✅ merged |

The agent is now feature-complete for the write + read + discover flows against both Vault and AWS Secrets Manager, with TLS validation + CA pinning + bi-directional wire-envelope crypto on top of TLS. See [`skills/PROGRESS.md`](https://github.com/secrets-bridge/skills/blob/main/PROGRESS.md) for the slice-by-slice log.

## Hard rules

| Invariant | How enforced |
|---|---|
| **No Postgres / Redis / any DB driver** | CI job `no-db-or-redis` greps `go.sum` for forbidden module paths and fails the build if any appear |
| **No inbound public listener** | Local probe + metrics server binds to `127.0.0.1` only (configurable but loopback by default) |
| **One credential — no on-disk identity state** | Pod restart re-reads the same K8s Secret; no PVC needed |

## How it works

Two onboarding paths. **Enroll-on-first-boot (default for new agents):**

```
admin → CP:    POST /provider-connections/:id/agent-enrollment-token → { enrollment_token }   (returned once)
admin → agent: enrollment_token (SB_ENROLLMENT_TOKEN, one-time)
Pod first boot: no stored credential → POST /api/v1/agents/enroll
                  → { agent_id, agent_token }  (agent_token returned once)
                persist {agent_id, agent_token} to SB_IDENTITY_FILE (writable), then heartbeat
Pod restart:    stored credential found → skip enrollment, heartbeat directly
                (the one-time token is NEVER reused)
```

**Static credential (legacy / existing agents), unchanged:**

```
admin → CP:    POST /api/v1/agents       → { id, agent_secret }   (break-glass; see api docs)
admin → K8s:   creates Secret with both fields
Pod start:     reads Secret (env vars OR file) → heartbeats forever
Pod restart:   same — reads the same Secret
```

**Credential resolution (precedence):** stored env vars (`SB_AGENT_ID`+`SB_AGENT_SECRET`) → populated identity file → enroll-on-first-boot (if enabled + token) → else **fail closed** (`agent credential not configured`). The enrollment token and the returned `agent_token` are never logged.

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
| `SB_CLAIM_INTERVAL` | `--claim-interval` | `5s` | Time between job-claim polls |
| `SB_CLAIM_CONCURRENCY` | `--claim-concurrency` | `4` | Max in-flight jobs at once |
| `SB_SHUTDOWN_GRACE` | `--shutdown-grace` | `15s` | |
| `LOG_LEVEL` | — | `info` | `debug`/`info`/`warn`/`error` |
| `SB_ENROLLMENT_ENABLED` | `--enrollment-enabled` | `true` | Allow enroll-on-first-boot when no credential is stored |
| `SB_ENROLLMENT_TOKEN` | `--enrollment-token` | (unset) | One-time enrollment token; used ONLY on first boot. **Redacted from logs** |
| `SB_AGENT_NAME` | `--agent-name` | hostname | Agent name reported at enrollment |
| `SB_PROVIDER_TYPE` | `--provider-type` | `aws-sm` | Provider type reported at enrollment (must match the token's binding) |
| `SB_CLUSTER_NAME` | `--cluster-name` | (unset) | Cluster identity; also reported at enrollment |
| `SB_REGION` | `--region` | (unset) | Region reported at enrollment |

**Credential precedence:** `SB_AGENT_ID`+`SB_AGENT_SECRET` (env) → populated `SB_IDENTITY_FILE` → enroll-on-first-boot (`SB_ENROLLMENT_ENABLED=true` + `SB_ENROLLMENT_TOKEN`) → else fail closed. On enrollment the agent persists the returned `{agent_id, agent_token}` to `SB_IDENTITY_FILE`, so **that path must be a writable, restart-persistent volume** (a PVC or writable mount) — not a read-only Secret. The CP's `heartbeat_interval_seconds` / `job_poll_interval_seconds` (enroll response) and per-beat `next_heartbeat_seconds` (heartbeat response) drive the cadence unless the operator sets the intervals explicitly.

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

### Mode C — enroll-on-first-boot (self-enrollment; needs a writable identity volume)

The chart should surface these values (wiring lives in `secrets-bridge/charts`):

```yaml
controlPlane:
  url: https://sb.example.com          # → SB_CP_ENDPOINT
enrollment:
  enabled: true                        # → SB_ENROLLMENT_ENABLED
  token: ""                            # → SB_ENROLLMENT_TOKEN (one-time; from the CP, injected via Secret)
agent:
  name: ""                             # → SB_AGENT_NAME (defaults to the pod hostname)
  clusterName: ""                      # → SB_CLUSTER_NAME
  providerType: "aws-sm"               # → SB_PROVIDER_TYPE (must match the token's binding)
  region: ""                           # → SB_REGION
credential:
  # The agent persists {agent_id, agent_token} here after enrollment so a
  # restart reuses it instead of spending a second token. MUST be writable
  # and survive restarts (a small PVC, or a writable emptyDir if
  # re-enrollment on reschedule is acceptable). → SB_IDENTITY_FILE
  persistPath: /var/lib/secrets-bridge/identity.json
```

The enrollment token is spent exactly once: after a successful enroll the agent writes its persistent credential and, on every subsequent restart, loads that credential and skips enrollment. If the identity path is not writable/persistent the agent would re-enroll on restart and fail on the now-consumed token — so this mode requires a writable, restart-persistent volume (unlike Modes A/B).

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
