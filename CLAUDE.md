# CLAUDE.md: secrets-bridge/agent

Instructions for Claude Code and contributors working in this repo. For the whole platform, see https://secrets-bridge.io.

## What this repo is

The Secrets Bridge agent. It runs inside the boundary that holds the secrets (a cluster or cloud account), polls the control plane for approved work, and talks to the local provider. It is the only component that reads or writes secret values.

## Layout

| Path | Purpose |
|---|---|
| `cmd/agent` | Config, boot sequence, heartbeat and claim loops, TLS setup (`transport.go`) |
| `internal/client` | HTTPS client to the API: enroll, heartbeat, claim, complete, public key, DEK, wraps, bulk discovery |
| `internal/executor` | Router by job type: `read` (fetch keys, post sealed wraps), `patch` (get, merge, put), `discover` (post metadata). `resolvers.go` builds providers from agent config |
| `internal/identity` | Persistent identity from enrollment, X25519 keypair loading |
| `internal/sealing` | Mirror of `api/pkg/sealing` (X25519 + HKDF + AES-GCM) |
| `internal/local`, `internal/observability` | Loopback health/metrics server, JSON logging |

Enrollment: an admin creates a one-time token bound to a provider connection. The agent exchanges it once at `POST /api/v1/agents/enroll` for a persistent identity, stores it (`SB_IDENTITY_FILE`), and heartbeats with `X-Agent-Secret`.

## Build and test

```bash
go build ./... && go vet ./...
go test -race -count=1 ./...
golangci-lint run
go mod tidy   # CI fails on a diff
```

CI also runs `no-db-or-redis`, which fails the build if `go.sum` contains any database or Redis driver.

## Configuration

`SB_CP_ENDPOINT`, `SB_CP_CA_FILE`, `SB_CP_TLS_SERVER_NAME`, `SB_ENROLLMENT_ENABLED`, `SB_ENROLLMENT_TOKEN`, `SB_IDENTITY_FILE`, `SB_CLUSTER_NAME`, `SB_PROVIDER_TYPE`, `SB_AWS_*` or `SB_VAULT_*`, `SB_CLAIM_INTERVAL`, `SB_CLAIM_CONCURRENCY`, `SB_HEARTBEAT_INTERVAL`, `SB_LOCAL_ADDR`.

## Rules for this repo

- **Outbound only.** No inbound listener except the loopback health server.
- **No Postgres, no Redis, no database driver.** The CI guard enforces this.
- **Provider credentials come from the platform** (IRSA, instance role, Vault Kubernetes auth) or agent env. Never accept credentials, tokens or connection identity from a job payload; refuse them.
- **Never log values.** Error messages name wrap IDs, key names and counts only. Zero plaintext buffers after use.
- Refuse `http://` control plane URLs unless `SB_INSECURE_TRANSPORT=true` (dev only). TLS 1.2 minimum.
- Never silently fall back from sealed to unsealed payloads.
- Keep dependencies minimal; new SDKs only when a provider needs them.

## Contributing

Feature branch off `main`, conventional commits, small PRs, CI green, then open a PR for maintainer review. Never push to `main`. Changes that need a new API endpoint land in `api` first.

This repo is public. Keep account IDs, hostnames, cluster names, real secret paths and company names out of code, tests, commits, PRs and issues. Use placeholders such as `123456789012` and `vault.example.com`.
