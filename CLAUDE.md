# CLAUDE.md: secrets-bridge/agent

Instructions for Claude Code and contributors working in this repo. For the whole platform, see https://secrets-bridge.io.

## What this repo is

The Secrets Bridge agent. It runs inside the boundary that holds the secrets (a cluster or cloud account), polls the control plane for approved work, and talks to the local provider. It is the only component that reads or writes secret values.

## Layout

| Path | Purpose |
|---|---|
| `cmd/agent` | Subcommand dispatch, runtime config, boot sequence, heartbeat and claim loops |
| `internal/cli` | Operator subcommands `enroll` and `rotate-key`. The only code that generates a key (`keygen.go`) or writes a file (`output.go`) |
| `internal/client` | HTTPS client to the API: enroll and rotation challenges, heartbeat, claim, complete, DEK, wraps, bulk discovery |
| `internal/executor` | Router by job type: `read` (fetch keys, post sealed wraps), `patch` (get, merge, put), `discover` (post metadata). `resolvers.go` builds providers from agent config |
| `internal/identity` | Read-only credentials directory loader (`agent_id`, `agent_secret`, `private_key`) with the file mode check |
| `internal/sealing` | Mirror of `api/pkg/sealing` (X25519 + HKDF + AES-GCM), fingerprint, public key validation. `sealtest` seals like the CP, for tests only |
| `internal/transport` | TLS client and endpoint validation, shared by the runtime and the CLI |
| `internal/guard` | Source guards (tests only): no file writes or key generation outside `internal/cli`, removed surface stays removed |
| `internal/local`, `internal/observability` | Loopback health/metrics server, JSON logging |

Enrollment (skills#116): an admin creates a one-time token bound to a provider connection. The operator runs `secrets-bridge-agent enroll`, which generates the X25519 key locally, proves possession through `POST /api/v1/agents/enroll/challenge` and `POST /api/v1/agents/enroll` (schema_version "2"), and writes the bundle for a secret store. The runtime reads `agent_id`, `agent_secret` and `private_key` from the read-only `SB_AGENT_CREDENTIALS_DIR`, sends `X-Agent-Secret` and `X-Agent-Key-Fingerprint` on every call, and exits on 401 or 409 `agent_key_mismatch`. It never writes a file and never generates a key.

## Build and test

```bash
go build ./... && go vet ./...
go test -race -count=1 ./...
golangci-lint run
go mod tidy   # CI fails on a diff
```

CI also runs `no-db-or-redis`, which fails the build if `go.sum` contains any database or Redis driver, and `runtime-guards`, which runs `internal/guard` and the runtime no-write tests.

## Configuration

`SB_CP_ENDPOINT`, `SB_CP_CA_FILE`, `SB_CP_TLS_SERVER_NAME`, `SB_INSECURE_TRANSPORT`, `SB_AGENT_CREDENTIALS_DIR`, `SB_CLUSTER_NAME`, `SB_AWS_*` or `SB_VAULT_*`, `SB_CLAIM_INTERVAL`, `SB_CLAIM_CONCURRENCY`, `SB_HEARTBEAT_INTERVAL`, `SB_LOCAL_ADDR`. Credentials are files only; there are no credential env vars.

## Rules for this repo

- **Outbound only.** No inbound listener except the loopback health server.
- **No Postgres, no Redis, no database driver.** The CI guard enforces this.
- **Provider credentials come from the platform** (IRSA, instance role, Vault Kubernetes auth) or agent env. Never accept credentials, tokens or connection identity from a job payload; refuse them.
- **Never log values.** Error messages name wrap IDs, key names and counts only. Zero plaintext buffers after use.
- Refuse `http://` control plane URLs unless `SB_INSECURE_TRANSPORT=true` (dev only). TLS 1.2 minimum.
- Never fall back from sealed to unsealed payloads. The public key is bound at enrollment; there is no registration call. A wrap whose `recipient_key_fingerprint` is not the agent's is refused, and without a key the executors refuse to move values.
- The runtime never writes a file, a PVC or a Kubernetes Secret, and never generates a key. A credential file with `mode & 0o037 != 0` (checked on the symlink target) refuses start; `0400` and `0440` (fsGroup) pass.
- Keep dependencies minimal; new SDKs only when a provider needs them.

## Contributing

Feature branch off `main`, conventional commits, small PRs, CI green, then open a PR for maintainer review. Never push to `main`. Changes that need a new API endpoint land in `api` first.

This repo is public. Keep account IDs, hostnames, cluster names, real secret paths and company names out of code, tests, commits, PRs and issues. Use placeholders such as `123456789012` and `vault.example.com`.

**No AI attribution.** Commits and PRs describe the change, nothing else. Don't add `Co-Authored-By` trailers for AI assistants, "Generated with ..." lines or links to AI sessions to commit messages, PR titles or PR bodies. A squash merge copies the PR body into the commit on `main`, where it can't be edited later. If you use a coding assistant, turn off its commit and PR attribution in its settings.
