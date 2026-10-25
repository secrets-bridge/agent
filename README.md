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

The outbound-only execution agent for [Secrets Bridge](https://github.com/secrets-bridge). It runs inside the boundary that holds the secrets (a Kubernetes cluster, a private VPC, a customer account) and talks only outbound: to the control plane API and to the local secrets provider. It has no inbound listener on a public interface.

## Hard rules

| Invariant | How it is enforced |
|---|---|
| No Postgres, Redis or other database driver | CI job `no-db-or-redis` greps `go.sum` for forbidden module paths |
| No inbound public listener | The probe and metrics server binds to `127.0.0.1` by default |
| Stateless runtime: reads credentials, never writes | The runtime reads three files from a read-only directory. CI job `runtime-guards` fails the build if non-test code outside the CLI bundle writer can create, write or delete a file, or if code outside the CLI key generator generates a key |
| Fails closed | A missing, malformed or too-open credential file stops the agent before any network call |
| Sealed values only | Wraps are sealed to the agent's X25519 key; a plaintext value, or a wrap sealed to another key, is refused |

## How enrollment works

Enrollment happens once, on the operator's side, with the same binary. The private key is generated there and never reaches the control plane or the UI.

```
admin    -> control plane: create a one-time enrollment token for a provider connection
operator -> local CLI:     secrets-bridge-agent enroll --token-file - ...   (token on stdin)
CLI:       generate an X25519 key with crypto/rand
CLI      -> control plane: POST /api/v1/agents/enroll/challenge  {public key, token}
control plane -> CLI:      a 32-byte challenge sealed to that public key
CLI      -> control plane: POST /api/v1/agents/enroll  {opened challenge, token}
control plane -> CLI:      agent_id, agent_secret (once), public_key_fingerprint
CLI:       check the fingerprint, write the bundle to a new 0600 file or stdout
operator:  store the bundle in AWS Secrets Manager, Vault or a Kubernetes Secret
agent pod: mounts the Secret read-only and starts
```

The runtime does not enroll, write files or generate keys. A restart or reschedule reads the same Secret again. There is no PVC and no Kubernetes Secret write permission.

The agent credential and the wire key are separate. The credential (`agent_id` and `agent_secret`) authenticates the agent through `X-Agent-Secret`, and the control plane stores only its hash. The wire key is an X25519 key pair that the control plane seals values to; the control plane stores only the public key. The wire key is not a TLS client certificate.

### Enroll

```bash
# The token comes from the UI or the API. Read it from a file or stdin, never from argv.
secrets-bridge-agent enroll \
  --cp-endpoint https://sb.example.com \
  --token-file - \
  --name payments-uat \
  --cluster-name tenant-a-uat \
  --provider-type aws-sm \
  --region eu-west-1 \
  --output - \
  < token.txt \
  | aws secretsmanager put-secret-value --secret-id agents/payments-uat \
      --secret-string file:///dev/stdin
```

Other destinations:

```bash
# Vault KV (JSON on stdin)
secrets-bridge-agent enroll ... --output - | vault kv put secret/agents/payments-uat -

# Kubernetes Secret, straight from an env file on stdin
secrets-bridge-agent enroll ... --format env --output - \
  | kubectl -n secrets-bridge create secret generic secrets-bridge-agent-identity --from-env-file=/dev/stdin

# Kubernetes Secret manifest (server-side apply only, never commit it)
secrets-bridge-agent enroll ... --format k8s-secret --namespace secrets-bridge --output - \
  | kubectl apply --server-side --field-manager=secrets-bridge-agent -f -

# A local file, created 0600 and never overwritten
secrets-bridge-agent enroll ... --output ./payments-uat.json
```

Always apply the `k8s-secret` manifest with `--server-side`. Client-side `kubectl apply` stores the whole manifest, including the plaintext `agent_secret` and `private_key` from `stringData`, in the `kubectl.kubernetes.io/last-applied-configuration` annotation. That copy sits outside `.data`, where tools that treat metadata as non-sensitive (metadata-only watches and listings, `kubectl describe`, logs and diffs of annotations) can expose it. Server-side apply keeps no such copy. The same holds for any `kubectl create secret ... --dry-run=client -o yaml | kubectl apply -f -` pipeline: add `--server-side` to the final `kubectl apply`.

With the container image, pass `-i` so stdin reaches the CLI:

```bash
docker run -i --rm ghcr.io/secrets-bridge/agent:dev enroll --cp-endpoint https://sb.example.com \
  --token-file - --name payments-uat --provider-type aws-sm --output - < token.txt
```

The Kubernetes Secret is named `secrets-bridge-agent-identity` by default (`--secret-name` changes it for `--format k8s-secret`), the name the chart's `identity.existingSecret` and the UI use. The bundle has four fields: `agent_id`, `agent_secret`, `private_key` (base64) and `public_key_fingerprint`. Formats are `json` (default), `env` and `k8s-secret`. The CLI prints only the agent_id and the fingerprint to stderr. If the output file already exists, or the path is a symlink, the CLI stops before it calls the control plane, so the token is not spent.

### Rotate the wire key

An admin requests a one-time rotation token (`POST /api/v1/admin/agents/:id/key-rotation`). The operator then runs:

```bash
secrets-bridge-agent rotate-key \
  --cp-endpoint https://sb.example.com \
  --credentials-dir ./current-credentials \
  --rotation-token-file - \
  --output - < rotation-token.txt
```

`--credentials-dir` must hold `agent_id` and `agent_secret` (owner-only modes). The CLI runs the same challenge with a new key and writes a bundle with the same agent credential and the new private key. Update the Secret and restart the agent. For a Kubernetes Secret, pipe `--format k8s-secret --output -` into `kubectl apply --server-side --field-manager=secrets-bridge-agent --force-conflicts -f -`; `--force-conflicts` takes over the fields that `kubectl create secret` or another field manager set at enrollment. Until the restart, the control plane answers the old key with `409 agent_key_mismatch`, and the agent exits with a message that says so.

### Usage

```
Usage:
  secrets-bridge-agent                 run the agent (reads SB_AGENT_CREDENTIALS_DIR)
  secrets-bridge-agent enroll [flags]  enroll a new agent with a one-time token
  secrets-bridge-agent rotate-key [flags]
                                       replace the agent's wire key with a rotation token
```

`secrets-bridge-agent enroll -h` and `secrets-bridge-agent rotate-key -h` list the flags. The transport flags (`--cp-endpoint`, `--cp-ca-file`, `--cp-tls-server-name`, `--insecure-transport`) default from the same env vars as the runtime.

## Runtime

### Credentials

The agent reads only `SB_AGENT_CREDENTIALS_DIR` (default `/etc/secrets-bridge/agent`):

| File | Content |
|---|---|
| `agent_id` | the agent UUID |
| `agent_secret` | 32 bytes, base64url |
| `private_key` | the X25519 private key, 32 bytes, base64 |

Every file must be present and well-formed. A file with a group write or execute bit, or any bit for others (`mode & 0o037`), is refused. Group read is allowed because a non-root pod reads a Secret volume through `fsGroup`, which the kubelet mounts as `0440`. The check runs on the file a path resolves to, so the `..data` symlinks of a Secret volume work.

At start the agent derives the public key and its fingerprint (`sha256:` plus the hex SHA-256 of the public key) and sends `X-Agent-Key-Fingerprint` on every control plane request. A `401` (revoked credential) or a `409 agent_key_mismatch` (rotated key, or the wrong Secret) stops the agent with exit code 1. Kubernetes then restarts it with its usual backoff.

There are no credential env vars. `SB_AGENT_ID`, `SB_AGENT_SECRET`, `SB_AGENT_PRIVATE_KEY[_FILE]`, `SB_ENROLLMENT_*` and `SB_IDENTITY_FILE` were removed and are ignored.

### Kubernetes

The chart mounts one Secret, `secrets-bridge-agent-identity` by default, with the keys `agent_id`, `agent_secret` and `private_key` (`identity.existingSecret`):

```yaml
volumes:
  - name: credentials
    secret:
      secretName: secrets-bridge-agent-identity
      defaultMode: 0400
volumeMounts:
  - { name: credentials, mountPath: /etc/secrets-bridge/agent, readOnly: true }
```

The Secret can come from `kubectl` as above, or from External Secrets Operator reading AWS Secrets Manager or Vault. See [secrets-bridge/charts](https://github.com/secrets-bridge/charts) for the values.

### Configuration

| Env var | Flag | Default | Notes |
|---|---|---|---|
| `SB_CP_ENDPOINT` | `--cp-endpoint` | (required) | Control plane base URL, `https://` |
| `SB_AGENT_CREDENTIALS_DIR` | `--credentials-dir` | `/etc/secrets-bridge/agent` | Read-only credentials directory |
| `SB_CP_CA_FILE` | `--cp-ca-file` | (system roots) | PEM CA bundle; replaces the system roots when set |
| `SB_CP_TLS_SERVER_NAME` | `--cp-tls-server-name` | (from URL) | TLS server name override |
| `SB_INSECURE_TRANSPORT` | `--insecure-transport` | `false` | Allow `http://` to the control plane. Dev only |
| `SB_CLUSTER_NAME` | `--cluster-name` | (unset) | Stamped on discovered secrets; required for discover jobs |
| `SB_LOCAL_ADDR` | `--local-addr` | `127.0.0.1:8090` | `/healthz`, `/readyz`, `/metrics` |
| `SB_HEARTBEAT_INTERVAL` | `--heartbeat-interval` | `30s` | Used when the control plane suggests no cadence |
| `SB_CLAIM_INTERVAL` | `--claim-interval` | `5s` | Time between job claims |
| `SB_CLAIM_CONCURRENCY` | `--claim-concurrency` | `4` | Max jobs in flight |
| `SB_SHUTDOWN_GRACE` | `--shutdown-grace` | `15s` | |
| `LOG_LEVEL` | | `info` | `debug`, `info`, `warn`, `error` |

Provider settings: `SB_AWS_REGION`, `SB_AWS_ENDPOINT`, `SB_AWS_ROLE_ARN`, `SB_AWS_TAG_FILTER` for AWS Secrets Manager; `SB_VAULT_ADDR`, `SB_VAULT_NAMESPACE`, `SB_VAULT_TOKEN`, `SB_VAULT_KUBERNETES_ROLE`, `SB_VAULT_KUBERNETES_MOUNT_PATH`, `SB_VAULT_KV_MOUNT`, `SB_VAULT_KV_PREFIX` for Vault. Provider credentials come from the platform (IRSA, instance role, Vault Kubernetes auth), never from a job.

The heartbeat reports the job types the agent runs (`discover`, `patch`, `read`) as `capabilities`.

## Layout

```
cmd/agent/              entry point: subcommand dispatch, runtime config, heartbeat and claim loops
internal/
  cli/                  enroll and rotate-key (the only code that generates a key or writes a file)
  client/               HTTPS client to the control plane
  executor/             read, patch and discover executors and provider resolvers
  guard/                source guards for the runtime invariants (tests only)
  identity/             read-only credentials directory loader
  local/                loopback /healthz /readyz /metrics
  observability/        JSON logger
  sealing/              X25519 + HKDF + AES-GCM, mirror of api/pkg/sealing
  transport/            TLS client, endpoint validation
```

The agent depends on the standard library, `github.com/secrets-bridge/core/providers` (AWS Secrets Manager and Vault), Prometheus and `golang.org/x/crypto`.

## Local development

```bash
go build ./... && go vet ./...
go test -race -count=1 ./...
golangci-lint run
go mod tidy   # CI fails on a diff
```

End to end against a local control plane:

```bash
# 1. Start the control plane (separate repo).
( cd ../api && docker compose up -d )

# 2. In the UI (or the API, with an admin session), create a provider connection
#    and an enrollment token for it. Save the token to token.txt.

# 3. Enroll. The local control plane is plain http, so opt in to insecure transport.
go run ./cmd/agent enroll --cp-endpoint http://localhost:8080 --insecure-transport \
  --token-file - --name dev-agent --cluster-name dev --provider-type aws-sm \
  --format env --output - < token.txt > /tmp/agent.env
rm token.txt

# 4. Lay the bundle out as the credentials directory, owner-only.
mkdir -p /tmp/sb-agent && chmod 700 /tmp/sb-agent
while IFS='=' read -r k v; do
  case "$k" in agent_id|agent_secret|private_key) (umask 077; printf '%s' "$v" > "/tmp/sb-agent/$k") ;; esac
done < /tmp/agent.env
rm /tmp/agent.env

# 5. Run the agent.
SB_CP_ENDPOINT=http://localhost:8080 SB_INSECURE_TRANSPORT=true \
SB_AGENT_CREDENTIALS_DIR=/tmp/sb-agent SB_CLUSTER_NAME=dev \
go run ./cmd/agent
```

The agent's `last_seen_at` then updates in the UI's Agents view.

## Container

```bash
docker build -t secrets-bridge-agent:dev .
```

Multi-stage build on `golang:1.27-alpine`, runtime `distroless/static:nonroot`: no shell, no package manager. The image's entry point is `secrets-bridge-agent`, so `docker run <image>` runs the agent and `docker run -i <image> enroll ...` runs the CLI.
