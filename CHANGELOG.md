# Changelog

All notable changes to `secrets-bridge/agent` are tracked here. Format
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and
the project uses [SemVer](https://semver.org/).

Until `v0.1.0` ships, every change lands under `[Unreleased]`. The
rolling `:dev` container tag (published by
`.github/workflows/docker-publish.yml`) reflects whatever is currently
on `main`.

## [Unreleased]

### Added
- Docker image publishing workflow — multi-arch (amd64 + arm64),
  pushed to `ghcr.io/secrets-bridge/agent`. Tags: rolling `dev` on
  every push to `main`; semver tags + `latest` activate post-`v0.1.0`.

### Changed
- Security batch, October 2026:
  - A job can't widen the agent's scope. A Vault `kvMount` / `kvPrefix`
    in a payload has to equal `SB_VAULT_KV_MOUNT` / `SB_VAULT_KV_PREFIX`
    (unset means `kv` and no prefix), connection-steering keys such as
    `address` or `region` fail the job, and a payload `tagFilter` is
    ANDed with `SB_AWS_TAG_FILTER` (#24).
  - No unsealed fallback: `/readyz` stays 503 until the public key is
    registered. The control-plane client refuses redirects and caps
    response bodies, and an identity file with world permissions is
    refused (#24).
  - core bump (#32): Vault refs with a leading or trailing `/`, empty
    refs, a discover scope of `/` and any `..` or encoded traversal are
    refused before a request reaches Vault.

---

## How to cut a release (post-v0.1.0)

1. Land all release-bound work on `main`.
2. Update this file: move `[Unreleased]` entries under a new
   `[vX.Y.Z] — YYYY-MM-DD` heading. Add a fresh empty `[Unreleased]`
   on top.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. The `docker-publish` workflow picks up the tag and publishes:
   - `ghcr.io/secrets-bridge/agent:vX.Y.Z`
   - `ghcr.io/secrets-bridge/agent:vX.Y`
   - `ghcr.io/secrets-bridge/agent:latest` (only for non-prerelease)
5. Create the GitHub Release pointing at the tag.
