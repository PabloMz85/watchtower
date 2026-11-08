# Docker API compatibility upgrade

## Scope and cause

The original startup forced `DOCKER_API_VERSION=1.25` and constructed a Docker SDK client without API negotiation. The failure was reproduced on Docker Engine 29.9.1 (API 1.56, minimum 1.40) using a one-shot, monitor-only scan of a nonexistent target. A failed scan additionally dereferenced a nil report while creating metrics.

This change removes the implicit pin, migrates from the deprecated Docker monolith to the split Moby SDK, validates explicit CLI/environment overrides, and handles failed scans without a panic. A failed one-shot scan exits with status 1. Valid explicit overrides remain exact pins; `--api-version=` restores automatic negotiation.

Selected versions:

- Moby client: `v0.6.2`.
- Moby API: `v1.56.1`.
- Docker CLI configuration library: `v29.9.3+incompatible`.
- Go language/toolchain minimum: `1.26.0`; container builder and CI: `1.27.3`.
- Client API range: `1.40`–`1.56`. Newer daemons negotiate down to the client ceiling. Daemons older than API 1.40 are not supported.

## Repeatable acceptance gate

From the repository root:

```sh
WATCHTOWER_INTEGRATION=1 bash scripts/verify.sh
```

The gate checks Go formatting, module checksums, the full test suite with the race detector, `go vet`, Staticcheck `v0.8.2`, govulncheck `v1.9.0`, compilation, and a real Docker update. Omit `WATCHTOWER_INTEGRATION=1` to run only the tests and checks that do not require Docker.

The integration test creates uniquely scoped fixture images, a network, and a container. It replaces the image under its test tag and verifies that Watchtower recreates the running container while preserving environment overrides, labels, restart policy, and network aliases. A second scan must not recreate an unchanged container. Cleanup removes only the generated fixtures and verifies the container's scope first. It does not target existing application containers.

## Verification performed

- Original API error and nil-report panic reproduced before the fixes.
- Default-pin, API negotiation, and nil-report tests observed failing before the corresponding fixes.
- Full acceptance gate: **PASS**, including real Docker update and configuration preservation.
- Full suite with the actual Go 1.26.0 toolchain: **PASS**.
- govulncheck: **No vulnerabilities found** for the tested build and database snapshot.
- Module tidiness, checksum verification, and whitespace checks: **PASS**.
- Both self-contained Dockerfiles built successfully from the local checkout.
- ARM64 and AMD64 container images ran one-shot monitor-only scans against Docker 29.9.1 without the old API error.
- An explicit API 1.40 scan succeeded. Legacy and malformed overrides are rejected by CLI tests before Docker requests.
- A real registry pull succeeded after deliberately failing the optional registry HEAD request using a process-local unreachable proxy; monitor-only preserved the fixture container.
- Cross-compilation succeeded for Linux amd64, arm64, 386, arm/v6; Windows amd64, 386, arm64; and macOS arm64. Cross-compilation is not a claim of runtime testing on every platform.
- Compose validation rejects a missing external API token and confirms localhost binding with a temporary runtime-only token.
- `python3 scripts/test-compose-monitoring.py`: **PASS**, with the newly built Watchtower image and Prometheus `v3.16.0` pinned by digest. A generated non-demo token authenticates with HTTP 200; missing/wrong/old-demo tokens return 401; actual Prometheus scraping reports `up=1`. Private token-file permissions, non-root ownership, absence from Prometheus PID 1 environment, and cleanup are verified. The test never starts the fixed-name demo.
- Legacy-MAC safety and healthcheck `StartInterval` regressions passed after observed failing tests; the legacy-MAC feature boundary is described below.

Recreate-wire regression tests additionally cover image-default subtraction, published ports, mounts, resource limits, static IPAM, MAC addresses, capability normalization, network reconnection, and preservation of image-pruning behavior.

## Build and rollout

```sh
docker build -f dockerfiles/Dockerfile.self-contained -t watchtower:local .
```

Both self-contained Dockerfiles build the checked-out source, not an upstream clone. Build bases are pinned by tag and digest. `.dockerignore` excludes common environment and private-key files from the build context.

Use the resulting image in the deployment you control and remove old `DOCKER_API_VERSION` or `--api-version` pins. The optional root Compose demo requires `WATCHTOWER_HTTP_API_TOKEN` from an environment or secret manager and exposes Watchtower's API only on localhost.

The Docker socket grants daemon-level control even when bind-mounted read-only. This upgrade does not turn the demo into a hardened production deployment, certify every optional notification service or private registry, or guarantee future Docker API compatibility. Existing services were not redeployed, no image was published, and no remote Git changes were pushed as part of local verification.

## Configuration-preservation boundaries

### Legacy container-wide MAC addresses

The selected split SDK cannot send the legacy `Config.MacAddress` create field. Watchtower retains this field from the SDK's raw container-inspect result and **refuses automatic recreation when it is non-empty**, regardless of negotiated/pinned API version. Configuration preflight reports an actionable error, and stop/remove, rename, and create entry points reject that inspected container before issuing a mutating Docker request. Empty, null, or absent legacy values do not block updates, and inspection/monitoring remain available. This is a bounded feature limitation, not a higher minimum API version for other containers.

This deliberately conservative policy also blocks legacy-configured containers on newer engines rather than guessing how to translate a container-wide setting to per-network settings. Exclude such a container from updates, or manually recreate it with explicit per-network MAC configuration after checking the engine's network-connect behavior. Merely placing the old value in endpoint settings is not an old-engine compatibility fix: endpoint-specific MAC input was added in API 1.44, but Docker's version history records that network-connect ignored it until the fix listed under API 1.54. Watchtower's existing recreation sequence disconnects and reconnects its initial network, so accepting MAC input at container creation alone is insufficient. The old container-wide input was removed in API 1.52.

The earlier recreate-wire test's MAC assertion checks serialized endpoint values, not whether every daemon applies them. In particular, it is not a claim of endpoint-MAC preservation on pre-fix engines. The new legacy-MAC regression uses actual SDK inspect decoding and proves no stop/remove/rename/create mutation for running and stopped legacy-configured containers across API fixtures 1.40, 1.43, 1.44, 1.51, 1.52, 1.53, 1.54, and 1.56. No request-body hook, custom TLS transport, deprecated SDK, or silent MAC conversion is used.

Primary reference: Docker Engine API version history, sections 1.44, 1.52, and 1.54: https://docs.docker.com/reference/api/engine/version-history/ . The 1.54 entry describes the daemon fix; an older API pin alone does not identify whether a newer daemon has that implementation fix.

### Healthcheck start interval

`Healthcheck.StartInterval` now follows the same image-default subtraction as the other healthcheck durations: an equal image default is cleared so a replacement image can supply its new default; a differing user value is retained. Regression tests cover equal defaults, user overrides, both-zero, zero-container/nonzero-image, and nonzero-container/zero-image values.
