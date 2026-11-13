# Race CI cache (adapted from upstream #2131)

Only the existing `test` job in `.github/workflows/pull-request.yml` gets an
explicit cache. `setup-go@v7` already caches both `GOMODCACHE` and `GOCACHE`, but
its key does not distinguish jobs or race builds. The first successful writer
can populate an immutable entry without the race artifacts; a later exact hit
will not save its additions. This is a source-confirmed possibility, not a
measured slowdown in this repository.

The test job alone disables setup-go's built-in cache. The new action caches
both paths obtained from `go env`, not OS-specific directory guesses. Explicit
Bash works on all three existing runners; the discovery step handles Windows
CRLF and rejects empty, relative or multiline values before writing outputs.
Go-generated values are quoted data, never shell source. Tests, vulnerability
checks, Docker integration and coverage upload remain in the same order and
are not gated on a cache hit. Other jobs' cache behavior, triggers, permissions,
credentials and publishing policy are unchanged. A separately approved security
prerequisite moves existing application-module/CI/documentation Go pins to **1.27.4** and
both source Docker builders to `golang:1.27.4-alpine3.24`, pinned to verified
index digest `sha256:0a5f7fe796599ff487605987432e7619ae45beeb2fba4c2ce0b907879932aebf`.
The official Go release
feed and `GO-2026-6859` advisory identify the fixed version; the Docker tag's
multi-platform manifest was inspected read-only. No publishing was performed.
The approved prerequisite also updates the docs workflow's Go setup and
CircleCI's `cimg/go` image to 1.27.4. Their steps, triggers, targets and cache
semantics are unchanged; the CircleCI tag's amd64/arm64 index was verified.

## Key boundaries and tradeoffs

- The `race-test-v1` namespace is separate from setup-go and non-race jobs.
- Keys include runner OS, runner architecture, matrix platform, exact matrix Go
  version and a hash of both `go.mod` and `go.sum`.
- The only restore prefix omits the dependency hash. Reuse across dependency
  changes stays within the same race namespace, Go version, OS, architecture
  and matrix platform. Cross-OS archives remain disabled (the action default).
- No commit SHA or run ID: avoid a new large immutable cache on every commit.
  Exact hits consequently do not update the saved build cache for source-only
  changes. Dependency changes can save a new entry after a successful job;
  `v1` can be deliberately bumped if a future policy needs a fresh seed.
- PR/default-branch cache scope still follows GitHub's existing rules. This
  change does not create a new trusted default-branch cache producer, broaden
  events or grant write permissions. Fork tokens may be read-only.
- Separate race entries duplicate some modules and consume quota. No hosted
  cold/warm timings or cache-service calls were made; any speedup is unmeasured.

## Verified action contract (November 13, 2026)

Official `actions/cache` metadata identified **v6.1.0** as the latest stable,
non-draft release, at commit `55cc8345863c7cc4c66a329aec7e433d2d1c52a9`.
The repository was neither archived nor disabled. Its exact `action.yml` uses
Node24, `dist/restore/index.js`, and `dist/save/index.js` as a success-only post
step. The selected inputs are `path`, `key` and `restore-keys`; cache misses
are not configured to fail. Exact-key saves are skipped by the action source.
The published JavaScript entrypoints were fetched and passed `node --check`.

Primary references:

- Official Go releases: <https://go.dev/dl/?mode=json>
- Fixed stdlib advisory: <https://vuln.go.dev/ID/GO-2026-6859.json>
- Release: <https://api.github.com/repos/actions/cache/releases/latest>
- Tag: <https://api.github.com/repos/actions/cache/git/ref/tags/v6.1.0>
- Exact source: <https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9>
- setup-go source inspected: <https://github.com/actions/setup-go/tree/b7ad1dad31e06c5925ef5d2fc7ad053ef454303e>
- Public repository advisories: <https://api.github.com/repos/actions/cache/security-advisories>
- Global reviewed advisory lookup: <https://api.github.com/advisories?affects=actions%2Fcache>

Both advisory endpoints returned HTTP 200 and empty arrays. That is not proof
of no undisclosed vulnerabilities or a complete audit of bundled dependencies.

## Executable local checks

The regression runs outside CI, so it adds no hosted job, permissions or
Python dependency to the existing workflow. Use Python 3.9+ and a temporary
location appropriate for your machine (`TMPDIR` below). From the repository
root, export the original reviewed workflow and fetch the pinned metadata:

```bash
scratch="$(mktemp -d "${TMPDIR:?}/race-cache.XXXXXX")"
git show 3ee5a5953a13a48aa9375cc63e485aef17771624:.github/workflows/pull-request.yml > "$scratch/baseline.yml"
curl -fsSL https://raw.githubusercontent.com/actions/cache/55cc8345863c7cc4c66a329aec7e433d2d1c52a9/action.yml -o "$scratch/action.yml"
python3 -m venv "$scratch/venv"
"$scratch/venv/bin/python" -m pip install PyYAML==6.0.3
"$scratch/venv/bin/python" scripts/test-race-cache.py --baseline "$scratch/baseline.yml" --action-metadata "$scratch/action.yml"
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12 .github/workflows/pull-request.yml
```

The parsed-YAML check permits only the two cache steps, test-job `cache: false`
and approved setup-go/matrix version-only updates to 1.27.4 relative to that
explicit baseline. It also checks current module/CI/source-builder Go pins and
the pinned action input/runtime
contract, rejects isolated mutations (missing cache, unsafe keys, missing build
path, duplicate ownership, skipped tests and trigger changes), and executes
the actual YAML Bash against Linux/macOS/Windows-path and invalid-output
fixtures, including a command-injection sentinel. `bash -n` is also executed;
actionlint uses ShellCheck when available. Windows path probes on a macOS Bash
are not a hosted Windows run. If the baseline/toolchain is intentionally
changed separately, review and export that new baseline explicitly.
