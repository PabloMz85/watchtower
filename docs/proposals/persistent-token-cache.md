# Pluggable instance-owned registry token cache

This branch implements the safe in-memory foundation of upstream proposal
#2130; it does not import the accumulated upstream patch. It depends on the
`feat/2129-clock` prerequisite (`pkg/clock` and the Go 1.27.4 security pins).
The CI-cache branch is independent after that common prerequisite.

## Implemented contract

- `auth.TokenCache` exposes context-aware `Get`, `Set` and `Delete` operations.
  Implementations must be concurrency safe and honor cancellation.
- `auth.NewClient` owns its backend, injected `clock.Clock`, bounded route map,
  HTTPS transport and random cache identity. Defaults are `clock.RealClock`, a
  1024-entry RAM LRU and a 30-second HTTP timeout. No process-global time setter
  or mutable TLS configuration is introduced.
- Realm, service, derived repository pull scope, registry and credentials are
  bound to opaque cache keys using standard-library HMAC-SHA256. Anonymous and
  authenticated requests cannot reuse each other's entries. Entries are also
  checked for their key, token, finite expiry and integrity before use.
- Missing `expires_in` uses the protocol's 60-second default. Explicit values
  must be positive integer seconds and at most 24 hours. A five-second safety
  margin is applied. An omitted `issued_at` starts the lifetime at response
  receipt, not request start; a token legitimately issued while a request was
  in flight is accepted. Invalid, empty, expired or conflicting tokens fail.
- Concurrent misses are coalesced without an unbounded in-flight map. Waiting
  callers can cancel. The simple per-client gate serializes unrelated misses,
  deliberately favoring bounded state over maximum parallel throughput.
- Manifest 401/403 rejects invalidate the exact authorization handle, including
  when route metadata was evicted. A late rejection cannot remove a replacement
  token. Failed rejection deletion disables further reuse on that client.
- Cache/backend failures never bypass authentication. They fail the HEAD
  optimization; the application's existing Docker pull fallback remains.

## TLS and application wiring

The actual application Docker client retains an injected registry/digest client,
so cache reuse spans containers and update sessions. Compatibility free functions
retain their signatures but use fresh clients and do not offer reusable caches.

Challenge, token and manifest requests use one secure transport. Absolute HTTPS,
certificate/hostname validation, bounded redirects, timeouts, response sizes and
sanitized errors are enforced. There is no insecure registry TLS option.

`--registry-ca` / `WATCHTOWER_REGISTRY_CA` adds strictly validated CA certificate
PEM blocks to system roots before contacting Docker. Invalid, empty, unreadable,
oversized or partially malformed files abort startup. The bundle is loaded per
client; changing it requires a restart. This does not configure Docker Engine's
separate registry trust store. See `docs/secure-connections.md`.

## Explicitly deferred

Redis, Memcached and file-backed storage, their deployment configuration and
cross-instance token sharing are not implemented. Per-client random keys and
entry tags intentionally isolate separate client instances, even if they receive
the same backend. A future distributed design must establish a reviewed shared
trust domain, key coordination, backend authentication, storage confidentiality,
TTL/clock-skew rules and failure behavior. This interface alone is not a claim
that distributed caching is operational.

## Verification

Tests exercise actual local TLS servers with runtime-generated certificates and
synthetic credentials. Coverage includes credential/anonymous isolation, cache
expiry and capacity, receipt-time lifetimes, backend failures and cancellation,
concurrent misses, rejection invalidation, redirects, TLS trust, invalid PEM,
startup failure before Docker access, and the actual container pull cache path.
No real registry credentials or external publishing are used.

Run the project gate from this worktree:

```sh
bash scripts/verify.sh
```

Real Docker smoke testing is separately opt-in and touches only uniquely scoped
fixture resources. No publication workflow should be dispatched for validation.
