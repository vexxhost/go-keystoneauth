# Changelog

## Unreleased

- Replace cache-wide scans with a bounded LRU (`hashicorp/golang-lru/v2`), retaining opt-in caching, hashed token keys, expiry limits, and independent identity copies.
- Share service-token refresh results without holding a mutex during network I/O. Canceled waiters return promptly; shared refresh has its own bounded lifetime. Old 401 responses cannot invalidate a newer token generation.
- Preserve cancellation and deadline errors; expose sanitized `BackendError` classification through `errors.As` while retaining `ErrUnavailable` matching and generic HTTP responses.
- Omit unused service catalogs during subject validation.
- Reject unsupported token binding and application-credential access-rule metadata. Negative HTTP client timeouts are now rejected.
- Add `AdminPolicy.RequireAdmin` for admin-only routes and clarify that `Authorize` also permits ordinary project tokens.
- Separate transport, claims, cache, and refresh implementation; document the existing `Validator` extension point.
- Add concurrency, expiry, authorization, response-limit, and mutation-isolation tests, fuzz targets, a cache benchmark, and an opt-in live Keystone integration test.
- Test minimum-series and stable Go in CI and run pinned Staticcheck and vulnerability checks.

Compatibility: use `errors.Is` for sentinel errors; backend failures may now carry a sanitized `BackendError`. Caching eviction changes from arbitrary to LRU. Validation rejects unsupported restrictions instead of ignoring them. The package now has one small runtime dependency.
