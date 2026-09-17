# go-keystoneauth

Lean Keystone v3 authentication for Go HTTP services. The only runtime dependency is a
bounded, concurrency-safe LRU cache. Works with `net/http`, chi, and any router that
accepts standard HTTP middleware.

## Install

```sh
go get github.com/vexxhost/go-keystoneauth@v0.1.0
```

Go 1.25 or newer is required.

## Protect routes

```go
client, err := keystoneauth.New(keystoneauth.Config{
    URL: os.Getenv("KEYSTONE_URL"), // base URL or /v3 endpoint
    ApplicationCredentialID: os.Getenv("OS_APPLICATION_CREDENTIAL_ID"),
    ApplicationCredentialSecret: os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET"),
})
if err != nil { return err }

protected := keystoneauth.Middleware(client, keystoneauth.Options{
    Policy: keystoneauth.ProjectOrSystem,
})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    identity, _ := keystoneauth.FromContext(r.Context())
    fmt.Fprintln(w, identity.UserID, identity.ProjectID)
}))
mux.Handle("/api/", protected)
```

Import `github.com/vexxhost/go-keystoneauth`. See `examples/server` for a complete
runnable server. Leave health checks and routes using other authentication outside the
middleware. In chi, use `r.Use(keystoneauth.Middleware(client, options))` inside the
protected route group.

Both application credential fields must be set or both omitted. When omitted, the
caller's token authenticates the Keystone validation request. When set, the client
authenticates with an application credential, caches the service token until one minute
before expiry, and refreshes once if validation returns 401. Concurrent callers share a
refresh, including its result on failure. Each caller may cancel its own wait; the
shared refresh has an independent deadline bounded by the configured HTTP timeout. The
service identity needs permission to validate caller tokens under the deployment's
Keystone policy; ordinary application credentials do not automatically grant this
capability.

Exactly one `X-Auth-Token` or `Authorization: Bearer <token>` is accepted. Duplicate,
combined, empty, malformed, and oversized values are rejected. Client-supplied identity
headers are ignored. Verified claims are available through `FromContext`; `Validate(ctx,
token)` also supports non-HTTP consumers.

## Authorization

Validation returns verified claims, including unscoped and domain-scoped tokens. Choose
an explicit application policy:

- `ProjectOrSystem` permits project or system scope.
- `RequireRoles(roles, true)` requires any listed role and system scope.
- `AdminPolicy{Roles: roles, ProjectIDs: operatorProjects}.Authorize` permits
  project tokens and system administrators; it is **not** an admin-only gate.
- `AdminPolicy.RequireAdmin` permits only configured administrators.
- A nil middleware policy permits every valid token; handlers must then enforce
  their own authorization.

`AdminPolicy.IsAdmin` requires an allowed role plus system scope or an explicitly
configured operator project. There are no implicit admin role names or projects.
`AdminPolicy.Scope(identity, requestedProjectIDs)` prevents tenant queries from
expanding beyond their own project. Nil means all authorized projects; an explicit empty
slice stays empty. Authentication alone does not enforce resource ownership.

## Errors, transport, and caching

`ErrUnauthorized` maps to 401; `ErrForbidden` to 403; other failures to 503.
`Options.OnError` can preserve an application's existing response format and request
IDs. Backend bodies, credentials, and tokens never appear in default errors. A
persistent service-token 401 is a service failure (503), while a missing subject token
(404) is unauthorized. Context cancellation and deadline errors are preserved, including
while waiting for a service-token refresh. Other backend failures support `errors.As`
into `*BackendError` for sanitized operation, reason, and HTTP status information, and
`errors.Is(err, ErrUnavailable)`. Default HTTP error responses remain generic.

HTTPS is required unless `AllowHTTP` is explicitly enabled. Redirects are disabled
including for a custom HTTP client. A zero client timeout becomes 15 seconds; custom
transport, TLS settings, and positive timeouts are preserved. Negative timeouts are
rejected. The timeout bounds each HTTP operation and the shared refresh; pass a context
deadline to bound an entire validation including retries. Response bodies are limited to
1 MiB. Invalid, expired, missing-expiry, and contradictory-scope responses are rejected.
Subject validation requests omit the unused service catalog with `?nocatalog`.

Subject-token caching is **disabled by default**. Set `CacheTTL` to enable it, with
`MaxCacheEntries` defaulting to 10,000. Entries use SHA-256 token keys and expire at the
earlier of TTL and token expiry; failures are never cached. Cached identities are copied
so a handler cannot mutate another request's roles. Storage uses a bounded LRU with
constant-time ordinary insertion and eviction, without background cleanup goroutines.
Expiry is checked on every lookup and hits do not extend it. Expired entries may remain
in storage until replaced or evicted; they are never served. Concurrent subject-cache
misses may make duplicate validation requests (service-token refreshes are shared).
Caching delays observation of token revocation by up to the TTL; use zero where
immediate revalidation is required.

## Supported token features

Project, domain, system, and unscoped bearer tokens are supported. Tokens carrying
nonempty binding metadata or non-null application-credential access rules are rejected,
including an explicit empty access-rule list. Request-specific access rules and
bound-token proofs are not implemented.

The client does not advertise `OpenStack-Identity-Access-Rules` support. Standard
Keystone rejects restricted tokens when that capability is absent. Do not add that
header in a custom transport or proxy: supporting access rules requires
service/method/path enforcement on every request, including cache hits.

## Extending validation

`Validator` is the extension point for consumer-owned caching, metrics, or other
validation decorators. For example, pass your wrapper to `Middleware` in place of the
client. Disable the client's subject cache when your wrapper owns caching. There is no
public storage-backend interface or distributed-cache dependency.

A cache wrapper holds trusted authentication data. It must check expiry on every hit,
limit freshness to both its TTL and token expiry, never extend TTL on hits, copy mutable
claims, and validate with Keystone on a cache miss or backend error. Shared caches must
separate Keystone endpoints and validation configurations; entries must not cross those
trust boundaries. Protect cache writes accordingly.

Use `FromContext` for verified identity. Caller-supplied identity headers are ignored,
not removed, and remain untrusted to downstream handlers.

The example server listens on HTTP for use behind a TLS terminator. Protect the
client-to-server connection with TLS before sending real bearer tokens.

## Development

```sh
gofmt -w .
go test -race -cover ./...
go vet ./...
go run honnef.co/go/tools/cmd/staticcheck@v0.8.1 ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.8.0 ./...
go test -run '^$' -bench BenchmarkCacheChurn -benchmem
go test -run '^$' -fuzz FuzzTokenFromRequest -fuzztime 10s
go test -run '^$' -fuzz FuzzDecodeToken -fuzztime 10s
```

Tests use local fake Keystone servers and do not require cloud credentials. CI tests Go
1.25 and the current stable release; development analyzers run on stable Go. Use a
maintained, patched Go toolchain for production builds.

An opt-in integration test checks an actual Keystone deployment. Set
`KEYSTONEAUTH_INTEGRATION_URL`, `KEYSTONEAUTH_INTEGRATION_TOKEN`,
`KEYSTONEAUTH_INTEGRATION_USER_ID`, and `KEYSTONEAUTH_INTEGRATION_PROJECT_ID` for a
known project-scoped bearer token. Optionally set `OS_APPLICATION_CREDENTIAL_ID` and
`OS_APPLICATION_CREDENTIAL_SECRET` to exercise service-authenticated validation. Then
run:

```sh
go test -tags integration -run TestKeystoneIntegration -v .
```

The endpoint must use HTTPS and a trusted certificate. The test verifies expected claims
and invalid-token rejection. Run it once per authentication mode to check both modes
against the deployment's policy; ordinary application credentials may not have
permission to validate other users' tokens. Never commit credentials or real tokens to
fixtures.

## License

Copyright 2026 VEXXHOST, Inc.

Licensed under the [Apache License, Version 2.0](LICENSE).
