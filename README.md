# go-keystoneauth

Dependency-free Keystone v3 authentication for Go HTTP services.
Works with `net/http`, chi, and any router that accepts standard HTTP middleware.

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
runnable server. Leave health checks and routes using other authentication outside
the middleware. In chi, use `r.Use(keystoneauth.Middleware(client, options))` inside
the protected route group.

Both application credential fields must be set or both omitted. When omitted,
the caller's token authenticates the Keystone validation request. When set, the client authenticates with an
application credential, caches the service token until one minute before expiry,
and refreshes once if validation returns 401. The service identity needs permission
to validate caller tokens under the deployment's Keystone policy; ordinary
application credentials do not automatically grant this capability.

Exactly one `X-Auth-Token` or `Authorization: Bearer <token>` is accepted.
Duplicate, combined, empty, malformed, and oversized values are rejected.
Client-supplied identity headers are ignored. Verified claims are available through
`FromContext`; `Validate(ctx, token)` also supports non-HTTP consumers.

## Authorization

Validation returns verified claims, including unscoped and domain-scoped tokens.
Choose an explicit application policy:

- `ProjectOrSystem` permits project or system scope.
- `RequireRoles(roles, true)` requires any listed role and system scope.
- `AdminPolicy{Roles: roles, ProjectIDs: operatorProjects}.Authorize` permits
  project tokens and system administrators.
- A nil middleware policy permits every valid token; handlers must then enforce
  their own authorization.

`AdminPolicy.IsAdmin` requires an allowed role plus system scope or an explicitly
configured operator project. There are no implicit admin role names or projects.
`AdminPolicy.Scope(identity, requestedProjectIDs)` prevents tenant queries from
expanding beyond their own project. Nil means all authorized projects; an explicit
empty slice stays empty. Authentication alone does not enforce resource ownership.

## Errors, transport, and caching

`ErrUnauthorized` maps to 401; `ErrForbidden` to 403; other failures to 503.
`Options.OnError` can preserve an application's existing response format and
request IDs. Backend bodies, credentials, and tokens never appear in default errors.
A persistent service-token 401 is a service failure (503), while a missing subject
token (404) is unauthorized. Network cancellation during a request currently maps
to unavailable; a context already canceled before validation is returned directly.

HTTPS is required unless `AllowHTTP` is explicitly enabled. Redirects are disabled
including for a custom HTTP client. A zero client timeout becomes 15 seconds;
custom transport, TLS settings, and nonzero timeouts are preserved. Response bodies
are limited to 1 MiB. Invalid, expired, missing-expiry, and contradictory-scope
responses are rejected.

Subject-token caching is **disabled by default**. Set `CacheTTL` to enable it, with
`MaxCacheEntries` defaulting to 10,000. Entries use SHA-256 token keys and expire at
the earlier of TTL and token expiry; failures are never cached. Cached identities
are copied so a handler cannot mutate another request's roles. Eviction removes
expired entries first and then an arbitrary entry at capacity. Concurrent cache
misses may make duplicate validation requests. Caching delays observation of token
revocation by up to the TTL; use zero where immediate revalidation is required.

## Development

```sh
gofmt -w .
go test -race -cover ./...
go vet ./...
```

Tests use local fake Keystone servers and do not require cloud credentials.

## License

Copyright 2026 VEXXHOST, Inc.

Licensed under the [Apache License, Version 2.0](LICENSE).
