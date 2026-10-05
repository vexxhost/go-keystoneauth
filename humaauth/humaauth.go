// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package humaauth authenticates Huma operations with Keystone.
//
// Its middleware reads exactly one token with keystoneauth.TokenFromRequest,
// authenticates it, and passes the resulting Principal to the operation through the
// request context. Failures are written as Huma errors (application/problem+json), so
// they match every other error the API returns.
package humaauth

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/vexxhost/go-keystoneauth"
)

// Options configures Middleware. The zero value is usable.
type Options struct {
	// Timeout, when positive, bounds the rest of the request: Keystone validation and
	// the operation that follows share one deadline.
	Timeout time.Duration
	// Public reports whether an operation needs no token. Nil uses IsPublic.
	Public func(*huma.Operation) bool
	// OnError writes a failure. Nil uses WriteError. A custom hook can log with its
	// own request ID and then call WriteError to keep the default responses.
	OnError func(huma.API, huma.Context, error)
	// Logger records failures that are not the caller's fault: Keystone being
	// unreachable or the deadline passing. Nil uses slog.Default. It is not used
	// when OnError is set.
	Logger *slog.Logger
}

type principalKey struct{}

// Middleware returns Huma middleware that authenticates every operation Public does
// not exempt. Register it with api.UseMiddleware.
func Middleware(api huma.API, auth keystoneauth.Authenticator, opts Options) func(huma.Context, func(huma.Context)) {
	public := opts.Public
	if public == nil {
		public = IsPublic
	}
	fail := opts.OnError
	if fail == nil {
		logger := opts.Logger
		if logger == nil {
			logger = slog.Default()
		}
		fail = func(api huma.API, ctx huma.Context, err error) {
			if !errors.Is(err, keystoneauth.ErrUnauthorized) && !errors.Is(err, keystoneauth.ErrForbidden) {
				logger.ErrorContext(ctx.Context(), "authenticating a Keystone token", "error", err)
			}
			WriteError(api, ctx, err)
		}
	}
	return func(ctx huma.Context, next func(huma.Context)) {
		if public(ctx.Operation()) {
			next(ctx)
			return
		}
		r, _ := humago.Unwrap(ctx)
		token, err := keystoneauth.TokenFromRequest(r)
		if err != nil {
			fail(api, ctx, err)
			return
		}
		c := ctx.Context()
		if opts.Timeout > 0 {
			var cancel context.CancelFunc
			c, cancel = context.WithTimeout(c, opts.Timeout)
			defer cancel()
		}
		principal, err := auth.Authenticate(c, token)
		if err != nil {
			fail(api, ctx, err)
			return
		}
		next(huma.WithContext(ctx, NewContext(c, principal)))
	}
}

// IsPublic exempts what is not a registered operation: no operation, or one without
// an OperationID, which is how Huma's own schema and documentation routes appear. An
// operation that declares an explicitly empty security requirement is also public,
// which is what OpenAPI means by it.
func IsPublic(op *huma.Operation) bool {
	return op == nil || op.OperationID == "" || (op.Security != nil && len(op.Security) == 0)
}

// WriteError writes the response for an authentication failure: 401 with
// WWW-Authenticate for a missing or invalid token, 403 for a token whose scope is
// refused, 504 when the deadline passed, and 503 otherwise. The message never
// includes the cause, which may name Keystone's host.
func WriteError(api huma.API, ctx huma.Context, err error) {
	status, message := Status(err)
	if status == http.StatusUnauthorized {
		ctx.SetHeader("WWW-Authenticate", "Bearer")
	}
	_ = huma.WriteErr(api, ctx, status, message)
}

// Status maps an authentication failure to the status and message WriteError uses.
func Status(err error) (int, string) {
	switch {
	case errors.Is(err, keystoneauth.ErrUnauthorized):
		return http.StatusUnauthorized, "a valid Keystone token is required in X-Auth-Token or Authorization: Bearer"
	case errors.Is(err, keystoneauth.ErrForbidden):
		return http.StatusForbidden, "the token must be project scoped, or an administrator's"
	case errors.Is(err, context.DeadlineExceeded):
		return http.StatusGatewayTimeout, "the request deadline passed while validating the token"
	default:
		return http.StatusServiceUnavailable, "Keystone could not validate the token"
	}
}

// NewContext returns ctx carrying p, as the middleware passes it to an operation.
// Tests and non-HTTP callers can use it to call operations directly.
func NewContext(ctx context.Context, p keystoneauth.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the principal the middleware authenticated.
func PrincipalFrom(ctx context.Context) (keystoneauth.Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(keystoneauth.Principal)
	if ok {
		p.Roles = append([]string(nil), p.Roles...)
	}
	return p, ok
}
