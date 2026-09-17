// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// TokenFromRequest accepts exactly one X-Auth-Token or Bearer header. Identity
// headers such as X-Project-ID and X-Roles are never trusted.
func TokenFromRequest(r *http.Request) (string, error) {
	xs, as := r.Header.Values("X-Auth-Token"), r.Header.Values("Authorization")
	if len(xs)+len(as) != 1 {
		return "", ErrUnauthorized
	}
	var value string
	if len(xs) == 1 {
		value = xs[0]
	} else {
		scheme, token, ok := strings.Cut(as[0], " ")
		if !ok || !strings.EqualFold(scheme, "Bearer") {
			return "", ErrUnauthorized
		}
		value = token
	}
	if !validToken(value) {
		return "", ErrUnauthorized
	}
	return value, nil
}

// ErrorHandler allows applications to retain their own JSON error contract.
type ErrorHandler func(http.ResponseWriter, *http.Request, error)
type Options struct {
	Policy  Policy
	OnError ErrorHandler
}

// Middleware wraps any net/http handler, including chi routers. Apply it only
// to Keystone-protected routes; health checks and API-key routes can stay outside.
func Middleware(v Validator, opts Options) func(http.Handler) http.Handler {
	fail := opts.OnError
	if fail == nil {
		fail = DefaultErrorHandler
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := TokenFromRequest(r)
			if err != nil {
				fail(w, r, err)
				return
			}
			i, err := v.Validate(r.Context(), token)
			if err != nil {
				fail(w, r, err)
				return
			}
			if opts.Policy != nil {
				if err = opts.Policy(i.clone()); err != nil {
					fail(w, r, err)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), contextKey{}, i.clone())))
		})
	}
}

// DefaultErrorHandler never exposes backend errors or token values.
func DefaultErrorHandler(w http.ResponseWriter, r *http.Request, err error) {
	status, message := http.StatusServiceUnavailable, "identity service unavailable"
	if errors.Is(err, ErrUnauthorized) {
		status = 401
		message = "unauthorized"
		w.Header().Set("WWW-Authenticate", "Bearer")
	}
	if errors.Is(err, ErrForbidden) {
		status = 403
		message = "forbidden"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": message})
}
