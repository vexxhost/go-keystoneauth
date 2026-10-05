// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package humaauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
	"github.com/vexxhost/go-keystoneauth"
)

type authFunc func(context.Context, string) (keystoneauth.Principal, error)

func (f authFunc) Authenticate(ctx context.Context, token string) (keystoneauth.Principal, error) {
	return f(ctx, token)
}

type whoami struct {
	Body struct {
		UserID   string `json:"user_id"`
		Admin    bool   `json:"admin"`
		Deadline bool   `json:"deadline"`
	}
}

func newAPI(t *testing.T, auth keystoneauth.Authenticator, opts Options) http.Handler {
	t.Helper()
	mux := http.NewServeMux()
	api := humago.New(mux, huma.DefaultConfig("test", "1"))
	api.UseMiddleware(Middleware(api, auth, opts))
	huma.Register(api, huma.Operation{OperationID: "whoami", Method: http.MethodGet, Path: "/whoami"},
		func(ctx context.Context, _ *struct{}) (*whoami, error) {
			p, ok := PrincipalFrom(ctx)
			if !ok {
				return nil, errors.New("no principal")
			}
			out := &whoami{}
			out.Body.UserID, out.Body.Admin = p.UserID, p.Admin
			_, out.Body.Deadline = ctx.Deadline()
			return out, nil
		})
	huma.Register(api, huma.Operation{OperationID: "ping", Method: http.MethodGet, Path: "/ping", Security: []map[string][]string{}},
		func(context.Context, *struct{}) (*struct{}, error) { return nil, nil })
	return mux
}

func get(h http.Handler, path, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	if token != "" {
		r.Header.Set("X-Auth-Token", token)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestMiddleware(t *testing.T) {
	var calls int
	auth := authFunc(func(ctx context.Context, token string) (keystoneauth.Principal, error) {
		calls++
		switch token {
		case "admin":
			return keystoneauth.Principal{Identity: keystoneauth.Identity{UserID: "a"}, Admin: true}, nil
		case "domain":
			return keystoneauth.Principal{}, keystoneauth.ErrForbidden
		case "down":
			return keystoneauth.Principal{}, &keystoneauth.BackendError{}
		case "slow":
			<-ctx.Done()
			return keystoneauth.Principal{}, ctx.Err()
		}
		return keystoneauth.Principal{}, keystoneauth.ErrUnauthorized
	})
	h := newAPI(t, auth, Options{Timeout: 50 * time.Millisecond})

	w := get(h, "/whoami", "admin")
	var body struct {
		UserID   string `json:"user_id"`
		Admin    bool   `json:"admin"`
		Deadline bool   `json:"deadline"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); w.Code != 200 || err != nil || body.UserID != "a" || !body.Admin || !body.Deadline {
		t.Fatalf("authenticated: %d %s", w.Code, w.Body)
	}

	for token, status := range map[string]int{"": 401, "bad": 401, "domain": 403, "down": 503, "slow": 504} {
		w := get(h, "/whoami", token)
		if w.Code != status || w.Header().Get("Content-Type") != "application/problem+json" {
			t.Errorf("token %q: %d %q %s", token, w.Code, w.Header().Get("Content-Type"), w.Body)
		}
		if (status == 401) != (w.Header().Get("WWW-Authenticate") == "Bearer") {
			t.Errorf("token %q: WWW-Authenticate %q", token, w.Header().Get("WWW-Authenticate"))
		}
	}

	calls = 0
	for _, path := range []string{"/ping", "/openapi.yaml", "/docs"} {
		if w := get(h, path, ""); w.Code >= 300 {
			t.Errorf("%s must not need a token: %d %s", path, w.Code, w.Body)
		}
	}
	if calls != 0 {
		t.Errorf("public routes must not reach Keystone, got %d calls", calls)
	}
}

func TestOnErrorReplacesDefault(t *testing.T) {
	var seen error
	h := newAPI(t, authFunc(func(context.Context, string) (keystoneauth.Principal, error) {
		return keystoneauth.Principal{}, keystoneauth.ErrUnavailable
	}), Options{OnError: func(api huma.API, ctx huma.Context, err error) {
		seen = err
		ctx.SetHeader("X-Hook", "yes")
		WriteError(api, ctx, err)
	}})
	w := get(h, "/whoami", "token")
	if w.Code != 503 || w.Header().Get("X-Hook") != "yes" || !errors.Is(seen, keystoneauth.ErrUnavailable) {
		t.Fatalf("%d %v %s", w.Code, seen, w.Body)
	}
}

func TestPrincipalFromCopiesRoles(t *testing.T) {
	ctx := NewContext(context.Background(), keystoneauth.Principal{Identity: keystoneauth.Identity{Roles: []string{"member"}}})
	p, _ := PrincipalFrom(ctx)
	p.Roles[0] = "admin"
	if q, _ := PrincipalFrom(ctx); q.Roles[0] != "member" {
		t.Fatal("a handler must not be able to change another reader's roles")
	}
	if _, ok := PrincipalFrom(context.Background()); ok {
		t.Fatal("no principal in an empty context")
	}
}
