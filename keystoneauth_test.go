// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func response(w http.ResponseWriter, expiry time.Time) {
	fmt.Fprintf(w, `{"token":{"user":{"id":"u","domain":{"id":"ud"}},"project":{"id":"p","domain":{"id":"pd"}},"roles":[{"name":"member"}],"expires_at":%q}}`, expiry.UTC().Format(time.RFC3339Nano))
}

func TestValidationModesAndCache(t *testing.T) {
	for _, service := range []bool{false, true} {
		t.Run(fmt.Sprint(service), func(t *testing.T) {
			var posts, gets atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/identity/v3/auth/tokens" {
					t.Errorf("path: %s", r.URL.Path)
				}
				if r.Method == "POST" {
					posts.Add(1)
					var body struct {
						Auth struct {
							Identity struct {
								Methods    []string                    `json:"methods"`
								Credential struct{ ID, Secret string } `json:"application_credential"`
							} `json:"identity"`
						} `json:"auth"`
					}
					if json.NewDecoder(r.Body).Decode(&body) != nil || body.Auth.Identity.Credential.ID != "id" || body.Auth.Identity.Credential.Secret != "secret" || len(body.Auth.Identity.Methods) != 1 || body.Auth.Identity.Methods[0] != "application_credential" {
						t.Error("bad auth payload")
					}
					w.Header().Set("X-Subject-Token", "svc")
					w.WriteHeader(201)
					response(w, time.Now().Add(time.Hour))
					return
				}
				gets.Add(1)
				want := "user"
				if service {
					want = "svc"
				}
				if r.Header.Get("X-Auth-Token") != want || r.Header.Get("X-Subject-Token") != "user" {
					t.Error("wrong token headers")
				}
				response(w, time.Now().Add(time.Hour))
			}))
			defer s.Close()
			cfg := Config{URL: s.URL + "/identity", AllowHTTP: true, CacheTTL: time.Minute}
			if service {
				cfg.ApplicationCredentialID = "id"
				cfg.ApplicationCredentialSecret = "secret"
			}
			c, err := New(cfg)
			if err != nil {
				t.Fatal(err)
			}
			for n := 0; n < 2; n++ {
				i, err := c.Validate(context.Background(), "user")
				if err != nil || i.ProjectID != "p" || i.UserDomainID != "ud" || i.DomainID != "pd" || i.Roles[0] != "member" {
					t.Fatalf("%+v %v", i, err)
				}
				i.Roles[0] = "admin"
			}
			if gets.Load() != 1 {
				t.Fatal("cache miss")
			}
			if service && posts.Load() != 1 {
				t.Fatal("service token not reused")
			}
		})
	}
}

func TestServiceRefreshAndFailures(t *testing.T) {
	for _, tc := range []struct {
		name     string
		statuses []int
		want     error
		posts    int32
	}{
		{"refresh", []int{401, 200}, nil, 2}, {"bad service", []int{401, 401}, ErrUnavailable, 2},
		{"missing", []int{404}, ErrUnauthorized, 1}, {"policy", []int{403}, ErrUnavailable, 1}, {"outage", []int{500}, ErrUnavailable, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var posts, gets int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts++
					w.Header().Set("X-Subject-Token", fmt.Sprint("svc", posts))
					w.WriteHeader(201)
					response(w, time.Now().Add(time.Hour))
					return
				}
				status := tc.statuses[gets]
				gets++
				w.WriteHeader(status)
				if status == 200 {
					response(w, time.Now().Add(time.Hour))
				}
			}))
			defer s.Close()
			c, _ := New(Config{URL: s.URL + "/v3/", AllowHTTP: true, ApplicationCredentialID: "id", ApplicationCredentialSecret: "secret"})
			_, err := c.Validate(context.Background(), "user")
			if !errors.Is(err, tc.want) || posts != tc.posts {
				t.Fatalf("err=%v posts=%d", err, posts)
			}
		})
	}
}

func TestRejectInvalidResponses(t *testing.T) {
	for _, body := range []string{`{`, `{}`, `{"token":{"user":{"id":"u"},"expires_at":"2000-01-01T00:00:00Z"}}`, `{"token":{"user":{"id":"u"},"project":{"id":"p"},"system":{"all":true},"expires_at":"2099-01-01T00:00:00Z"}}`} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
		c, _ := New(Config{URL: s.URL, AllowHTTP: true})
		if _, err := c.Validate(context.Background(), "user"); err == nil {
			t.Errorf("accepted %s", body)
		}
		s.Close()
	}
}

func TestRedirects(t *testing.T) {
	var reached atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached.Store(true) }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	for _, service := range []bool{false, true} {
		cfg := Config{URL: s.URL, AllowHTTP: true, HTTPClient: s.Client()}
		if service {
			cfg.ApplicationCredentialID = "id"
			cfg.ApplicationCredentialSecret = "secret"
		}
		c, _ := New(cfg)
		_, err := c.Validate(context.Background(), "user")
		if !errors.Is(err, ErrUnavailable) || reached.Load() {
			t.Fatal("redirect followed", err)
		}
	}
}

func TestHeaders(t *testing.T) {
	for _, tc := range []struct {
		x, a []string
		ok   bool
	}{
		{x: []string{"token"}, ok: true}, {a: []string{"Bearer token"}, ok: true}, {a: []string{"bearer token"}, ok: true},
		{}, {x: []string{""}}, {x: []string{"a", "b"}}, {a: []string{"Bearer a", "Bearer b"}},
		{x: []string{"a"}, a: []string{"Bearer a"}}, {a: []string{"Basic a"}}, {a: []string{"Bearer "}}, {a: []string{"Bearer a b"}}, {x: []string{"a,b"}},
	} {
		r := httptest.NewRequest("GET", "/", nil)
		for _, x := range tc.x {
			r.Header.Add("X-Auth-Token", x)
		}
		for _, a := range tc.a {
			r.Header.Add("Authorization", a)
		}
		_, err := TokenFromRequest(r)
		if (err == nil) != tc.ok {
			t.Errorf("%+v: %v", tc, err)
		}
	}
}

func TestAuthorizationBoundaries(t *testing.T) {
	p := AdminPolicy{Roles: []string{"admin"}, ProjectIDs: []string{"ops"}}
	for _, tc := range []struct {
		i              Identity
		admin, allowed bool
	}{
		{Identity{ProjectID: "p", Roles: []string{"admin"}}, false, true},
		{Identity{ProjectID: "ops", Roles: []string{"admin"}}, true, true},
		{Identity{ProjectID: "ops", Roles: []string{"member"}}, false, true},
		{Identity{SystemScope: "all", Roles: []string{"admin"}}, true, true},
		{Identity{SystemScope: "all", Roles: []string{"reader"}}, false, false},
		{Identity{Roles: []string{"admin"}}, false, false},
	} {
		if p.IsAdmin(tc.i) != tc.admin || (p.Authorize(tc.i) == nil) != tc.allowed {
			t.Errorf("%+v", tc)
		}
	}
	i := Identity{ProjectID: "p"}
	if _, err := p.Scope(i, []string{"p", "other"}); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	ids, err := p.Scope(i, nil)
	if err != nil || len(ids) != 1 || ids[0] != "p" {
		t.Fatal(ids, err)
	}
	ids, err = p.Scope(i, []string{})
	if err != nil || ids == nil || len(ids) != 0 {
		t.Fatal(ids, err)
	}
	if RequireRoles([]string{"admin"}, true)(Identity{ProjectID: "p", Roles: []string{"admin"}}) == nil {
		t.Fatal("tenant granted system access")
	}
}

type validatorFunc func(context.Context, string) (Identity, error)

func (f validatorFunc) Validate(c context.Context, s string) (Identity, error) { return f(c, s) }

func TestMiddleware(t *testing.T) {
	for _, tc := range []struct {
		err    error
		policy Policy
		status int
	}{{nil, nil, 204}, {ErrUnauthorized, nil, 401}, {ErrUnavailable, nil, 503}, {nil, RequireRoles([]string{"admin"}, true), 403}} {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			i, ok := FromContext(r.Context())
			if !ok || i.ProjectID != "p" {
				t.Error("missing context")
			}
			w.WriteHeader(204)
		})
		h := Middleware(validatorFunc(func(context.Context, string) (Identity, error) { return Identity{ProjectID: "p"}, tc.err }), Options{Policy: tc.policy})(next)
		r := httptest.NewRequest("GET", "/", nil)
		r.Header.Set("Authorization", "Bearer token")
		r.Header.Set("X-Project-ID", "other")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatal(w.Code, tc.status)
		}
	}
}

func TestBoundedConcurrentCache(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { response(w, time.Now().Add(time.Hour)) }))
	defer s.Close()
	c, _ := New(Config{URL: s.URL, AllowHTTP: true, CacheTTL: time.Minute, MaxCacheEntries: 2})
	var wg sync.WaitGroup
	for n := 0; n < 30; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			if _, err := c.Validate(context.Background(), fmt.Sprint(n)); err != nil {
				t.Error(err)
			}
		}(n)
	}
	wg.Wait()
	if c.cache.entries.Len() > 2 {
		t.Fatal("unbounded cache")
	}

}

func TestConfig(t *testing.T) {
	for _, cfg := range []Config{{URL: "http://example.com"}, {URL: "https://user:pass@example.com"}, {URL: "https://example.com?q=x"}, {URL: "https://example.com", ApplicationCredentialID: "id"}, {URL: "https://example.com", CacheTTL: -1}} {
		if _, err := New(cfg); err == nil {
			t.Errorf("accepted %+v", cfg)
		}
	}
}
