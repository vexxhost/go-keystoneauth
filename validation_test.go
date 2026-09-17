// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestClaimScopesAndRestrictions(t *testing.T) {
	for _, tc := range []struct {
		name, extra             string
		project, domain, system string
		reject                  bool
	}{
		{name: "unscoped"},
		{name: "project", extra: `"project":{"id":"p","domain":{"id":"pd"}}`, project: "p", domain: "pd"},
		{name: "domain", extra: `"domain":{"id":"d"}`, domain: "d"},
		{name: "system", extra: `"system":{"all":true}`, system: "all"},
		{name: "empty project", extra: `"project":{}`, reject: true},
		{name: "empty domain", extra: `"domain":{}`, reject: true},
		{name: "false system", extra: `"system":{"all":false}`, reject: true},
		{name: "conflicting", extra: `"domain":{"id":"d"},"project":{"id":"p"}`, reject: true},
		{name: "bound", extra: `"bind":{"kerberos":"alice@EXAMPLE.COM"}`, reject: true},
		{name: "rules", extra: `"application_credential":{"access_rules":[{"method":"GET","path":"/allowed","service":"compute"}]}`, reject: true},
		{name: "empty rules", extra: `"application_credential":{"access_rules":[]}`, reject: true},
		{name: "null rules", extra: `"application_credential":{"access_rules":null}`},
		{name: "ordinary application credential", extra: `"application_credential":{"id":"app"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"token":{"user":{"id":"u","domain":{"id":"ud"}},"expires_at":"2099-01-01T00:00:00Z"`
			if tc.extra != "" {
				body += "," + tc.extra
			}
			body += "}}"
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.Query().Has("nocatalog") {
					t.Error("catalog was requested")
				}
				if r.Header.Get("OpenStack-Identity-Access-Rules") != "" {
					t.Error("advertised unsupported access rules")
				}
				_, _ = io.WriteString(w, body)
			}))
			defer s.Close()
			c, err := New(Config{URL: s.URL, AllowHTTP: true, CacheTTL: time.Minute})
			if err != nil {
				t.Fatal(err)
			}
			i, err := c.Validate(context.Background(), "token")
			if tc.reject {
				if !errors.Is(err, ErrUnauthorized) {
					t.Fatalf("restriction accepted: %+v %v", i, err)
				}
				if c.cache.entries.Len() != 0 {
					t.Fatal("rejected claims cached")
				}
			} else if err != nil || i.ProjectID != tc.project || i.DomainID != tc.domain || i.SystemScope != tc.system || i.UserDomainID != "ud" {
				t.Fatalf("%+v %v", i, err)
			}
		})
	}
}

func TestResponseLimitsAndErrors(t *testing.T) {
	for _, tc := range []struct{ name, body, reason string }{
		{"oversized", strings.Repeat(" ", (1<<20)+1), "size"},
		{"malformed", `{"token":`, "json"},
		{"trailing JSON", `{"token":{}} {}`, "json"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := decodeToken(strings.NewReader(tc.body), "validate")
			var backend *BackendError
			if !errors.Is(err, ErrUnavailable) || !errors.As(err, &backend) || backend.Reason != tc.reason {
				t.Fatal(err)
			}
		})
	}
	// Exactly the size limit is permitted when the payload is valid JSON.
	body := `{"token":{}}`
	_, err := decodeToken(strings.NewReader(body+strings.Repeat(" ", (1<<20)-len(body))), "validate")
	if err != nil {
		t.Fatal(err)
	}
}

func TestTransportErrorsAreSanitized(t *testing.T) {
	c, err := New(Config{URL: "https://keystone.example", HTTPClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("SECRET token and backend details")
	})}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Validate(context.Background(), "token")
	var backend *BackendError
	if !errors.As(err, &backend) || !errors.Is(err, ErrUnavailable) || backend.Reason != "transport" || strings.Contains(err.Error(), "SECRET") {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	DefaultErrorHandler(w, httptest.NewRequest(http.MethodGet, "/", nil), err)
	if strings.Contains(w.Body.String(), "SECRET") || w.Code != http.StatusServiceUnavailable {
		t.Fatal(w)
	}
}

func TestValidationCancellation(t *testing.T) {
	entered := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(entered); <-r.Context().Done() }))
	defer s.Close()
	c, err := New(Config{URL: s.URL, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Validate(ctx, "token"); done <- err }()
	waitFor(t, entered)
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("validation ignored cancellation")
	}
	_, err = c.Validate(ctx, "token")
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestHeaderLimits(t *testing.T) {
	for _, tc := range []struct {
		value string
		ok    bool
	}{
		{strings.Repeat("a", 16384), true}, {strings.Repeat("a", 16385), false},
		{"token\t", false}, {"token\r\n", false}, {"tokén", false}, {"token\x7f", false},
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Auth-Token", tc.value)
		_, err := TokenFromRequest(r)
		if (err == nil) != tc.ok {
			t.Errorf("length=%d: %v", len(tc.value), err)
		}
	}
}

func TestPolicyBoundaries(t *testing.T) {
	p := AdminPolicy{Roles: []string{"admin"}, ProjectIDs: []string{"ops"}}
	for _, tc := range []struct {
		i       Identity
		allowed bool
	}{
		{Identity{}, false}, {Identity{DomainID: "d"}, false}, {Identity{ProjectID: "p"}, true}, {Identity{SystemScope: "all"}, true},
	} {
		if (ProjectOrSystem(tc.i) == nil) != tc.allowed {
			t.Fatal(tc)
		}
	}
	if p.RequireAdmin(Identity{ProjectID: "p", Roles: []string{"admin"}}) == nil {
		t.Fatal("tenant admin elevated")
	}
	for _, i := range []Identity{{ProjectID: "ops", Roles: []string{"admin"}}, {SystemScope: "all", Roles: []string{"admin"}}} {
		if p.RequireAdmin(i) != nil {
			t.Fatal("admin rejected")
		}
		got, err := p.Scope(i, nil)
		if err != nil || got != nil {
			t.Fatal(got, err)
		}
		got, err = p.Scope(i, []string{})
		if err != nil || got == nil || len(got) != 0 {
			t.Fatal(got, err)
		}
	}
	if _, err := p.Scope(Identity{}, nil); !errors.Is(err, ErrForbidden) {
		t.Fatal(err)
	}
	roles := []string{"member"}
	policy := RequireRoles(roles, false)
	roles[0] = "admin"
	if policy(Identity{Roles: []string{"member"}}) != nil {
		t.Fatal("policy captured mutable role slice")
	}
	if RequireRoles(nil, false)(Identity{Roles: []string{"member"}}) == nil {
		t.Fatal("empty role policy allowed access")
	}
}

func TestMiddlewareIsolationAndErrorHook(t *testing.T) {
	original := Identity{ProjectID: "p", Roles: []string{"member"}}
	v := validatorFunc(func(context.Context, string) (Identity, error) { return original, nil })
	policy := func(i Identity) error { i.Roles[0] = "admin"; return nil }
	reached := false
	h := Middleware(v, Options{Policy: policy})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		i, ok := FromContext(r.Context())
		if !ok || i.Roles[0] != "member" {
			t.Fatal(i, ok)
		}
		i.Roles[0] = "admin"
		again, _ := FromContext(r.Context())
		if again.Roles[0] != "member" {
			t.Fatal("context identity mutated")
		}
	}))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Auth-Token", "token")
	h.ServeHTTP(httptest.NewRecorder(), r)
	if !reached || original.Roles[0] != "member" {
		t.Fatal("identity isolation failed")
	}
	called := false
	h = Middleware(v, Options{OnError: func(w http.ResponseWriter, r *http.Request, err error) {
		called = true
		if !errors.Is(err, ErrUnauthorized) {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusTeapot)
	}})(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("missing token reached handler") }))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", nil))
	if !called || w.Code != http.StatusTeapot {
		t.Fatal(w.Code)
	}
	if _, ok := FromContext(context.Background()); ok {
		t.Fatal("unexpected identity")
	}
}

func FuzzTokenFromRequest(f *testing.F) {
	for _, s := range []string{"", "token", "a,b", "a b", "a\r\n", "é"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 20000 {
			t.Skip()
		}
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("X-Auth-Token", s)
		got, err := TokenFromRequest(r)
		if err == nil && (got != s || len(got) == 0 || len(got) > 16384 || strings.ContainsAny(got, " ,\r\n\t")) {
			t.Fatalf("accepted invalid token %q", got)
		}
	})
}

func FuzzDecodeToken(f *testing.F) {
	for _, s := range []string{`{}`, `{"token":{}}`, `{"token":{"expires_at":"2099-01-01T00:00:00Z"}}`, `null`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1<<20 {
			t.Skip()
		}
		token, err := decodeToken(strings.NewReader(s), "validate")
		if err == nil {
			if !json.Valid([]byte(s)) {
				t.Fatal("invalid JSON accepted")
			}
			i, err := token.identity(time.Now())
			if err == nil && (i.UserID == "" || i.ExpiresAt.IsZero()) {
				t.Fatal("incomplete identity accepted")
			}
		}
	})
}

func TestBodyFailurePreservesStatus(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "invalid JSON") }))
	defer s.Close()
	c, err := New(Config{URL: s.URL, AllowHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.Validate(context.Background(), "token")
	var backend *BackendError
	if !errors.As(err, &backend) || backend.StatusCode != http.StatusOK || backend.Reason != "json" {
		t.Fatal(err)
	}
}

func TestNegativeHTTPTimeout(t *testing.T) {
	_, err := New(Config{URL: "https://keystone.example", HTTPClient: &http.Client{Timeout: -time.Second}})
	if err == nil {
		t.Fatal("negative timeout accepted")
	}
}
