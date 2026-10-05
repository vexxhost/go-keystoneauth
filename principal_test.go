// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestFileConfig(t *testing.T) {
	env := map[string]string{"ID": "id", "SECRET": "secret", "": "must not be read"}
	f := FileConfig{
		URL: "http://keystone/v3", AllowHTTP: true,
		ApplicationCredentialIDEnv: "ID", ApplicationCredentialSecretEnv: "SECRET",
		AdminRoles: []string{"admin"}, AdminProjectIDs: []string{"ops"},
	}
	got := f.Config(func(k string) string { return env[k] })
	want := Config{URL: "http://keystone/v3", AllowHTTP: true, ApplicationCredentialID: "id", ApplicationCredentialSecret: "secret"}
	if got != want {
		t.Fatalf("Config() = %+v, want %+v", got, want)
	}
	if c := (FileConfig{}).Config(func(k string) string { return env[k] }); c.ApplicationCredentialID != "" || c.ApplicationCredentialSecret != "" {
		t.Fatalf("an unset variable name must resolve to nothing, got %+v", c)
	}

	p := f.AdminPolicy()
	p.Roles[0] = "changed"
	if f.AdminRoles[0] != "admin" {
		t.Fatal("AdminPolicy must copy the role list")
	}
	if (FileConfig{}).AdminPolicy().IsAdmin(Identity{Roles: []string{"admin"}, SystemScope: "all"}) {
		t.Fatal("no admin roles must mean no administrators")
	}
}

func TestAuthenticator(t *testing.T) {
	identities := map[string]Identity{
		"member":   {UserID: "u", ProjectID: "p", Roles: []string{"member"}},
		"operator": {UserID: "o", ProjectID: "ops", Roles: []string{"admin"}},
		"system":   {UserID: "s", SystemScope: "all", Roles: []string{"admin"}},
		"domain":   {UserID: "d", DomainID: "dom", Roles: []string{"admin"}},
	}
	v := validatorFunc(func(_ context.Context, token string) (Identity, error) {
		i, ok := identities[token]
		if !ok {
			return Identity{}, ErrUnauthorized
		}
		return i, nil
	})
	roles := []string{"admin"}
	a := NewAuthenticator(v, AdminPolicy{Roles: roles, ProjectIDs: []string{"ops"}})
	roles[0] = "member" // the authenticator keeps its own copy

	for token, admin := range map[string]bool{"member": false, "operator": true, "system": true} {
		p, err := a.Authenticate(context.Background(), token)
		if err != nil || p.Admin != admin || p.UserID != identities[token].UserID {
			t.Errorf("%s: %+v %v", token, p, err)
		}
	}
	if _, err := a.Authenticate(context.Background(), "domain"); !errors.Is(err, ErrForbidden) {
		t.Errorf("a domain token that is not an administrator's must be forbidden: %v", err)
	}
	if _, err := a.Authenticate(context.Background(), "unknown"); !errors.Is(err, ErrUnauthorized) {
		t.Errorf("validation errors must pass through: %v", err)
	}

	p, _ := a.Authenticate(context.Background(), "member")
	p.Roles[0] = "admin"
	if identities["member"].Roles[0] != "member" {
		t.Error("the principal must not share the validator's role slice")
	}
}

func TestPrincipalScopeMatchesAdminPolicy(t *testing.T) {
	policy := AdminPolicy{Roles: []string{"admin"}}
	identities := []Identity{
		{ProjectID: "p"},
		{SystemScope: "all", Roles: []string{"admin"}},
		{DomainID: "d"},
	}
	requests := [][]string{nil, {}, {"p"}, {"q"}, {"p", "q"}}
	for _, i := range identities {
		for _, r := range requests {
			want, wantErr := policy.Scope(i, r)
			got, gotErr := Principal{Identity: i, Admin: policy.IsAdmin(i)}.Scope(r)
			if !reflect.DeepEqual(got, want) || !errors.Is(gotErr, wantErr) {
				t.Errorf("%+v %v: got %v %v, want %v %v", i, r, got, gotErr, want, wantErr)
			}
		}
	}
}
