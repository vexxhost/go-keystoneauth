// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

// Package keystoneauth provides Keystone v3 token validation and HTTP middleware.
package keystoneauth

import (
	"context"
	"errors"
	"time"
)

var (
	ErrUnauthorized = errors.New("keystoneauth: unauthorized")
	ErrForbidden    = errors.New("keystoneauth: forbidden")
	ErrUnavailable  = errors.New("keystoneauth: identity unavailable")
)

// Identity contains verified token claims. DomainID is the token's scope domain;
// UserDomainID is always the user's domain. No raw token is retained here.
type Identity struct {
	UserID, UserDomainID, ProjectID, DomainID, SystemScope string
	Roles                                                  []string
	ExpiresAt                                              time.Time
}

func (i Identity) HasRole(roles []string) bool {
	for _, have := range i.Roles {
		for _, want := range roles {
			if have == want {
				return true
			}
		}
	}
	return false
}
func (i Identity) clone() Identity { i.Roles = append([]string(nil), i.Roles...); return i }

type Validator interface {
	Validate(context.Context, string) (Identity, error)
}
type contextKey struct{}

// FromContext returns a copy of the authenticated identity.
func FromContext(ctx context.Context) (Identity, bool) {
	i, ok := ctx.Value(contextKey{}).(Identity)
	return i.clone(), ok
}

// Policy authorizes verified claims. Nil middleware policy permits any valid token.
type Policy func(Identity) error

func ProjectOrSystem(i Identity) error {
	if i.ProjectID == "" && i.SystemScope != "all" {
		return ErrForbidden
	}
	return nil
}
func RequireRoles(roles []string, system bool) Policy {
	roles = append([]string(nil), roles...)
	return func(i Identity) error {
		if !i.HasRole(roles) || (system && i.SystemScope != "all") {
			return ErrForbidden
		}
		return nil
	}
}

// AdminPolicy requires an allowed role AND system scope or an explicit operator
// project. A tenant's admin role alone never grants cross-project access.
type AdminPolicy struct{ Roles, ProjectIDs []string }

func (p AdminPolicy) IsAdmin(i Identity) bool {
	if !i.HasRole(p.Roles) {
		return false
	}
	if i.SystemScope == "all" {
		return true
	}
	for _, id := range p.ProjectIDs {
		if id != "" && id == i.ProjectID {
			return true
		}
	}
	return false
}
func (p AdminPolicy) Authorize(i Identity) error {
	if i.ProjectID == "" && !p.IsAdmin(i) {
		return ErrForbidden
	}
	return nil
}

// Scope preserves nil (all authorized projects) versus an explicit empty filter.
func (p AdminPolicy) Scope(i Identity, requested []string) ([]string, error) {
	if p.IsAdmin(i) {
		return requested, nil
	}
	if i.ProjectID == "" {
		return nil, ErrForbidden
	}
	if requested != nil {
		for _, id := range requested {
			if id != i.ProjectID {
				return nil, ErrForbidden
			}
		}
		if len(requested) == 0 {
			return []string{}, nil
		}
	}
	return []string{i.ProjectID}, nil
}
