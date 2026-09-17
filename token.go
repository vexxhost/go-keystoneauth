// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"encoding/json"
	"time"
)

type token struct {
	User struct {
		ID     string `json:"id"`
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
	} `json:"user"`
	Project *struct {
		ID     string `json:"id"`
		Domain struct {
			ID string `json:"id"`
		} `json:"domain"`
	} `json:"project"`
	Domain *struct {
		ID string `json:"id"`
	} `json:"domain"`
	System *struct {
		All bool `json:"all"`
	} `json:"system"`
	Roles []struct {
		Name string `json:"name"`
	} `json:"roles"`
	ExpiresAt             time.Time                  `json:"expires_at"`
	Bind                  map[string]json.RawMessage `json:"bind"`
	ApplicationCredential *struct {
		AccessRules json.RawMessage `json:"access_rules"`
	} `json:"application_credential"`
}

// identity rejects unsupported restrictions before any claims can be cached.
func (t token) identity(now time.Time) (Identity, error) {
	if len(t.Bind) != 0 {
		return Identity{}, ErrUnauthorized
	}
	if t.ApplicationCredential != nil {
		rules := t.ApplicationCredential.AccessRules
		if len(rules) != 0 && string(rules) != "null" {
			return Identity{}, ErrUnauthorized
		}
	}
	if t.User.ID == "" || !t.ExpiresAt.After(now) {
		return Identity{}, ErrUnauthorized
	}
	i := Identity{UserID: t.User.ID, UserDomainID: t.User.Domain.ID, ExpiresAt: t.ExpiresAt}
	scopes := 0
	if t.Project != nil {
		if t.Project.ID == "" {
			return Identity{}, ErrUnauthorized
		}
		scopes++
		i.ProjectID = t.Project.ID
		i.DomainID = t.Project.Domain.ID
	}
	if t.Domain != nil {
		if t.Domain.ID == "" {
			return Identity{}, ErrUnauthorized
		}
		scopes++
		i.DomainID = t.Domain.ID
	}
	if t.System != nil {
		if !t.System.All {
			return Identity{}, ErrUnauthorized
		}
		scopes++
		i.SystemScope = "all"
	}
	if scopes > 1 {
		return Identity{}, ErrUnauthorized
	}
	for _, r := range t.Roles {
		i.Roles = append(i.Roles, r.Name)
	}
	return i, nil
}
