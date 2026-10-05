// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import "context"

// FileConfig is the keystone section of a service's configuration file. Secrets are
// never written in the file: it names the environment variables that hold the
// application credential, so the file can be a ConfigMap.
//
// FileConfig applies no defaults. In particular an empty AdminRoles makes nobody an
// administrator; a service that wants a conventional role must set it itself.
type FileConfig struct {
	URL                            string   `yaml:"url" json:"url"`
	AllowHTTP                      bool     `yaml:"allow_http" json:"allow_http"`
	ApplicationCredentialIDEnv     string   `yaml:"application_credential_id_env" json:"application_credential_id_env"`
	ApplicationCredentialSecretEnv string   `yaml:"application_credential_secret_env" json:"application_credential_secret_env"`
	AdminRoles                     []string `yaml:"admin_roles" json:"admin_roles"`
	AdminProjectIDs                []string `yaml:"admin_project_ids" json:"admin_project_ids"`
}

// Config resolves the file into a client Config, reading the application credential
// with getenv. An unset or empty variable name yields an empty value. HTTPClient and
// cache settings are left for the caller.
func (f FileConfig) Config(getenv func(string) string) Config {
	lookup := func(name string) string {
		if name == "" {
			return ""
		}
		return getenv(name)
	}
	return Config{
		URL:                         f.URL,
		AllowHTTP:                   f.AllowHTTP,
		ApplicationCredentialID:     lookup(f.ApplicationCredentialIDEnv),
		ApplicationCredentialSecret: lookup(f.ApplicationCredentialSecretEnv),
	}
}

// AdminPolicy returns the administrator policy the file describes.
func (f FileConfig) AdminPolicy() AdminPolicy {
	return AdminPolicy{
		Roles:      append([]string(nil), f.AdminRoles...),
		ProjectIDs: append([]string(nil), f.AdminProjectIDs...),
	}
}

// Principal is an authorized caller: the verified claims and whether the
// AdminPolicy that authorized them treats the caller as an administrator.
type Principal struct {
	Identity
	Admin bool
}

// Scope restricts requested project IDs to what the principal may see. It applies
// the same rule as AdminPolicy.Scope: administrators keep their request, and anyone
// else is limited to their own project. Nil means all authorized projects; an
// explicit empty slice stays empty.
func (p Principal) Scope(requested []string) ([]string, error) {
	return scope(p.Admin, p.ProjectID, requested)
}

// Authenticator turns a token into an authorized Principal.
type Authenticator interface {
	Authenticate(context.Context, string) (Principal, error)
}

// NewAuthenticator validates tokens with v and authorizes them with p.Authorize, so
// a caller must be project scoped or an administrator. Admin is p.IsAdmin.
func NewAuthenticator(v Validator, p AdminPolicy) Authenticator {
	return &authenticator{validator: v, policy: AdminPolicy{
		Roles:      append([]string(nil), p.Roles...),
		ProjectIDs: append([]string(nil), p.ProjectIDs...),
	}}
}

type authenticator struct {
	validator Validator
	policy    AdminPolicy
}

func (a *authenticator) Authenticate(ctx context.Context, token string) (Principal, error) {
	i, err := a.validator.Validate(ctx, token)
	if err != nil {
		return Principal{}, err
	}
	if err := a.policy.Authorize(i); err != nil {
		return Principal{}, err
	}
	return Principal{Identity: i.clone(), Admin: a.policy.IsAdmin(i)}, nil
}
