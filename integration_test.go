//go:build integration

// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

func TestKeystoneIntegration(t *testing.T) {
	endpoint := os.Getenv("KEYSTONEAUTH_INTEGRATION_URL")
	if endpoint == "" {
		t.Skip("set KEYSTONEAUTH_INTEGRATION_URL to run against Keystone")
	}
	subject := os.Getenv("KEYSTONEAUTH_INTEGRATION_TOKEN")
	user := os.Getenv("KEYSTONEAUTH_INTEGRATION_USER_ID")
	project := os.Getenv("KEYSTONEAUTH_INTEGRATION_PROJECT_ID")
	if subject == "" || user == "" || project == "" {
		t.Fatal("integration token and expected user/project IDs are required")
	}
	c, err := New(Config{
		URL:                         endpoint,
		ApplicationCredentialID:     os.Getenv("OS_APPLICATION_CREDENTIAL_ID"),
		ApplicationCredentialSecret: os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET"),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	i, err := c.Validate(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if i.UserID != user || i.ProjectID != project || !i.ExpiresAt.After(time.Now()) {
		t.Fatal("validated claims do not match expected live identity")
	}
	_, err = c.Validate(ctx, "deliberately-invalid-keystoneauth-integration-token")
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("invalid token must be unauthorized: %v", err)
	}
}
