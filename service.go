// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"time"
)

type serviceCredential struct {
	value   string
	expires time.Time
}

type serviceRefresh struct {
	done       chan struct{}
	credential *serviceCredential
	err        error
}

type authenticationRequest struct {
	Auth struct {
		Identity struct {
			Methods    []string `json:"methods"`
			Credential struct {
				ID     string `json:"id"`
				Secret string `json:"secret"`
			} `json:"application_credential"`
		} `json:"identity"`
	} `json:"auth"`
}

func (c *Client) serviceToken(ctx context.Context) (*serviceCredential, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c.serviceMu.Lock()
	if c.service != nil && time.Now().Add(time.Minute).Before(c.service.expires) {
		credential := c.service
		c.serviceMu.Unlock()
		return credential, nil
	}
	call := c.refresh
	if call == nil {
		call = &serviceRefresh{done: make(chan struct{})}
		c.refresh = call
		// Preserve context values for transports, but give shared work its own deadline.
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), c.http.Timeout)
		go c.refreshService(refreshCtx, cancel, call)
	}
	c.serviceMu.Unlock()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-call.done:
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return call.credential, call.err
	}
}

func (c *Client) refreshService(ctx context.Context, cancel context.CancelFunc, call *serviceRefresh) {
	defer cancel()
	credential, err := c.authenticate(ctx)
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()
	call.credential, call.err = credential, err
	if err == nil {
		c.service = credential
	}
	c.refresh = nil
	close(call.done)
}

func (c *Client) invalidateService(credential *serviceCredential) {
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()
	// Compare generations, not token strings: Keystone may issue the same value again.
	if c.service == credential {
		c.service = nil
	}
}

func (c *Client) authenticate(ctx context.Context) (*serviceCredential, error) {
	var payload authenticationRequest
	payload.Auth.Identity.Methods = []string{"application_credential"}
	payload.Auth.Identity.Credential.ID = c.cfg.ApplicationCredentialID
	payload.Auth.Identity.Credential.Secret = c.cfg.ApplicationCredentialSecret
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, backendError("authenticate", "request", 0)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+"/auth/tokens", bytes.NewReader(data))
	if err != nil {
		return nil, backendError("authenticate", "request", 0)
	}
	req.Header.Set("Content-Type", "application/json")
	t, headers, status, err := c.requestToken(req, http.StatusCreated, "authenticate")
	if err != nil {
		return nil, err
	}
	if status != http.StatusCreated {
		return nil, backendError("authenticate", "status", status)
	}
	value := headers.Get("X-Subject-Token")
	if !validToken(value) || !t.ExpiresAt.After(time.Now().Add(time.Minute)) {
		return nil, backendError("authenticate", "claims", status)
	}
	return &serviceCredential{value, t.ExpiresAt}, nil
}
