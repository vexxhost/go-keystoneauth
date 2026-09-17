// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Config configures a Client. Custom HTTP clients and transports must be safe for concurrent use.
type Config struct {
	// URL accepts an identity base URL or its /v3 endpoint.
	URL       string
	AllowHTTP bool
	// Set both credentials to validate using a service token. With neither set,
	// the subject token also authenticates the validation request.
	ApplicationCredentialID, ApplicationCredentialSecret string
	HTTPClient                                           *http.Client
	// CacheTTL defaults to zero (disabled). Revocation may be delayed by this TTL.
	CacheTTL time.Duration
	// MaxCacheEntries defaults to 10000 when caching is enabled.
	MaxCacheEntries int
}

// Client validates Keystone tokens and is safe for concurrent use. Construct it with New.
// Configuration is fixed for its lifetime; do not copy a Client after first use.
type Client struct {
	cfg       Config
	http      *http.Client
	cache     *identityCache
	serviceMu sync.Mutex
	service   *serviceCredential
	refresh   *serviceRefresh
}

// New constructs a client without contacting Keystone.
func New(cfg Config) (*Client, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return nil, fmt.Errorf("keystoneauth: invalid URL")
	}
	if u.Scheme != "https" && !(cfg.AllowHTTP && u.Scheme == "http") {
		return nil, fmt.Errorf("keystoneauth: HTTPS required")
	}
	if (cfg.ApplicationCredentialID == "") != (cfg.ApplicationCredentialSecret == "") {
		return nil, fmt.Errorf("keystoneauth: both application credential fields required")
	}
	if cfg.HTTPClient != nil && cfg.HTTPClient.Timeout < 0 {
		return nil, fmt.Errorf("keystoneauth: negative HTTP timeout")
	}
	if cfg.CacheTTL < 0 || cfg.MaxCacheEntries < 0 {
		return nil, fmt.Errorf("keystoneauth: negative cache setting")
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	if !strings.HasSuffix(cfg.URL, "/v3") {
		cfg.URL += "/v3"
	}
	if cfg.MaxCacheEntries == 0 {
		cfg.MaxCacheEntries = 10000
	}
	h := http.Client{Timeout: 15 * time.Second}
	if cfg.HTTPClient != nil {
		h = *cfg.HTTPClient
		if h.Timeout == 0 {
			h.Timeout = 15 * time.Second
		}
	}
	h.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{cfg: cfg, http: &h, cache: newIdentityCache(cfg.CacheTTL, cfg.MaxCacheEntries)}, nil
}

func validToken(s string) bool {
	if s == "" || len(s) > 16384 {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 || c == ',' {
			return false
		}
	}
	return true
}

// Validate authenticates a token; scope and role authorization are separate.
func (c *Client) Validate(ctx context.Context, subject string) (Identity, error) {
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	if !validToken(subject) {
		return Identity{}, ErrUnauthorized
	}
	if i, ok := c.cache.get(subject, time.Now()); ok {
		return i, nil
	}
	// Start the TTL before validation so a slow response cannot extend freshness.
	started := time.Now()
	t, err := c.validateToken(ctx, subject)
	if err != nil {
		return Identity{}, err
	}
	i, err := t.identity(time.Now())
	if err != nil {
		return Identity{}, err
	}
	c.cache.put(subject, i, started)
	return i, nil
}

func (c *Client) validateToken(ctx context.Context, subject string) (token, error) {
	serviceMode := c.cfg.ApplicationCredentialID != ""
	for attempt := 0; attempt < 2; attempt++ {
		auth := subject
		var credential *serviceCredential
		if serviceMode {
			var err error
			credential, err = c.serviceToken(ctx)
			if err != nil {
				return token{}, err
			}
			auth = credential.value
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+"/auth/tokens?nocatalog", nil)
		if err != nil {
			return token{}, backendError("validate", "request", 0)
		}
		req.Header.Set("X-Auth-Token", auth)
		req.Header.Set("X-Subject-Token", subject)
		t, _, status, err := c.requestToken(req, http.StatusOK, "validate")
		if err != nil {
			return token{}, err
		}
		if status == http.StatusOK {
			return t, nil
		}
		if status == http.StatusUnauthorized && serviceMode {
			c.invalidateService(credential)
			if attempt == 0 {
				continue
			}
			return token{}, backendError("validate", "status", status)
		}
		if status == http.StatusNotFound || status == http.StatusUnauthorized {
			return token{}, ErrUnauthorized
		}
		return token{}, backendError("validate", "status", status)
	}
	return token{}, ErrUnavailable
}
