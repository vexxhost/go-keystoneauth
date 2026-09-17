// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

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
type entry struct {
	identity Identity
	until    time.Time
}
type Client struct {
	cfg            Config
	http           *http.Client
	serviceMu      sync.Mutex
	service        string
	serviceExpires time.Time
	mu             sync.Mutex
	cache          map[[32]byte]entry
}
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
	ExpiresAt time.Time `json:"expires_at"`
}

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
	return &Client{cfg: cfg, http: &h, cache: make(map[[32]byte]entry)}, nil
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
func decodeToken(r io.Reader) (token, error) {
	var body struct {
		Token token `json:"token"`
	}
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return token{}, ErrUnavailable
	}
	if json.Unmarshal(data, &body) != nil {
		return token{}, ErrUnavailable
	}
	return body.Token, nil
}
func (c *Client) serviceToken(ctx context.Context) (string, error) {
	c.serviceMu.Lock()
	defer c.serviceMu.Unlock()
	if c.service != "" && time.Now().Add(time.Minute).Before(c.serviceExpires) {
		return c.service, nil
	}
	payload := map[string]any{"auth": map[string]any{"identity": map[string]any{"methods": []string{"application_credential"}, "application_credential": map[string]string{"id": c.cfg.ApplicationCredentialID, "secret": c.cfg.ApplicationCredentialSecret}}}}
	data, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.URL+"/auth/tokens", bytes.NewReader(data))
	if err != nil {
		return "", ErrUnavailable
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.http.Do(req)
	if err != nil {
		return "", ErrUnavailable
	}
	defer res.Body.Close()
	if res.StatusCode != 201 {
		return "", ErrUnavailable
	}
	t, err := decodeToken(res.Body)
	value := res.Header.Get("X-Subject-Token")
	if err != nil || !validToken(value) || !t.ExpiresAt.After(time.Now().Add(time.Minute)) {
		return "", ErrUnavailable
	}
	c.service = value
	c.serviceExpires = t.ExpiresAt
	return value, nil
}

// Validate authenticates a token; scope and role authorization are separate.
func (c *Client) Validate(ctx context.Context, subject string) (Identity, error) {
	if !validToken(subject) {
		return Identity{}, ErrUnauthorized
	}
	if err := ctx.Err(); err != nil {
		return Identity{}, err
	}
	key := sha256.Sum256([]byte(subject))
	now := time.Now()
	c.mu.Lock()
	cached, ok := c.cache[key]
	c.mu.Unlock()
	if ok && now.Before(cached.until) {
		return cached.identity.clone(), nil
	}
	serviceMode := c.cfg.ApplicationCredentialID != ""
	for attempt := 0; attempt < 2; attempt++ {
		auth := subject
		if serviceMode {
			var err error
			auth, err = c.serviceToken(ctx)
			if err != nil {
				return Identity{}, err
			}
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.URL+"/auth/tokens", nil)
		if err != nil {
			return Identity{}, ErrUnavailable
		}
		req.Header.Set("X-Auth-Token", auth)
		req.Header.Set("X-Subject-Token", subject)
		res, err := c.http.Do(req)
		if err != nil {
			return Identity{}, ErrUnavailable
		}
		if res.StatusCode != 200 {
			res.Body.Close()
			if res.StatusCode == 401 && serviceMode {
				c.serviceMu.Lock()
				if c.service == auth {
					c.service = ""
				}
				c.serviceMu.Unlock()
				if attempt == 0 {
					continue
				}
				return Identity{}, ErrUnavailable
			}
			if res.StatusCode == 404 || res.StatusCode == 401 {
				return Identity{}, ErrUnauthorized
			}
			return Identity{}, ErrUnavailable
		}
		t, err := decodeToken(res.Body)
		res.Body.Close()
		if err != nil {
			return Identity{}, err
		}
		if t.User.ID == "" || !t.ExpiresAt.After(time.Now()) {
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
		if c.cfg.CacheTTL > 0 {
			until := now.Add(c.cfg.CacheTTL)
			if i.ExpiresAt.Before(until) {
				until = i.ExpiresAt
			}
			c.mu.Lock()
			if len(c.cache) >= c.cfg.MaxCacheEntries {
				for k, v := range c.cache {
					if !time.Now().Before(v.until) {
						delete(c.cache, k)
					}
				}
				if len(c.cache) >= c.cfg.MaxCacheEntries {
					for k := range c.cache {
						delete(c.cache, k)
						break
					}
				}
			}
			c.cache[key] = entry{i.clone(), until}
			c.mu.Unlock()
		}
		return i, nil
	}
	return Identity{}, ErrUnavailable
}
