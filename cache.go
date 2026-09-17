// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"crypto/sha256"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
)

type cacheEntry struct {
	identity Identity
	until    time.Time
}

type identityCache struct {
	entries *lru.Cache[[32]byte, cacheEntry]
	ttl     time.Duration
}

func newIdentityCache(ttl time.Duration, capacity int) *identityCache {
	if ttl == 0 {
		return nil
	}
	entries, err := lru.New[[32]byte, cacheEntry](capacity)
	if err != nil {
		// New validates capacity before reaching here.
		panic(err)
	}
	return &identityCache{entries: entries, ttl: ttl}
}

func (c *identityCache) get(subject string, now time.Time) (Identity, bool) {
	if c == nil {
		return Identity{}, false
	}
	entry, ok := c.entries.Get(sha256.Sum256([]byte(subject)))
	if !ok || !now.Before(entry.until) || !now.Before(entry.identity.ExpiresAt) {
		return Identity{}, false
	}
	return entry.identity.clone(), true
}

func (c *identityCache) put(subject string, i Identity, validatedAt time.Time) {
	if c == nil {
		return
	}
	until := validatedAt.Add(c.ttl)
	if i.ExpiresAt.Before(until) {
		until = i.ExpiresAt
	}
	c.entries.Add(sha256.Sum256([]byte(subject)), cacheEntry{i.clone(), until})
}
