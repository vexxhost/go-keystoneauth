// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheExpiryAndIsolation(t *testing.T) {
	now := time.Now()
	c := newIdentityCache(time.Minute, 2)
	i := Identity{UserID: "u", Roles: []string{"member"}, ExpiresAt: now.Add(30 * time.Second)}
	c.put("token", i, now)
	i.Roles[0] = "admin"
	got, ok := c.get("token", now.Add(10*time.Second))
	if !ok || got.Roles[0] != "member" {
		t.Fatal(got, ok)
	}
	got.Roles[0] = "admin"
	got, ok = c.get("token", now.Add(20*time.Second))
	if !ok || got.Roles[0] != "member" {
		t.Fatal(got, ok)
	}
	if _, ok := c.get("token", now.Add(30*time.Second)); ok {
		t.Fatal("served token at expiry")
	}
	i.ExpiresAt = now.Add(time.Hour)
	c.put("long", i, now)
	if _, ok := c.get("long", now.Add(59*time.Second)); !ok {
		t.Fatal("early expiry")
	}
	if _, ok := c.get("long", now.Add(time.Minute)); ok {
		t.Fatal("hit extended TTL")
	}
}

func TestCacheLRUEviction(t *testing.T) {
	now := time.Now()
	c := newIdentityCache(time.Minute, 2)
	i := Identity{ExpiresAt: now.Add(time.Hour)}
	c.put("a", i, now)
	c.put("b", i, now)
	c.get("a", now)
	c.put("c", i, now)
	if _, ok := c.get("b", now); ok {
		t.Fatal("least-recently used token retained")
	}
	for _, token := range []string{"a", "c"} {
		if _, ok := c.get(token, now); !ok {
			t.Fatalf("lost %s", token)
		}
	}
	if c.entries.Len() != 2 {
		t.Fatal(c.entries.Len())
	}
}

func TestCacheRevalidatesAndNeverCachesFailures(t *testing.T) {
	var calls atomic.Int32
	var reject atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if reject.Load() {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		response(w, time.Now().Add(time.Hour))
	}))
	defer s.Close()
	c, err := New(Config{URL: s.URL, AllowHTTP: true, CacheTTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	validate := func(wantOK bool) {
		t.Helper()
		_, err := c.Validate(context.Background(), "subject")
		if (err == nil) != wantOK {
			t.Fatalf("err=%v", err)
		}
	}
	validate(true)
	validate(true)
	if calls.Load() != 1 {
		t.Fatal("expected cache hit", calls.Load())
	}
	key := sha256.Sum256([]byte("subject"))
	entry, ok := c.cache.entries.Peek(key)
	if !ok {
		t.Fatal("test token missing")
	}
	entry.until = time.Now().Add(-time.Second)
	c.cache.entries.Add(key, entry)
	reject.Store(true)
	validate(false)
	validate(false)
	if calls.Load() != 3 {
		t.Fatal("expired entries or failures were cached", calls.Load())
	}
	reject.Store(false)
	validate(true)
	validate(true)
	if calls.Load() != 4 {
		t.Fatal("successful revalidation not cached", calls.Load())
	}
}

func TestCacheDisabled(t *testing.T) {
	c, err := New(Config{URL: "https://keystone.example"})
	if err != nil {
		t.Fatal(err)
	}
	if c.cache != nil {
		t.Fatal("allocated disabled cache")
	}
}

func BenchmarkCacheChurn(b *testing.B) {
	for _, capacity := range []int{100, 1000, 10000} {
		b.Run(fmt.Sprint(capacity), func(b *testing.B) {
			now := time.Now()
			c := newIdentityCache(time.Hour, capacity)
			i := Identity{UserID: "u", Roles: []string{"member"}, ExpiresAt: now.Add(time.Hour)}
			for n := 0; n < capacity; n++ {
				c.put(fmt.Sprint("fill", n), i, now)
			}
			b.ResetTimer()
			for n := 0; n < b.N; n++ {
				c.put(fmt.Sprint("new", n), i, now)
			}
		})
	}
}
