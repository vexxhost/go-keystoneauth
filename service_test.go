// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// waitContext signals that a caller has reached the refresh completion select.
// This avoids sleeps or scheduler assumptions when arranging concurrent waiters.
type waitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *waitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func waitFor(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test synchronization")
	}
}

func serviceClient(t *testing.T, server *httptest.Server) *Client {
	t.Helper()
	c, err := New(Config{URL: server.URL, AllowHTTP: true, ApplicationCredentialID: "id", ApplicationCredentialSecret: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRefreshSharedOutcome(t *testing.T) {
	for _, status := range []int{http.StatusCreated, http.StatusServiceUnavailable} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			entered, release := make(chan struct{}), make(chan struct{})
			var posts atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if posts.Add(1) == 1 {
					close(entered)
				}
				<-release
				w.Header().Set("X-Subject-Token", "service")
				w.WriteHeader(status)
				if status == http.StatusCreated {
					response(w, time.Now().Add(time.Hour))
				}
			}))
			defer s.Close()
			var releaseOnce sync.Once
			defer releaseOnce.Do(func() { close(release) })
			c := serviceClient(t, s)
			const count = 12
			results := make(chan error, count)
			start := func() {
				ctx := &waitContext{Context: context.Background(), waiting: make(chan struct{})}
				go func() { _, err := c.serviceToken(ctx); results <- err }()
				waitFor(t, ctx.waiting)
			}
			start()
			waitFor(t, entered)
			for n := 1; n < count; n++ {
				start()
			}
			releaseOnce.Do(func() { close(release) })
			for n := 0; n < count; n++ {
				select {
				case err := <-results:
					if status == http.StatusCreated && err != nil {
						t.Fatal(err)
					}
					if status != http.StatusCreated && !errors.Is(err, ErrUnavailable) {
						t.Fatal(err)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("waiter never completed")
				}
			}
			if posts.Load() != 1 {
				t.Fatalf("refresh was not shared: %d requests", posts.Load())
			}
			// A successful refresh is reused; a failed refresh may be retried by a later call.
			_, err := c.serviceToken(context.Background())
			if status == http.StatusCreated {
				if err != nil || posts.Load() != 1 {
					t.Fatal("service token not reused", err, posts.Load())
				}
			} else if !errors.Is(err, ErrUnavailable) || posts.Load() != 2 {
				t.Fatal("failed refresh could not be retried", err, posts.Load())
			}
		})
	}
}

func TestRefreshCallerCancellationDoesNotCancelSharedWork(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	var posts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if posts.Add(1) == 1 {
			close(entered)
		}
		<-release
		w.Header().Set("X-Subject-Token", "service")
		w.WriteHeader(http.StatusCreated)
		response(w, time.Now().Add(time.Hour))
	}))
	defer s.Close()
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	c := serviceClient(t, s)
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	initiator := &waitContext{Context: parent, waiting: make(chan struct{})}
	first := make(chan error, 1)
	go func() { _, err := c.serviceToken(initiator); first <- err }()
	waitFor(t, initiator.waiting)
	waitFor(t, entered)
	follower := &waitContext{Context: context.Background(), waiting: make(chan struct{})}
	second := make(chan error, 1)
	go func() { _, err := c.serviceToken(follower); second <- err }()
	waitFor(t, follower.waiting)
	// A separately canceled waiter must also leave while refresh is still blocked.
	waiterParent, cancelWaiter := context.WithCancel(context.Background())
	defer cancelWaiter()
	waiter := &waitContext{Context: waiterParent, waiting: make(chan struct{})}
	third := make(chan error, 1)
	go func() { _, err := c.serviceToken(waiter); third <- err }()
	waitFor(t, waiter.waiting)
	cancel()
	cancelWaiter()
	for _, result := range []chan error{first, third} {
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("canceled caller remained blocked")
		}
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case err := <-second:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("shared refresh did not complete")
	}
	if posts.Load() != 1 {
		t.Fatal(posts.Load())
	}
}

func TestRefreshBoundedLifetime(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(io.Discard, r.Body); <-r.Context().Done() }))
	defer s.Close()
	c := serviceClient(t, s)
	c.http.Timeout = 30 * time.Millisecond
	_, err := c.serviceToken(context.Background())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected refresh deadline: %v", err)
	}
}

func TestServiceInvalidationUsesGeneration(t *testing.T) {
	c, err := New(Config{URL: "https://keystone.example"})
	if err != nil {
		t.Fatal(err)
	}
	old := &serviceCredential{value: "same", expires: time.Now().Add(time.Hour)}
	fresh := &serviceCredential{value: "same", expires: time.Now().Add(time.Hour)}
	c.service = fresh
	c.invalidateService(old)
	if c.service != fresh {
		t.Fatal("stale 401 cleared a newer generation")
	}
	c.invalidateService(fresh)
	if c.service != nil {
		t.Fatal("current service token not cleared")
	}
}

func TestServiceRefreshesBeforeExpiry(t *testing.T) {
	var posts atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		w.Header().Set("X-Subject-Token", "fresh")
		w.WriteHeader(http.StatusCreated)
		response(w, time.Now().Add(time.Hour))
	}))
	defer s.Close()
	c := serviceClient(t, s)
	c.service = &serviceCredential{value: "old", expires: time.Now().Add(30 * time.Second)}
	got, err := c.serviceToken(context.Background())
	if err != nil || got.value != "fresh" || posts.Load() != 1 {
		t.Fatal(got, err, posts.Load())
	}
}
