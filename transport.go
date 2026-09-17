// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package keystoneauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// BackendError describes a sanitized Keystone failure. It never contains credentials,
// request URLs, response bodies, or transport error messages. It matches ErrUnavailable.
type BackendError struct {
	Operation  string // "authenticate" or "validate"
	Reason     string // "request", "transport", "body", "size", "json", "claims", or "status"
	StatusCode int    // Zero when no HTTP status is available.
}

func (e *BackendError) Error() string {
	return fmt.Sprintf("keystoneauth: %s failed (%s, status %d)", e.Operation, e.Reason, e.StatusCode)
}

func (e *BackendError) Unwrap() error { return ErrUnavailable }

func backendError(operation, reason string, status int) error {
	return &BackendError{operation, reason, status}
}

func decodeToken(r io.Reader, operation string) (token, error) {
	var body struct {
		Token token `json:"token"`
	}
	data, err := io.ReadAll(io.LimitReader(r, (1<<20)+1))
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return token{}, context.Canceled
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return token{}, context.DeadlineExceeded
		}
		return token{}, backendError(operation, "body", 0)
	}
	if len(data) > 1<<20 {
		return token{}, backendError(operation, "size", 0)
	}
	if json.Unmarshal(data, &body) != nil {
		return token{}, backendError(operation, "json", 0)
	}
	return body.Token, nil
}

func (c *Client) requestToken(req *http.Request, expected int, operation string) (token, http.Header, int, error) {
	res, err := c.http.Do(req)
	if err != nil {
		if req.Context().Err() != nil {
			return token{}, nil, 0, req.Context().Err()
		}
		if errors.Is(err, context.DeadlineExceeded) {
			return token{}, nil, 0, context.DeadlineExceeded
		}
		return token{}, nil, 0, backendError(operation, "transport", 0)
	}
	defer res.Body.Close()
	if res.StatusCode != expected {
		return token{}, res.Header, res.StatusCode, nil
	}
	t, err := decodeToken(res.Body, operation)
	var backend *BackendError
	if errors.As(err, &backend) {
		backend.StatusCode = res.StatusCode
	}
	if req.Context().Err() != nil {
		err = req.Context().Err()
	}
	return t, res.Header, res.StatusCode, err
}
