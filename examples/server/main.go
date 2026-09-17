// Copyright 2026 VEXXHOST, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/vexxhost/go-keystoneauth"
)

func main() {
	c, err := keystoneauth.New(keystoneauth.Config{URL: os.Getenv("KEYSTONE_URL"), ApplicationCredentialID: os.Getenv("OS_APPLICATION_CREDENTIAL_ID"), ApplicationCredentialSecret: os.Getenv("OS_APPLICATION_CREDENTIAL_SECRET")})
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	mux.Handle("GET /whoami", keystoneauth.Middleware(c, keystoneauth.Options{Policy: keystoneauth.ProjectOrSystem})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		i, _ := keystoneauth.FromContext(r.Context())
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(i)
	})))
	s := &http.Server{Addr: ":8080", Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(s.ListenAndServe())
}
