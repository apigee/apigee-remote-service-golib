// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iamclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	iam "google.golang.org/api/iamcredentials/v1"
)

func TestAccessTokenRefresh(t *testing.T) {
	ctr := 0
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.Error(w, "server bot ready", http.StatusInternalServerError)
			return
		}
		req := &iam.GenerateAccessTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp *iam.GenerateAccessTokenResponse
		if ctr == 0 {
			resp = &iam.GenerateAccessTokenResponse{
				AccessToken: "token-1",
				ExpireTime:  time.Now().Add(time.Second).Format(time.RFC3339),
			}
		} else {
			resp = &iam.GenerateAccessTokenResponse{
				AccessToken: "token-2",
				ExpireTime:  time.Now().Add(time.Hour).Format(time.RFC3339),
			}
		}
		ctr++
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))

	ctxWithCancel, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	ts, err := NewAccessTokenSource(ctxWithCancel, TokenSourceOption{
		Client:          http.DefaultClient,
		Scopes:          []string{"https://www.googleapis.com/auth/cloud-platform"},
		RefreshInterval: time.Hour,
		ServiceAccount:  "foo@bar.iam.gserviceaccount.com",
		Endpoint:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ready = true
	if tk := ts.Token(); tk != "token-1" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-1")
	}

	time.Sleep(100 * time.Millisecond)
	// The token should be refreshed because the previous one expired.
	if tk := ts.Token(); tk != "token-2" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-2")
	}
}

func TestNewAccessTokenSourceError(t *testing.T) {
	tests := []struct {
		desc string
		opt  TokenSourceOption
	}{
		{
			desc: "missing scopes",
			opt: TokenSourceOption{
				ServiceAccount: "foo@bar.iam.gserviceaccount.com",
			},
		},
		{
			desc: "missing service account",
			opt: TokenSourceOption{
				Scopes: []string{"scope-1"},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := NewAccessTokenSource(context.Background(), test.opt)
			if err == nil {
				t.Errorf("NewAccessTokenSource(...) err = nil, wanted error")
			}
		})
	}
}

func TestIdentityTokenRefresh(t *testing.T) {
	ctr := 0
	ready := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !ready {
			http.Error(w, "server not ready", http.StatusInternalServerError)
			return
		}
		req := &iam.GenerateIdTokenRequest{}
		if err := json.NewDecoder(r.Body).Decode(req); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		var resp *iam.GenerateIdTokenResponse
		if ctr == 0 {
			resp = &iam.GenerateIdTokenResponse{
				Token: "token-1",
			}
		} else {
			resp = &iam.GenerateIdTokenResponse{
				Token: "token-2",
			}
		}
		ctr++
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			http.Error(w, "failed to marshal response", http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))

	ctxWithCancel, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	ts, err := NewIdentityTokenSource(ctxWithCancel, TokenSourceOption{
		Client:          http.DefaultClient,
		RefreshInterval: 100 * time.Millisecond,
		Audience:        "aud",
		ServiceAccount:  "foo@bar.iam.gserviceaccount.com",
		Endpoint:        srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ready = true
	if tk := ts.Token(); tk != "token-1" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-1")
	}

	time.Sleep(200 * time.Millisecond)
	// The token should be refreshed because the previous one expired.
	if tk := ts.Token(); tk != "token-2" {
		t.Errorf("ts.Token() returned %q, wanted %q", tk, "token-2")
	}
}

func TestNewIdentityTokenSourceError(t *testing.T) {
	tests := []struct {
		desc string
		opt  TokenSourceOption
	}{
		{
			desc: "missing audience",
			opt: TokenSourceOption{
				ServiceAccount: "foo@bar.iam.gserviceaccount.com",
			},
		},
		{
			desc: "missing service account",
			opt: TokenSourceOption{
				Audience: "aud",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			_, err := NewIdentityTokenSource(context.Background(), test.opt)
			if err == nil {
				t.Errorf("NewAccessTokenSource(...) err = nil, wanted error")
			}
		})
	}
}
