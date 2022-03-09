// Copyright 2018 Google LLC
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

package jwt

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
	"github.com/google/go-cmp/cmp"
)

func TestMinAllowedRefresh(t *testing.T) {

	for _, test := range []struct {
		desc string
		dur1 time.Duration
		dur2 time.Duration
		want time.Duration
	}{
		{"first", time.Hour, time.Hour, time.Hour},
		{"second", 2 * time.Hour, time.Hour, time.Hour},
		{"force min", time.Minute, time.Minute, minAllowedRefreshInterval},
		{"negative", -time.Hour, -time.Hour, minAllowedRefreshInterval},
	} {
		t.Run(test.desc, func(t *testing.T) {
			got := minAllowedRefresh(test.dur1, test.dur2)
			if diff := cmp.Diff(test.want, got); diff != "" {
				t.Errorf("for: %v (-want +got):\n%s", test.want, diff)
			}
		})
	}
}

func TestJwksRefresh(t *testing.T) {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !called {
			called = true
			authtest.JWKSHandlerFunc(privateKey, t)(w, r)
		} else {
			authtest.DeniedHandler()(w, r)
		}
	}))

	p := Provider{JWKSURL: ts.URL}
	m := jwksManager{
		client:    http.DefaultClient,
		providers: []Provider{p},
	}
	// bypass minRefresh by bypassing Start()
	rates := map[string]time.Duration{
		p.JWKSURL: time.Millisecond,
	}
	ctx, cancelFunc := context.WithCancel(context.Background())
	m.startRefreshing(ctx, rates)
	defer cancelFunc()

	jwks, err := m.Get(ctx, p.JWKSURL)
	if jwks == nil || err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	time.Sleep(5 * time.Millisecond)
	jwks, err = m.Get(ctx, p.JWKSURL)
	if jwks != nil || err == nil {
		t.Fatalf("expected error on second poll")
	}
}
