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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
)

func TestJWTCaching(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	wrongPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := authtest.GenerateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	noExpireJwt, err := authtest.GenerateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	called := make(map[string]bool)
	keyForPath := map[string]http.HandlerFunc{
		"/hasit":         authtest.JWKsHandlerFunc(privateKey, t),
		"/doesnothaveit": authtest.JWKsHandlerFunc(wrongPrivateKey, t),
	}

	// fails after first attempt - thus, if caching fails, the test below fails
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := keyForPath[r.URL.Path]; ok && !called[r.URL.Path] {
			called[r.URL.Path] = true
			handler(w, r)
		} else {
			send401Handler(w, r)
		}
	}))
	defer ts.Close()

	// Refresh time is too small and will be overriden.
	hasProvider := Provider{JWKSURL: ts.URL + "/hasit", Refresh: 10 * time.Second}
	missingProvider := Provider{JWKSURL: ts.URL + "/doesnothaveit", Refresh: 10 * time.Second}
	jwtVerifier := NewVerifier(VerifierOptions{
		Client:    http.DefaultClient,
		Providers: []Provider{missingProvider, hasProvider},
	})
	jwtVerifier.Start()
	defer jwtVerifier.Stop()

	// Make sure the missing provider caches its results first.
	_, err = jwtVerifier.Parse(jwt, missingProvider)
	if err == nil {
		t.Errorf("no error found checking %q, expected error", missingProvider.JWKSURL)
	}

	for i := 0; i < 3; i++ {
		_, err = jwtVerifier.Parse(jwt, hasProvider)
		if err != nil {
			t.Fatal(err)
		}
		_, err = jwtVerifier.Parse(noExpireJwt, hasProvider)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Ensure that good results are only cached on the correct provider.
	_, err = jwtVerifier.Parse(jwt, missingProvider)
	if err == nil {
		t.Errorf("no error found checking %q, expected error", missingProvider.JWKSURL)
	}
}

func TestGoodAndBadJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(authtest.JWKsHandlerFunc(privateKey, t))
	defer ts.Close()

	provider := Provider{JWKSURL: ts.URL}
	jwtVerifier := NewVerifier(VerifierOptions{
		Client:    http.DefaultClient,
		Providers: []Provider{provider},
	})
	jwtVerifier.Start()
	defer jwtVerifier.Stop()

	// A good JWT request
	var jwt string
	jwt, err = authtest.GenerateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("good JWT should not get error: %v", err)
	}

	// expired within acceptible skew
	jwt, err = authtest.GenerateSignedJWT(privateKey, 0, 0, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("expired JWT within acceptible skew should not get error, got %v", err)
	}

	// expired
	jwt, err = authtest.GenerateSignedJWT(privateKey, 0, 0, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("expired JWT should get error")
	}

	// expired (from cache)
	cacheKey := fmt.Sprintf("%s-%s", provider.JWKSURL, jwt)
	knownBad, ok := jwtVerifier.(*verifier).knownBad.Get(cacheKey)
	if !ok {
		t.Errorf("known bad should be cached")
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != knownBad {
		t.Errorf("should return known bad")
	}

	// future nbf within acceptable skew
	jwt, err = authtest.GenerateSignedJWT(privateKey, 0, time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("future JWT within acceptible skew should not get error, got: %v", err)
	}

	// future nbf
	jwt, err = authtest.GenerateSignedJWT(privateKey, 0, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("future JWT should get error")
	}

	// future iss within acceptable skew
	jwt, err = authtest.GenerateSignedJWT(privateKey, time.Second, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("future JWT within acceptible skew should not get error, got: %v", err)
	}

	// future iss
	jwt, err = authtest.GenerateSignedJWT(privateKey, time.Hour, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("future JWT should get error")
	}

	// wrong key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err = authtest.GenerateSignedJWT(wrongKey, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("JWT with wrong key should get error")
	}
}

func send401Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)
}
