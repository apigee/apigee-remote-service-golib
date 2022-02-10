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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/jwx/jwk"
)

func TestJWTCaching(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := generateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	good := sendGoodJWKsHandler(privateKey, t)
	called := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !called {
			called = true
			good(w, r)
		} else {
			send401Handler(w, r)
		}
	}))
	defer ts.Close()

	// Refresh time is too small and will be overriden.
	provider := Provider{JWKSURL: ts.URL, Refresh: 10 * time.Second}
	jwtVerifier := NewVerifier(VerifierOptions{
		Providers: []Provider{provider},
	})
	jwtVerifier.Start()
	defer jwtVerifier.Stop()

	for i := 0; i < 5; i++ {
		// Do a first request and confirm that things look good.
		_, err = jwtVerifier.Parse(jwt, provider)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnsureProvidersLoaded(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	fail := true
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			send401Handler(w, r)
			return
		}
		sendGoodJWKsHandler(privateKey, t)(w, r)
	}))
	defer ts.Close()

	provider := Provider{JWKSURL: ts.URL}
	jwtVerifier := NewVerifier(VerifierOptions{
		// Duplicates will be ignored when added.
		Providers: []Provider{provider, provider},
	})
	jwtVerifier.Start()
	time.Sleep(time.Second)
	defer jwtVerifier.Stop()

	jwt, err := generateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}

	err = jwtVerifier.EnsureProvidersLoaded(context.Background())
	if err == nil {
		t.Errorf("no JWKs available, expected error")
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("no JWKs available, expected error")
	}

	fail = false
	err = jwtVerifier.EnsureProvidersLoaded(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("good JWT and JWKs should not get error: %v", err)
	}
}

func TestGoodAndBadJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(sendGoodJWKsHandler(privateKey, t))
	defer ts.Close()

	provider := Provider{JWKSURL: ts.URL}
	jwtVerifier := NewVerifier(VerifierOptions{
		Providers: []Provider{provider},
	})
	jwtVerifier.Start()
	defer jwtVerifier.Stop()

	// A good JWT request
	var jwt string
	jwt, err = generateSignedJWT(privateKey, 0, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("good JWT should not get error: %v", err)
	}

	// expired within acceptible skew
	jwt, err = generateSignedJWT(privateKey, 0, 0, -time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("expired JWT within acceptible skew should not get error, got %v", err)
	}

	// expired
	jwt, err = generateSignedJWT(privateKey, 0, 0, -time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("expired JWT should get error")
	}

	// expired (from cache)
	knownBad, ok := jwtVerifier.(*verifier).knownBad.Get(jwt)
	if !ok {
		t.Errorf("known bad should be cached")
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != knownBad {
		t.Errorf("should return known bad")
	}

	// future nbf within acceptable skew
	jwt, err = generateSignedJWT(privateKey, 0, time.Second, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("future JWT within acceptible skew should not get error, got: %v", err)
	}

	// future nbf
	jwt, err = generateSignedJWT(privateKey, 0, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("future JWT should get error")
	}

	// future iss within acceptable skew
	jwt, err = generateSignedJWT(privateKey, time.Second, 0, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("future JWT within acceptible skew should not get error, got: %v", err)
	}

	// future iss
	jwt, err = generateSignedJWT(privateKey, time.Hour, 0, time.Minute)
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
	jwt, err = generateSignedJWT(wrongKey, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("JWT with wrong key should get error")
	}
}

// iat, nbf, exp are deltas from time.Now() (may be zero)
func generateSignedJWT(privateKey *rsa.PrivateKey, iat, nbf, exp time.Duration) (string, error) {
	return makeJWTToken(iat, nbf, exp).SignedString(privateKey)
}

// iat, nbf, exp are deltas from time.Now() (may be zero)
func makeJWTToken(iat, nbf, exp time.Duration) *jwt.Token {
	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Header["kid"] = "1"
	now := time.Now()
	t.Claims = &ClaimsWithApigeeClaims{
		StandardClaims: &jwt.StandardClaims{
			// http://tools.ietf.org/html/draft-ietf-oauth-json-web-token-20#section-4.1.4
			IssuedAt:  now.Add(iat).Unix(),
			NotBefore: now.Add(nbf).Unix(),
			ExpiresAt: now.Add(exp).Unix(),
		},
		ApigeeClaims: ApigeeClaims{
			AccessToken:    "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G",
			ClientID:       "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H",
			AppName:        "61cd4d83-06b5-4270-a9ee-cf9255ef45c3",
			Scope:          "scope",
			APIProductList: []string{"TestProduct"},
		},
	}
	return t
}

func sendGoodJWKsHandler(privateKey *rsa.PrivateKey, t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key, err := jwk.New(&privateKey.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := key.Set("kid", "1"); err != nil {
			t.Fatal(err)
		}
		if err := key.Set("alg", jwt.SigningMethodRS256.Alg()); err != nil {
			t.Fatal(err)
		}

		type JWKS struct {
			Keys []jwk.Key `json:"keys"`
		}

		jwks := JWKS{
			Keys: []jwk.Key{
				key,
			},
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Fatal(err)
		}
	}
}

func send401Handler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(401)
}
