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

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
)

func TestJWTCaching(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err := generateJWT(privateKey)
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

	jwt, err := generateJWT(privateKey)
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
	jwt, err := generateJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("good JWT should not get error: %v", err)
	}

	// expired JWT
	jwt, err = generateExpiredJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("expired JWT should get error")
	}

	// near future JWT
	jwt, err = generateFutureJWT(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err != nil {
		t.Errorf("near future JWT should not get error, got: %s", err)
	}

	// wrong key
	wrongKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwt, err = generateJWT(wrongKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, provider)
	if err == nil {
		t.Errorf("JWT with wrong key should get error")
	}
}

func generateJWT(privateKey *rsa.PrivateKey) (string, error) {

	key, err := jwk.New(privateKey)
	if err != nil {
		return "", err
	}
	if err := key.Set("kid", "1"); err != nil {
		return "", err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return "", err
	}

	token := jwt.New()
	_ = token.Set(jwt.AudienceKey, "remote-service-client")
	_ = token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwt.IssuerKey, "https://theganyo1-eval-test.apigee.net/remote-service/token")
	_ = token.Set(jwt.NotBeforeKey, time.Now().Add(-10*time.Minute).Unix())
	_ = token.Set(jwt.IssuedAtKey, time.Now().Unix())
	_ = token.Set(jwt.ExpirationKey, (time.Now().Add(50 * time.Millisecond)).Unix())
	_ = token.Set("access_token", "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G")
	_ = token.Set("client_id", "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
	_ = token.Set("application_name", "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
	_ = token.Set("scope", "scope1 scope2")
	_ = token.Set("api_product_list", []string{"TestProduct"})
	payload, err := jwt.Sign(token, jwa.RS256, key)

	return string(payload), err
}

func generateExpiredJWT(privateKey *rsa.PrivateKey) (string, error) {

	key, err := jwk.New(privateKey)
	if err != nil {
		return "", err
	}
	if err := key.Set("kid", "1"); err != nil {
		return "", err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return "", err
	}

	token := jwt.New()
	_ = token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwt.IssuerKey, "https://theganyo1-eval-test.apigee.net/remote-service/token")
	_ = token.Set(jwt.NotBeforeKey, (time.Now().Add(-10 * time.Minute)).Unix())
	_ = token.Set(jwt.IssuedAtKey, (time.Now().Add(-10 * time.Minute)).Unix())
	_ = token.Set(jwt.ExpirationKey, (time.Now().Add(-2 * time.Minute)).Unix())
	payload, err := jwt.Sign(token, jwa.RS256, key)

	return string(payload), err
}

func generateFutureJWT(privateKey *rsa.PrivateKey) (string, error) {

	key, err := jwk.New(privateKey)
	if err != nil {
		return "", err
	}
	if err := key.Set("kid", "1"); err != nil {
		return "", err
	}
	if err := key.Set("alg", jwa.RS256.String()); err != nil {
		return "", err
	}

	token := jwt.New()
	_ = token.Set(jwt.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwt.IssuerKey, "https://theganyo1-eval-test.apigee.net/remote-service/token")
	_ = token.Set(jwt.NotBeforeKey, (time.Now().Add(5 * time.Second)).Unix())
	_ = token.Set(jwt.IssuedAtKey, (time.Now().Add(5 * time.Second)).Unix())
	_ = token.Set(jwt.ExpirationKey, (time.Now().Add(2 * time.Second)).Unix())
	payload, err := jwt.Sign(token, jwa.RS256, key)

	return string(payload), err
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
		if err := key.Set("alg", jwa.RS256.String()); err != nil {
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
