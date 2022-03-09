// Copyright 2022 Google LLC
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

package authtest

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// Generate a signed JWT
func GenerateSignedJWT(privateKey *rsa.PrivateKey, iat, nbf, exp time.Duration) (string, error) {
	rsaSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.RS256, Key: privateKey},
		(&jose.SignerOptions{}).
			WithType("JWT").
			WithHeader("kid", "1"))
	if err != nil {
		panic("failed to create signer:" + err.Error())
	}

	now := time.Now()
	claims := jwt.Claims{}
	if iat != 0 {
		claims.IssuedAt = jwt.NewNumericDate(now.Add(iat))
	}
	if nbf != 0 {
		claims.NotBefore = jwt.NewNumericDate(now.Add(nbf))
	}
	if exp != 0 {
		claims.Expiry = jwt.NewNumericDate(now.Add(exp))
	}
	jwt, err := jwt.Signed(rsaSigner).Claims(claims).
		Claims(map[string]interface{}{
			"access_token":     "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G",
			"client_id":        "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H",
			"application_name": "61cd4d83-06b5-4270-a9ee-cf9255ef45c3",
			"scope":            "scope",
			"api_product_list": []string{"TestProduct"},
		}).
		CompactSerialize()
	return jwt, err
}

// JWKSHandlerFunc creates a HandlerFunc to deliver a JWKS for the private key
func JWKSHandlerFunc(privateKey *rsa.PrivateKey, t *testing.T) http.HandlerFunc {
	jwk := jose.JSONWebKey{
		KeyID:     "1",
		Algorithm: "RSA",
		Key:       &privateKey.PublicKey,
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}

	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwks); err != nil {
			t.Fatal(err)
		}
	}
}

const (
	certsPath = "/certs"
)

// APIKeyHandlerFunc creates an HTTP handler that handles API Key requests properly.
func APIKeyHandlerFunc(apiKey string, t *testing.T) http.HandlerFunc {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := GenerateSignedJWT(privateKey, 0, 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	jwksH := JWKSHandlerFunc(privateKey, t)

	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, certsPath) {
			jwksH(w, r)
			return
		}

		// api key
		var req APIKeyRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()

		if apiKey != req.APIKey {
			t.Fatalf("expected: %v, got: %v", apiKey, req)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(APIKeyResponse{Token: jwt}); err != nil {
			t.Fatal(err)
		}
	}
}

// GoodOnceAPIKeyHandler creates an HTTP handler that handles API Key requests.
// On the first iteration, use a normal HTTP handler that will return good
// results for the various HTTP requests that go out. After the first run,
// replace with bad responses to ensure that we do not go out and fetch any
// new pages (things are cached).
func GoodOnceAPIKeyHandler(goodAPIKey string, t *testing.T) http.HandlerFunc {
	called := false
	good := APIKeyHandlerFunc(goodAPIKey, t)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, certsPath) {
			// We don't care about jwks expiry here.
			good(w, r)
			return
		}
		if !called {
			called = true
			good(w, r)
		} else {
			DeniedHandler()(w, r)
		}
	})
}

// DeniedHandler gives a handler that just gives a 401 for all requests.
func DeniedHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}
}

// StringHandler gives a handler that sends a string w/ a 200 status
func StringHandler(v string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(v))
	}
}

// APIKeyRequest is the request to Apigee's verifyAPIKey API
type APIKeyRequest struct {
	APIKey string `json:"apiKey"`
}

// APIKeyResponse is the response from Apigee's verifyAPIKey API
type APIKeyResponse struct {
	Token string `json:"token"`
}
