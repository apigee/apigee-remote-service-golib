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
	jwt, err := jwt.Signed(rsaSigner).
		Claims(&jwt.Claims{
			IssuedAt:  jwt.NewNumericDate(now.Add(iat)),
			NotBefore: jwt.NewNumericDate(now.Add(nbf)),
			Expiry:    jwt.NewNumericDate(now.Add(exp)),
		}).
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

func JWKsHandlerFunc(privateKey *rsa.PrivateKey, t *testing.T) http.HandlerFunc {
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

// APIKeyHandlerFunc is an HTTP handler that handles all the requests in a proper fashion.
func APIKeyHandlerFunc(apiKey string, t *testing.T) http.HandlerFunc {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	jwt, err := GenerateSignedJWT(privateKey, 0, 0, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	jwksH := JWKsHandlerFunc(privateKey, t)

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
			badHandler()(w, r)
		}
	})
}

// badHandler gives a handler that just gives a 401 for all requests.
func badHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		// _ = json.NewEncoder(w).Encode(badKeyResponse)
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
