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
	"crypto/rsa"
	"encoding/json"
	"net/http"
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
