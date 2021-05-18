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

package key

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	jwx "github.com/lestrrat-go/jwx/jwt"
)

var (
	badKeyResponse = []byte(`{"fault":{"faultstring":"Invalid ApiKey","detail":{"errorcode":"oauth.v2.InvalidApiKey"}}}`)
)

// goodHandler is an HTTP handler that handles all the requests in a proper fashion.
func goodHandler(apiKey string, t *testing.T) http.HandlerFunc {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

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

	return func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, certsPath) {
			// Handling the JWK verifier
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(jwks); err != nil {
				t.Fatal(err)
			}
			return
		}

		var req APIKeyRequest
		err := json.NewDecoder(r.Body).Decode(&req)
		if err != nil {
			t.Fatal(err)
		}
		defer r.Body.Close()

		if apiKey != req.APIKey {
			t.Fatalf("expected: %v, got: %v", apiKey, req)
		}

		jwt, err := generateAPIKeyJWT(privateKey)
		if err != nil {
			t.Fatal(err)
		}

		jwtResponse := APIKeyResponse{Token: jwt}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(jwtResponse); err != nil {
			t.Fatal(err)
		}
	}
}

func generateAPIKeyJWT(privateKey *rsa.PrivateKey) (string, error) {

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

	token := jwx.New()
	_ = token.Set(jwx.AudienceKey, "remote-service-client")
	_ = token.Set(jwx.JwtIDKey, "29e2320b-787c-4625-8599-acc5e05c68d0")
	_ = token.Set(jwx.IssuerKey, "https://theganyo1-eval-test.apigee.net/remote-service/token")
	_ = token.Set(jwx.NotBeforeKey, time.Now().Add(-10*time.Minute).Unix())
	_ = token.Set(jwx.IssuedAtKey, time.Now().Unix())
	_ = token.Set(jwx.ExpirationKey, (time.Now().Add(50 * time.Millisecond)).Unix())
	_ = token.Set("access_token", "8E7Az3ZgPHKrgzcQA54qAzXT3Z1G")
	_ = token.Set("client_id", "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
	_ = token.Set("application_name", "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
	_ = token.Set("api_product_list", []string{"TestProduct"})
	payload, err := jwx.Sign(token, jwa.RS256, key)

	return string(payload), err
}

// badHandler gives a handler that just gives a 401 for all requests.
func badHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(401)
		_ = json.NewEncoder(w).Encode(badKeyResponse)
	}
}

// note: call Stop() on returned jwt.Verifier
func testVerifier(t *testing.T, baseURL string, opts VerifierOpts) (Verifier, jwt.Verifier) {
	jwtVerifier := jwt.NewVerifier(jwt.VerifierOptions{})
	jwtVerifier.Start()
	opts.Client = http.DefaultClient
	opts.JwtVerifier = jwtVerifier
	jwks, _ := url.Parse(baseURL)
	jwks.Path = path.Join(jwks.Path, certsPath)
	return NewVerifier(opts), jwtVerifier
}

func TestVerifyAPIKeyValid(t *testing.T) {
	apiKey := "testID"

	ts := httptest.NewServer(goodHandler(apiKey, t))
	defer ts.Close()

	v, j := testVerifier(t, ts.URL, VerifierOpts{})
	defer j.Stop()

	ctx := authtest.NewContext(ts.URL)

	claims, err := v.Verify(ctx, apiKey)
	if err != nil {
		t.Fatal(err)
	}

	if claims["client_id"].(string) != "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H" {
		t.Errorf("bad client_id, got: %s, want: %s", claims["client_id"].(string), "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
	}

	if claims["application_name"].(string) != "61cd4d83-06b5-4270-a9ee-cf9255ef45c3" {
		t.Errorf("bad client_id, got: %s, want: %s", claims["application_name"].(string), "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
	}
}

func TestVerifyAPIKeyCacheWithClear(t *testing.T) {
	apiKey := "testID"

	// On the first iteration, use a normal HTTP handler that will return good
	// results for the various HTTP requests that go out. After the first run,
	// replace with bad responses to ensure that we do not go out and fetch any
	// new pages (things are cached).
	called := map[string]bool{}
	good := goodHandler(apiKey, t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !called[r.URL.Path] {
			called[r.URL.Path] = true
			good(w, r)
		} else {
			badHandler()(w, r)
		}
	}))
	defer ts.Close()

	v, j := testVerifier(t, ts.URL, VerifierOpts{})
	defer j.Stop()

	ctx := authtest.NewContext(ts.URL)

	for i := 0; i < 5; i++ {
		claims, err := v.Verify(ctx, apiKey)
		if err != nil {
			t.Fatal(err)
		}

		if claims["client_id"].(string) != "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H" {
			t.Errorf("bad client_id, got: %s, want: %s", claims["client_id"].(string), "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
		}

		if claims["application_name"].(string) != "61cd4d83-06b5-4270-a9ee-cf9255ef45c3" {
			t.Errorf("bad client_id, got: %s, want: %s", claims["application_name"].(string), "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
		}
	}

	// Clear the cache.
	v.(*verifierImpl).cache.RemoveAll()

	if _, err := v.Verify(ctx, apiKey); err == nil {
		t.Errorf("expected error result on cleared cache")
	}
}

func TestVerifyAPIKeyCacheWithExpiry(t *testing.T) {
	apiKey := "testID"

	// On the first iteration, use a normal HTTP handler that will return good
	// results for the various HTTP requests that go out. After the first run,
	// replace with bad responses to ensure that we do not go out and fetch any
	// new pages (things are cached).
	called := false
	good := goodHandler(apiKey, t)
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
	}))
	defer ts.Close()

	v, j := testVerifier(t, ts.URL, VerifierOpts{
		CacheTTL:              100 * time.Millisecond,
		CacheEvictionInterval: 100 * time.Millisecond,
		Client:                http.DefaultClient,
	})
	defer j.Stop()

	ctx := authtest.NewContext(ts.URL)

	for i := 0; i < 5; i++ {
		t.Logf("run %d", i)
		claims, err := v.Verify(ctx, apiKey)
		if err != nil {
			t.Fatal(err)
		}

		if claims["client_id"].(string) != "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H" {
			t.Errorf("bad client_id, got: %s, want: %s", claims["client_id"].(string), "yBQ5eXZA8rSoipYEi1Rmn0Z8RKtkGI4H")
		}

		if claims["application_name"].(string) != "61cd4d83-06b5-4270-a9ee-cf9255ef45c3" {
			t.Errorf("bad client_id, got: %s, want: %s", claims["application_name"].(string), "61cd4d83-06b5-4270-a9ee-cf9255ef45c3")
		}
	}

	// Wait until the key is expired. This should give us an error since we are
	// now going to make an HTTP request that will fail.
	time.Sleep(200 * time.Millisecond)

	if _, err := v.Verify(ctx, apiKey); err == nil {
		t.Errorf("expected error result on cleared cache")
	}
}

func TestVerifyAPIKeyFail(t *testing.T) {
	ts := httptest.NewServer(badHandler())
	defer ts.Close()

	v, j := testVerifier(t, ts.URL, VerifierOpts{})
	defer j.Stop()

	ctx := authtest.NewContext(ts.URL)
	success, err := v.Verify(ctx, "badKey")

	if success != nil {
		t.Errorf("success should be nil, is: %v", success)
	}

	if err == nil {
		t.Errorf("error should not be nil")
	} else if err.Error() != ErrBadKeyAuth.Error() {
		t.Errorf("got error: '%s', expected: '%s'", err.Error(), ErrBadKeyAuth.Error())
	}
}

func TestVerifyAPIKeyError(t *testing.T) {
	v, j := testVerifier(t, "", VerifierOpts{})
	defer j.Stop()

	ctx := authtest.NewContext("")
	success, err := v.Verify(ctx, "badKey")

	if err == nil {
		t.Errorf("error should not be nil")
	}

	if success != nil {
		t.Errorf("success should be nil, is: %v", success)
	}
}

func TestVerifyAPIKeyCallFail(t *testing.T) {
	v, j := testVerifier(t, "", VerifierOpts{})
	defer j.Stop()

	ctx := authtest.NewContext("http://badhost/badpath")
	success, err := v.Verify(ctx, "badKey")

	if success != nil {
		t.Errorf("success should be nil, is: %v", success)
	}

	if _, ok := err.(*url.Error); !ok {
		t.Errorf("error should be a *url.Error")
	}
}
