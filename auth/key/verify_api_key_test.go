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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
)

var (
	badKeyResponse = []byte(`{"fault":{"faultstring":"Invalid ApiKey","detail":{"errorcode":"oauth.v2.InvalidApiKey"}}}`)
)

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

	ts := httptest.NewServer(authtest.APIKeyHandlerFunc(apiKey, t))
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

	good := authtest.GoodOnceAPIKeyHandler(apiKey, t)
	ts := httptest.NewServer(good)
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
	ts := httptest.NewServer(authtest.GoodOnceAPIKeyHandler(apiKey, t))
	defer ts.Close()

	v, j := testVerifier(t, ts.URL, VerifierOpts{
		CacheTTL:              100 * time.Millisecond,
		CacheEvictionInterval: 100 * time.Millisecond,
		Client:                http.DefaultClient,
	})
	now := time.Now()
	veriferNow := func() time.Time {
		return now
	}
	v.(*verifierImpl).now = veriferNow

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

	// expire the key
	now = time.Now().Add(time.Minute)

	// will be cached but expired
	if _, err := v.Verify(ctx, apiKey); err != nil {
		t.Errorf("expected no error, got %s", err)
	}

	// allow fetch to run
	time.Sleep(100 * time.Millisecond)

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
