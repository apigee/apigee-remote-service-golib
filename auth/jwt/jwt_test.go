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

	called := make(map[string]bool)
	keyForPath := map[string]http.HandlerFunc{
		"/hasit":         authtest.JWKSHandlerFunc(privateKey, t),
		"/doesnothaveit": authtest.JWKSHandlerFunc(wrongPrivateKey, t),
		"/badformat":     authtest.StringHandler("bad"),
		"/denied":        authtest.DeniedHandler(),
	}

	// fails after first attempt - thus, if caching fails, the test below fails
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := keyForPath[r.URL.Path]; ok && !called[r.URL.Path] {
			called[r.URL.Path] = true
			handler(w, r)
		} else {
			authtest.DeniedHandler()(w, r)
		}
	}))
	defer ts.Close()

	goodProvider := Provider{JWKSURL: ts.URL + "/hasit", Refresh: -time.Second}
	goodProvider2 := Provider{JWKSURL: ts.URL + "/hasit"}
	wrongProvider := Provider{JWKSURL: ts.URL + "/doesnothaveit"}
	badUrlProvider := Provider{JWKSURL: "badurl"}
	badFormatProvider := Provider{JWKSURL: ts.URL + "/badformat"}
	deniedProvider := Provider{JWKSURL: ts.URL + "/denied"}
	jwtVerifier := NewVerifier(VerifierOptions{
		Client:    http.DefaultClient,
		Providers: []Provider{goodProvider, goodProvider2, wrongProvider, badUrlProvider, badFormatProvider, deniedProvider},
	})
	jwtVerifier.Start()
	time.Sleep(10 * time.Millisecond)
	defer jwtVerifier.Stop()

	for _, test := range []struct {
		desc           string
		provider       Provider
		wantParseError bool
		wantJwksError  bool
	}{
		{"good provider", goodProvider, false, false},
		{"wrong provider", wrongProvider, true, false},
		{"bad provider url", badUrlProvider, true, true},
		{"bad jwks format", badFormatProvider, true, true},
		{"denied provider", deniedProvider, true, true},
	} {
		t.Run("parse "+test.desc, func(t *testing.T) {

			// check first run & cached run
			for i := 0; i < 2; i++ {
				_, err = jwtVerifier.Parse(jwt, test.provider)
				if test.wantParseError && err == nil {
					t.Error("wanted error, got none")
				}
				if !test.wantParseError && err != nil {
					t.Errorf("wanted no error, got: %v", err)
				}
			}
		})

		t.Run("caches "+test.desc, func(t *testing.T) {

			cacheKey := fmt.Sprintf("%s-%s", test.provider.JWKSURL, jwt)
			v, ok := jwtVerifier.(*verifier).cache.Get(cacheKey)
			if test.wantParseError && ok {
				t.Errorf("want nothing in verifier cache, got: %v", v)
			}
			if !test.wantParseError && !ok {
				t.Error("want in verifier cache, got none")
			}

			v, ok = jwtVerifier.(*verifier).knownBad.Get(cacheKey)
			if test.wantParseError && !ok {
				t.Error("want in verifier knownbad, got none")
			}
			if !test.wantParseError && ok {
				t.Errorf("want nothing in verifier knownbad, got: %v", v)
			}

			// ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			// defer cancel()
			// jwks, err := jwtVerifier.(*verifier).jwksManager.Get(ctx, test.provider.JWKSURL)
			// cv, _ := jwtVerifier.(*verifier).jwksManager.cache.Load(test.provider.JWKSURL)
			// switch cv := cv.(type) {
			// case *jose.JSONWebKeySet:
			// 	if cv != jwks {
			// 		t.Errorf("mismatched values, want: %v, got: %v", jwks, cv)
			// 	}
			// 	if test.wantJwksError {
			// 		t.Errorf("want error in jwks cache, got: %v", cv)
			// 	}
			// case error:
			// 	if cv != err {
			// 		t.Errorf("mismatched values, want: %v, got: %v", err, cv)
			// 	}
			// 	if !test.wantJwksError {
			// 		t.Errorf("want jwks in jwks cache, got: %v", cv)
			// 	}
			// }
		})
	}
}

func TestGoodAndBadJWT(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(authtest.JWKSHandlerFunc(privateKey, t))
	defer ts.Close()

	provider := Provider{JWKSURL: ts.URL}
	noJWKSProvider := Provider{}
	jwtVerifier := NewVerifier(VerifierOptions{
		Client:    http.DefaultClient,
		Providers: []Provider{provider, noJWKSProvider},
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

	// no provider JWKS
	jwt, err = authtest.GenerateSignedJWT(wrongKey, 0, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = jwtVerifier.Parse(jwt, noJWKSProvider)
	if err != nil {
		t.Errorf("provider without JWKS should not error, got: %v", err)
	}

	// bad JWT format
	_, err = jwtVerifier.Parse("jwt", noJWKSProvider)
	if err == nil {
		t.Errorf("bad JWT format should get error")
	}
}
