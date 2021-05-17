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

package auth

import (
	"net/http"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/key"
	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
)

type testVerifier struct {
	keyErrors map[string]error
}

var testJWTClaims = map[string]interface{}{
	"client_id":        "hi",
	"application_name": "taco",
	"exp":              14.0,
	"api_product_list": []string{"superapp"},
	"scope":            "scope",
}

func (tv *testVerifier) Verify(ctx context.Context, apiKey string) (map[string]interface{}, error) {
	err := tv.keyErrors[apiKey]
	if err != nil {
		return nil, err
	}

	return testJWTClaims, nil
}

func TestNewManager(t *testing.T) {
	log.Log.SetLevel(log.Debug)
	opts := Options{
		Client: &http.Client{},
		Org:    "org",
		JWTProviders: []jwt.Provider{
			{
				JWKSURL: "bad",
			},
		},
	}
	m, err := NewManager(opts)
	if err != nil {
		t.Fatalf("create and start manager: %v", err)
	}
	m.Close()
}

func TestAuthenticate(t *testing.T) {
	goodAPIKey := "good"
	badAPIKey := "bad"
	errAPIKey := "error"
	missingProductListError := "api_product_list claim is required"

	for _, test := range []struct {
		desc           string
		apiKey         string
		apiKeyClaimKey string
		claims         map[string]interface{}
		wantError      string
	}{
		{"with valid JWT", "", "", testJWTClaims, ""},
		{"with invalid JWT", "", "", map[string]interface{}{"exp": "1"}, missingProductListError},
		{"with valid API key", goodAPIKey, "", nil, ""},
		{"with invalid API key", badAPIKey, "", nil, ErrBadAuth.Error()},
		{"with valid claims API key", "", "goodkey", map[string]interface{}{
			"exp":              "1",
			"api_product_list": "[]",
			"goodkey":          goodAPIKey,
		}, ""},
		{"with invalid claims API key", "", "badkey", map[string]interface{}{
			"exp":     "1",
			"somekey": goodAPIKey,
			"badkey":  badAPIKey,
		}, ErrBadAuth.Error()},
		{"with missing claims API key", "", "missingkey", map[string]interface{}{
			"exp": "1",
		}, missingProductListError},
		{"error verifying API key", errAPIKey, "", nil, ErrInternalError.Error()},
	} {
		t.Run(test.desc, func(t *testing.T) {

			jwtVerifier := jwt.NewVerifier(jwt.VerifierOptions{})
			tv := &testVerifier{
				keyErrors: map[string]error{
					goodAPIKey: nil,
					badAPIKey:  key.ErrBadKeyAuth,
					errAPIKey:  ErrInternalError,
				},
			}
			authMan := &manager{
				jwtVerifier: jwtVerifier,
				keyVerifier: tv,
			}
			authMan.start()
			defer authMan.Close()

			ctx := authtest.NewContext("")
			_, err := authMan.Authenticate(ctx, test.apiKey, test.claims, test.apiKeyClaimKey)
			if err != nil {
				if test.wantError != err.Error() {
					t.Errorf("wanted error: %s, got: %s", test.wantError, err.Error())
				}
			} else if test.wantError != "" {
				t.Errorf("wanted error, got none")
			}
		})
	}
}

func TestValidateOptions(t *testing.T) {
	opts := Options{}
	var err error

	err = opts.validate()
	if err == nil || err.Error() != "client is required" {
		t.Errorf("wanted error 'client is required', got %v", err)
	}

	opts.Client = &http.Client{}
	err = opts.validate()
	if err == nil || err.Error() != "org is required" {
		t.Errorf("wanted error 'org is required', got %v", err)
	}

	opts.Org = "hi"
	err = opts.validate()
	if err != nil {
		t.Errorf("wanted no error, got %v", err)
	}
}
