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
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/jwt"
)

func TestSetClaims(t *testing.T) {
	c := Context{}
	now := time.Unix(time.Now().Unix(), 0)
	claims := map[string]interface{}{
		jwt.AudienceKey:    "aud",
		jwt.ExpirationKey:  float64(now.Unix()),
		apiProductListKey:  time.Now(),
		clientIDKey:        nil,
		applicationNameKey: "app",
		scopeKey:           nil,
		developerEmailKey:  "email",
	}
	if err := c.setClaims(claims); err == nil {
		t.Errorf("setClaims without client_id should get error")
	}

	claims[clientIDKey] = "clientID"
	if err := c.setClaims(claims); err == nil {
		t.Errorf("bad product list should error")
	}

	productsWant := []string{"product 1", "product 2"}
	claims[apiProductListKey] = `["product 1", "product 2"]`
	if err := c.setClaims(claims); err != nil {
		t.Errorf("valid setClaims, got: %v", err)
	}
	if !reflect.DeepEqual(c.APIProducts, productsWant) {
		t.Errorf("apiProducts want: %s, got: %v", productsWant, c.APIProducts)
	}

	claimsWant := []string{"scope1", "scope2"}
	claims[scopeKey] = "scope1 scope2"
	if err := c.setClaims(claims); err != nil {
		t.Errorf("valid setClaims, got: %v", err)
	}
	if !reflect.DeepEqual(claimsWant, c.Scopes) {
		t.Errorf("claims want: %s, got: %v", claimsWant, claims[scopeKey])
	}
}

func TestParseArrays(t *testing.T) {
	arr := []interface{}{
		"this",
		"is",
		"a",
		"test",
		123,
	}

	res, err := parseArrayOfStrings(arr)
	if err == nil || err.Error() != "unable to interpret: 123" {
		t.Errorf("wanted 'unable to interpret: 123', got %v", err)
	}
	if len(res) != 4 {
		t.Errorf("wanted an array of 4, got %d", len(res))
	}
	output := strings.Join(res, " ")
	if output != "this is a test" {
		t.Errorf("wanted result to be 'this is a test', got %s", output)
	}
}
