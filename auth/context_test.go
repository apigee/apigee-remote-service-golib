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
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseExp(t *testing.T) {
	now := time.Unix(time.Now().Unix(), 0)

	claims := map[string]interface{}{
		expClaim: float64(now.Unix()),
	}
	exp, err := parseExp(claims)
	if err != nil {
		t.Errorf("parseExp: %v", err)
	}
	if exp != now {
		t.Errorf("parseExp float got: %v, want: %v", exp, now)
	}

	claims[expClaim] = strconv.FormatInt(time.Now().Unix(), 10)
	exp, err = parseExp(claims)
	if err != nil {
		t.Errorf("parseExp: %v", err)
	}
	if exp != now {
		t.Errorf("parseExp string got: %v, want: %v", exp, now)
	}

	claims[expClaim] = "badexp"
	_, err = parseExp(claims)
	if err == nil {
		t.Error("parseExp should have gotten an error")
	}
}

func TestSetClaims(t *testing.T) {
	c := Context{}
	now := time.Unix(time.Now().Unix(), 0)
	claims := map[string]interface{}{
		apiProductListClaim:  time.Now(),
		audienceClaim:        "aud",
		clientIDClaim:        nil,
		applicationNameClaim: "app",
		scopeClaim:           nil,
		expClaim:             float64(now.Unix()),
		developerEmailClaim:  "email",
	}
	if err := c.setClaims(claims); err == nil {
		t.Errorf("setClaims without client_id should get error")
	}

	claims[clientIDClaim] = "clientID"
	if err := c.setClaims(claims); err == nil {
		t.Errorf("bad product list should error")
	}

	productsWant := []string{"product 1", "product 2"}
	claims[apiProductListClaim] = `["product 1", "product 2"]`
	if err := c.setClaims(claims); err != nil {
		t.Errorf("valid setClaims, got: %v", err)
	}
	if !reflect.DeepEqual(c.APIProducts, productsWant) {
		t.Errorf("apiProducts want: %s, got: %v", productsWant, c.APIProducts)
	}

	claimsWant := []string{"scope1", "scope2"}
	claims[scopeClaim] = "scope1 scope2"
	if err := c.setClaims(claims); err != nil {
		t.Errorf("valid setClaims, got: %v", err)
	}
	if !reflect.DeepEqual(claimsWant, c.Scopes) {
		t.Errorf("claims want: %s, got: %v", claimsWant, claims[scopeClaim])
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
