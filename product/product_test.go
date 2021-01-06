// Copyright 2020 Google LLC
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

package product

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/auth"
)

func TestAuthorize(t *testing.T) {

	productsMap := map[string]*APIProduct{
		"Name 1": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Name:      "Name 1",
			Resources: []string{"/"},
			Scopes:    []string{"scope1"},
			Targets:   []string{"service1.test", "shared.test"},
		},
		"Name 2": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service2.test, shared.test"},
			},
			Environments: []string{"prod"},
			Name:         "Name 2",
			Resources:    []string{"/**"},
			Scopes:       []string{"scope2"},
			Targets:      []string{"service2.test", "shared.test"},
		},
		"Name 3": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "shared.test"},
			},
			Environments: []string{"prod"},
			Name:         "Name 3",
			Resources:    []string{"/name3"},
			Scopes:       []string{},
			Targets:      []string{"shared.test"},
		},
	}

	// marshal/unmarshal to ensure structs
	b, err := json.Marshal(productsMap)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(b, &productsMap)
	if err != nil {
		t.Fatal(err)
	}

	target := "shared.test"
	path := "/name3"
	method := "GET"

	authContext := &auth.Context{
		APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
		Scopes:      []string{"scope1", "scope2"},
		Application: "app",
	}
	targets, hints := authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 3 {
		t.Errorf("want: 3, got: %v", len(targets))
	}
	want := `Authorizing request:
	products: [Name 1 Name 2 Name 3 Invalid]
	scopes: [scope1 scope2]
	operation: GET /name3
	target: shared.test
	- product: Name 1
		authorized
	- product: Name 2
		authorized
	- product: Name 3
		authorized
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// specific path
	targets, hints = authorize(authContext, productsMap, target, "/path", method, true)
	if len(targets) != 2 {
		t.Errorf("want: 2, got: %d", len(targets))
	} else {
		got := targets[0]
		want := AuthorizedOperation{
			ID:         "Name 1-app",
			QuotaLimit: productsMap["Name 1"].QuotaLimitInt,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("\nwant: %v\n got: %v", want, got)
		}
	}
	want = `Authorizing request:
	products: [Name 1 Name 2 Name 3 Invalid]
	scopes: [scope1 scope2]
	operation: GET /path
	target: shared.test
	- product: Name 1
		authorized
	- product: Name 2
		authorized
	- product: Name 3
		no path: /path
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// bad target
	targets, hints = authorize(authContext, productsMap, "target", "/path", method, true)
	if len(targets) != 0 {
		t.Errorf("want: 0, got: %d", len(targets))
	}
	want = `Authorizing request:
	products: [Name 1 Name 2 Name 3 Invalid]
	scopes: [scope1 scope2]
	operation: GET /path
	target: target
	- product: Name 1
		no targets: target
	- product: Name 2
		no targets: target
	- product: Name 3
		no targets: target
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// scope
	authContext.Scopes = []string{"scope2"}
	targets, hints = authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 2 {
		t.Errorf("want: 2, got: %d", len(targets))
	} else {
		got := targets[0]
		want := AuthorizedOperation{
			ID:         "Name 2-app",
			QuotaLimit: productsMap["Name 2"].QuotaLimitInt,
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("\nwant: %v\n got: %v", want, got)
		}
	}
	want = `Authorizing request:
	products: [Name 1 Name 2 Name 3 Invalid]
	scopes: [scope2]
	operation: GET /name3
	target: shared.test
	- product: Name 1
		incorrect scopes: [scope1]
	- product: Name 2
		authorized
	- product: Name 3
		authorized
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// specific product
	authContext.APIProducts = []string{"Name 1"}
	targets, hints = authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 0 {
		t.Errorf("want: 0, got: %d", len(targets))
	}
	want = `Authorizing request:
	products: [Name 1]
	scopes: [scope2]
	operation: GET /name3
	target: shared.test
	- product: Name 1
		incorrect scopes: [scope1]
	`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// API Key - no scopes required!
	authContext.APIKey = "x"
	authContext.APIProducts = []string{"Name 1", "Name 2", "Name 3"}
	authContext.Scopes = []string{}
	targets, hints = authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 3 {
		t.Errorf("want: 3, got: %d", len(targets))
	}
	want = `Authorizing request:
	products: [Name 1 Name 2 Name 3]
	scopes: []
	operation: GET /name3
	target: shared.test
	- product: Name 1
			authorized
	- product: Name 2
			authorized
	- product: Name 3
			authorized
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}
}

func TestAuthorizeOperations(t *testing.T) {

	productsMap := map[string]*APIProduct{
		"Name 1": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Name:          "Name 1",
			Resources:     []string{"/"},
			Scopes:        []string{"scope1"},
			Targets:       []string{"service1.test", "shared.test"},
			QuotaInterval: "2",
			QuotaLimit:    "2",
			QuotaTimeUnit: "second",
			OperationGroup: &OperationGroup{
				OperationConfigType: "remoteservice",
				OperationConfigs: []OperationConfig{
					{
						APISource: "host",
						Operations: []Operation{
							{
								Resource: "/operation1",
								Methods:  []string{"GET"},
							},
						},
						Quota: &Quota{
							Limit:    "1",
							Interval: "1",
							TimeUnit: "minute",
						},
					},
				},
			},
		},
		"Name 2": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Name:          "Name 2",
			Resources:     []string{"/"},
			Scopes:        []string{"scope1"},
			Targets:       []string{"service1.test", "shared.test"},
			QuotaInterval: "2",
			QuotaLimit:    "2",
			QuotaTimeUnit: "second",
			OperationGroup: &OperationGroup{
				OperationConfigType: "remoteservice",
				OperationConfigs: []OperationConfig{
					{
						APISource: "host",
						Operations: []Operation{
							{
								Resource: "/operation2",
								Methods:  []string{"GET"},
							},
						},
					},
					{
						APISource: "host2",
						Operations: []Operation{
							{
								Resource: "/operation3",
								Methods:  []string{"POST"},
							},
						},
					},
				},
			},
		},
	}

	// marshal/unmarshal to ensure structs
	b, err := json.Marshal(productsMap)
	if err != nil {
		t.Fatal(err)
	}
	err = json.Unmarshal(b, &productsMap)
	if err != nil {
		t.Fatal(err)
	}

	target := "host"
	path := "/operation1"
	method := "GET"

	authContext := &auth.Context{
		APIProducts: []string{"Name 1", "Name 2", "Invalid"},
		Scopes:      []string{"scope1", "scope2"},
		Application: "app",
	}
	targets, hints := authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 1 {
		t.Errorf("want: 1, got: %v", len(targets))
	}

	wantProduct := productsMap["Name 1"]
	wantQuota := wantProduct.OperationGroup.OperationConfigs[0].Quota
	wantTargetID := fmt.Sprintf("%s-%s-%s-%x", wantProduct.Name, authContext.Application, target, md5hash(wantProduct.OperationGroup.OperationConfigs[0].Operations))
	if wantTargetID != targets[0].ID {
		t.Errorf("want: '%s', got: '%s'", wantTargetID, targets[0].ID)
	}
	if wantQuota.TimeUnit != targets[0].QuotaTimeUnit {
		t.Errorf("want: '%s', got: '%s'", wantQuota.TimeUnit, targets[0].QuotaTimeUnit)
	}
	if wantQuota.IntervalInt != targets[0].QuotaInterval {
		t.Errorf("want: '%d', got: '%d'", wantQuota.IntervalInt, targets[0].QuotaInterval)
	}
	if wantQuota.LimitInt != targets[0].QuotaLimit {
		t.Errorf("want: '%d', got: '%d'", wantQuota.LimitInt, targets[0].QuotaLimit)
	}

	want := `Authorizing request:
	products: [Name 1 Name 2 Invalid]
	scopes: [scope1 scope2]
	operation: GET /operation1
	target: host
	- product: Name 1
		operation configs:
			0: authorized
	- product: Name 2
		operation configs:
			0: no path: /operation1
			1: no target: host
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// quota override
	path = "/operation2"
	targets, hints = authorize(authContext, productsMap, target, path, method, true)
	if len(targets) != 1 {
		t.Errorf("want: 1, got: %v", len(targets))
	}

	wantProduct = productsMap["Name 2"]
	wantTargetID = fmt.Sprintf("%s-%s-%s-%x", wantProduct.Name, authContext.Application, target, md5hash(wantProduct.OperationGroup.OperationConfigs[0].Operations))
	if wantTargetID != targets[0].ID {
		t.Errorf("want: '%s', got: '%s'", wantTargetID, targets[0].ID)
	}
	if wantProduct.QuotaTimeUnit != targets[0].QuotaTimeUnit {
		t.Errorf("want: '%s', got: '%s'", wantProduct.QuotaTimeUnit, targets[0].QuotaTimeUnit)
	}
	if wantProduct.QuotaIntervalInt != targets[0].QuotaInterval {
		t.Errorf("want: '%d', got: '%d'", wantProduct.QuotaIntervalInt, targets[0].QuotaInterval)
	}
	if wantProduct.QuotaLimitInt != targets[0].QuotaLimit {
		t.Errorf("want: '%d', got: '%d'", wantProduct.QuotaLimitInt, targets[0].QuotaLimit)
	}

	want = `Authorizing request:
	products: [Name 1 Name 2 Invalid]
	scopes: [scope1 scope2]
	operation: GET /operation2
	target: host
	- product: Name 1
		operation configs:
			0: no path: /operation2
	- product: Name 2
		operation configs:
			0: authorized
			1: no target: host
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// no method
	targets, hints = authorize(authContext, productsMap, target, path, "POST", true)
	if len(targets) != 0 {
		t.Errorf("want: 0, got: %v", len(targets))
	}

	want = `Authorizing request:
	products: [Name 1 Name 2 Invalid]
	scopes: [scope1 scope2]
	operation: POST /operation2
	target: host
	- product: Name 1
		operation configs:
			0: no method: POST
	- product: Name 2
		operation configs:
			0: no method: POST
			1: no target: host
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}

	// no target
	targets, hints = authorize(authContext, productsMap, "target", path, method, true)
	if len(targets) != 0 {
		t.Errorf("want: 0, got: %v", len(targets))
	}

	want = `Authorizing request:
	products: [Name 1 Name 2 Invalid]
	scopes: [scope1 scope2]
	operation: GET /operation2
	target: target
	- product: Name 1
		operation configs:
			0: no target: target
	- product: Name 2
		operation configs:
			0: no target: target
			1: no target: target
	- product: Invalid
		not found
		`
	if noSymbols(want) != noSymbols(hints) {
		t.Errorf("want: '%s', got: '%s'", want, hints)
	}
}

func noSymbols(str string) string {
	symbols := regexp.MustCompile(`\s+`)
	return symbols.ReplaceAllString(str, " ")
}

func TestValidScopes(t *testing.T) {
	p := APIProduct{
		Scopes: []string{"scope1"},
	}
	authContext := &auth.Context{
		Scopes: []string{"scope1"},
	}
	if !p.isValidScopes(authContext) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	authContext.Scopes = []string{"scope1", "scope2"}
	if !p.isValidScopes(authContext) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	authContext.Scopes = []string{"scope2"}
	if p.isValidScopes(authContext) {
		t.Errorf("expected %s is not valid", p.Scopes)
	}
	p.Scopes = []string{"scope1", "scope2"}
	authContext.Scopes = []string{"scope1"}
	if !p.isValidScopes(authContext) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	authContext.Scopes = []string{"scope1", "scope2"}
	if !p.isValidScopes(authContext) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	authContext.Scopes = []string{"scope2"}
	if !p.isValidScopes(authContext) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
}

func TestParseJSONWithOperations(t *testing.T) {
	var product APIProduct
	if err := json.Unmarshal([]byte(productJSON), &product); err != nil {
		t.Fatalf("can't parse productJSON: %v", err)
	}

	if product.Name != "enforce-on-verbs" {
		t.Errorf("want: 'enforce-on-verbs', got: '%s'", product.Name)
	}
	if product.DisplayName != "enforce-on-verbs" {
		t.Errorf("want: 'enforce-on-verbs', got: '%s'", product.DisplayName)
	}
	if len(product.Attributes) != 1 {
		t.Errorf("want 1 attribute")
	}
	if product.Attributes[0].Name != "access" {
		t.Errorf("want: 'access', got: '%s'", product.Attributes[0].Name)
	}
	if product.Attributes[0].Value != "public" {
		t.Errorf("want: 'public', got: '%s'", product.Attributes[0].Value)
	}
	if len(product.Environments) != 1 {
		t.Errorf("want 1 environment")
	}
	if product.Environments[0] != "test" {
		t.Errorf("want: 'test', got: '%s'", product.Environments[0])
	}
	if product.QuotaLimit != "1" {
		t.Errorf("want: '1', got: '%s'", product.QuotaLimit)
	}
	if product.QuotaInterval != "1" {
		t.Errorf("want: '1', got: '%s'", product.QuotaInterval)
	}
	if product.QuotaTimeUnit != "minute" {
		t.Errorf("want: '1', got: '%s'", product.QuotaTimeUnit)
	}

	if product.OperationGroup == nil {
		t.Fatalf("want OperationGroup")
	}
	if product.OperationGroup.OperationConfigType != "remoteservice" {
		t.Errorf("want: 'remote-service', got: '%s'", product.OperationGroup.OperationConfigType)
	}

	if len(product.OperationGroup.OperationConfigs) != 2 {
		t.Fatalf("want 2 OperationConfig, got: %d", len(product.OperationGroup.OperationConfigs))
	}
	oc := product.OperationGroup.OperationConfigs[0]
	if oc.APISource != "quota-demo" {
		t.Errorf("want: 'quota-demo', got: '%s'", oc.APISource)
	}

	if len(oc.Operations) != 4 {
		t.Fatalf("want 1 Operation")
	}
	var op Operation

	op = oc.Operations[0]
	if op.Resource != "/all" {
		t.Errorf("want: '/all', got: '%s'", op.Resource)
	}
	if len(op.Methods) != 5 {
		t.Fatalf("want 5 method, got: %d", len(op.Methods))
	}
	if op.Methods[0] != "DELETE" {
		t.Errorf("want: 'DELETE', got: '%s'", op.Methods[0])
	}

	op = oc.Operations[3]
	if op.Resource != "/put" {
		t.Errorf("want: '/put', got: '%s'", op.Resource)
	}
	if len(op.Methods) != 1 {
		t.Fatalf("want 1 method, got: %d", len(op.Methods))
	}
	if op.Methods[0] != "PUT" {
		t.Errorf("want: 'PUT', got: '%s'", op.Methods[0])
	}

	if oc.Quota == nil {
		t.Fatalf("want a quota")
	}
	if oc.Quota.Limit != "1" {
		t.Errorf("want: '1', got: '%s'", oc.Quota.Limit)
	}
	if oc.Quota.Interval != "1" {
		t.Errorf("want: '1', got: '%s'", oc.Quota.Interval)
	}
	if oc.Quota.TimeUnit != "minute" {
		t.Errorf("want: 'minute', got: '%s'", oc.Quota.TimeUnit)
	}

}

const productJSON = `
{
  "name": "enforce-on-verbs",
  "displayName": "enforce-on-verbs",
  "approvalType": "auto",
  "attributes": [
    {
      "name": "access",
      "value": "public"
    }
  ],
  "environments": [
    "test"
  ],
  "quota": "1",
  "quotaInterval": "1",
  "quotaTimeUnit": "minute",
  "operationGroup": {
    "operationConfigs": [
      {
        "apiSource": "quota-demo",
        "operations": [
					{
            "resource": "/all",
            "methods": [
							"GET",
							"POST",
							"PATCH",
							"PUT",
							"DELETE"
            ]
					},
          {
            "resource": "/put",
            "methods": [
              "PUT"
            ]
					},
					{
            "resource": "/post",
            "methods": [
              "POST"
            ]
					},
					{
            "resource": "/get",
            "methods": [
              "GET"
            ]
          }
        ],
        "quota": {
          "limit": "1",
          "interval": "1",
          "timeUnit": "minute"
        }
      },
      {
        "apiSource": "quota-demo",
        "operations": [],
        "quota": {
          "limit": "null",
          "interval": "null",
          "timeUnit": "null"
        }
      }
    ],
    "operationConfigType": "remoteservice"
  }
}`
