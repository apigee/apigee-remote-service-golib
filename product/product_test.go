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
	"net/url"
	"reflect"
	"regexp"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/auth"
)

type fakeContext struct {
	org string
	env string
}

func (fc *fakeContext) Organization() string       { return fc.org }
func (fc *fakeContext) Environment() string        { return fc.env }
func (fc *fakeContext) RemoteServiceAPI() *url.URL { return nil }
func (fc *fakeContext) InternalAPI() *url.URL      { return nil }

func TestAuthorize(t *testing.T) {

	productsMap := map[string]*APIProduct{
		"Name 1": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Environments: []string{"prod"},
			Name:         "Name 1",
			Resources:    []string{"/"},
			Scopes:       []string{"scope1"},
			Targets:      []string{"service1.test", "shared.test"},
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

	testCases := []struct {
		ctx            *auth.Context
		productsMap    map[string]*APIProduct
		target         string
		path           string
		method         string
		wantTargetsLen int
		wantHints      string
		wantAuthOp     *AuthorizedOperation
	}{
		{ // good
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 3,
			wantHints: `Authorizing request:
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
				`,
		},
		{ // specific path
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/path",
			method:         "GET",
			wantTargetsLen: 2,
			wantHints: `Authorizing request:
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
				`,
		},
		{ // bad target
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "target",
			path:           "/path",
			method:         "GET",
			wantTargetsLen: 0,
			wantHints: `Authorizing request:
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
				`,
		},
		{ // specific scope
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 2,
			wantAuthOp: &AuthorizedOperation{
				ID:         "Name 2-prod-app",
				QuotaLimit: productsMap["Name 2"].QuotaLimitInt,
			},
			wantHints: `Authorizing request:
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
				`,
		},
		{ // specifc product
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1"},
				Scopes:      []string{"scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 0,
			wantHints: `Authorizing request:
			products: [Name 1]
			scopes: [scope2]
			operation: GET /name3
			target: shared.test
			- product: Name 1
				incorrect scopes: [scope1]
			`,
		},
		{ // API key - no scopes required!
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3"},
				Scopes:      []string{},
				Application: "app",
				APIKey:      "x",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 3,
			wantAuthOp: &AuthorizedOperation{
				ID:         "Name 1-prod-app",
				QuotaLimit: productsMap["Name 1"].QuotaLimitInt,
			},
			wantHints: `Authorizing request:
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
				`,
		},
		{ // API key - no scopes required!
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3"},
				Scopes:      []string{},
				Application: "app",
				APIKey:      "x",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 3,
			wantHints: `Authorizing request:
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
				`,
		},
		{ // invalid environment
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "test"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3"},
				Scopes:      []string{},
				Application: "app",
				APIKey:      "x",
			},
			productsMap:    productsMap,
			target:         "shared.test",
			path:           "/name3",
			method:         "GET",
			wantTargetsLen: 0,
			wantHints: `Authorizing request:
			products: [Name 1 Name 2 Name 3]
			scopes: []
			operation: GET /name3
			target: shared.test
			- product: Name 1
			  incorrect environments: []string{"prod"}
			- product: Name 2
			  incorrect environments: []string{"prod"}
			- product: Name 3
			  incorrect environments: []string{"prod"}
				`,
		},
	}

	for i, tc := range testCases {
		targets, hints := authorize(tc.ctx, tc.productsMap, tc.target, tc.path, tc.method, true)
		if len(targets) != tc.wantTargetsLen {
			t.Errorf("test %d: number of targets wrong; want: %d, got: %d", i, tc.wantTargetsLen, len(targets))
		} else if tc.wantAuthOp != nil {
			got := targets[0]
			if !reflect.DeepEqual(*tc.wantAuthOp, got) {
				t.Errorf("test %d: \nwant: %v\n got: %v", i, tc.wantAuthOp, got)
			}
		}
		if noSymbols(tc.wantHints) != noSymbols(hints) {
			t.Errorf("test %d: want: '%s', got: '%s'", i, tc.wantHints, hints)
		}
	}
}

func TestAuthorizeOperations(t *testing.T) {

	productsMap := map[string]*APIProduct{
		"Name 1": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Environments:  []string{"prod"},
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
			Environments:  []string{"prod"},
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
					{
						APISource: "host3",
						Operations: []Operation{
							{
								Resource: "/operation3",
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

	testCases := []struct {
		ctx            *auth.Context
		productsMap    map[string]*APIProduct
		target         string
		path           string
		method         string
		wantTargetsLen int
		wantTargetID   string
		wantQuota      *Quota
		wantHints      string
		wantAuthOp     *AuthorizedOperation
	}{
		{ // good
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "host",
			path:           "/operation1",
			method:         "GET",
			wantTargetsLen: 1,
			wantTargetID:   "Name 1-prod-app-host-7c5532d6fca7a87312365219212de443",
			wantQuota:      productsMap["Name 1"].OperationGroup.OperationConfigs[0].Quota,
			wantHints: `Authorizing request:
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
					2: no target: host
			- product: Invalid
				not found
				`,
		},
		{ // quota override
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "host",
			path:           "/operation2",
			method:         "GET",
			wantTargetsLen: 1,
			wantTargetID:   "Name 2-prod-app-host-547dbfc99f0432d3dbc607784917b1bc",
			wantQuota:      productsMap["Name 2"].OperationGroup.OperationConfigs[0].Quota,
			wantHints: `Authorizing request:
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
					2: no target: host
			- product: Invalid
				not found
				`,
		},
		{ // no method
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "host",
			path:           "/operation2",
			method:         "POST",
			wantTargetsLen: 0,
			wantHints: `Authorizing request:
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
					2: no target: host
			- product: Invalid
				not found
				`,
		},
		{ // all methods allowed if none specified
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "host3",
			path:           "/operation3",
			method:         "POST",
			wantTargetsLen: 1,
			wantTargetID:   "Name 2-prod-app-host-547dbfc99f0432d3dbc607784917b1bc",
			wantQuota:      productsMap["Name 2"].OperationGroup.OperationConfigs[0].Quota,
			wantHints: `Authorizing request:
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: POST /operation3
			target: host3
			- product: Name 1
				operation configs:
					0: no target: host3
			- product: Name 2
				operation configs:
					0: no target: host3
					1: no target: host3
					2: authorized
			- product: Invalid
				not found
				`,
		},
		{ // no target
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap:    productsMap,
			target:         "target",
			path:           "/operation2",
			method:         "GET",
			wantTargetsLen: 0,
			wantHints: `Authorizing request:
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
					2: no target: target
			- product: Invalid
				not found
				`,
		},
	}

	for i, tc := range testCases {
		targets, hints := authorize(tc.ctx, tc.productsMap, tc.target, tc.path, tc.method, true)
		if len(targets) != tc.wantTargetsLen {
			t.Errorf("test %d: number of targets wrong; want: %d, got: %d", i, tc.wantTargetsLen, len(targets))
		} else if tc.wantQuota != nil {
			if tc.wantTargetID != targets[0].ID {
				t.Errorf("test %d: want: '%s', got: '%s'", i, tc.wantTargetID, targets[0].ID)
			}
			if tc.wantQuota.TimeUnit != targets[0].QuotaTimeUnit {
				t.Errorf("test %d: want: '%s', got: '%s'", i, tc.wantQuota.TimeUnit, targets[0].QuotaTimeUnit)
			}
			if tc.wantQuota.IntervalInt != targets[0].QuotaInterval {
				t.Errorf("test %d: want: '%d', got: '%d'", i, tc.wantQuota.IntervalInt, targets[0].QuotaInterval)
			}
			if tc.wantQuota.LimitInt != targets[0].QuotaLimit {
				t.Errorf("test %d: want: '%d', got: '%d'", i, tc.wantQuota.LimitInt, targets[0].QuotaLimit)
			}
		}
		if noSymbols(tc.wantHints) != noSymbols(hints) {
			t.Errorf("test %d: want: '%s', got: '%s'", i, tc.wantHints, hints)
		}
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
	if want := "quota-demo-98c34c322202a4f9e01aea733326a129"; oc.ID != want {
		t.Errorf("want OperationConfig.ID: '%s', got '%s'", want, oc.ID)
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
