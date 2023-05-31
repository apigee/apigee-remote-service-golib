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

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
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
			APIs:         []string{"service1.test", "shared.test"},
		},
		"Name 2": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service2.test, shared.test"},
			},
			Environments: []string{"prod"},
			Name:         "Name 2",
			Resources:    []string{"/**"},
			Scopes:       []string{"scope2"},
			APIs:         []string{"service2.test", "shared.test"},
		},
		"Name 3": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "shared.test"},
			},
			Environments: []string{"prod"},
			Name:         "Name 3",
			Resources:    []string{"/name3"},
			Scopes:       []string{},
			APIs:         []string{"shared.test"},
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
		ctx         *auth.Context
		productsMap map[string]*APIProduct
		api         string
		path        string
		method      string
		wantAPIsLen int
		wantHints   string
		wantAuthOp  *AuthorizedOperation
	}{
		{ // good
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 3,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3 Invalid]
			scopes: [scope1 scope2]
			operation: GET /name3
			api: shared.test
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/path",
			method:      "GET",
			wantAPIsLen: 2,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3 Invalid]
			scopes: [scope1 scope2]
			operation: GET /path
			api: shared.test
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
		{ // bad api
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "api",
			path:        "/path",
			method:      "GET",
			wantAPIsLen: 0,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3 Invalid]
			scopes: [scope1 scope2]
			operation: GET /path
			api: api
			- product: Name 1
				no apis: api
			- product: Name 2
				no apis: api
			- product: Name 3
				no apis: api
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 2,
			wantAuthOp: &AuthorizedOperation{
				ID:         "Name 2-prod-app",
				QuotaLimit: productsMap["Name 2"].QuotaLimitInt,
			},
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3 Invalid]
			scopes: [scope2]
			operation: GET /name3
			api: shared.test
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 0,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1]
			scopes: [scope2]
			operation: GET /name3
			api: shared.test
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 3,
			wantAuthOp: &AuthorizedOperation{
				ID:         "Name 1-prod-app",
				QuotaLimit: productsMap["Name 1"].QuotaLimitInt,
			},
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3]
			scopes: []
			operation: GET /name3
			api: shared.test
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 3,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Name 3]
			scopes: []
			operation: GET /name3
			api: shared.test
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
			productsMap: productsMap,
			api:         "shared.test",
			path:        "/name3",
			method:      "GET",
			wantAPIsLen: 0,
			wantHints: `Authorizing request:
			environment: test
			products: [Name 1 Name 2 Name 3]
			scopes: []
			operation: GET /name3
			api: shared.test
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
		apis, hints := authorize(tc.ctx, tc.productsMap, tc.api, tc.path, tc.method, true)
		if len(apis) != tc.wantAPIsLen {
			t.Errorf("test %d: number of apis wrong; want: %d, got: %d", i, tc.wantAPIsLen, len(apis))
		} else if tc.wantAuthOp != nil {
			got := apis[0]
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
	productQuota := &Quota{
		TimeUnit:    "second",
		Interval:    "2",
		Limit:       "2",
		IntervalInt: 2,
		LimitInt:    2,
	}
	productsMap := map[string]*APIProduct{
		"Name 1": {
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "service1.test, shared.test"},
			},
			Environments:  []string{"prod"},
			Name:          "Name 1",
			Resources:     []string{"/"},
			Scopes:        []string{"scope1"},
			APIs:          []string{"service1.test", "shared.test"},
			QuotaInterval: productQuota.Interval,
			QuotaLimit:    productQuota.Limit,
			QuotaTimeUnit: productQuota.TimeUnit,
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
			APIs:          []string{"service1.test", "shared.test"},
			QuotaInterval: productQuota.Interval,
			QuotaLimit:    productQuota.Limit,
			QuotaTimeUnit: productQuota.TimeUnit,
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
						Quota: &Quota{
							Limit:    "1",
							Interval: "1",
							TimeUnit: "minute",
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
		name        string
		ctx         *auth.Context
		productsMap map[string]*APIProduct
		api         string
		path        string
		method      string
		wantAPIsLen int
		wantAPIID   string
		wantQuota   *Quota
		wantHints   string
		wantAuthOp  *AuthorizedOperation
	}{
		{
			name: "good",
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "host",
			path:        "/operation1",
			method:      "GET",
			wantAPIsLen: 1,
			wantAPIID:   "Name 1-prod-app-host",
			wantQuota:   productQuota,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: GET /operation1
			api: host
			- product: Name 1
				operation configs:
					0: authorized
			- product: Name 2
				operation configs:
					0: no path: /operation1
					1: no api: host
					2: no api: host
			- product: Invalid
				not found
				`,
		},
		{
			name: "quota override",
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "host",
			path:        "/operation2",
			method:      "GET",
			wantAPIsLen: 1,
			wantAPIID:   "Name 2-prod-app-host-547dbfc99f0432d3dbc607784917b1bc",
			wantQuota:   productsMap["Name 2"].OperationGroup.OperationConfigs[0].Quota,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: GET /operation2
			api: host
			- product: Name 1
				operation configs:
					0: no path: /operation2
			- product: Name 2
				operation configs:
					0: authorized
					1: no api: host
					2: no api: host
			- product: Invalid
				not found
				`,
		},
		{
			name: "no method",
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "host",
			path:        "/operation2",
			method:      "POST",
			wantAPIsLen: 0,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: POST /operation2
			api: host
			- product: Name 1
				operation configs:
					0: no method: POST
			- product: Name 2
				operation configs:
					0: no method: POST
					1: no api: host
					2: no api: host
			- product: Invalid
				not found
				`,
		},
		{
			name: "all methods allowed if none specified",
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "host3",
			path:        "/operation3",
			method:      "POST",
			wantAPIsLen: 1,
			wantAPIID:   "Name 2-prod-app-host3",
			wantQuota:   productQuota,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: POST /operation3
			api: host3
			- product: Name 1
				operation configs:
					0: no api: host3
			- product: Name 2
				operation configs:
					0: no api: host3
					1: no api: host3
					2: authorized
			- product: Invalid
				not found
				`,
		},
		{
			name: "no api",
			ctx: &auth.Context{
				Context:     &fakeContext{org: "org", env: "prod"},
				APIProducts: []string{"Name 1", "Name 2", "Invalid"},
				Scopes:      []string{"scope1", "scope2"},
				Application: "app",
			},
			productsMap: productsMap,
			api:         "api",
			path:        "/operation2",
			method:      "GET",
			wantAPIsLen: 0,
			wantHints: `Authorizing request:
			environment: prod
			products: [Name 1 Name 2 Invalid]
			scopes: [scope1 scope2]
			operation: GET /operation2
			api: api
			- product: Name 1
				operation configs:
					0: no api: api
			- product: Name 2
				operation configs:
					0: no api: api
					1: no api: api
					2: no api: api
			- product: Invalid
				not found
				`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			apis, hints := authorize(tc.ctx, tc.productsMap, tc.api, tc.path, tc.method, true)
			if len(apis) != tc.wantAPIsLen {
				t.Errorf("number of apis wrong; want: %d, got: %d", tc.wantAPIsLen, len(apis))
			} else if tc.wantAuthOp != nil {
				got := apis[0]
				if !reflect.DeepEqual(*tc.wantAuthOp, got) {
					t.Errorf("authop want: %v\n got: %v", tc.wantAuthOp, got)
				}
			} else if tc.wantQuota != nil {
				if tc.wantAPIID != apis[0].ID {
					t.Errorf("want id: '%s', got: '%s'", tc.wantAPIID, apis[0].ID)
				}
				if tc.wantQuota.TimeUnit != apis[0].QuotaTimeUnit {
					t.Errorf("want timeunit: '%s', got: '%s'", tc.wantQuota.TimeUnit, apis[0].QuotaTimeUnit)
				}
				if tc.wantQuota.IntervalInt != apis[0].QuotaInterval {
					t.Errorf("want interval: '%d', got: '%d'", tc.wantQuota.IntervalInt, apis[0].QuotaInterval)
				}
				if tc.wantQuota.LimitInt != apis[0].QuotaLimit {
					t.Errorf("want limit: '%d', got: '%d'", tc.wantQuota.LimitInt, apis[0].QuotaLimit)
				}
			}
			if noSymbols(tc.wantHints) != noSymbols(hints) {
				t.Errorf("want hints: '%s', got: '%s'", tc.wantHints, hints)
			}
		})
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
