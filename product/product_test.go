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
	"reflect"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/auth"
)

func TestResolve(t *testing.T) {

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
				{Name: TargetsAttr, Value: "service2.test,shared.test"},
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
			Resources:    []string{"/"},
			Scopes:       []string{},
			Targets:      []string{"shared.test"},
		},
	}

	for _, p := range productsMap {
		p.resolveResourceMatchers()
	}

	api := "shared.test"
	path := "/"

	ac := &auth.Context{
		APIProducts: []string{"Name 1", "Name 2", "Name 3", "Invalid"},
		Scopes:      []string{"scope1", "scope2"},
	}
	resolved, failHints := resolve(ac, productsMap, api, path)
	if len(resolved) != 3 {
		t.Errorf("want: 3, got: %v", failHints)
	}
	if len(failHints) != 1 {
		t.Errorf("want: 1, got: %v", failHints)
	}

	ac.Scopes = []string{"scope2"}
	resolved, failHints = resolve(ac, productsMap, api, path)
	if len(resolved) != 2 {
		t.Errorf("want: 2, got: %d", len(resolved))
	} else {
		got := resolved[0]
		want := productsMap["Name 2"]
		if !reflect.DeepEqual(want, got) {
			t.Errorf("\nwant: %v\n got: %v", want, got)
		}
	}
	if len(failHints) != 2 {
		t.Errorf("want: 2, got: %v", failHints)
	}

	ac.APIProducts = []string{"Name 1"}
	resolved, failHints = resolve(ac, productsMap, api, path)
	if len(resolved) != 0 {
		t.Errorf("want: 0, got: %d", len(resolved))
	}
	if len(failHints) != 1 {
		t.Errorf("want: 1, got: %v", failHints)
	}

	// check API Key - no scopes required!
	ac.APIKey = "x"
	ac.APIProducts = []string{"Name 1", "Name 2", "Name 3"}
	ac.Scopes = []string{}
	resolved, failHints = resolve(ac, productsMap, api, path)
	if len(resolved) != 3 {
		t.Errorf("want: 3, got: %d", len(resolved))
	}
	if len(failHints) != 0 {
		t.Errorf("want: 0, got: %v", failHints)
	}
}

// Path matching is similar to wildcard semantics described in the Apigee product documentation here:
// https://docs.apigee.com/developer-services/content/create-api-products#resourcebehavior.
// However, as there is no base path, it is simplified as follows:
// 1. A single slash (/) by itself matches any path.
// 2. * is valid anywhere and matches within a segment (between slashes).
// 3. ** is valid at the end and matches anything to the end of line.
func TestValidPath(t *testing.T) {

	resources := []string{"/", "/v1/*", "/v1/**", "/v1/weatherapikey/*/2/**"}
	specs := []struct {
		Path    string
		Results []bool
	}{
		{"/v1/weatherapikey", []bool{true, true, true, false}},
		{"/v1/weatherapikey/", []bool{true, false, true, false}},
		{"/v1/weatherapikey/1", []bool{true, false, true, false}},
		{"/v1/weatherapikey/1/", []bool{true, false, true, false}},
		{"/v1/weatherapikey/1/2", []bool{true, false, true, false}},
		{"/v1/weatherapikey/1/2/", []bool{true, false, true, true}},
		{"/v1/weatherapikey/1/2/3/", []bool{true, false, true, true}},
		{"/v1/weatherapikey/1/a/2/3/", []bool{true, false, true, false}},
	}

	for _, spec := range specs {
		for j, resource := range resources {
			p := &APIProduct{
				Resources: []string{resource},
			}
			p.resolveResourceMatchers()
			if p.isValidPath(spec.Path) != spec.Results[j] {
				t.Errorf("expected: %v got: %v for path: %s, resource: %s",
					spec.Results[j], p.isValidPath(spec.Path), spec.Path, resource)
			}
		}
	}
}

func TestValidScopes(t *testing.T) {
	p := APIProduct{
		Scopes: []string{"scope1"},
	}
	if !p.isValidScopes([]string{"scope1"}) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	if !p.isValidScopes([]string{"scope1", "scope2"}) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	if p.isValidScopes([]string{"scope2"}) {
		t.Errorf("expected %s is not valid", p.Scopes)
	}
	p.Scopes = []string{"scope1", "scope2"}
	if !p.isValidScopes([]string{"scope1"}) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	if !p.isValidScopes([]string{"scope1", "scope2"}) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
	if !p.isValidScopes([]string{"scope2"}) {
		t.Errorf("expected %s is valid", p.Scopes)
	}
}

func TestParseNewJSON(t *testing.T) {
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
	if product.OperationGroup.OperationConfigType != "remote-service" {
		t.Errorf("want: 'remote-service', got: '%s'", product.OperationGroup.OperationConfigType)
	}

	if len(product.OperationGroup.OperationConfigs) != 1 {
		t.Fatalf("want 1 OperationConfig")
	}
	oc := product.OperationGroup.OperationConfigs[0]
	if oc.APISource != "quota-demo" {
		t.Errorf("want: 'quota-demo', got: '%s'", oc.APISource)
	}

	if len(oc.Operations) != 1 {
		t.Fatalf("want 1 Operation")
	}
	op := oc.Operations[0]
	if op.Resource != "/put" {
		t.Errorf("want: '/put', got: '%s'", op.Resource)
	}
	if len(op.Methods) != 1 {
		t.Fatalf("want 1 method")
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
            "resource": "/put",
            "methods": [
              "PUT"
            ]
          }
        ],
        "quota": {
          "limit": "1",
          "interval": "1",
          "timeUnit": "minute"
        }
      }
    ],
    "operationConfigType": "remote-service"
  }
}`
