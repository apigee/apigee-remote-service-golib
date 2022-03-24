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
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/path"
)

// APIResponse is the response from the Apigee products API
type APIResponse struct {
	APIProducts []APIProduct `json:"apiProduct"`
}

// An APIProduct is an Apigee API product. See the Apigee docs for details:
// https://docs.apigee.com/api-platform/publish/what-api-product
type APIProduct struct {
	Attributes       []Attribute     `json:"attributes,omitempty" yaml:"attributes"`
	Description      string          `json:"description,omitempty" yaml:"description"`
	DisplayName      string          `json:"displayName,omitempty" yaml:"displayName"`
	Environments     []string        `json:"environments,omitempty" yaml:"environments"`
	Name             string          `json:"name,omitempty" yaml:"name"`
	OperationGroup   *OperationGroup `json:"operationGroup,omitempty" yaml:"operationGroup"`
	Proxies          []string        `json:"proxies" yaml:"proxies"`
	QuotaLimit       string          `json:"quota,omitempty" yaml:"quota"`
	QuotaInterval    string          `json:"quotaInterval,omitempty" yaml:"quotaInterval"`
	QuotaTimeUnit    string          `json:"quotaTimeUnit,omitempty" yaml:"quotaTimeUnit"`
	Resources        []string        `json:"apiResources" yaml:"apiResources"`
	Scopes           []string        `json:"scopes" yaml:"scopes"`
	APIs             map[string]bool `json:"-" yaml:"-"` // api name -> true
	EnvironmentMap   map[string]bool `json:"-" yaml:"-"` // env name -> true
	QuotaLimitInt    int64           `json:"-" yaml:"-"`
	QuotaIntervalInt int64           `json:"-" yaml:"-"`
	PathTree         path.Tree       `json:"-" yaml:"-"` // APIProduct-level only
}

// An Attribute is a name-value-pair attribute of an API product.
type Attribute struct {
	Name  string `json:"name,omitempty" yaml:"name"`
	Value string `json:"value,omitempty" yaml:"value"`
}

// An OperationGroup holds OperationConfigs
type OperationGroup struct {
	OperationConfigType string            `json:"operationConfigType" yaml:"operationConfigType"`
	OperationConfigs    []OperationConfig `json:"operationConfigs,omitempty" yaml:"operationConfigs"`
}

// An OperationConfig is a group of Operations
type OperationConfig struct {
	ID         string      `json:"-" yaml:"-"`
	APISource  string      `json:"apiSource" yaml:"apiSource"`
	Attributes []Attribute `json:"attributes,omitempty" yaml:"attributes"`
	Operations []Operation `json:"operations" yaml:"operations"`
	Quota      *Quota      `json:"quota" yaml:"quota"`
	PathTree   path.Tree   `json:"-" yaml:"-"`
}

// list of all HTTP verbs
var allMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"}

func (oc *OperationConfig) UnmarshalJSON(data []byte) error {

	type Unmarsh OperationConfig
	var un Unmarsh
	if err := json.Unmarshal(data, &un); err != nil {
		return err
	}
	*oc = OperationConfig(un)

	oc.PathTree = path.NewTree()
	for i, op := range oc.Operations {
		// sort operation's methods lexicographically to make sure
		// the later hashing always yields consistent results
		sort.Strings(oc.Operations[i].Methods)

		methods := op.Methods
		if len(methods) == 0 { // no method in the operation means all methods are allowed
			methods = allMethods
		}
		resourcePath := makeChildPath(op.Resource)
		for _, method := range methods {
			fullPath := append([]string{method}, resourcePath...)
			oc.PathTree.AddChild(fullPath, 0, "x") // value doesn't matter
		}
	}

	// sort the Operations by resource, the uniqueness of which
	// within the same OperationConfig are enforced by Apigee
	sort.Slice(oc.Operations, func(i, j int) bool {
		return oc.Operations[i].Resource < oc.Operations[j].Resource
	})

	oc.ID = fmt.Sprintf("%s-%x", oc.APISource, hash(oc.Operations))

	return nil
}

func (oc *OperationConfig) isValidOperation(api, path, method string, treePath []string, hints bool) (valid bool, hint string) {
	if oc.APISource != api {
		if hints {
			hint = fmt.Sprintf("no api: %s", api)
		}
		return
	}
	valid = oc.PathTree.Find(treePath, 0) != nil
	if !valid && hints {
		hint = fmt.Sprintf("no operation: %s %s", method, path)
	}
	return
}

// An Operation represents methods on a Resource
type Operation struct {
	Methods  []string `json:"methods" yaml:"methods"`
	Resource string   `json:"resource" yaml:"resource"`
}

// A Quota is attached to an OperationConfig
type Quota struct {
	Interval    string `json:"interval,omitempty" yaml:"interval"`
	Limit       string `json:"limit,omitempty" yaml:"limit"`
	TimeUnit    string `json:"timeUnit,omitempty" yaml:"timeUnit"`
	IntervalInt int64  `json:"-" yaml:"-"`
	LimitInt    int64  `json:"-" yaml:"-"`
}

func (q *Quota) UnmarshalJSON(data []byte) error {

	type Unmarsh Quota
	var un Unmarsh
	if err := json.Unmarshal(data, &un); err != nil {
		return err
	}
	*q = Quota(un)

	// normalize nulls from server to empty
	if q.Limit == "null" {
		q.Limit = ""
	}
	if q.Interval == "null" {
		q.Interval = ""
	}
	if q.TimeUnit == "null" {
		q.TimeUnit = ""
	}

	// parse limit from server
	var err error
	if q.Limit != "" {
		q.LimitInt, err = strconv.ParseInt(q.Limit, 10, 64)
		if err != nil {
			log.Errorf("unable to parse quota limit: %#v", q)
		}
	}

	// parse interval from server
	if q.Interval != "" {
		q.IntervalInt, err = strconv.ParseInt(q.Interval, 10, 64)
		if err != nil {
			log.Errorf("unable to parse quota interval: %#v", q)
		}
	}

	return nil
}

// GetBoundAPIs returns an array of api names bound to this product
func (p *APIProduct) GetBoundAPIs() []string {
	keys := make([]string, 0, len(p.APIs))
	for k := range p.APIs {
		keys = append(keys, k)
	}
	return keys
}

func (p *APIProduct) UnmarshalJSON(data []byte) error {

	type Unmarsh APIProduct
	var un Unmarsh
	if err := json.Unmarshal(data, &un); err != nil {
		return err
	}
	*p = APIProduct(un)

	// put Environments into EnvironmentMap
	p.EnvironmentMap = make(map[string]bool)
	for _, e := range p.Environments {
		p.EnvironmentMap[e] = true
	}

	// parse TargetsAttr, if exists
	p.APIs = make(map[string]bool)
	for _, attr := range p.Attributes {
		if attr.Name == TargetsAttr {
			apis := strings.Split(attr.Value, ",")
			for _, t := range apis {
				p.APIs[strings.TrimSpace(t)] = true
			}
			break
		}
	}

	// add APIs from Operations
	if p.OperationGroup != nil {
		for _, oc := range p.OperationGroup.OperationConfigs {
			p.APIs[oc.APISource] = true
		}
	}

	// server returns empty scopes as array with a single empty string, remove for consistency
	if len(p.Scopes) == 1 && p.Scopes[0] == "" {
		p.Scopes = []string{}
	}

	// normalize nulls from server to empty
	if p.QuotaLimit == "null" {
		p.QuotaLimit = ""
	}
	if p.QuotaInterval == "null" {
		p.QuotaInterval = ""
	}
	if p.QuotaTimeUnit == "null" {
		p.QuotaTimeUnit = ""
	}

	// parse limit from server
	var err error
	if p.QuotaLimit != "" {
		p.QuotaLimitInt, err = strconv.ParseInt(p.QuotaLimit, 10, 64)
		if err != nil {
			log.Errorf("x unable to parse quota limit: %#v", p)
		}
	}

	// parse interval from server
	if p.QuotaInterval != "" {
		p.QuotaIntervalInt, err = strconv.ParseInt(p.QuotaInterval, 10, 64)
		if err != nil {
			log.Errorf("unable to parse quota interval: %#v", p)
		}
	}

	p.PathTree = path.NewTree()
	for _, resource := range p.Resources {
		fullPath := makeChildPath(resource)
		p.PathTree.AddChild(fullPath, 0, "x") // value doesn't matter
	}

	return nil
}

// if OperationGroup, all matching OperationConfigs
// if no OperationGroup, the API Product if it matches
func (p *APIProduct) authorize(authContext *auth.Context, api, path, method string, hints bool) (authorizedOps []AuthorizedOperation, hint string) {
	env := authContext.Environment()
	if !p.EnvironmentMap[env] { // the product is not authorized in context environment
		if hints {
			hint = fmt.Sprintf("    incorrect environments: %#v\n", p.Environments)
		}
		return
	}

	// scopes apply for both APIProduct and OperationGroups
	if !p.isValidScopes(authContext) {
		if hints {
			hint = fmt.Sprintf("    incorrect scopes: %s\n", p.Scopes)
		}
		return
	}

	// if OperationGroup is present, OperationConfigs override APIProduct api
	if p.OperationGroup != nil {
		var hintsBuilder strings.Builder
		if hints {
			hintsBuilder.WriteString("    operation configs:\n")
		}
		treePath := append([]string{method}, strings.Split(path, "/")...)
		for i, oc := range p.OperationGroup.OperationConfigs {
			var valid bool
			valid, hint = oc.isValidOperation(api, path, method, treePath, hints)
			if valid {
				// api is already defined outside this block as a string so ao is used here to avoid confusion
				ao := AuthorizedOperation{
					ID:            fmt.Sprintf("%s-%s-%s-%s", p.Name, env, authContext.Application, oc.ID),
					QuotaLimit:    p.QuotaLimitInt,
					QuotaInterval: p.QuotaIntervalInt,
					QuotaTimeUnit: p.QuotaTimeUnit,
				}
				// OperationConfig quota is an override
				if oc.Quota != nil && oc.Quota.LimitInt > 0 {
					ao.QuotaLimit = oc.Quota.LimitInt
					ao.QuotaInterval = oc.Quota.IntervalInt
					ao.QuotaTimeUnit = oc.Quota.TimeUnit
				}
				authorizedOps = append(authorizedOps, ao)
				if hints {
					hintsBuilder.WriteString(fmt.Sprintf("      %d: authorized\n", i))
				}
			} else if hints {
				hintsBuilder.WriteString(fmt.Sprintf("      %d: %s\n", i, hint))
			}
		}
		if hints {
			hint = hintsBuilder.String()
		}

		return
	}

	// no OperationGroup
	var valid bool
	valid, hint = p.isValidAPI(api, path, hints)
	if !valid {
		return
	}

	authorizedOps = append(authorizedOps, AuthorizedOperation{
		ID:            fmt.Sprintf("%s-%s-%s", p.Name, env, authContext.Application),
		QuotaLimit:    p.QuotaLimitInt,
		QuotaInterval: p.QuotaIntervalInt,
		QuotaTimeUnit: p.QuotaTimeUnit,
	})
	hint = "    authorized\n"

	return
}

// true if valid api for API Product
func (p *APIProduct) isValidAPI(api, path string, hints bool) (valid bool, hint string) {
	if p.APIs[api] {
		var resourcePath []string
		if path == "/" {
			resourcePath = []string{"/"}
		} else {
			resourcePath = strings.Split(path, "/")
		}
		valid = p.PathTree.Find(resourcePath, 0) != nil
		if hints {
			hint = fmt.Sprintf("    no path: %s\n", path)
		}
		return
	}
	if hints {
		hint = fmt.Sprintf("    no apis: %s\n", api)
	}
	return
}

// true if any intersect of scopes or no product scopes
// scopes are ignored when APIKey is present
func (p *APIProduct) isValidScopes(ac *auth.Context) bool {
	if ac.APIKey != "" || len(p.Scopes) == 0 {
		return true
	}
	for _, ds := range p.Scopes {
		for _, s := range ac.Scopes {
			if ds == s {
				return true
			}
		}
	}
	return false
}

// A single slash by itself matches any path
func makeChildPath(resource string) []string {
	if resource == "/" {
		resource = "/**"
	}
	return strings.Split(resource, "/")
}

// hash returns a hash signature based on oc.APISource and oc.Operations
func hash(os []Operation) [32]byte {
	data, err := json.Marshal(os)
	if err != nil { // this causes sum of nil to be returned
		log.Errorf("unable to marshal operations, %#v", os)
	}
	return sha256.Sum256(data)
}
