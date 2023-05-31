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
	"crypto/md5"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
)

// APIResponse is the response from the Apigee products API
type APIResponse struct {
	APIProducts []APIProduct `json:"apiProduct"`
}

// An APIProduct is an Apigee API product. See the Apigee docs for details:
// https://docs.apigee.com/api-platform/publish/what-api-product
type APIProduct struct {
	Attributes       []Attribute     `json:"attributes,omitempty"`
	Description      string          `json:"description,omitempty"`
	DisplayName      string          `json:"displayName,omitempty"`
	Environments     []string        `json:"environments,omitempty"`
	Name             string          `json:"name,omitempty"`
	OperationGroup   *OperationGroup `json:"operationGroup,omitempty"`
	Proxies          []string        `json:"proxies"`
	QuotaLimit       string          `json:"quota,omitempty"`
	QuotaInterval    string          `json:"quotaInterval,omitempty"`
	QuotaTimeUnit    string          `json:"quotaTimeUnit,omitempty"`
	Resources        []string        `json:"apiResources"`
	Scopes           []string        `json:"scopes"`
	APIs             []string
	EnvironmentMap   map[string]struct{}
	QuotaLimitInt    int64
	QuotaIntervalInt int64
	resourceRegexps  []*regexp.Regexp // APIProduct-level only
}

// An Attribute is a name-value-pair attribute of an API product.
type Attribute struct {
	Name  string `json:"name,omitempty"`
	Value string `json:"value,omitempty"`
}

// An OperationGroup holds OperationConfigs
type OperationGroup struct {
	OperationConfigType string            `json:"operationConfigType"`
	OperationConfigs    []OperationConfig `json:"operationConfigs,omitempty"`
}

// An OperationConfig is a group of Operations
type OperationConfig struct {
	ID                      string      `json:"-"`
	APISource               string      `json:"apiSource"`
	Attributes              []Attribute `json:"attributes,omitempty"`
	Operations              []Operation `json:"operations"`
	Quota                   *Quota      `json:"quota"`
	resourceRegexpsByMethod map[string][]*regexp.Regexp
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

	oc.resourceRegexpsByMethod = map[string][]*regexp.Regexp{}
	for i, op := range oc.Operations {
		// sort operation's methods lexicographically to make sure
		// the later hashing always yields consistent results
		sort.Strings(oc.Operations[i].Methods)

		reg, err := makeResourceRegex(op.Resource)
		if err != nil {
			log.Errorf("unable to create resource matcher: %#v", op.Resource)
			continue
		}
		methods := op.Methods
		if len(methods) == 0 { // no method in the operation means all methods are allowed
			methods = allMethods
		}
		for _, method := range methods {
			oc.resourceRegexpsByMethod[method] = append(oc.resourceRegexpsByMethod[method], reg)
		}
	}

	// sort the Operations by resource, the uniqueness of which
	// within the same OperationConfig are enforced by Apigee
	sort.Slice(oc.Operations, func(i, j int) bool {
		return oc.Operations[i].Resource < oc.Operations[j].Resource
	})

	oc.ID = fmt.Sprintf("%s-%x", oc.APISource, md5hash(oc.Operations))

	return nil
}

func (oc *OperationConfig) isValidOperation(api, path, method string, hints bool) (valid bool, hint string) {
	if oc.APISource != api {
		if hints {
			hint = fmt.Sprintf("no api: %s", api)
		}
		return
	}
	regexps, ok := oc.resourceRegexpsByMethod[method]
	if !ok {
		if hints {
			hint = fmt.Sprintf("no method: %s", method)
		}
		return
	}
	for _, regexp := range regexps {
		if regexp.MatchString(path) {
			valid = true
			break
		}
	}
	if !valid && hints {
		hint = fmt.Sprintf("no path: %s", path)
	}
	return
}

// An Operation represents methods on a Resource
type Operation struct {
	Methods  []string `json:"methods"`
	Resource string   `json:"resource"`
}

// A Quota is attached to an OperationConfig
type Quota struct {
	Interval    string `json:"interval,omitempty"`
	Limit       string `json:"limit,omitempty"`
	TimeUnit    string `json:"timeUnit,omitempty"`
	IntervalInt int64
	LimitInt    int64
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
	return p.APIs
}

func (p *APIProduct) UnmarshalJSON(data []byte) error {

	type Unmarsh APIProduct
	var un Unmarsh
	if err := json.Unmarshal(data, &un); err != nil {
		return err
	}
	*p = APIProduct(un)

	// put Environments into EnvironmentMap
	p.EnvironmentMap = make(map[string]struct{})
	for _, e := range p.Environments {
		p.EnvironmentMap[e] = struct{}{}
	}

	// parse TargetsAttr, if exists
	p.APIs = []string{}
	for _, attr := range p.Attributes {
		if attr.Name == TargetsAttr {
			apis := strings.Split(attr.Value, ",")
			for _, t := range apis {
				p.APIs = append(p.APIs, strings.TrimSpace(t))
			}
			break
		}
	}

	// add APIs from Operations
	if p.OperationGroup != nil {
		for _, oc := range p.OperationGroup.OperationConfigs {
			p.APIs = append(p.APIs, oc.APISource)
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

	for _, resource := range p.Resources {
		reg, err := makeResourceRegex(resource)
		if err != nil {
			log.Errorf("unable to create resource matcher: %#v", p)
			continue
		}
		p.resourceRegexps = append(p.resourceRegexps, reg)
	}

	return nil
}

// if OperationGroup, all matching OperationConfigs
// if no OperationGroup, the API Product if it matches
func (p *APIProduct) authorize(authContext *auth.Context, api, path, method string, hints bool) (authorizedOps []AuthorizedOperation, hint string) {
	env := authContext.Environment()
	if _, ok := p.EnvironmentMap[env]; !ok { // the product is not authorized in context environment
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
		for i, oc := range p.OperationGroup.OperationConfigs {
			var valid bool
			valid, hint = oc.isValidOperation(api, path, method, hints)
			if valid {
				ao := AuthorizedOperation{
					ID:            fmt.Sprintf("%s-%s-%s-%s", p.Name, env, authContext.Application, oc.APISource),
					QuotaLimit:    p.QuotaLimitInt,
					QuotaInterval: p.QuotaIntervalInt,
					QuotaTimeUnit: p.QuotaTimeUnit,
				}
				// OperationConfig quota is an override
				if oc.Quota != nil && oc.Quota.LimitInt > 0 {
					ao.ID = fmt.Sprintf("%s-%s-%s-%s", p.Name, env, authContext.Application, oc.ID)
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
	valid, hint = p.isValidOperation(api, path, hints)
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
func (p *APIProduct) isValidOperation(api, path string, hints bool) (valid bool, hint string) {
	for _, v := range p.APIs {
		if v == api {
			for _, reg := range p.resourceRegexps {
				if reg.MatchString(path) {
					valid = true
					return
				}
			}
			if hints {
				hint = fmt.Sprintf("    no path: %s\n", path)
			}
			return
		}
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

// - A single slash by itself matches any path
// - * is valid anywhere and matches within a segment (between slashes)
// - ** is valid only at the end and matches anything to EOL
func makeResourceRegex(resource string) (*regexp.Regexp, error) {

	if resource == "/" {
		return regexp.Compile(".*")
	}

	// only allow ** as suffix
	doubleStarIndex := strings.Index(resource, "**")
	if doubleStarIndex >= 0 && doubleStarIndex != len(resource)-2 {
		return nil, fmt.Errorf("bad resource specification")
	}

	// remove ** suffix if exists
	pattern := resource
	if doubleStarIndex >= 0 {
		pattern = pattern[:len(pattern)-2]
	}

	// let * = any non-slash
	pattern = strings.Replace(pattern, "*", "[^/]*", -1)

	// if ** suffix, allow anything at end
	if doubleStarIndex >= 0 {
		pattern = pattern + ".*"
	}

	return regexp.Compile("^" + pattern + "$")
}

// md5hash returns a md5 signature based on oc.APISource and oc.Operations
func md5hash(os []Operation) [16]byte {
	data, err := json.Marshal(os)
	if err != nil { // this causes md5.Sum(nil) to be returned
		log.Errorf("unable to marshal operations, %#v", os)
	}
	return md5.Sum(data)
}
