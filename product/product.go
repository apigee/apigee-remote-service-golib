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
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/apigee/apigee-remote-service-golib/log"
)

// APIResponse is the response from the Apigee products API
type APIResponse struct {
	APIProducts []APIProduct `json:"apiProduct"`
}

// An APIProduct is an Apigee API product. See the Apigee docs for details:
// https://docs.apigee.com/api-platform/publish/what-api-product
type APIProduct struct {
	Attributes       []Attribute     `json:"attributes,omitempty"`
	CreatedAt        int64           `json:"createdAt,omitempty"` // note: empty from products jar
	CreatedBy        string          `json:"createdBy,omitempty"`
	Description      string          `json:"description,omitempty"`
	DisplayName      string          `json:"displayName,omitempty"`
	Environments     []string        `json:"environments,omitempty"`
	LastModifiedAt   int64           `json:"lastModifiedAt,omitempty"` // note: empty from products jar
	LastModifiedBy   string          `json:"lastModifiedBy,omitempty"`
	Name             string          `json:"name,omitempty"`
	OperationGroup   *OperationGroup `json:"operationGroup,omitempty"`
	QuotaLimit       string          `json:"quota,omitempty"`
	QuotaInterval    string          `json:"quotaInterval,omitempty"`
	QuotaTimeUnit    string          `json:"quotaTimeUnit,omitempty"`
	Resources        []string        `json:"apiResources"`
	Scopes           []string        `json:"scopes"`
	Targets          []string
	QuotaLimitInt    int64
	QuotaIntervalInt int64
	resourceRegexps  []*regexp.Regexp
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
	APISource  string      `json:"apiSource"`
	Operations []Operation `json:"operations"`
	Quota      *Quota      `json:"quota"`
}

// An Operation represents methods on a Resource
type Operation struct {
	Resource string   `json:"resource"`
	Methods  []string `json:"methods"`
}

// A Quota is attached to an OperationConfig
type Quota struct {
	Limit    string `json:"limit,omitempty"`
	Interval string `json:"interval,omitempty"`
	TimeUnit string `json:"timeUnit,omitempty"`
}

// true if valid target for API Product
func (p *APIProduct) isValidTarget(api string) bool {
	for _, target := range p.Targets {
		if target == api {
			return true
		}
	}
	return false
}

// true if valid path for API Product
func (p *APIProduct) isValidPath(requestPath string) bool {
	for _, reg := range p.resourceRegexps {
		if reg.MatchString(requestPath) {
			return true
		}
	}
	return false
}

// true if any intersect of scopes (or no product scopes)
func (p *APIProduct) isValidScopes(scopes []string) bool {
	if len(p.Scopes) == 0 {
		return true
	}
	for _, ds := range p.Scopes {
		for _, s := range scopes {
			if ds == s {
				return true
			}
		}
	}
	return false
}

// GetTargetsAttribute returns a pointer to the target attribute or nil
func (p *APIProduct) GetTargetsAttribute() *Attribute {
	for _, attr := range p.Attributes {
		if attr.Name == TargetsAttr {
			return &attr
		}
	}
	return nil
}

// GetBoundTargets returns an array of target names bound to this product
func (p *APIProduct) GetBoundTargets() []string {
	attr := p.GetTargetsAttribute()
	if attr != nil {
		return strings.Split(attr.Value, ",")
	}
	return nil
}

// called after JSON parsing
func (p *APIProduct) parse() {

	if attr := p.GetTargetsAttribute(); attr != nil {
		targets := strings.Split(attr.Value, ",")
		for _, t := range targets {
			p.Targets = append(p.Targets, strings.TrimSpace(t))
		}
	}

	// server returns empty scopes as array with a single empty string, remove for consistency
	if len(p.Scopes) == 1 && p.Scopes[0] == "" {
		p.Scopes = []string{}
	}

	// parse limit from server
	var err error
	if p.QuotaLimit != "" && p.QuotaInterval != "null" {
		p.QuotaLimitInt, err = strconv.ParseInt(p.QuotaLimit, 10, 64)
		if err != nil {
			log.Errorf("unable to parse quota limit: %#v", p)
		}
	}

	// parse interval from server
	if p.QuotaInterval != "" && p.QuotaInterval != "null" {
		p.QuotaIntervalInt, err = strconv.ParseInt(p.QuotaInterval, 10, 64)
		if err != nil {
			log.Errorf("unable to parse quota interval: %#v", p)
		}
	}

	// normalize null from server to empty
	if p.QuotaTimeUnit == "null" {
		p.QuotaTimeUnit = ""
	}

	p.resolveResourceMatchers()
}

// generate matchers for resources (path)
func (p *APIProduct) resolveResourceMatchers() {
	for _, resource := range p.Resources {
		reg, err := makeResourceRegex(resource)
		if err != nil {
			log.Errorf("unable to create resource matcher: %#v", p)
			continue
		}
		p.resourceRegexps = append(p.resourceRegexps, reg)
	}
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
