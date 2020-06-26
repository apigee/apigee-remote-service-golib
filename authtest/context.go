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

package authtest

import (
	"fmt"
	"net/url"
)

// Context implements the context.Context interface and is to be used in tests.
type Context struct {
	internalAPI      *url.URL
	remoteServiceAPI *url.URL
	orgName          string
	envName          string
}

// NewContext constructs a new test context.
func NewContext(base string) *Context {
	u, err := url.Parse(base)
	if err != nil {
		panic(fmt.Sprintf("Could not parse URL: %s", base))
	}
	return &Context{
		internalAPI:      u,
		remoteServiceAPI: u,
	}
}

// InternalAPI gets a URL base to send HTTP requests to.
func (c *Context) InternalAPI() *url.URL { return c.internalAPI }

// RemoteServiceAPI gets a URL base to send HTTP requests to.
func (c *Context) RemoteServiceAPI() *url.URL { return c.remoteServiceAPI }

// Organization gets this context's organization.
func (c *Context) Organization() string { return c.orgName }

// Environment gets this context's environment.
func (c *Context) Environment() string { return c.envName }

// SetOrganization sets this context's organization.
func (c *Context) SetOrganization(o string) { c.orgName = o }

// SetEnvironment sets this context's environment.
func (c *Context) SetEnvironment(e string) { c.envName = e }
