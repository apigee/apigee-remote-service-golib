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
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/pkg/errors"
)

const (
	apiProductListKey  = "api_product_list"
	clientIDKey        = "client_id"
	applicationNameKey = "application_name"
	scopeKey           = "scope"
	developerEmailKey  = "developer_email"
	accessTokenKey     = "access_token"
)

// A Context wraps all the various information that is needed to make requests
// through the Apigee adapter.
type Context struct {
	context.Context
	ClientID       string
	AccessToken    string
	Application    string
	APIProducts    []string
	Expires        time.Time
	DeveloperEmail string
	Scopes         []string
	APIKey         string
}

// if claims can't be processed, returns error and sets no fields
// claims map must not be written to: treat as const
func (a *Context) setClaims(claims map[string]interface{}) error {
	if claims[apiProductListKey] == nil {
		return ErrMissingProductListClaim
	}

	products, err := parseArrayOfStrings(claims[apiProductListKey])
	if err != nil {
		return errors.Wrapf(err, "unable to interpret api_product_list: %v", claims[apiProductListKey])
	}

	var scope string
	var ok bool
	if scope, ok = claims[scopeKey].(string); !ok && claims[scopeKey] != nil { // nil is ok
		return fmt.Errorf("unable to interpret %s: %v", scopeKey, claims[scopeKey])
	}
	scopes := strings.Split(scope, " ")

	if _, ok := claims[clientIDKey].(string); !ok {
		return fmt.Errorf("unable to interpret %s: %v", clientIDKey, claims[clientIDKey])
	}
	if _, ok := claims[applicationNameKey].(string); !ok {
		return fmt.Errorf("unable to interpret %s: %v", applicationNameKey, claims[applicationNameKey])
	}
	a.ClientID = claims[clientIDKey].(string)
	a.Application = claims[applicationNameKey].(string)
	a.APIProducts = products
	a.Scopes = scopes
	a.Expires, _ = claims[developerEmailKey].(time.Time)
	a.DeveloperEmail, _ = claims[developerEmailKey].(string)
	a.AccessToken, _ = claims[accessTokenKey].(string)

	return nil
}

func (a *Context) isAuthenticated() bool {
	return a.ClientID != ""
}

func parseArrayOfStrings(obj interface{}) (results []string, err error) {
	if obj == nil {
		// nil is ok
	} else if arr, ok := obj.([]string); ok {
		results = arr
	} else if arr, ok := obj.([]interface{}); ok {
		for _, unk := range arr {
			if obj, ok := unk.(string); ok {
				results = append(results, obj)
			} else {
				err = fmt.Errorf("unable to interpret: %v", unk)
				break
			}
		}
	} else if str, ok := obj.(string); ok {
		err = json.Unmarshal([]byte(str), &results)
	} else {
		err = fmt.Errorf("unable to interpret: %v", obj)
	}
	return
}
