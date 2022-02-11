// Copyright 2022 Google LLC
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

package jwt

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"time"

	"gopkg.in/square/go-jose.v2"
)

// TODO: configure http client
// TODO: JWKS must be cached, renewed, etc.

type Provider struct {
	JWKSURL string
	Refresh time.Duration
}

// TODO: GET if not present, otherwise return from cache
func (p *Provider) Fetch(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if p.JWKSURL == "" {
		return nil, nil
	}

	resp, err := http.Get(p.JWKSURL)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var set jose.JSONWebKeySet
	err = json.Unmarshal(body, &set)
	if err != nil {
		return nil, err
	}
	return &set, nil
}
