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

// import (
// 	"context"
// 	"encoding/json"
// 	"time"

// 	"github.com/apigee/apigee-remote-service-golib/v2/log"
// 	"github.com/lestrrat-go/backoff/v2"
// 	"github.com/lestrrat-go/jwx/jwk"
// 	"gopkg.in/square/go-jose.v2"
// )

// /*
// Replacement for standard jwksManager. To enable:
// 1. run `go get github.com/lestrrat-go/jwx/jwk`
// 1. run `go get github.com/lestrrat-go/backoff/v2`
// 2. change instantiation in jwt.go
// */

// type lestrrat_jwksManager struct {
// 	providers []Provider
// 	jwks      *jwk.AutoRefresh
// }

// // stop by canceling passed context
// func (j *lestrrat_jwksManager) Start(ctx context.Context) {
// 	refreshRates := map[string]time.Duration{}
// 	for _, p := range j.providers {
// 		refreshRates[p.JWKSURL] = minAllowedRefresh(p.Refresh, refreshRates[p.JWKSURL])
// 	}

// 	j.jwks = jwk.NewAutoRefresh(ctx)
// 	for _, p := range j.providers {
// 		options := []jwk.AutoRefreshOption{
// 			jwk.WithFetchBackoff(backoff.Exponential()),
// 			jwk.WithMinRefreshInterval(refreshRates[p.JWKSURL]),
// 		}
// 		j.jwks.Configure(p.JWKSURL, options...)
// 	}

// 	ch := make(chan jwk.AutoRefreshError)
// 	j.jwks.ErrorSink(ch)

// 	go func() {
// 		for {
// 			select {
// 			case <-ctx.Done():
// 				close(ch)
// 				return
// 			case fetchError := <-ch:
// 				log.Errorf("fetching jwks from %q: %v", fetchError.URL, fetchError.Error)
// 			}
// 		}
// 	}()
// }

// func (j *lestrrat_jwksManager) Get(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {
// 	s, err := j.jwks.Fetch(ctx, url)
// 	if err != nil {
// 		return nil, err
// 	}

// 	b, err := json.Marshal(s)
// 	if err != nil {
// 		return nil, err
// 	}

// 	// translate to jose
// 	var keys jose.JSONWebKeySet
// 	err = json.Unmarshal(b, &keys)

// 	return &keys, err
// }
