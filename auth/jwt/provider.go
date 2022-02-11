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
	"fmt"
	"io/ioutil"
	"net/http"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/pkg/errors"
	"golang.org/x/sync/singleflight"
	"gopkg.in/square/go-jose.v2"
)

type providerSet struct {
	sync.RWMutex
	providers []provider
	jwksCache jwksCache
}

func (p *providerSet) GetJWKs(pr Provider) (*jose.JSONWebKeySet, error) {
	return p.jwksCache.Get(pr.JWKSURL)
}

// TODO: do proper polling w/ Refresh intervals
func (p *providerSet) Start(ctx context.Context) {
	p.jwksCache = jwksCache{}
	// ensure providers are registered to this set
	for _, ps := range p.providers {
		ps.providerSet = p
	}

	go func() {
		select {
		case <-ctx.Done():
		case <-time.After(minAllowedRefreshInterval):
			err := p.Refresh(ctx)
			if err != nil {
				log.Errorf("refresh: %v", err)
			}
		}
	}()
}

// Fetch jwks for all providers
func (p *providerSet) Refresh(ctx context.Context) error {
	wg := sync.WaitGroup{}
	errSync := sync.Mutex{}
	var errors error
	for i := range p.providers {
		p := p.providers[i]
		wg.Add(1)
		go func() {
			if _, err := p.GetJWKs(ctx); err != nil {
				errSync.Lock()
				errors = errorset.Append(errors, err)
				errSync.Unlock()
			}
			wg.Done()
		}()
	}
	wg.Wait()
	return errors
}

func (p *providerSet) Add(pr Provider) {
	p.RWMutex.Lock()
	internalP := provider{
		Provider:    &pr,
		providerSet: p,
	}
	p.providers = append(p.providers, internalP)
	p.RWMutex.Unlock()

	// // JWKs url may be shared, find min refresh
	// jwksConfigured := false
	// minRefresh := provider.Refresh
	// for _, p := range p.providers {
	// 	if p.JWKSURL == provider.JWKSURL {
	// 		jwksConfigured = true
	// 		if p.Refresh > 0 && p.Refresh < minRefresh {
	// 			minRefresh = p.Refresh
	// 		}
	// 	}
	// }

	// if !jwksConfigured || minRefresh != provider.Refresh {
	// 	if minRefresh < minAllowedRefreshInterval {
	// 		minRefresh = minAllowedRefreshInterval
	// 	}
	// }
}

// external
type Provider struct {
	JWKSURL string
	Refresh time.Duration
}

// internal
type provider struct {
	*Provider
	providerSet *providerSet
}

// GET if not present, else return from cache
func (p *provider) GetJWKs(ctx context.Context) (*jose.JSONWebKeySet, error) {
	if p.JWKSURL == "" {
		return nil, nil
	}

	return p.providerSet.jwksCache.Get(p.JWKSURL)
}

// TODO: backoff
type jwksCache struct {
	cache      sync.Map
	herdBuster singleflight.Group
}

func (j *jwksCache) Get(url string) (*jose.JSONWebKeySet, error) {

	if r, ok := j.cache.Load(url); ok {
		switch r := r.(type) {
		case *jose.JSONWebKeySet:
			return r, nil
		case error:
			return nil, r
		}
	}

	jwks, err, _ := j.herdBuster.Do("", func() (interface{}, error) {
		var jwks *jose.JSONWebKeySet

		resp, err := http.Get(url)
		if err == nil {
			var body []byte
			body, err = ioutil.ReadAll(resp.Body)
			if err == nil {
				err = json.Unmarshal(body, jwks)
			}
		}

		if err != nil {
			err = errors.Wrap(err, fmt.Sprintf("fetching jwks from %q", url))
			j.cache.Store(url, err)
			return nil, err
		}

		j.cache.Store(url, jwks)
		return jwks, nil
	})

	if err != nil {
		return nil, err
	} else {
		return jwks.(*jose.JSONWebKeySet), err
	}
}
