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

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"golang.org/x/sync/singleflight"
	"gopkg.in/square/go-jose.v2"
)

type jwksCache interface {
	Start(ctx context.Context)
	Get(ctx context.Context, url string) (*jose.JSONWebKeySet, error)
}

// initialize with providers and call Start() to populate
// call WaitForLoad() to wait
type jwksManager struct {
	providers  []Provider
	client     *http.Client
	cache      sync.Map // URL -> jwks | error
	herdBuster singleflight.Group
	refreshers []util.Looper
}

// stop by canceling passed context
func (j *jwksManager) Start(ctx context.Context) {

	refreshRates := map[string]time.Duration{}
	for _, p := range j.providers {
		refreshRates[p.JWKSURL] = minAllowedRefresh(p.Refresh, refreshRates[p.JWKSURL])
	}
	j.startRefreshing(ctx, refreshRates)
}

func (j *jwksManager) startRefreshing(ctx context.Context, refreshRates map[string]time.Duration) {
	for url, rate := range refreshRates {
		l := util.Looper{
			Backoff: util.DefaultExponentialBackoff(),
		}
		j.refreshers = append(j.refreshers, l)

		work := func(ctx context.Context) error {
			_, err := j.fetch(ctx, url)
			return err
		}
		errH := func(err error) error {
			log.Errorf("fetching jwks from %q: %v", url, err)
			return nil
		}

		l.Start(ctx, work, rate, errH)
	}
}

func minAllowedRefresh(a, b time.Duration) time.Duration {
	min := func(a, b time.Duration) time.Duration {
		if a <= b {
			return a
		}
		return b
	}
	max := func(a, b time.Duration) time.Duration {
		if a <= b {
			return b
		}
		return a
	}
	return max(min(a, b), minAllowedRefreshInterval)
}

// Get the JWKS for the url
// If not in cache, fetches from source
func (j *jwksManager) Get(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {

	if r, ok := j.cache.Load(url); ok {
		switch r := r.(type) {
		case *jose.JSONWebKeySet:
			return r, nil
		case error:
			return nil, r
		}
	}

	return j.fetch(ctx, url)
}

// Fetches the JWKS for the url from the source.
// Does herdbusting and caching.
func (j *jwksManager) fetch(ctx context.Context, url string) (*jose.JSONWebKeySet, error) {

	fetch := func() (interface{}, error) {
		log.Debugf("fetching jwks %s", url)
		req, err := http.NewRequest(http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := j.client.Do(req.WithContext(ctx))
		var jwks jose.JSONWebKeySet
		if err == nil {
			if resp.StatusCode == 200 {
				var body []byte
				body, err = ioutil.ReadAll(resp.Body)
				if err == nil {
					err = json.Unmarshal(body, &jwks)
					if err != nil {
						err = fmt.Errorf("fetch %q unmarshal %q: %v", url, body, err)
					}
				}
			} else {
				err = fmt.Errorf("fetch %q status %q", url, resp.Status)
			}
		}
		if err != nil {
			j.cache.Store(url, err)
		} else {
			j.cache.Store(url, &jwks)
			log.Debugf("cached jwks %s: %v", url, &jwks)
		}
		return &jwks, err
	}

	res, err, _ := j.herdBuster.Do(url, fetch)
	if err != nil {
		return nil, err
	} else {
		return res.(*jose.JSONWebKeySet), nil
	}
}
