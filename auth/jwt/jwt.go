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

/*
1. When an JWT check comes in, check a LRU cache.
2. If token is cached, return cached token.
3. If token is not cached, check bad token cache, return invalid if present.
4. If token is in neither cache, make a synchronous request to Apigee to refresh it. Update good and bad caches.
*/

package jwt

import (
	"context"
	"fmt"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/cache"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
)

const (
	acceptableSkew               = 10 * time.Second
	defaultCacheTTL              = 30 * time.Minute
	defaultCacheEvictionInterval = 10 * time.Second
	defaultMaxCachedEntries      = 10000
	defaultBadEntryCacheTTL      = 10 * time.Second
	minAllowedRefreshInterval    = 10 * time.Minute
)

// NewVerifier creates a Verifier. Call Start() after creation.
func NewVerifier(opts VerifierOptions) Verifier {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = defaultCacheTTL
	}
	if opts.CacheEvictionInterval == 0 {
		opts.CacheEvictionInterval = defaultCacheEvictionInterval
	}
	if opts.MaxCachedEntries == 0 {
		opts.MaxCachedEntries = defaultMaxCachedEntries
	}
	return &verifier{
		providers: opts.Providers,
		cache:     cache.NewLRU(opts.CacheTTL, opts.CacheEvictionInterval, int32(opts.MaxCachedEntries)),
		knownBad:  cache.NewLRU(defaultBadEntryCacheTTL, opts.CacheEvictionInterval, 100),
	}
}

type Verifier interface {
	Start()
	Stop()
	AddProvider(provider Provider)
	EnsureProvidersLoaded(ctx context.Context) error
	Parse(raw string, provider Provider) (map[string]interface{}, error)
}

type Provider struct {
	JWKSURL string
	Refresh time.Duration
}

type VerifierOptions struct {
	Providers             []Provider
	CacheTTL              time.Duration
	CacheEvictionInterval time.Duration
	MaxCachedEntries      int
}

// An verifier handles all of the various JWT authentication functionality.
type verifier struct {
	jwks          *jwk.AutoRefresh
	cancelContext context.Context
	cancelFunc    context.CancelFunc
	providers     []Provider
	cache         cache.ExpiringCache
	knownBad      cache.ExpiringCache
}

// Start begins JWKS polling. Call Stop() when done.
func (a *verifier) Start() {
	a.cancelContext, a.cancelFunc = context.WithCancel(context.Background())
	a.jwks = jwk.NewAutoRefresh(a.cancelContext)

	// initialize JWKs
	providers := a.providers
	a.providers = []Provider{}
	for _, p := range providers {
		a.AddProvider(p)
	}

	ch := make(chan jwk.AutoRefreshError)
	a.jwks.ErrorSink(ch)

	go func() {
		for {
			select {
			case <-a.cancelContext.Done():
				close(ch)
				return
			case fetchError := <-ch:
				log.Errorf("fetching jwks from %s error: %v", fetchError.URL, fetchError.Error)
			}
		}
	}()
}

// EnsureProvidersLoaded ensures all JWKs certs have been retrieved for the first time.
func (a *verifier) EnsureProvidersLoaded(ctx context.Context) error {
	for i := range a.providers {
		p := a.providers[i]
		if _, err := a.jwks.Refresh(ctx, p.JWKSURL); err != nil {
			return err
		}
	}
	return nil
}

// Stop all background tasks.
func (a *verifier) Stop() {
	if a != nil && a.cancelFunc != nil {
		a.cancelFunc()
	}
}

// AddProvider adds a JWKs provider
func (a *verifier) AddProvider(provider Provider) {
	// JWKs url could be shared amongst providers, find min refresh
	jwksConfigured := false
	minRefresh := provider.Refresh
	for _, p := range a.providers {
		if p.JWKSURL == provider.JWKSURL {
			jwksConfigured = true
			if p.Refresh > 0 && p.Refresh < minRefresh {
				minRefresh = p.Refresh
			}
		}
	}
	a.providers = append(a.providers, provider)

	if !jwksConfigured || minRefresh != provider.Refresh {
		options := []jwk.AutoRefreshOption{
			jwk.WithFetchBackoff(backoff.Exponential()),
		}
		if minRefresh > 0 {
			if minRefresh < minAllowedRefreshInterval {
				minRefresh = minAllowedRefreshInterval
			}
			options = append(options, jwk.WithMinRefreshInterval(minRefresh))
		}
		a.jwks.Configure(provider.JWKSURL, options...)
	}
}

func (a *verifier) fetchJWKs(provider Provider) (jwk.Set, error) {
	if provider.JWKSURL != "" {
		return a.jwks.Fetch(a.cancelContext, provider.JWKSURL)
	}
	return nil, nil
}

// Parse and verify a JWT
// if provider has no JWKSURL, the cert will not be verified
func (a *verifier) Parse(raw string, provider Provider) (map[string]interface{}, error) {
	cacheKey := fmt.Sprintf("%s-%s", provider.JWKSURL, raw)
	if cached, ok := a.knownBad.Get(cacheKey); ok {
		return nil, cached.(error)
	}

	if cached, ok := a.cache.Get(cacheKey); ok {
		return cached.(map[string]interface{}), nil
	}

	cacheKnownBad := func(err error) (map[string]interface{}, error) {
		a.knownBad.Set(cacheKey, err)
		return nil, err
	}

	parseOptions := []jwt.ParseOption{jwt.WithAcceptableSkew(acceptableSkew), jwt.WithValidate(true)}

	if provider.JWKSURL != "" {
		set, err := a.fetchJWKs(provider)
		if err != nil {
			return nil, err
		}
		if set != nil {
			parseOptions = append(parseOptions, jwt.WithKeySet(set))
		}
	}

	token, err := jwt.Parse([]byte(raw), parseOptions...)
	if err != nil {
		return cacheKnownBad(errors.Wrap(err, "jwt.Parse"))
	}

	claims, err := token.AsMap(a.cancelContext)
	if err != nil {
		return cacheKnownBad(errors.Wrap(err, "failed to parse claims"))
	}

	exp := token.Expiration()
	if exp.After(time.Now()) {
		a.cache.SetWithExpiration(cacheKey, claims, time.Until(exp))
	} else if exp.IsZero() {
		a.cache.Set(cacheKey, claims)
	}

	return claims, nil
}
