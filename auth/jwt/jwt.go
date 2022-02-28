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
	"net/http"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/cache"
	"github.com/pkg/errors"
	"gopkg.in/square/go-jose.v2/jwt"
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
		jwksManager: &jwksManager{
			providers: opts.Providers,
			client:    opts.Client,
		},
		cache:    cache.NewLRU(opts.CacheTTL, opts.CacheEvictionInterval, int32(opts.MaxCachedEntries)),
		knownBad: cache.NewLRU(defaultBadEntryCacheTTL, opts.CacheEvictionInterval, 100),
	}
}

type Verifier interface {
	Start()
	Stop()
	Parse(raw string, provider Provider) (map[string]interface{}, error)
}

type VerifierOptions struct {
	Providers             []Provider
	CacheTTL              time.Duration
	CacheEvictionInterval time.Duration
	MaxCachedEntries      int
	Client                *http.Client
}

type Provider struct {
	JWKSURL string
	Refresh time.Duration
}

// An verifier handles all of the various JWT authentication functionality.
type verifier struct {
	cancelContext context.Context
	cancelFunc    context.CancelFunc
	cache         cache.ExpiringCache // key -> JWT
	knownBad      cache.ExpiringCache // key -> error
	jwksManager   *jwksManager
}

// Start begins JWKS polling. Call Stop() when done.
func (v *verifier) Start() {
	v.cancelContext, v.cancelFunc = context.WithCancel(context.Background())
	v.jwksManager.Start(v.cancelContext)
}

// Stop all background tasks.
func (v *verifier) Stop() {
	if v != nil && v.cancelFunc != nil {
		v.cancelFunc()
	}
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

	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return cacheKnownBad(errors.Wrap(err, "jwt.Parse"))
	}

	getClaims := func(tok *jwt.JSONWebToken) (map[string]interface{}, error) {
		var claims map[string]interface{}
		if provider.JWKSURL == "" {
			err = tok.UnsafeClaimsWithoutVerification(&claims)
			return claims, err
		}

		ks, err := v.jwksManager.Get(v.cancelContext, provider.JWKSURL)
		if err != nil {
			return nil, err
		}

		err = tok.Claims(ks, &claims)
		return claims, err
	}
	claims, err := getClaims(tok)
	if err != nil {
		return cacheKnownBad(errors.Wrap(err, "jwt.Parse"))
	}

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	now := time.Now()
	var ttl time.Duration
	if exp, ok := claims["exp"].(float64); ok {
		ttl = time.Unix(int64(exp), 0).Add(acceptableSkew).Sub(now)
		if ttl <= 0 {
			err := fmt.Errorf("token is expired per exp claim")
			return cacheKnownBad(errors.Wrap(err, "jwt.Parse"))
		}
	}

	if iss, ok := claims["iat"].(float64); ok {
		if now.Add(acceptableSkew).Before(time.Unix(int64(iss), 0)) {
			err := fmt.Errorf("token used before issued per iat claim")
			return nil, errors.Wrap(err, "jwt.Parse")
		}
	}

	if nbf, ok := claims["nbf"].(float64); ok {
		if now.Add(acceptableSkew).Before(time.Unix(int64(nbf), 0)) {
			err := fmt.Errorf("token is not valid yet per nbf claim")
			return nil, errors.Wrap(err, "jwt.Parse")
		}
	}

	if ttl > 0 {
		v.cache.SetWithExpiration(cacheKey, claims, ttl)
	} else {
		v.cache.Set(cacheKey, claims)
	}

	return claims, nil
}
