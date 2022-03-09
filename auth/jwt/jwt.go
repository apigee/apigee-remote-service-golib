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

var (
	ErrExp = errors.New("token is expired per exp claim")
	ErrNbf = errors.New("token is not valid yet per nbf claim")
	ErrIat = errors.New("token used before issued per iat claim")
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

// Parse and verify a JWT against a provider's certificates.
// If provider has no JWKSURL, there will be no cert verification.
// Time claims (nbf, exp, iat) are verified against now +/- acceptableSkew and an inappropriate
// value will result in an error, other claims are not checked.
func (v *verifier) Parse(raw string, provider Provider) (map[string]interface{}, error) {
	cacheKey := fmt.Sprintf("%s-%s", provider.JWKSURL, raw)
	if cached, ok := v.knownBad.Get(cacheKey); ok {
		return nil, cached.(error)
	}

	if cached, ok := v.cache.Get(cacheKey); ok {
		return cached.(map[string]interface{}), nil
	}

	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return v.cacheKnownBad(cacheKey, errors.Wrap(err, "jwt.Parse"))
	}

	registeredClaims, claimsMap, err := v.claims(provider, tok)
	if err != nil {
		return v.cacheKnownBad(cacheKey, errors.Wrap(err, "jwt.Parse"))
	}

	now := time.Now()
	err = registeredClaims.ValidateWithLeeway(jwt.Expected{}.WithTime(now), acceptableSkew)
	switch err {
	case jwt.ErrExpired:
		err = ErrExp
	case jwt.ErrNotValidYet:
		err = ErrNbf
	case jwt.ErrIssuedInTheFuture:
		err = ErrIat
	case nil:
		// ok
	default:
		err = fmt.Errorf("unexpected err: %s", err)
	}
	if err != nil {
		return v.cacheKnownBad(cacheKey, errors.Wrap(err, "jwt.Parse"))
	}

	ttl := registeredClaims.Expiry.Time().Add(acceptableSkew).Sub(now)
	if ttl > 0 {
		v.cache.SetWithExpiration(cacheKey, claimsMap, ttl)
	} else {
		v.cache.Set(cacheKey, claimsMap)
	}

	return claimsMap, nil
}

// put an error in the known bad cache
func (v *verifier) cacheKnownBad(cacheKey string, err error) (map[string]interface{}, error) {
	v.knownBad.Set(cacheKey, err)
	return nil, err
}

// return the claims for a provider
func (v *verifier) claims(provider Provider, tok *jwt.JSONWebToken) (*jwt.Claims, map[string]interface{}, error) {
	var claims1 jwt.Claims
	var claims map[string]interface{}
	if provider.JWKSURL == "" {
		err := tok.UnsafeClaimsWithoutVerification(&claims)
		return &claims1, claims, err
	}

	ks, err := v.jwksManager.Get(v.cancelContext, provider.JWKSURL)
	if err != nil {
		return nil, nil, err
	}

	err = tok.Claims(ks, &claims1, &claims)
	return &claims1, claims, err
}
