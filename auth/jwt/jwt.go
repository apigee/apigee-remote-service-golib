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
	jwt2 "github.com/dgrijalva/jwt-go"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
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

	if cached, ok := a.knownBad.Get(raw); ok {
		return nil, cached.(error)
	}

	if cached, ok := a.cache.Get(raw); ok {
		return cached.(jwt2.MapClaims), nil
	}

	cacheKnownBad := func(err error) (jwt2.MapClaims, error) {
		a.knownBad.Set(raw, err)
		return nil, err
	}

	ks, err := a.fetchJWKs(provider)
	if err != nil {
		return nil, err
	}

	claims := jwt2.MapClaims{}
	parser := jwt2.Parser{
		SkipClaimsValidation: true,
	}
	_, err = parser.ParseWithClaims(raw, &claims, func(token *jwt2.Token) (interface{}, error) {
		return verifyJWSWithKeySet(ks, token)
	})
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
		a.cache.SetWithExpiration(raw, claims, ttl)
	} else {
		a.cache.Set(raw, claims)
	}

	return claims, nil
}

type ClaimsWithApigeeClaims struct {
	*jwt2.StandardClaims
	ApigeeClaims
}

type ApigeeClaims struct {
	AccessToken    string   `json:"access_token,omitempty"`
	ClientID       string   `json:"client_id,omitempty"`
	AppName        string   `json:"application_name,omitempty"`
	Scope          string   `json:"scope,omitempty"`
	APIProductList []string `json:"api_product_list,omitempty"`
}

func verifyJWSWithKeySet(ks jwk.Set, msg *jwt2.Token) (interface{}, error) {
	if ks == nil || ks.Len() == 0 {
		return nil, errors.New(`empty keyset provided`)
	}

	useDefault := true
	inferAlgorithm := true
	var key jwk.Key

	// find the key
	kid := msg.Header["kid"].(string)
	if kid == "" {
		// if no kid, useDefault must be true and JWKs must have exactly one key
		if !useDefault {
			return nil, errors.New(`failed to find matching key: no key ID ("kid") specified in token`)
		} else if ks.Len() > 1 {
			return nil, errors.New(`failed to find matching key: no key ID ("kid") specified in token but multiple keys available in key set`)
		}
		key, _ = ks.Get(0)
	} else {
		v, ok := ks.LookupKeyID(kid)
		if !ok {
			return nil, errors.Errorf(`failed to find key with key ID %q in key set`, kid)
		}
		key = v
	}

	// if the key has an algorithm, check it
	if v := key.Algorithm(); v != "" {
		var alg jwa.SignatureAlgorithm
		if err := alg.Accept(v); err != nil {
			return nil, errors.Wrapf(err, `invalid signature algorithm %s`, key.Algorithm())
		}

		var rawkey interface{}
		err := key.Raw(&rawkey)
		return rawkey, err
	}

	// infer the algorithm from JWT headers
	if inferAlgorithm {
		algs, err := jws.AlgorithmsForKey(key)
		if err != nil {
			return nil, errors.Wrapf(err, `failed to get a list of signature methods for key type %s`, key.KeyType())
		}

		for _, alg := range algs {
			if tokAlg, ok := msg.Header["alg"]; ok && tokAlg != alg.String() {
				// JWT has a `alg` field but it doesn't match
				continue
			}

			var rawkey interface{}
			err := key.Raw(&rawkey)
			return rawkey, err
		}
	}

	return nil, errors.New(`failed to match any of the keys`)
}
