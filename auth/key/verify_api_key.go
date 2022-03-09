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

package key

/*
1. When an API Key check comes in, check a LRU cache.
2. If token is cached, initiate background check if token is expired, return cached token.
3. If token is not cached, check bad token cache, return invalid if present.
4. If token is in neither cache, make a synchronous request to Apigee to refresh it. Update good and bad caches.
*/

import (
	"bytes"
	contex "context"
	"encoding/json"
	"net/http"
	"path"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/cache"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"golang.org/x/sync/singleflight"
)

const (
	certsPath                    = "/certs"
	verifyAPIKeyURL              = "/verifyApiKey"
	defaultCacheTTL              = 30 * time.Minute
	defaultCacheEvictionInterval = 10 * time.Second
	defaultMaxCachedEntries      = 10000
	defaultBadEntryCacheTTL      = 10 * time.Second
)

// ErrBadKeyAuth will be translated into auth.ErrBadAuth for external consumption.
var ErrBadKeyAuth = errors.New("api key permission denied")

// Verifier encapsulates API key verification logic.
type Verifier interface {
	Verify(ctx context.Context, apiKey string) (map[string]interface{}, error)
}

// APIKeyRequest is the request to Apigee's verifyAPIKey API
type APIKeyRequest struct {
	APIKey string `json:"apiKey"`
}

// APIKeyResponse is the response from Apigee's verifyAPIKey API
type APIKeyResponse struct {
	Token string `json:"token"`
}

type verifierImpl struct {
	jwtVerifier      jwt.Verifier
	cache            cache.ExpiringCache
	now              func() time.Time
	client           *http.Client
	herdBuster       singleflight.Group
	knownBad         cache.ExpiringCache
	checking         sync.Map
	prometheusLabels prometheus.Labels
}

type VerifierOpts struct {
	JwtVerifier           jwt.Verifier
	CacheTTL              time.Duration
	CacheEvictionInterval time.Duration
	MaxCachedEntries      int
	Client                *http.Client
	Org                   string
}

func NewVerifier(opts VerifierOpts) Verifier {
	if opts.CacheTTL == 0 {
		opts.CacheTTL = defaultCacheTTL
	}
	if opts.CacheEvictionInterval == 0 {
		opts.CacheEvictionInterval = defaultCacheEvictionInterval
	}
	if opts.MaxCachedEntries == 0 {
		opts.MaxCachedEntries = defaultMaxCachedEntries
	}
	return &verifierImpl{
		jwtVerifier:      opts.JwtVerifier,
		cache:            cache.NewLRU(opts.CacheTTL, opts.CacheEvictionInterval, int32(opts.MaxCachedEntries)),
		now:              time.Now,
		client:           opts.Client,
		knownBad:         cache.NewLRU(defaultBadEntryCacheTTL, opts.CacheEvictionInterval, 100),
		prometheusLabels: prometheus.Labels{"org": opts.Org},
	}
}

// use singleFetchToken() to avoid multiple active requests
func (kv *verifierImpl) fetchToken(ctx context.Context, apiKey string) (map[string]interface{}, error) {
	if errResp, ok := kv.knownBad.Get(apiKey); ok {
		if log.DebugEnabled() {
			log.Debugf("fetchToken: known bad token: %s", util.Truncate(apiKey, 5))
		}
		return nil, errResp.(error)
	}

	if log.DebugEnabled() {
		log.Debugf("fetchToken fetching: %s", util.Truncate(apiKey, 5))
	}
	verifyRequest := APIKeyRequest{
		APIKey: apiKey,
	}

	apiURL := *ctx.RemoteServiceAPI()
	apiURL.Path = path.Join(apiURL.Path, verifyAPIKeyURL)

	body := new(bytes.Buffer)
	_ = json.NewEncoder(body).Encode(verifyRequest)

	req, err := http.NewRequest(http.MethodPost, apiURL.String(), body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := kv.client.Do(req)
	if err != nil {
		kv.knownBad.Set(apiKey, err)
		return nil, err
	}
	defer resp.Body.Close()

	apiKeyResp := APIKeyResponse{}
	_ = json.NewDecoder(resp.Body).Decode(&apiKeyResp)

	token := apiKeyResp.Token
	if token == "" { // bad API Key
		kv.knownBad.Set(apiKey, ErrBadKeyAuth)
		kv.cache.Remove(apiKey)
		return nil, ErrBadKeyAuth
	}

	// Parse will not verify empty provider
	claims, err := kv.jwtVerifier.Parse(token, jwt.Provider{})
	if err != nil {
		kv.knownBad.Set(apiKey, err)
		return nil, err
	}

	kv.cache.Set(apiKey, claims)
	kv.knownBad.Remove(apiKey)

	return claims, nil
}

// ensures only a single request for any given api key is active
func (kv *verifierImpl) singleFetchToken(ctx context.Context, apiKey string) (map[string]interface{}, error) {
	fetch := func() (interface{}, error) {
		return kv.fetchToken(ctx, apiKey)
	}
	res, err, _ := kv.herdBuster.Do(apiKey, fetch)
	if err != nil {
		log.Errorf("token fetching for API key failed: %v", err)
		return nil, err
	}

	return res.(map[string]interface{}), nil
}

// verify returns the list of claims that an API key has.
// claims map must not be written to: treat as const
func (kv *verifierImpl) Verify(ctx context.Context, apiKey string) (claims map[string]interface{}, err error) {

	if existing, ok := kv.cache.Get(apiKey); ok {
		claims = existing.(map[string]interface{})
		prometheusAPIKeysCacheHits.With(kv.prometheusLabels).Add(1)
	}

	// if token is expired, initiate a background refresh
	if claims != nil {
		if e, ok := claims["exp"].(float64); ok {
			ttl := time.Unix(int64(e), 0).Sub(kv.now())
			if ttl <= 0 { // refresh if possible
				if _, ok := kv.checking.Load(apiKey); !ok { // one refresh per apiKey at a time
					kv.checking.Store(apiKey, apiKey)

					// make the call with a backoff
					// will only call once and cancel loop if successful
					looper := util.Looper{
						Backoff: util.DefaultExponentialBackoff(),
					}
					c, cancel := contex.WithCancel(contex.Background())
					work := func(c contex.Context) error {
						claims, err = kv.singleFetchToken(ctx, apiKey)
						if err != nil && err != ErrBadKeyAuth {
							log.Debugf("fetchToken error: %s", err)
							return err
						}
						cancel()
						kv.checking.Delete(apiKey)
						return nil
					}
					looper.Start(c, work, time.Minute, func(err error) error {
						log.Errorf("Error refreshing token: %s", err)
						return nil
					})
				}
			}
		}
		return claims, nil
	}

	// not found, force new request
	prometheusAPIKeysCacheMisses.With(kv.prometheusLabels).Add(1)
	return kv.singleFetchToken(ctx, apiKey)
}

var (
	prometheusAPIKeysCacheHits = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "auth",
		Name:      "apikeys_cache_hit_count",
		Help:      "Number of apikey cache hits",
	}, []string{"org"})

	prometheusAPIKeysCacheMisses = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "auth",
		Name:      "apikeys_cache_miss_count",
		Help:      "Number of apikey cache misses",
	}, []string{"org"})
)
