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

// This file defines the primary entry point for the auth module, which is the
// Authenticate function.

import (
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth/jwt"
	"github.com/apigee/apigee-remote-service-golib/v2/auth/key"
	"github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/pkg/errors"
)

// A Manager wraps all things related to auth processing
type Manager interface {
	Close()
	Authenticate(ctx context.Context, apiKey string, claims map[string]interface{}, apiKeyClaimKey string) (authContext *Context, err error)
	ParseJWT(jwtString string, provider jwt.Provider) (claims map[string]interface{}, err error)
}

// ErrNoAuth is an error because of missing auth
var ErrNoAuth = errors.New("missing authentication")

// ErrBadAuth is an error because of incorrect auth
var ErrBadAuth = errors.New("permission denied")

// ErrInternalError is an error because of internal error
var ErrInternalError = errors.New("internal error")

// ErrNetworkError is an error because of network
var ErrNetworkError = errors.New("network error")

// NewManager constructs a new Manager for JWT functions.
// Call Close() when done.
func NewManager(options Options) (Manager, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	jwtVerifier := jwt.NewVerifier(jwt.VerifierOptions{
		Providers: options.JWTProviders,
	})
	v := key.NewVerifier(key.VerifierOpts{
		JwtVerifier: jwtVerifier,
		Client:      options.Client,
		CacheTTL:    options.APIKeyCacheDuration,
		Org:         options.Org,
	})
	am := &manager{
		jwtVerifier: jwtVerifier,
		keyVerifier: v,
	}
	am.start()
	return am, nil
}

// An Manager handles all things related to authentication.
type manager struct {
	jwtVerifier jwt.Verifier
	keyVerifier key.Verifier
}

// Close shuts down the Manager.
func (m *manager) Close() {
	if m != nil {
		m.jwtVerifier.Stop()
	}
}

// Authenticate constructs an Apigee context from an existing context and either
// a set of JWT claims, or an Apigee API key.
// The following logic applies:
// 1. If JWT w/ API Key - use API Key in claims
// 2. API Key - use API Key
// 3. Has JWT token - use JWT claims
// If any method is provided but fails, the next available one(s) will be attempted. If all provided methods fail,
// the request will be rejected.
// May return errors: ErrNoAuth, ErrBadAuth, ErrNetworkError, ErrInternalError
func (m *manager) Authenticate(ctx context.Context, apiKey string,
	claims map[string]interface{}, apiKeyClaimKey string) (*Context, error) {
	if log.DebugEnabled() {
		redacts := []interface{}{
			claims["access_token"],
			claims["client_id"],
			claims[apiKeyClaimKey],
		}
		redactedClaims := util.SprintfRedacts(redacts, "%#v", claims)
		log.Debugf("Authenticate: key: %v, claims: %v", util.Truncate(apiKey, 5), redactedClaims)
	}

	var authContext = &Context{Context: ctx}

	// use API Key in JWT if available
	authAttempted := false
	var authenticationError, claimsError error
	var verifiedClaims map[string]interface{}

	if claims[apiKeyClaimKey] != nil {
		authAttempted = true
		if apiKey, ok := claims[apiKeyClaimKey].(string); ok {
			verifiedClaims, authenticationError = m.keyVerifier.Verify(ctx, apiKey)
			if authenticationError == nil {
				log.Debugf("using api key from jwt claim %s", apiKeyClaimKey)
				authContext.APIKey = apiKey
				claimsError = authContext.setClaims(verifiedClaims)
			}
		}
	}

	// else, use API Key if available
	if !authAttempted && apiKey != "" {
		authAttempted = true
		verifiedClaims, authenticationError = m.keyVerifier.Verify(ctx, apiKey)
		if authenticationError == nil {
			log.Debugf("using api key from request")
			authContext.APIKey = apiKey
			claimsError = authContext.setClaims(verifiedClaims)
		}
	}

	// if we're not authenticated yet, try the jwt claims directly
	if !authContext.isAuthenticated() && len(claims) > 0 {
		claimsError = authContext.setClaims(claims)
		if authAttempted && claimsError == nil {
			log.Warnf("apiKey verification error: %s, using jwt claims", authenticationError)
			authenticationError = nil
		}
		authAttempted = true
	}

	// logs the auth result before the potential auth error gets overwritten
	if log.DebugEnabled() {
		redacts := []interface{}{authContext.APIKey, authContext.AccessToken, authContext.ClientID}
		redactedAC := util.SprintfRedacts(redacts, "%#v", authContext)
		if !authAttempted {
			log.Debugf("Authenticate error: %s [%v]", redactedAC, ErrNoAuth)
		} else if authenticationError == nil {
			if claimsError == nil {
				log.Debugf("Authenticate success: %s", redactedAC)
			} else {
				log.Debugf("Authenticate error: %s [%v]", redactedAC, claimsError)
			}
		} else {
			log.Debugf("Authenticate error: %s [%v]", redactedAC, authenticationError)
		}
	}

	// translate errors to auth.Err* types
	if !authAttempted {
		authenticationError = ErrNoAuth
	} else if authenticationError != nil {
		if authenticationError == key.ErrBadKeyAuth {
			authenticationError = ErrBadAuth
		} else if _, ok := authenticationError.(*url.Error); ok {
			authenticationError = ErrNetworkError
		} else {
			authenticationError = ErrInternalError
		}
	} else if claimsError != nil {
		authenticationError = claimsError
	}

	return authContext, authenticationError
}

func (m *manager) ParseJWT(jwtString string, provider jwt.Provider) (map[string]interface{}, error) {
	return m.jwtVerifier.Parse(jwtString, provider)
}

func (m *manager) start() {
	m.jwtVerifier.Start()
}

// Options allows us to specify options for how this auth manager will run
type Options struct {
	// Client is a configured HTTPClient
	Client *http.Client
	// APIKeyCacheDuration is the length of time APIKeys are cached when unable to refresh
	APIKeyCacheDuration time.Duration
	// Org is organization
	Org string
	// JWKSProviders
	JWTProviders []jwt.Provider
}

func (o *Options) validate() error {
	if o.Client == nil {
		return fmt.Errorf("client is required")
	}
	if o.Org == "" {
		return fmt.Errorf("org is required")
	}
	return nil
}
