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

// TODO: handle external issuers and JWTs, not just API Keys
// TODO: store and retrieve JWT claims in expiring cache (see cache in verify_api_key.go)

package auth

import (
	"context"
	"encoding/json"
	"path"
	"time"

	adapterContext "github.com/apigee/apigee-remote-service-golib/v2/context"
	"github.com/lestrrat-go/backoff/v2"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
)

const (
	certsPath      = "/certs"
	acceptableSkew = 10 * time.Second
)

func newJWTManager() *jwtManager {
	return &jwtManager{}
}

// An jwtManager handles all of the various JWT authentication functionality.
type jwtManager struct {
	jwks             *jwk.AutoRefresh
	cancelJWKRefresh context.CancelFunc
}

func (a *jwtManager) start() {
	ctx, cancel := context.WithCancel(context.Background())
	a.cancelJWKRefresh = cancel
	a.jwks = jwk.NewAutoRefresh(ctx)
}

func (a *jwtManager) stop() {
	if a != nil && a.cancelJWKRefresh != nil {
		a.cancelJWKRefresh()
	}
}

func (a *jwtManager) jwkSet(ctx adapterContext.Context) (jwk.Set, error) {
	jwksURL := *ctx.RemoteServiceAPI()
	jwksURL.Path = path.Join(jwksURL.Path, certsPath)
	url := jwksURL.String()

	a.jwks.Configure(url, jwk.WithFetchBackoff(backoff.Exponential()))
	return a.jwks.Fetch(context.Background(), url)
}

func (a *jwtManager) parseJWT(ctx adapterContext.Context, raw string, verify bool) (map[string]interface{}, error) {

	if verify {
		set, err := a.jwkSet(ctx)
		if err != nil {
			return nil, err
		}

		// verify against public keys
		_, err = jws.VerifySet([]byte(raw), set)
		if err != nil {
			return nil, err
		}

		// validate fields
		token, err := jwt.ParseString(raw)
		if err != nil {
			return nil, errors.Wrap(err, "invalid jws message")
		}

		err = jwt.Validate(token, jwt.WithAcceptableSkew(acceptableSkew))
		if err != nil {
			return nil, errors.Wrap(err, "invalid jws message")
		}
	}

	// get claims
	m, err := jws.ParseString(raw)
	if err != nil {
		return nil, errors.Wrap(err, "invalid jws message")
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(m.Payload(), &claims); err != nil {
		return nil, errors.Wrap(err, "failed to parse claims")
	}

	return claims, nil
}
