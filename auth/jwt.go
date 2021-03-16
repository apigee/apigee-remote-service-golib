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

import (
	"context"
	"encoding/json"
	"path"
	"sync"
	"time"

	adapterContext "github.com/apigee/apigee-remote-service-golib/context"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/util"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jws"
	"github.com/lestrrat-go/jwx/jwt"
	"github.com/pkg/errors"
)

const (
	certsPath      = "/certs"
	acceptableSkew = 10 * time.Second
)

func newJWTManager(pollInterval time.Duration) *jwtManager {
	return &jwtManager{
		jwkSets:      sync.Map{},
		pollInterval: pollInterval,
	}
}

// An jwtManager handles all of the various JWT authentication functionality.
type jwtManager struct {
	jwkSets       sync.Map
	pollInterval  time.Duration
	cancelPolling context.CancelFunc
}

func (a *jwtManager) start() {
	if a.pollInterval > 0 {
		log.Debugf("starting cert polling")
		looper := util.Looper{
			Backoff: util.NewExponentialBackoff(200*time.Millisecond, a.pollInterval, 2, true),
		}
		ctx, cancel := context.WithCancel(context.Background())
		a.cancelPolling = cancel
		looper.Start(ctx, a.refresh, a.pollInterval, func(err error) error {
			log.Errorf("Error refreshing cert set: %s", err)
			return nil
		})
	}
}

func (a *jwtManager) stop() {
	if a != nil && a.cancelPolling != nil {
		a.cancelPolling()
	}
}

func (a *jwtManager) ensureSet(url string) error {
	set, err := jwk.Fetch(context.Background(), url)
	if err != nil {
		return err
	}
	a.jwkSets.Store(url, set)
	return nil
}

func (a *jwtManager) refresh(ctx context.Context) error {
	var errRet error
	a.jwkSets.Range(func(urlI interface{}, setI interface{}) bool {
		if err := a.ensureSet(urlI.(string)); err != nil {
			errRet = err
		}
		return ctx.Err() == nil // if not canceled, keep going
	})
	return errRet
}

func (a *jwtManager) jwkSet(ctx adapterContext.Context) (jwk.Set, error) {
	jwksURL := *ctx.RemoteServiceAPI()
	jwksURL.Path = path.Join(jwksURL.Path, certsPath)
	url := jwksURL.String()
	if _, ok := a.jwkSets.Load(url); !ok {
		if err := a.ensureSet(url); err != nil {
			return nil, err
		}
	}
	set, _ := a.jwkSets.Load(url)
	return set.(jwk.Set), nil
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
