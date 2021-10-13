// Copyright 2021 Google LLC
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

package google

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"golang.org/x/oauth2"
	iam "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

const (
	defaultRefreshInterval = 30 * time.Minute

	serviceAccountNameFormat = "projects/-/serviceAccounts/%s"
)

// AccessTokenSource defines an access token source.
// It supplies access tokens via Token() method.
type AccessTokenSource struct {
	iamsvc *iam.Service
	saName string
	scopes []string

	token *oauth2.Token
	mu    sync.Mutex
}

// IdentityTokenSource defines an ID token source.
// It supplies ID tokens via Token() method.
type IdentityTokenSource struct {
	iamsvc       *iam.Service
	saName       string
	audience     string
	includeEmail bool

	token *oauth2.Token
	mu    sync.Mutex
}

// TokenSourceOption contains configurations for ID and/or access token sources.
type TokenSourceOption struct {
	Client          *http.Client
	RefreshInterval time.Duration
	ServiceAccount  string
	Scopes          []string
	Audience        string
	IncludeEmail    bool
	Endpoint        string
}

// NewAccessTokenSource returns a new access token source.
// Service account email and scopes are required fields.
// The http client, which can be specified, needs to have proper authorization information
// to generate tokens for the given service account.
func NewAccessTokenSource(ctx context.Context, opt TokenSourceOption) (*AccessTokenSource, error) {
	var opts []option.ClientOption
	if opt.Client != nil {
		opts = append(opts, option.WithHTTPClient(opt.Client))
	}
	if opt.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(opt.Endpoint))
	}
	iamsvc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new IAM credentials service: %v", err)
	}
	if opt.ServiceAccount == "" {
		return nil, fmt.Errorf("service account is required to create access token source")
	}
	if len(opt.Scopes) == 0 {
		return nil, fmt.Errorf("scopes are required to create access token source")
	}
	ats := &AccessTokenSource{
		iamsvc: iamsvc,
		saName: fmt.Sprintf(serviceAccountNameFormat, opt.ServiceAccount),
		scopes: opt.Scopes,
	}

	refreshInterval := defaultRefreshInterval
	if opt.RefreshInterval > 0 {
		refreshInterval = opt.RefreshInterval
	}
	go func() {
		tick := time.NewTicker(refreshInterval)
		for {
			select {
			case <-tick.C:
				if err := ats.refresh(); err != nil {
					log.Errorf("%v", err)
				}
			case <-ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	if err := ats.refresh(); err != nil {
		log.Errorf("%v", err)
	}
	return ats, nil
}

// NewIdentityTokenSource returns a new ID token source.
// Service account email and audience are required fields.
// The http client, which can be specified, needs to have proper authorization information
// to generate tokens for the given service account.
func NewIdentityTokenSource(ctx context.Context, opt TokenSourceOption) (*IdentityTokenSource, error) {
	var opts []option.ClientOption
	if opt.Client != nil {
		opts = append(opts, option.WithHTTPClient(opt.Client))
	}
	if opt.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(opt.Endpoint))
	}
	iamsvc, err := iam.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create new IAM credentials service: %v", err)
	}
	if opt.ServiceAccount == "" {
		return nil, fmt.Errorf("service account is required to create identity token source")
	}
	if opt.Audience == "" {
		return nil, fmt.Errorf("audience is required to create identity token source")
	}
	its := &IdentityTokenSource{
		iamsvc:       iamsvc,
		saName:       fmt.Sprintf(serviceAccountNameFormat, opt.ServiceAccount),
		audience:     opt.Audience,
		includeEmail: opt.IncludeEmail,
	}

	refreshInterval := defaultRefreshInterval
	if opt.RefreshInterval > 0 {
		refreshInterval = opt.RefreshInterval
	}
	go func() {
		tick := time.NewTicker(refreshInterval)
		for {
			select {
			case <-tick.C:
				if err := its.refresh(); err != nil {
					log.Errorf("%v", err)
				}
			case <-ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	if err := its.refresh(); err != nil {
		log.Errorf("%v", err)
	}
	return its, nil
}

// Token returns the access token from the source.
func (ats *AccessTokenSource) Token() (*oauth2.Token, error) {
	if !ats.token.Valid() {
		if err := ats.refresh(); err != nil {
			return nil, err
		}
	}
	ats.mu.Lock()
	defer ats.mu.Unlock()
	// Deep copy the object to avoid data race.
	return &oauth2.Token{
		AccessToken: ats.token.AccessToken,
		Expiry:      ats.token.Expiry,
	}, nil
}

func (ats *AccessTokenSource) refresh() error {
	req := &iam.GenerateAccessTokenRequest{
		Scope: ats.scopes,
	}
	resp, err := ats.iamsvc.Projects.ServiceAccounts.GenerateAccessToken(ats.saName, req).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch access token for %q: %v", ats.saName, err)
	}
	t, err := time.Parse(time.RFC3339, resp.ExpireTime)
	if err != nil {
		return fmt.Errorf("failed to parse access token expire time for %q: %v", ats.saName, err)
	}
	ats.mu.Lock()
	defer ats.mu.Unlock()
	ats.token = &oauth2.Token{
		AccessToken: resp.AccessToken,
		Expiry:      t,
	}
	return nil
}

// Token returns the ID token from the source.
func (its *IdentityTokenSource) Token() (*oauth2.Token, error) {
	if !its.token.Valid() {
		if err := its.refresh(); err != nil {
			return nil, err
		}
	}
	its.mu.Lock()
	defer its.mu.Unlock()
	// Deep copy the object to avoid data race.
	return &oauth2.Token{
		AccessToken: its.token.AccessToken,
		Expiry:      its.token.Expiry,
	}, nil
}

func (its *IdentityTokenSource) refresh() error {
	req := &iam.GenerateIdTokenRequest{
		Audience:     its.audience,
		IncludeEmail: its.includeEmail,
	}
	resp, err := its.iamsvc.Projects.ServiceAccounts.GenerateIdToken(its.saName, req).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch ID token for %q: %v", its.saName, err)
	}
	its.mu.Lock()
	defer its.mu.Unlock()
	its.token = &oauth2.Token{
		AccessToken: resp.Token,
		// ID token expires in one hour by default. Add 5 mins skew.
		Expiry: time.Now().Add(55 * time.Minute),
	}
	return nil
}
