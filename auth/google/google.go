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

	token      string
	expireTime time.Time
	mu         sync.Mutex
}

// IdentityTokenSource defines an ID token source.
// It supplies ID tokens via Token() method.
type IdentityTokenSource struct {
	iamsvc       *iam.Service
	saName       string
	audience     string
	includeEmail bool

	token      string
	expireTime time.Time
	mu         sync.Mutex
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
				ats.refresh()
			case <-ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	ats.refresh()
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
				its.refresh()
			case <-ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	its.refresh()
	return its, nil
}

// Token returns the access token from the source.
func (ats *AccessTokenSource) Token() string {
	// Refresh if the token has expired with 5 minutes skew.
	if ats.expireTime.Before(time.Now().Add(5 * time.Minute)) {
		ats.refresh()
	}
	ats.mu.Lock()
	defer ats.mu.Unlock()
	return ats.token
}

func (ats *AccessTokenSource) refresh() {
	req := &iam.GenerateAccessTokenRequest{
		Scope: ats.scopes,
	}
	resp, err := ats.iamsvc.Projects.ServiceAccounts.GenerateAccessToken(ats.saName, req).Do()
	if err != nil {
		log.Errorf("failed to fetch access token for %q: %v", ats.saName, err)
		return
	}
	ats.mu.Lock()
	ats.token = resp.AccessToken
	t, err := time.Parse(time.RFC3339, resp.ExpireTime)
	if err != nil {
		log.Errorf("failed to parse access token expire time for %q: %v", ats.saName, err)
	}
	ats.expireTime = t
	ats.mu.Unlock()
}

// Token returns the ID token from the source.
func (its *IdentityTokenSource) Token() string {
	// Refresh if the token has expired with 5 minutes skew.
	if its.expireTime.Before(time.Now().Add(5 * time.Minute)) {
		its.refresh()
	}
	its.mu.Lock()
	defer its.mu.Unlock()
	return its.token
}

func (its *IdentityTokenSource) refresh() {
	req := &iam.GenerateIdTokenRequest{
		Audience:     its.audience,
		IncludeEmail: its.includeEmail,
	}
	resp, err := its.iamsvc.Projects.ServiceAccounts.GenerateIdToken(its.saName, req).Do()
	if err != nil {
		log.Errorf("failed to fetch ID token for %q: %v", its.saName, err)
		return
	}
	its.mu.Lock()
	its.token = resp.Token
	// ID token expires in one hour by default.
	its.expireTime = time.Now().Add(time.Hour)
	its.mu.Unlock()
}
