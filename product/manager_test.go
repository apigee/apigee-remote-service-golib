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

package product

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
)

func TestManagerRemoteService(t *testing.T) {

	apiProducts := []APIProduct{
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "attr value"},
			},
			Description:   "product 1",
			DisplayName:   "APIProduct 1",
			Environments:  []string{"test"},
			Name:          "Name 1",
			QuotaLimit:    "10",
			QuotaInterval: "1",
			QuotaTimeUnit: "minute",
			Resources:     []string{"/"},
			Scopes:        []string{"scope1"},
		},
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "attr value"},
			},
			Description:   "product 2",
			DisplayName:   "APIProduct 2",
			Environments:  []string{"prod"},
			Name:          "Name 2",
			QuotaLimit:    "",
			QuotaInterval: "",
			QuotaTimeUnit: "",
			Resources:     []string{"/**"},
			Scopes:        []string{"scope1"},
		},
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "attr value"},
			},
			Description:   "product 3",
			DisplayName:   "APIProduct 3",
			Environments:  []string{"prod"},
			Name:          "Name 3",
			Resources:     []string{"/"},
			Scopes:        []string{""},
			QuotaLimit:    "null",
			QuotaInterval: "null",
			QuotaTimeUnit: "null",
		},
		{
			Description:  "product 4",
			DisplayName:  "APIProduct 4",
			Environments: []string{"prod"},
			Name:         "Name 4",
			Resources:    []string{"/whatever"},
			OperationGroup: &OperationGroup{
				OperationConfigs: []OperationConfig{
					{
						APISource: "Name 4",
						Operations: []Operation{
							{
								Resource: "/",
								Methods:  []string{"GET"},
							},
						},
					},
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result = APIResponse{
			APIProducts: apiProducts,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: time.Hour,
		Client:      http.DefaultClient,
	}
	pm := createManager(opts)
	pm.start()
	defer pm.Close()

	if len(pm.Products()) != len(apiProducts) {
		t.Errorf("num products want: %d, got: %d", len(apiProducts), len(pm.Products()))
	}

	for _, want := range apiProducts {
		got := pm.Products()[want.Name]
		if len(want.Attributes) > 0 && want.Attributes[0].Value != got.APIs[0] {
			t.Errorf("apis not created: %v", got)
		}
		if got.Name != want.Name {
			t.Errorf("got: %s, want %v", got.Name, want.Name)
		}

		apis := got.GetBoundAPIs()
		if len(apis) != 1 {
			t.Errorf("num apis want: %d, got: %d", len(apis), 1)
		}
		if len(want.Attributes) > 0 {
			if apis[0] != want.Attributes[0].Value {
				t.Errorf("got api: %s want: %s", apis[0], want.Attributes[0].Value)
			}
		} else {
			if apis[0] != want.OperationGroup.OperationConfigs[0].APISource {
				t.Errorf("got api: %s want: %s", apis[0], want.OperationGroup.OperationConfigs[0].APISource)
			}
		}
	}

	if len(pm.Products()["Name 3"].Scopes) != 0 {
		t.Errorf("empty scopes should be removed")
	}
}

// Test special case of Proxy name binding for ProxyOperationConfigType.
func TestManagerProxyName(t *testing.T) {

	apiProducts := []APIProduct{
		{
			Name:    "Name 1",
			Proxies: []string{"proxy1"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var result = APIResponse{
			APIProducts: apiProducts,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(result); err != nil {
			t.Fatal(err)
		}
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:              serverURL,
		RefreshRate:          time.Hour,
		Client:               http.DefaultClient,
		OperationConfigTypes: []string{ProxyOperationConfigType},
	}
	pm := createManager(opts)
	pm.start()
	defer pm.Close()

	for _, want := range apiProducts {
		got := pm.Products()[want.Name]
		apis := got.GetBoundAPIs()
		if len(apis) != 1 {
			t.Fatalf("num apis want: %d, got: %d", len(apis), 1)
		}
		if apis[0] != want.Proxies[0] {
			t.Errorf("want proxy name %q bound as an API", want.Name)
		}
	}
}

func TestManagerPolling(t *testing.T) {

	var count = 0
	var apiProducts []APIProduct

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count++
		apiProducts = append(apiProducts, APIProduct{
			Name: fmt.Sprintf("Name %d", count),
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "api"},
			},
			Environments: []string{"env"},
			Resources:    []string{"/"},
		})

		var result = APIResponse{
			APIProducts: apiProducts,
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: 5 * time.Millisecond,
		Client:      http.DefaultClient,
	}
	pp := createManager(opts)
	pp.start()
	defer pp.Close()

	pp1 := len(pp.Products())
	pp2 := len(pp.Products())
	if pp1 != pp2 {
		t.Errorf("number of products should not have incremented")
	}

	time.Sleep(opts.RefreshRate * 10)
	pp2 = len(pp.Products())
	if pp1 == pp2 {
		t.Errorf("number of products should have incremented")
	}

	authContext := &auth.Context{
		Context:     &fakeContext{org: "org", env: "env"},
		APIProducts: []string{"Name 1"},
	}
	apis := pp.Authorize(authContext, "api", "/", "GET")
	if len(apis) != 1 {
		t.Errorf("want: 1, got: %v", len(apis))
	}

	pp.Close()
}

func TestManagerHandlingEtag(t *testing.T) {
	cached := false
	apiProducts := []APIProduct{
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "api"},
			},
			Environments: []string{"env"},
			Name:         "Name 1",
			Resources:    []string{"/"},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if cached {
			if etag := r.Header.Get("If-None-Match"); etag != "etag" {
				t.Fatalf("wanted to receive etag in If-None-Match header, got '%s'", etag)
			}
			w.WriteHeader(http.StatusNotModified)
			return
		}
		cached = true
		var result = APIResponse{
			APIProducts: apiProducts,
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Etag", "etag")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: 5 * time.Millisecond,
		Client:      http.DefaultClient,
	}
	pp := createManager(opts)
	pp.start()
	defer pp.Close()

	time.Sleep(opts.RefreshRate * 10)

	authContext := &auth.Context{
		Context:     &fakeContext{org: "org", env: "env"},
		APIProducts: []string{"Name 1"},
	}
	apis := pp.Authorize(authContext, "api", "/", "GET")
	if len(apis) != 1 {
		t.Errorf("want: 1, got: %v", len(apis))
	}

	pp.Close()
}

func TestUnreachable(t *testing.T) {

	serverURL, err := url.Parse("http://localhost:9999")
	if err != nil {
		t.Fatal(err)
	}

	httpClient := &http.Client{
		Timeout: time.Millisecond,
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: 5 * time.Millisecond,
		Client:      httpClient,
	}
	pp := createManager(opts)

	ctx := context.Background()

	err = pp.pollingClosure(*serverURL)(ctx)
	if err == nil {
		t.Fatal("should have received error")
	}
}

func TestBadResponseCode(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: time.Hour,
		Client:      http.DefaultClient,
	}
	pp := createManager(opts)

	ctx := context.Background()

	err = pp.pollingClosure(*serverURL)(ctx)
	if err == nil {
		t.Error("should have received error")
	}
	if !strings.Contains(err.Error(), "products request failed (400)") {
		t.Errorf("want 'products request failed (400)' got %v", err)
	}
}

func TestBadResponseBody(t *testing.T) {

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("bad response"))
	}))
	defer ts.Close()

	serverURL, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	opts := Options{
		BaseURL:     serverURL,
		RefreshRate: time.Hour,
		Client:      http.DefaultClient,
	}
	pp := createManager(opts)

	ctx := context.Background()

	err = pp.pollingClosure(*serverURL)(ctx)
	if err == nil {
		t.Error("should have received error")
	}
	if !strings.Contains(err.Error(), "invalid character 'b' looking for beginning of value") {
		t.Errorf("want 'invalid character 'b' looking for beginning of value got %v", err)
	}
}
