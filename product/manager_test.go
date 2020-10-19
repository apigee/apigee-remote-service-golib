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

	"github.com/apigee/apigee-remote-service-golib/auth"
)

func TestManager(t *testing.T) {

	apiProducts := []APIProduct{
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "attr value"},
			},
			Description:    "product 1",
			DisplayName:    "APIProduct 1",
			Environments:   []string{"test"},
			LastModifiedBy: "test@apigee.com",
			Name:           "Name 1",
			QuotaLimit:     "10",
			QuotaInterval:  "1",
			QuotaTimeUnit:  "minute",
			Resources:      []string{"/"},
			Scopes:         []string{"scope1"},
		},
		{
			Attributes: []Attribute{
				{Name: TargetsAttr, Value: "attr value"},
			},
			CreatedBy:      "test2@apigee.com",
			Description:    "product 2",
			DisplayName:    "APIProduct 2",
			Environments:   []string{"prod"},
			LastModifiedBy: "test@apigee.com",
			Name:           "Name 2",
			QuotaLimit:     "",
			QuotaInterval:  "",
			QuotaTimeUnit:  "",
			Resources:      []string{"/**"},
			Scopes:         []string{"scope1"},
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
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
		RefreshRate: time.Hour,
		Client:      http.DefaultClient,
	}
	pp := createManager(opts)
	pp.start()
	defer pp.Close()

	if len(pp.Products()) != len(apiProducts) {
		t.Errorf("num products want: %d, got: %d", len(apiProducts), len(pp.Products()))
	}

	for _, want := range apiProducts {
		got := pp.Products()[want.Name]
		if want.Attributes[0].Value != got.Targets[0] {
			t.Errorf("targets not created: %v", got)
		}

		targets := got.GetBoundTargets()
		if len(targets) != len(want.Attributes) {
			t.Errorf("num targets want: %d, got: %d", len(targets), len(want.Attributes))
		}
		if targets[0] != want.Attributes[0].Value {
			t.Errorf("get target: %s want: %s", targets[0], want.Attributes[0].Value)
		}
	}

	if len(pp.Products()["Name 3"].Scopes) != 0 {
		t.Errorf("empty scopes should be removed")
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
				{Name: TargetsAttr, Value: "target"},
			},
			Resources: []string{"/"},
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

	ac := &auth.Context{
		APIProducts: []string{"Name 1"},
	}
	targets := pp.Authorize(ac, "target", "/", "GET")
	if len(targets) != 1 {
		t.Errorf("want: 1, got: %v", len(targets))
	}

	pp.Close()
}

// Path matching is similar to wildcard semantics described in the Apigee product documentation here:
// https://docs.apigee.com/developer-services/content/create-api-products#resourcebehavior.
// However, as there is no base path, it is simplified as follows:
// 1. A single slash (/) by itself matches any path.
// 2. * is valid anywhere and matches within a segment (between slashes).
// 3. ** is valid at the end and matches anything to the end of line.
func TestResources(t *testing.T) {
	matchTests := []struct {
		spec  string
		path  string
		match bool
	}{
		{spec: "/", path: "/", match: true},
		{spec: "/", path: "/foo", match: true},
		{spec: "/", path: "/foo/bar", match: true},
		{spec: "/", path: "/foo/bar/baz", match: true},
		{spec: "/**", path: "/", match: true},
		{spec: "/**", path: "/foo", match: true},
		{spec: "/**", path: "/foo/bar", match: true},
		{spec: "/**", path: "/foo/bar/baz", match: true},
		{spec: "/*", path: "/", match: true},
		{spec: "/*", path: "/foo", match: true},
		{spec: "/*", path: "/foo/bar", match: false},
		{spec: "/foo", path: "/", match: false},
		{spec: "/foo", path: "/foo", match: true},
		{spec: "/foo", path: "/foo/bar", match: false},
		{spec: "/foo/*", path: "/foo/bar", match: true},
		{spec: "/foo/*", path: "/foo/bar/baz", match: false},
		{spec: "/foo/**", path: "/foo/bar/baz", match: true},
		{spec: "/*/bar", path: "/foo/bar", match: true},
		{spec: "/*/bar", path: "/foo/bar/baz", match: false},
		{spec: "/*/*/baz", path: "/foo/bar/baz", match: true},
	}
	for _, m := range matchTests {
		r, e := makeResourceRegex(m.spec)
		if e != nil {
			t.Fatalf("invalid resource: %s", m.spec)
		}
		if r.MatchString(m.path) != m.match {
			if m.match {
				t.Errorf("spec %s should match path %s (regexp: %s)", m.spec, m.path, r)
			} else {
				t.Errorf("spec %s should not match path %s (regexp: %s)", m.spec, m.path, r)
			}
		}
	}
}

func TestBadResource(t *testing.T) {
	if _, e := makeResourceRegex("/**/bad"); e == nil {
		t.Errorf("expected error for resource: %s", "/**/bad")
	}
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
		_, _ = w.Write([]byte("hi"))
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
	if !strings.Contains(err.Error(), "invalid character 'h' looking for beginning of value") {
		t.Errorf("want 'invalid character 'h' looking for beginning of value got %v", err)
	}
}
