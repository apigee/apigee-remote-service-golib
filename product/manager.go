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
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	productsURL                 = "/products"
	productsEnvParam            = "env"
	productsOperationTypesParam = "types"
	multiTenantEnv              = "*"
)

/*
Usage:
	pp := createManager()
	pp.start()
	products := pp.Products()
	...
	pp.close() // when done
*/

// A Manager wraps all things related to a set of API products.
type Manager interface {
	Products() ProductsNameMap
	Authorize(authContext *auth.Context, api, path, method string) []AuthorizedOperation
	Close()
}

func createManager(options Options) *manager {
	return &manager{
		baseURL:              options.BaseURL,
		closedChan:           make(chan bool),
		returnChan:           make(chan map[string]*APIProduct),
		closed:               util.NewAtomicBool(false),
		refreshRate:          options.RefreshRate,
		client:               options.Client,
		env:                  options.Env,
		prometheusLabels:     prometheus.Labels{"org": options.Org},
		operationConfigTypes: strings.Join(options.OperationConfigTypes, ","),
	}
}

type manager struct {
	baseURL              *url.URL
	closed               *util.AtomicBool
	closedChan           chan bool
	returnChan           chan map[string]*APIProduct
	refreshRate          time.Duration
	client               *http.Client
	productsMux          productsMux
	cancelPolling        context.CancelFunc
	prometheusLabels     prometheus.Labels
	env                  string
	operationConfigTypes string // comma-delimited
}

// AuthorizedOperation is the result of Authorize including Quotas
type AuthorizedOperation struct {
	ID            string
	QuotaLimit    int64
	QuotaInterval int64
	QuotaTimeUnit string
}

// Authorize a request against API Products and its Operations
func (m *manager) Authorize(authContext *auth.Context, api, path, method string) []AuthorizedOperation {
	authorizedOps, hints := authorize(authContext, m.Products(), api, path, method, log.DebugEnabled())
	if log.DebugEnabled() {
		log.Debugf(hints)
	}
	return authorizedOps
}

// broken out for testing
func authorize(authContext *auth.Context, productsByName map[string]*APIProduct, api, path, method string, hints bool) ([]AuthorizedOperation, string) {
	var authorizedOps []AuthorizedOperation
	authorizedProducts := authContext.APIProducts

	var hintsBuilder strings.Builder
	addHint := func(hint string) {
		if hintsBuilder.Len() == 0 {
			hintsBuilder.WriteString("Authorizing request:\n")
			hintsBuilder.WriteString(fmt.Sprintf("  environment: %s\n", authContext.Environment()))
			hintsBuilder.WriteString(fmt.Sprintf("  products: %v\n", authorizedProducts))
			hintsBuilder.WriteString(fmt.Sprintf("  scopes: %v\n", authContext.Scopes))
			hintsBuilder.WriteString(fmt.Sprintf("  operation: %s %s\n", method, path))
			hintsBuilder.WriteString(fmt.Sprintf("  api: %s\n", api))
		}
		hintsBuilder.WriteString(hint)
	}

	for _, name := range authorizedProducts {
		var prodAPIs []AuthorizedOperation
		var hint string = "    not found\n"
		if product, ok := productsByName[name]; ok {
			prodAPIs, hint = product.authorize(authContext, api, path, method, hints)
			authorizedOps = append(authorizedOps, prodAPIs...)
		}
		if hints && hint != "" {
			addHint(fmt.Sprintf("  - product: %s\n", name))
			addHint(hint)
		}
	}

	return authorizedOps, hintsBuilder.String()
}

// Products atomically gets a mapping of name => APIProduct.
func (m *manager) Products() ProductsNameMap {
	if m.closed.IsTrue() {
		return nil
	}
	return m.productsMux.Get()
}

// Close shuts down the manager.
func (m *manager) Close() {
	if m == nil || m.closed.SetTrue() {
		return
	}
	log.Infof("closing product manager")
	m.cancelPolling()
	m.productsMux.Close()
	log.Infof("closed product manager")
}

func (m *manager) start() {
	log.Infof("starting product manager")
	m.productsMux = productsMux{
		setChan:   make(chan ProductsNameMap),
		getChan:   make(chan ProductsNameMap),
		closeChan: make(chan struct{}),
		closed:    util.NewAtomicBool(false),
	}
	go m.productsMux.mux()

	poller := util.Looper{
		Backoff: util.NewExponentialBackoff(200*time.Millisecond, m.refreshRate, 2, true),
	}
	apiURL := *m.baseURL
	apiURL.Path = path.Join(apiURL.Path, productsURL)
	if m.env != multiTenantEnv { // if not multi-tenant, request specified env
		apiURL.Query().Add(productsEnvParam, m.env)
	}
	if m.operationConfigTypes != "" { // request specified operation types (empty is all)
		apiURL.Query().Add(productsOperationTypesParam, m.operationConfigTypes)
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancelPolling = cancel
	poller.Start(ctx, m.pollingClosure(apiURL), m.refreshRate, func(err error) error {
		log.Errorf("Error retrieving products: %v", err)
		return nil
	})

	log.Infof("started product manager")
}

func (m *manager) pollingClosure(apiURL url.URL) func(ctx context.Context) error {
	var etag string
	return func(ctx context.Context) error {

		req, err := http.NewRequest(http.MethodGet, apiURL.String(), nil)
		if err != nil {
			return err
		}
		req = req.WithContext(ctx) // make cancelable from poller

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")

		if etag != "" {
			req.Header.Set("If-None-Match", etag)
		}

		log.Debugf("retrieving products from: %s", apiURL.String())

		resp, err := m.client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			log.Errorf("Unable to read server response: %v", err)
			return err
		}

		if resp.StatusCode == 304 {
			log.Debugf("products not modified")
			return nil
		}

		if resp.StatusCode != 200 {
			err := fmt.Errorf("products request failed (%d): %s", resp.StatusCode, string(body))
			log.Errorf(err.Error())
			return err
		}

		etag = resp.Header.Get("ETag")
		if etag != "" {
			log.Debugf("received etag for products request: '%s'", etag)
		}

		var res APIResponse
		err = json.Unmarshal(body, &res)
		if err != nil {
			log.Errorf("unable to unmarshal JSON response '%s': %v", string(body), err)
			return err
		}

		// parses products and creates name -> product lookup map
		pm := ProductsNameMap{}
		for i := range res.APIProducts {
			if ctx.Err() != nil {
				log.Debugf("product polling canceled, exiting")
				return nil
			}
			p := &res.APIProducts[i]
			// Only match against proxy name when dealing with Proxy types
			// We can't rely on p.OperationGroup.OperationConfigType because it
			// will not be set if there are no operations so we have to do this
			// here where we can check m.operationConfigTypes instead of in the
			// Unmarshal function.
			if p.OperationGroup == nil &&
				strings.Contains(m.operationConfigTypes, ProxyOperationConfigType) {
				for _, proxy := range p.Proxies {
					p.APIs[proxy] = true
				}
			}
			pm[p.Name] = p
		}
		m.productsMux.Set(pm)

		prometheusProductsRecords.With(m.prometheusLabels).Set(float64(len(pm)))

		log.Debugf("retrieved %d products, kept %d", len(res.APIProducts), len(pm))

		return nil
	}
}

// ProductsNameMap is a map of API Product name to API Product
type ProductsNameMap map[string]*APIProduct

type productsMux struct {
	setChan   chan ProductsNameMap
	getChan   chan ProductsNameMap
	closeChan chan struct{}
	closed    *util.AtomicBool
}

func (p productsMux) Get() ProductsNameMap {
	return <-p.getChan
}

func (p productsMux) Set(s ProductsNameMap) {
	if p.closed.IsFalse() {
		p.setChan <- s
	}
}

func (p productsMux) Close() {
	if !p.closed.SetTrue() {
		close(p.closeChan)
	}
}

func (p productsMux) mux() {
	var productsMap ProductsNameMap
	for {
		if productsMap == nil {
			select {
			case <-p.closeChan:
				close(p.setChan)
				close(p.getChan)
				return
			case productsMap = <-p.setChan:
				continue
			}
		}
		select {
		case productsMap = <-p.setChan:
		case p.getChan <- productsMap:
		case <-p.closeChan:
			close(p.setChan)
			close(p.getChan)
			return
		}
	}
}

var (
	prometheusProductsRecords = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "products",
		Name:      "cached",
		Help:      "Number of products cached in memory",
	}, []string{"org"})
)
