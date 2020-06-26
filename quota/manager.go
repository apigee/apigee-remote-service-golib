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

package quota

import (
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	quotaPath             = "/quotas"
	defaultSyncRate       = time.Second
	defaultNumSyncWorkers = 10
	defaultRefreshAfter   = 1 * time.Minute
	defaultDeleteAfter    = 10 * time.Minute
	syncQueueSize         = 100
	resultCacheBufferSize = 30
)

// A Manager tracks multiple Apigee quotas
type Manager interface {
	Start()
	Apply(auth *auth.Context, p *product.APIProduct, args Args) (*Result, error)
	Close()
}

type manager struct {
	baseURL            *url.URL
	close              chan bool
	closed             chan bool
	client             *http.Client
	now                func() time.Time
	syncRate           time.Duration
	bucketsLock        sync.RWMutex
	buckets            map[string]*bucket // Map from ID -> bucket
	syncQueue          chan *bucket
	numSyncWorkers     int
	dupCache           ResultCache
	syncingBuckets     map[*bucket]struct{}
	syncingBucketsLock sync.Mutex
	org                string
	env                string
}

// NewManager constructs and starts a new Manager. Call Close when done.
func NewManager(options Options) (Manager, error) {
	if err := options.validate(); err != nil {
		return nil, err
	}
	m := newManager(options)
	m.Start()
	return m, nil
}

// newManager constructs a new Manager
func newManager(options Options) *manager {
	return &manager{
		close:          make(chan bool),
		closed:         make(chan bool),
		client:         options.Client,
		now:            time.Now,
		syncRate:       defaultSyncRate,
		buckets:        map[string]*bucket{},
		syncQueue:      make(chan *bucket, syncQueueSize),
		baseURL:        options.BaseURL,
		numSyncWorkers: defaultNumSyncWorkers,
		dupCache:       ResultCache{size: resultCacheBufferSize},
		syncingBuckets: map[*bucket]struct{}{},
		org:            options.Org,
		env:            options.Env,
	}
}

// Start starts the manager.
func (m *manager) Start() {
	log.Infof("starting quota manager")

	go m.syncLoop()

	for i := 0; i < m.numSyncWorkers; i++ {
		go m.syncBucketWorker()
	}
	log.Infof("started quota manager with %d workers", m.numSyncWorkers)
}

// Close shuts down the manager.
func (m *manager) Close() {
	if m == nil {
		return
	}
	log.Infof("closing quota manager")
	m.close <- true
	close(m.syncQueue)
	for i := 0; i <= m.numSyncWorkers; i++ {
		<-m.closed
	}
	log.Infof("closed quota manager")
}

func getQuotaID(auth *auth.Context, p *product.APIProduct) string {
	return fmt.Sprintf("%s-%s", auth.Application, p.Name)
}

// Apply a quota request to the local quota bucket and schedule for sync
func (m *manager) Apply(auth *auth.Context, p *product.APIProduct, args Args) (*Result, error) {

	if result := m.dupCache.Get(args.DeduplicationID); result != nil {
		return result, nil
	}

	quotaID := getQuotaID(auth, p)

	req := &Request{
		Identifier: quotaID,
		Interval:   p.QuotaIntervalInt,
		Allow:      p.QuotaLimitInt,
		TimeUnit:   p.QuotaTimeUnit,
	}

	// a new bucket is created if missing or if product is no longer compatible
	var result *Result
	var err error
	m.bucketsLock.RLock()
	b, ok := m.buckets[quotaID]
	m.bucketsLock.RUnlock()
	if !ok || !b.compatible(req) {
		m.bucketsLock.Lock()
		b, ok = m.buckets[quotaID]
		if !ok || !b.compatible(req) {
			promLabels := m.prometheusLabelsForQuota(quotaID)
			b = newBucket(*req, m, promLabels)
			m.buckets[quotaID] = b
			log.Debugf("new quota bucket: %s", quotaID)
		}
		m.bucketsLock.Unlock()
	}

	req.Weight = args.QuotaAmount
	result, err = b.apply(req)

	if result != nil && err == nil && args.DeduplicationID != "" {
		m.dupCache.Add(args.DeduplicationID, result)
	}

	return result, err
}

// loop to sync active buckets and deletes old buckets
func (m *manager) syncLoop() {
	t := time.NewTicker(m.syncRate)
	for {
		select {
		case <-t.C:
			var deleteIDs []string
			m.bucketsLock.RLock()
			for id, b := range m.buckets {
				if b.needToDelete() {
					deleteIDs = append(deleteIDs, id)
				} else if b.needToSync() {
					bucket := b
					m.syncQueue <- bucket
				}
			}
			m.bucketsLock.RUnlock()
			if deleteIDs != nil {
				log.Debugf("deleting quota buckets: %v", deleteIDs)
				m.bucketsLock.Lock()
				for _, id := range deleteIDs {
					delete(m.buckets, id)
					labels := m.prometheusLabelsForQuota(id)
					prometheusBucketWindowExpires.Delete(labels)
					prometheusBucketChecked.Delete(labels)
					prometheusBucketSynced.Delete(labels)
					prometheusBucketValue.Delete(labels)
				}
				m.bucketsLock.Unlock()
			}
		case <-m.close:
			log.Debugf("closing quota sync loop")
			t.Stop()
			m.closed <- true
			return
		}
	}
}

func (m *manager) prometheusLabelsForQuota(quotaID string) prometheus.Labels {
	return prometheus.Labels{"org": m.org, "env": m.env, "quota": quotaID}
}

// worker routine for syncing a bucket with the server
func (m *manager) syncBucketWorker() {
	for {
		bucket, ok := <-m.syncQueue
		if ok {
			m.syncingBucketsLock.Lock()
			if _, ok := m.syncingBuckets[bucket]; !ok {
				m.syncingBuckets[bucket] = struct{}{}
				m.syncingBucketsLock.Unlock()
				// TODO: ideally, this should have a backoff on it
				bucket.sync()
				m.syncingBucketsLock.Lock()
				delete(m.syncingBuckets, bucket)
			}
			m.syncingBucketsLock.Unlock()
		} else {
			log.Debugf("closing quota sync worker")
			m.closed <- true
			return
		}
	}
}

// Options allows us to specify options for how this auth manager will run
type Options struct {
	// Client is a configured HTTPClient
	Client *http.Client
	// BaseURL of the Apigee internal proxy
	BaseURL *url.URL
	// Org is organization
	Org string
	// Env is environment
	Env string
}

func (o *Options) validate() error {
	if o.Client == nil ||
		o.BaseURL == nil ||
		o.Org == "" ||
		o.Env == "" {
		return fmt.Errorf("all quota options are required")
	}
	return nil
}

var (
	prometheusBucketValue = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "quota",
		Name:      "value",
		Help:      "Current value of a quota",
	}, []string{"org", "env", "quota"})

	prometheusBucketChecked = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "quota",
		Name:      "checked",
		Help:      "Time quota was last checked",
	}, []string{"org", "env", "quota"})

	prometheusBucketSynced = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "quota",
		Name:      "synced",
		Help:      "Time quota was last synced",
	}, []string{"org", "env", "quota"})

	prometheusBucketWindowExpires = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "quota",
		Name:      "window_expires",
		Help:      "Time quota window will expire",
	}, []string{"org", "env", "quota"})
)
