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
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/product"
	"github.com/apigee/apigee-remote-service-golib/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

const (
	quotaPath             = "/quotas"
	defaultSyncRate       = time.Second
	defaultNumSyncWorkers = 10
	defaultRefreshAfter   = 1 * time.Minute
	defaultDeleteAfter    = 10 * time.Minute
	syncQueueSize         = 1000
	resultCacheBufferSize = 30
)

/*
Dispatch basically works like this:
	every m.syncRate tick do
		if bucket needs to sync and isn't syncing
			m.bucketToSyncQueue <- bucket
	each of m.numSyncWorkers do:
		bucket <-m.bucketToSyncQueue
			bucket.sync() with backoff
*/

// A Manager tracks multiple Apigee quotas
type Manager interface {
	Start()
	Apply(authContext *auth.Context, o product.AuthorizedOperation, args Args) (*Result, error)
	Close()
}

type manager struct {
	baseURL            *url.URL
	close              chan bool
	client             *http.Client
	now                func() time.Time
	syncRate           time.Duration
	bucketsLock        sync.RWMutex
	buckets            map[string]*bucket // Map from ID -> bucket
	bucketToSyncQueue  chan *bucket
	numSyncWorkers     int
	syncWorkerWG       sync.WaitGroup
	dupCache           ResultCache
	bucketsSyncingLock sync.Mutex
	bucketsSyncing     map[*bucket]struct{}
	org                string
	env                string
	runningContext     context.Context
	cancelContext      context.CancelFunc
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
		close:             make(chan bool),
		client:            options.Client,
		now:               time.Now,
		syncRate:          defaultSyncRate,
		buckets:           map[string]*bucket{},
		bucketToSyncQueue: make(chan *bucket, syncQueueSize),
		baseURL:           options.BaseURL,
		numSyncWorkers:    defaultNumSyncWorkers,
		dupCache:          ResultCache{size: resultCacheBufferSize},
		bucketsSyncing:    map[*bucket]struct{}{},
		org:               options.Org,
		env:               options.Env,
	}
}

// Start starts the manager.
func (m *manager) Start() {
	log.Infof("starting quota manager")

	m.runningContext, m.cancelContext = context.WithCancel(context.Background())

	go m.bucketMaintenanceLoop()
	for i := 0; i < m.numSyncWorkers; i++ {
		go m.syncBucketDispatcher()
	}

	log.Infof("started quota manager with %d workers", m.numSyncWorkers)
}

// Close shuts down the manager.
func (m *manager) Close() {
	if m == nil {
		return
	}
	log.Infof("closing quota manager")
	m.cancelContext()
	m.runningContext = nil

	m.syncWorkerWG.Add(m.numSyncWorkers)
	m.close <- true
	close(m.bucketToSyncQueue)
	m.syncWorkerWG.Wait()
	log.Infof("closed quota manager")
}

// Apply a quota request to the local quota bucket and schedule for sync
func (m *manager) Apply(authContext *auth.Context, operation product.AuthorizedOperation, args Args) (*Result, error) {

	if operation.QuotaLimit == 0 {
		return nil, nil
	}

	if result := m.dupCache.Get(args.DeduplicationID); result != nil {
		return result, nil
	}

	req := &Request{
		Identifier: operation.ID,
		Interval:   operation.QuotaInterval,
		Allow:      operation.QuotaLimit,
		TimeUnit:   operation.QuotaTimeUnit,
	}

	// a new bucket is created if missing or if product is no longer compatible
	var result *Result
	var err error
	m.bucketsLock.RLock()
	b, ok := m.buckets[req.Identifier]
	m.bucketsLock.RUnlock()
	if !ok || !b.compatible(req) {
		m.bucketsLock.Lock()
		b, ok = m.buckets[req.Identifier]
		if !ok || !b.compatible(req) {
			promLabels := m.prometheusLabelsForQuota(req.Identifier)
			b = newBucket(*req, m, promLabels)
			m.buckets[req.Identifier] = b
			log.Debugf("new quota bucket: %s", req.Identifier)
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

// loop to sync active buckets and delete old buckets
func (m *manager) bucketMaintenanceLoop() {
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
					m.bucketsSyncingLock.Lock()
					if _, ok := m.bucketsSyncing[b]; !ok { // not already scheduled
						m.bucketsSyncing[b] = struct{}{}
					}
					m.bucketsSyncingLock.Unlock()
					m.bucketToSyncQueue <- b
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
			return
		}
	}
}

func (m *manager) prometheusLabelsForQuota(quotaID string) prometheus.Labels {
	return prometheus.Labels{"org": m.org, "env": m.env, "quota": quotaID}
}

// routine for dispatching work to sync a bucket with the server
func (m *manager) syncBucketDispatcher() {

	for bucket := range m.bucketToSyncQueue {
		looper := util.Looper{
			Backoff: util.NewExponentialBackoff(200*time.Millisecond, 30*time.Second, 2, true),
		}
		work := func(ctx context.Context) error {
			return bucket.sync()
		}
		errH := func(err error) error {
			log.Errorf("sync: %s", err)
			return nil
		}

		// run until success or canceled with backoff
		if err := looper.Run(m.runningContext, work, errH); err != nil {
			log.Errorf("looper run: %s", err)
		}

		m.bucketsSyncingLock.Lock()
		delete(m.bucketsSyncing, bucket)
		m.bucketsSyncingLock.Unlock()
	}

	m.syncWorkerWG.Done()
	log.Debugf("closing quota sync worker")
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
