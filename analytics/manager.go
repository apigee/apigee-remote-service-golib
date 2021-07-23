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

package analytics

import (
	"context"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// A Manager wraps all things related to analytics processing
type Manager interface {
	Start()
	Close()
	SendRecords(authContext *auth.Context, records []Record) error
}

// NewManager constructs and starts a new manager. Call Close when you are done.
func NewManager(opts Options) (Manager, error) {
	if opts.LegacyEndpoint {
		return &legacyAnalytics{client: opts.Client}, nil
	}

	if opts.now == nil {
		opts.now = time.Now
	}

	if err := opts.validate(); err != nil {
		return nil, err
	}

	uploader := &saasUploader{
		client:       opts.Client,
		baseURL:      opts.BaseURL,
		now:          opts.now,
		isGCPManaged: opts.isGCPManaged(),
	}

	mgr, err := newManager(uploader, opts)
	if err != nil {
		return nil, err
	}

	mgr.Start()
	return mgr, nil
}

func newManager(uploader uploader, opts Options) (*manager, error) {

	// Ensure that base temp dir exists
	bufferMode := os.FileMode(0700)
	td := filepath.Join(opts.BufferPath, "temp")
	if err := os.MkdirAll(td, bufferMode); err != nil {
		return nil, fmt.Errorf("mkdir %s: %s", td, err)
	}
	// Ensure that base stage dir exists
	sd := filepath.Join(opts.BufferPath, "staging")
	if err := os.MkdirAll(sd, bufferMode); err != nil {
		return nil, fmt.Errorf("mkdir %s: %s", sd, err)
	}

	return &manager{
		closeStaging:       make(chan bool),
		now:                opts.now,
		collectionInterval: opts.CollectionInterval,
		tempDir:            td,
		stagingDir:         sd,
		stagingFileLimit:   opts.StagingFileLimit,
		buckets:            map[string]*bucket{},
		sendChannelSize:    opts.SendChannelSize,
		uploader:           uploader,
	}, nil
}

// A manager is a way for a Remote Service client to interact with Apigee's analytics platform.
type manager struct {
	closeStaging       chan bool
	now                func() time.Time
	collectionInterval time.Duration
	tempDir            string // open files being written to
	stagingDir         string // files staged for upload
	stagingFileLimit   int
	bucketsLock        sync.RWMutex
	buckets            map[string]*bucket // dir ("org~env") -> bucket
	sendChannelSize    int
	closed             bool
	uploadChan         chan<- interface{}
	uploadersWait      sync.WaitGroup
	uploader           uploader
}

// Options allows us to specify options for how this analytics manager will run.
type Options struct {
	// LegacyEndpoint is true if using older direct-submit protocol (opdk)
	LegacyEndpoint bool
	// BufferPath is the directory where the adapter will buffer analytics records.
	BufferPath string
	// StagingFileLimit is the maximum number of files stored in the staging directory.
	// Once this is reached, the oldest files will start being removed.
	StagingFileLimit int
	// Base Apigee URL (legacy saas)
	BaseURL *url.URL
	// Client is a configured HTTPClient
	Client *http.Client
	// SendChannelSize is the size of the records channel
	SendChannelSize int
	// collection interval
	CollectionInterval time.Duration
	// now is for testing
	now func() time.Time
}

// validate checks if there is missing options
func (o *Options) validate() error {
	if o.BufferPath == "" ||
		o.StagingFileLimit <= 0 ||
		o.Client == nil ||
		o.now == nil {
		return fmt.Errorf("all analytics options are required")
	}
	return nil
}

// isGCPManaged checks if the given baseURL is GCPManagedHost
func (o *Options) isGCPManaged() bool {
	return o.BaseURL != nil && strings.HasSuffix(o.BaseURL.Hostname(), "googleapis.com")
}

const (
	// legacy saas path and parameters
	analyticsPath = "/analytics/organization/%s/environment/%s"
	axRecordType  = "APIAnalytics"
	pathFmt       = "date=%s/time=%s/"

	// gcp managed uap path and parameters
	uapAnalyticsPath    = "/v1/organizations/%s/environments/%s/datalocation"
	repoName            = "edge"
	datasetType         = "api"
	relativeFilePathFmt = "%v.api.%s.%s.%s.gz" // %timestamp.api.org.env.uuid.gz

	// limited to 2 for now to limit upload stress
	numUploaders = 2
)

// Start starts the manager.
func (m *manager) Start() {
	log.Infof("starting analytics manager: %s", m.tempDir)

	// start upload channel and workers
	errNoRetry := fmt.Errorf("analytics closed, no retry on upload")
	errHandler := func(err error) error {
		m.bucketsLock.RLock()
		if m.closed {
			m.bucketsLock.RUnlock()
			return errNoRetry
		}
		m.bucketsLock.RUnlock()
		log.Errorf("analytics upload: %v", err)
		return nil
	}
	m.startUploader(errHandler)

	// handle anything hanging around in temp or staging
	if err := m.crashRecovery(); err != nil {
		log.Errorf("Error(s) recovering crashed data: %s", err)
	}

	go m.stagingLoop()

	log.Infof("started analytics manager: %s", m.tempDir)
}

func (m *manager) startUploader(errHandler util.ErrorFunc) {
	m.uploadersWait = sync.WaitGroup{}
	ctx := context.Background()

	canceledCtx, cancel := context.WithCancel(ctx)
	cancel()

	limit := int(math.Max(float64(m.stagingFileLimit-numUploaders), 1))
	send, receive, overflow := util.NewReservoir(limit)
	m.uploadChan = send

	// handle uploads
	for i := 0; i < numUploaders; i++ {
		l := util.Looper{
			Backoff: util.DefaultExponentialBackoff(),
		}
		m.uploadersWait.Add(1)
		go func() {
			defer m.uploadersWait.Done()

			for work := range receive {
				if err := l.Run(ctx, work.(util.WorkFunc), errHandler); err != nil {
					log.Errorf("looper run: %v", err)
				}
			}
		}()
	}

	m.uploadersWait.Add(1)
	// handle overflow
	go func() {
		defer m.uploadersWait.Done()

		for dropped := range overflow {
			work := dropped.(util.WorkFunc)
			go func() {
				if err := work(canceledCtx); err != nil {
					log.Errorf("handling overflow: %v", err)
				}
			}()
		}
	}()
}

func (m *manager) upload(tenant, file string, numRecs int) {
	prometheusInstrumentedWork := func(ctx context.Context) error {
		err := m.uploader.workFunc(tenant, file)(ctx)
		if err == nil {
			org, env, _ := getOrgAndEnvFromTenant(tenant)
			prometheusRecordsByFile.Delete(prometheus.Labels{"org": org, "env": env, "file": file})
			countLabels := prometheus.Labels{"org": org, "env": env, "status": "uploaded"}
			prometheusRecordsCount.With(countLabels).Add(float64(numRecs))
		}
		return err
	}
	m.uploadChan <- prometheusInstrumentedWork
}

// Close shuts down the manager
func (m *manager) Close() {
	if m == nil {
		return
	}
	log.Infof("closing analytics manager: %s", m.tempDir)

	m.bucketsLock.Lock()
	m.closed = true
	m.bucketsLock.Unlock()

	m.closeStaging <- true

	// force stage and upload
	m.stageAllBucketsWait()
	close(m.uploadChan)
	m.uploadersWait.Wait()

	log.Infof("closed analytics manager: %s", m.tempDir)
}

// stagingLoop periodically closes and sweeps open buckets to staging
func (m *manager) stagingLoop() {
	t := time.NewTicker(m.collectionInterval)
	for {
		select {
		case <-t.C:
			m.stageAllBucketsWait()

		case <-m.closeStaging:
			log.Debugf("analytics staging loop closed: %s", m.tempDir)
			return
		}
	}
}

// SendRecords is called by Mixer, spools records for sending
func (m *manager) SendRecords(ctx *auth.Context, incoming []Record) error {
	if m == nil || len(incoming) == 0 {
		return nil
	}

	// Validate the records
	now := m.now()
	records := make([]Record, 0, len(incoming))
	promLabels := prometheus.Labels{"org": ctx.Organization(), "env": ctx.Environment()}
	localRecCount := prometheusRecordsCount.MustCurryWith(promLabels)
	for _, record := range incoming {
		record := record.EnsureFields(ctx)
		if err := record.validate(now); err != nil {
			log.Errorf("invalid record %#v: %s", record, err)
			localRecCount.WithLabelValues("error").Inc()
			continue
		}
		localRecCount.WithLabelValues("accepted").Inc()
		records = append(records, record)
	}

	return m.writeToBucket(ctx, records)
}

func (m *manager) writeToBucket(ctx *auth.Context, records []Record) error {
	if len(records) == 0 {
		return nil
	}
	tenant := getTenantName(ctx.Organization(), ctx.Environment())

	m.bucketsLock.RLock()
	if bucket, ok := m.buckets[tenant]; ok {
		bucket.write(records)
		m.bucketsLock.RUnlock()
		return nil
	}

	// no bucket, we'll have to work harder
	m.bucketsLock.RUnlock()
	m.bucketsLock.Lock()
	defer m.bucketsLock.Unlock()

	bucket, ok := m.buckets[tenant]
	if !ok {
		if err := m.prepTenant(tenant); err != nil {
			return err
		}

		var err error
		bucket, err = newBucket(m, m.uploader, tenant, m.getTempDir(tenant))
		if err != nil {
			return err
		}
		m.buckets[tenant] = bucket
	}
	bucket.write(records)
	return nil
}

// ensures tenant temp and staging dirs are created
func (m *manager) prepTenant(tenant string) error {
	bufferMode := os.FileMode(0700)

	dir := m.getTempDir(tenant)
	if err := os.MkdirAll(dir, bufferMode); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, err)
	}

	dir = m.getStagingDir(tenant)
	if err := os.MkdirAll(dir, bufferMode); err != nil {
		return fmt.Errorf("mkdir %s: %s", dir, err)
	}

	return nil
}

func (m *manager) getTempDir(tenant string) string {
	return filepath.Join(m.tempDir, tenant)
}

func (m *manager) getStagingDir(tenant string) string {
	return filepath.Join(m.stagingDir, tenant)
}

func getTenantName(org, env string) string {
	return fmt.Sprintf("%s~%s", org, env)
}

func getOrgAndEnvFromTenant(tenant string) (string, string, error) {
	split := strings.Split(tenant, "~")
	if len(split) != 2 {
		return "", "", fmt.Errorf("deriving Org and Env from tenant: %s", tenant)
	}
	return split[0], split[1], nil
}

var (
	prometheusRecordsCount = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "analytics",
		Name:      "records_count",
		Help:      "Analytics record counts by status",
	}, []string{"org", "env", "status"})

	prometheusRecordsByFile = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Subsystem: "analytics",
		Name:      "records_staged",
		Help:      "Analytics record counts by staging file",
	}, []string{"org", "env", "file"})
)
