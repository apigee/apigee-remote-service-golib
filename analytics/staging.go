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
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/hashicorp/go-multierror"
	"github.com/prometheus/client_golang/prometheus"
)

func (m *manager) stageFile(tenant, tempFile string, numRecs int) {

	stageDir := m.getStagingDir(tenant)
	stagedFile := filepath.Join(stageDir, filepath.Base(tempFile))
	if err := os.Rename(tempFile, stagedFile); err != nil {
		log.Errorf("can't rename file: %s", err)
		return
	}
	org, env, _ := getOrgAndEnvFromTenant(tenant)
	promLabels := prometheus.Labels{"org": org, "env": env, "file": stagedFile}
	prometheusRecordsByFile.With(promLabels).Set(float64(numRecs))

	m.upload(tenant, stagedFile, numRecs)
	log.Debugf("staged file: %s", stagedFile)
}

func (m *manager) getFilesInStaging() ([]string, error) {
	tenantDirs, err := os.ReadDir(m.stagingDir)
	if err != nil {
		return nil, fmt.Errorf("ReadDir(%s): %s", m.tempDir, err)
	}

	var errs error
	var filePaths []string
	for _, tenantDir := range tenantDirs {
		tenantDirPath := filepath.Join(m.stagingDir, tenantDir.Name())

		stagedFiles, err := os.ReadDir(tenantDirPath)
		if err != nil {
			errs = multierror.Append(errs, fmt.Errorf("ls %s: %s", tenantDirPath, err))
			continue
		}

		for _, stagedFile := range stagedFiles {
			filePaths = append(filePaths, filepath.Join(tenantDirPath, stagedFile.Name()))
		}
	}
	return filePaths, errs
}

func (m *manager) stageAllBucketsWait() {
	wait := &sync.WaitGroup{}
	m.stageAllBuckets(wait)
	wait.Wait()
}

func (m *manager) stageAllBuckets(wait *sync.WaitGroup) {
	m.bucketsLock.Lock()
	buckets := m.buckets
	m.buckets = map[string]*bucket{}
	m.bucketsLock.Unlock()
	for tenant, bucket := range buckets {
		m.stageBucket(tenant, bucket, wait)
	}
}

func (m *manager) stageBucket(tenant string, b *bucket, wait *sync.WaitGroup) {
	if wait != nil {
		wait.Add(1)
	}
	b.close(wait)
}
