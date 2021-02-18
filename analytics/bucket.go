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
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/prometheus/client_golang/prometheus"
)

func newBucket(m *manager, up uploader, tenant, dir string) (*bucket, error) {
	b := &bucket{
		manager:  m,
		uploader: up,
		tenant:   tenant,
		dir:      dir,
		incoming: make(chan []Record, m.sendChannelSize),
	}

	var tempFileSpec string
	if up.isGzipped() {
		tempFileSpec = fmt.Sprintf("%d-*.gz", b.manager.now().Unix())
	} else {
		tempFileSpec = fmt.Sprintf("%d-*.txt", b.manager.now().Unix())
	}

	f, err := os.CreateTemp(b.dir, tempFileSpec)
	if err != nil {
		log.Errorf("AX Records lost. Can't create bucket file: %s", err)
		return nil, err
	}
	b.w = &fileWriter{
		file:   f,
		writer: f,
	}
	if up.isGzipped() {
		b.w.writer = gzip.NewWriter(f)
	}

	go b.runLoop()
	return b, nil
}

// A bucket writes analytics to a temp file
type bucket struct {
	manager  *manager
	uploader uploader
	tenant   string
	dir      string
	w        *fileWriter
	incoming chan []Record
	wait     *sync.WaitGroup
}

// write records to bucket
func (b *bucket) write(records []Record) {
	if b != nil && len(records) > 0 {
		b.incoming <- records
	}
}

// close bucket
func (b *bucket) close(wait *sync.WaitGroup) {
	b.wait = wait
	close(b.incoming)
}

func (b *bucket) fileName() string {
	return b.w.file.Name()
}

func (b *bucket) runLoop() {
	written := 0
	org, env, _ := getOrgAndEnvFromTenant(b.tenant)
	promLabels := prometheus.Labels{"org": org, "env": env, "file": b.fileName()}
	defer prometheusRecordsByFile.Delete(promLabels)
	for records := range b.incoming {
		if err := b.uploader.write(records, b.w.writer); err != nil {
			log.Errorf("Write records to bucket: %s", err)
		}
		written = written + len(records)
		prometheusRecordsByFile.With(promLabels).Set(float64(written))
	}

	if err := b.w.close(); err != nil {
		log.Errorf("Can't close bucket file: %s", err)
	}

	b.manager.stageFile(b.tenant, b.fileName(), written)

	if b.wait != nil {
		b.wait.Done()
	}
	log.Debugf("bucket closed: %s", b.fileName())
}

type fileWriter struct {
	file   *os.File
	writer io.Writer
}

func (w *fileWriter) close() error {
	if gzw, ok := w.writer.(*gzip.Writer); ok {
		if err := gzw.Close(); err != nil {
			return fmt.Errorf("gz.Close: %s", err)
		}
	}

	if err := w.file.Close(); err != nil {
		return fmt.Errorf("f.Close: %s", err)
	}
	return nil
}
