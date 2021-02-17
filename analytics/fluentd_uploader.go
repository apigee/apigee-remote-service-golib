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
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/apigee/apigee-remote-service-golib/util"
	"github.com/google/uuid"
)

const (
	tagFormat     = "%s.%s.%s.%s" // recType, org, env, clientUUID
	recType       = "api"
	fluentdFormat = "[\"%s\", %d, %s]\n" // tag, unix timestamp, record json
)

func newFluentdUploader(opts Options) (*fluentdUploader, error) {
	tlsConfig, err := loadTLSConfig(opts)
	if err != nil {
		return nil, err
	}

	return &fluentdUploader{
		network:    "tcp",
		addr:       opts.FluentdEndpoint,
		tlsConfig:  tlsConfig,
		now:        opts.now,
		clientUUID: uuid.New().String(),
	}, nil
}

type fluentdUploader struct {
	network    string
	addr       string
	tlsConfig  *tls.Config
	now        func() time.Time
	clientUUID string
}

func (h *fluentdUploader) isGzipped() bool {
	return false
}

func (h *fluentdUploader) workFunc(tenant, fileName string) util.WorkFunc {
	return func(ctx context.Context) error {
		if ctx.Err() == nil {
			return h.upload(fileName)
		}

		log.Warnf("canceled upload of %s: %v", fileName, ctx.Err())
		if err := os.Remove(fileName); err != nil && !os.IsNotExist(err) {
			log.Warnf("unable to remove file %s: %v", fileName, err)
		}
		return nil
	}
}

// format and write records
func (h *fluentdUploader) write(incoming []Record, writer io.Writer) error {

	now := h.now()
	for _, record := range incoming {
		recJSON, err := json.Marshal(record)
		if err != nil {
			log.Errorf("dropping unmarshallable record %v: %s", record, err)
			continue
		}

		tag := fmt.Sprintf(tagFormat, recType, record.Organization, record.Environment, h.clientUUID)
		data := fmt.Sprintf(fluentdFormat, tag, now.Unix(), recJSON)
		log.Debugf("queuing analytics record for fluentd: %s", data)

		if _, err := writer.Write([]byte(data)); err != nil {
			return err
		}
	}

	return nil
}

// upload sends a file to UDCA
func (h *fluentdUploader) upload(fileName string) error {

	var client net.Conn
	var err error
	if h.tlsConfig == nil {
		client, err = net.Dial(h.network, h.addr)
	} else {
		client, err = tls.Dial(h.network, h.addr, h.tlsConfig)
	}
	if err != nil {
		log.Errorf("dial: %s", err)
		return err
	}
	defer client.Close()

	file, err := os.Open(fileName)
	if err != nil {
		log.Errorf("open: %s: %v", fileName, err)
		return err
	}
	defer file.Close()

	_, err = io.Copy(client, file)
	return err
}

func loadTLSConfig(opts Options) (*tls.Config, error) {

	if !opts.TLSSkipVerify && opts.TLSCAFile == "" {
		return nil, nil
	}

	config := &tls.Config{}

	if opts.TLSSkipVerify {
		config.InsecureSkipVerify = true
	}

	if opts.TLSCAFile != "" {
		// ca cert pool
		caCert, err := os.ReadFile(opts.TLSCAFile)
		if err != nil {
			return nil, err
		}
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			return nil, err
		}
		config.RootCAs = caCertPool

		//  tls key pair
		cert, err := tls.LoadX509KeyPair(opts.TLSCertFile, opts.TLSKeyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}
