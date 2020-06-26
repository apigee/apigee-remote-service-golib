// Copyright 2020 Google LLC
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
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/util"
)

func TestFluentdAnalyticsMTLS(t *testing.T) {
	ts := int64(1521221450) // This timestamp is roughly 11:30 MST on Mar. 16, 2018
	now := func() time.Time { return time.Unix(ts, 0) }
	startTime := now()

	authContext := makeAuthContext()
	axRecord := makeRecord(startTime)

	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("port: %d", port)
	d, err := ioutil.TempDir("", "TestFluentdAnalyticsMTLS")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %s", err)
	}
	defer os.RemoveAll(d)

	opts := Options{
		BufferPath:         d,
		StagingFileLimit:   1,
		BaseURL:            &url.URL{},
		Client:             http.DefaultClient,
		now:                now,
		CollectionInterval: time.Minute,
		FluentdEndpoint:    fmt.Sprintf("localhost:%d", port),
		TLSCAFile:          "testdata/cert.pem",
		TLSCertFile:        "testdata/cert.pem",
		TLSKeyFile:         "testdata/key.pem",
		TLSSkipVerify:      false,
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	listener := fluentdListener(t, port, cert)
	sendRecord(t, mgr, authContext, axRecord)
	got := fluentdReceive(t, listener)

	up := mgr.(*manager).uploader
	uuid := up.(*fluentdUploader).clientUUID

	tag := fmt.Sprintf(tagFormat, recType, authContext.Organization(), authContext.Environment(), uuid)
	axRecord = axRecord.ensureFields(authContext)
	axJSON, err := json.Marshal(axRecord)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[\"%s\", %d, %s]", tag, ts, axJSON)

	// the gatewayFlowID value is variable, just trim it off
	if got[:len(got)-40] != want[:len(want)-40] {
		t.Errorf("got record: %s, want: %s", got, want)
	}
}

func TestFluentdAnalyticsTLSSkipVerify(t *testing.T) {
	ts := int64(1521221450) // This timestamp is roughly 11:30 MST on Mar. 16, 2018
	now := func() time.Time { return time.Unix(ts, 0) }
	startTime := now()

	authContext := makeAuthContext()
	axRecord := makeRecord(startTime)

	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("port: %d", port)
	d, err := ioutil.TempDir("", "TestFluentdAnalyticsTLSSkipVerify")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %s", err)
	}
	defer os.RemoveAll(d)

	opts := Options{
		BufferPath:         d,
		StagingFileLimit:   1,
		BaseURL:            &url.URL{},
		Client:             http.DefaultClient,
		now:                now,
		CollectionInterval: time.Minute,
		FluentdEndpoint:    fmt.Sprintf("localhost:%d", port),
		TLSSkipVerify:      true,
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	cert, err := tls.LoadX509KeyPair("testdata/cert.pem", "testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}

	listener := fluentdListener(t, port, cert)
	sendRecord(t, mgr, authContext, axRecord)
	got := fluentdReceive(t, listener)

	up := mgr.(*manager).uploader
	uuid := up.(*fluentdUploader).clientUUID

	tag := fmt.Sprintf(tagFormat, recType, authContext.Organization(), authContext.Environment(), uuid)
	axRecord = axRecord.ensureFields(authContext)
	axJSON, err := json.Marshal(axRecord)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[\"%s\", %d, %s]", tag, ts, axJSON)

	// the gatewayFlowID value is variable, just trim it off
	if got[:len(got)-40] != want[:len(want)-40] {
		t.Errorf("got record: %s, want: %s", got, want)
	}
}

func TestFluentdAnalyticsNoTLS(t *testing.T) {
	ts := int64(1521221450) // This timestamp is roughly 11:30 MST on Mar. 16, 2018
	now := func() time.Time { return time.Unix(ts, 0) }
	startTime := now()

	authContext := makeAuthContext()
	axRecord := makeRecord(startTime)

	port, err := util.FreePort()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("port: %d", port)
	d, err := ioutil.TempDir("", "TestFluentdAnalyticsNoTLS")
	if err != nil {
		t.Fatalf("ioutil.TempDir: %s", err)
	}
	defer os.RemoveAll(d)

	opts := Options{
		BufferPath:         d,
		StagingFileLimit:   1,
		BaseURL:            &url.URL{},
		Client:             http.DefaultClient,
		now:                now,
		CollectionInterval: time.Minute,
		FluentdEndpoint:    fmt.Sprintf("localhost:%d", port),
	}
	mgr, err := NewManager(opts)
	if err != nil {
		t.Fatal(err)
	}

	listener := fluentdListener(t, port, tls.Certificate{})
	sendRecord(t, mgr, authContext, axRecord)
	got := fluentdReceive(t, listener)

	up := mgr.(*manager).uploader
	uuid := up.(*fluentdUploader).clientUUID

	tag := fmt.Sprintf(tagFormat, recType, authContext.Organization(), authContext.Environment(), uuid)
	axRecord = axRecord.ensureFields(authContext)
	axJSON, err := json.Marshal(axRecord)
	if err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("[\"%s\", %d, %s]", tag, ts, axJSON)

	// the gatewayFlowID value is variable, just trim it off
	if got[:len(got)-40] != want[:len(want)-40] {
		t.Errorf("got record: %s, want: %s", got, want)
	}
}

func makeAuthContext() *auth.Context {
	return &auth.Context{
		Context: &TestContext{
			orgName: "org",
			envName: "env",
		},
		DeveloperEmail: "email",
		Application:    "app",
		AccessToken:    "token",
		ClientID:       "clientId",
	}
}

func makeRecord(startTime time.Time) Record {
	return Record{
		ResponseStatusCode:           201,
		RequestVerb:                  "PATCH",
		RequestPath:                  "/test",
		UserAgent:                    "007",
		ClientReceivedStartTimestamp: timeToUnix(startTime),
		ClientReceivedEndTimestamp:   timeToUnix(startTime),
		ClientSentStartTimestamp:     timeToUnix(startTime),
		ClientSentEndTimestamp:       timeToUnix(startTime),
		TargetSentStartTimestamp:     timeToUnix(startTime),
		TargetSentEndTimestamp:       timeToUnix(startTime),
		TargetReceivedStartTimestamp: timeToUnix(startTime),
		TargetReceivedEndTimestamp:   timeToUnix(startTime),
	}
}

func sendRecord(t *testing.T, mgr Manager, authContext *auth.Context, axRecord Record) {
	if err := mgr.SendRecords(authContext, []Record{axRecord}); err != nil {
		panic(err)
	}
	go mgr.Close() // force write
}

func fluentdListener(t *testing.T, port int, cert tls.Certificate) net.Listener {
	endpoint := fmt.Sprintf("localhost:%d", port)

	var err error
	var listener net.Listener
	if cert.Certificate != nil {
		tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}}
		listener, err = tls.Listen("tcp", endpoint, tlsConfig)
	} else {
		listener, err = net.Listen("tcp", endpoint)
	}
	if err != nil {
		t.Fatal(err)
	}

	return listener
}

func fluentdReceive(t *testing.T, listener net.Listener) string {
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	if !scanner.Scan() {
		t.Fatal("scan failed")
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}

	txt := scanner.Text()
	t.Logf("scanned: %s\n", txt)
	return txt
}
