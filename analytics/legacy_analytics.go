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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
)

const (
	axPath = "/axpublisher/organization/%s/environment/%s"
)

type legacyAnalytics struct {
	client *http.Client
}

func (oa *legacyAnalytics) Start() {}
func (oa *legacyAnalytics) Close() {}

func (oa *legacyAnalytics) SendRecords(authContext *auth.Context, records []Record) error {
	axURL := *authContext.InternalAPI()
	axURL.Path = path.Join(axURL.Path, fmt.Sprintf(axPath, authContext.Organization(), authContext.Environment()))

	request, err := buildRequest(authContext, records)
	if request == nil || err != nil {
		return err
	}

	body := new(bytes.Buffer)
	_ = json.NewEncoder(body).Encode(request)

	req, err := http.NewRequest(http.MethodPost, axURL.String(), body)
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	log.Debugf("sending %d analytics records to: %s", len(records), axURL.String())

	resp, err := oa.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	bufLen := resp.ContentLength
	if bufLen < bytes.MinRead {
		bufLen = bytes.MinRead
	}
	buf := bytes.NewBuffer(make([]byte, 0, bufLen))
	_, err = buf.ReadFrom(resp.Body)
	if err != nil {
		return err
	}
	respBody := buf.Bytes()

	switch resp.StatusCode {
	case 200:
		log.Debugf("analytics accepted: %v", string(respBody))
		return nil
	default:
		return fmt.Errorf("analytics rejected. status: %d, body: %s", resp.StatusCode, string(respBody))
	}
}

func buildRequest(authContext *auth.Context, incoming []Record) (*legacyRequest, error) {
	if authContext == nil || len(incoming) == 0 {
		return nil, nil
	}
	if authContext.Organization() == "" || authContext.Environment() == "" {
		return nil, fmt.Errorf("organization and environment are required in auth: %v", authContext)
	}

	records := make([]Record, 0, len(incoming))
	for _, record := range incoming {
		records = append(records, record.EnsureFields(authContext))
	}

	return &legacyRequest{
		Organization: authContext.Organization(),
		Environment:  authContext.Environment(),
		Records:      records,
	}, nil
}

type legacyRequest struct {
	Organization string   `json:"organization"`
	Environment  string   `json:"environment"`
	Records      []Record `json:"records"`
}

type legacyResponse struct {
	Accepted int `json:"accepted"`
	Rejected int `json:"rejected"`
}
