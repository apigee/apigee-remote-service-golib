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
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apigee/apigee-remote-service-golib/auth"
	"github.com/apigee/apigee-remote-service-golib/log"
	"github.com/google/uuid"
	"github.com/hashicorp/go-multierror"
)

const (
	attributePrefix        = "dc."
	maxNumAttributes       = 100
	maxAttributeValueBytes = 400
)

// An Attribute is used to record custom Record values.
// Name will be forced to have "dc." prefix.
// Value will be limited to 400 bytes, truncated on rune boundary.
type Attribute struct {
	Name  string
	Value string
}

// A Record is a single event that is tracked via Apigee analytics.
// A limit of 100 Attributes will be transmitted.
type Record struct {
	ClientReceivedStartTimestamp int64       `json:"client_received_start_timestamp"`
	ClientReceivedEndTimestamp   int64       `json:"client_received_end_timestamp"`
	TargetSentStartTimestamp     int64       `json:"target_sent_start_timestamp,omitempty"`
	TargetSentEndTimestamp       int64       `json:"target_sent_end_timestamp,omitempty"`
	TargetReceivedStartTimestamp int64       `json:"target_received_start_timestamp,omitempty"`
	TargetReceivedEndTimestamp   int64       `json:"target_received_end_timestamp,omitempty"`
	ClientSentStartTimestamp     int64       `json:"client_sent_start_timestamp"`
	ClientSentEndTimestamp       int64       `json:"client_sent_end_timestamp"`
	RecordType                   string      `json:"recordType"`
	APIProxy                     string      `json:"apiproxy"`
	RequestURI                   string      `json:"request_uri"`
	RequestPath                  string      `json:"request_path"`
	RequestVerb                  string      `json:"request_verb"`
	ClientIP                     string      `json:"client_ip,omitempty"`
	UserAgent                    string      `json:"useragent"`
	APIProxyRevision             int         `json:"apiproxy_revision"`
	ResponseStatusCode           int         `json:"response_status_code"`
	DeveloperEmail               string      `json:"developer_email,omitempty"`
	DeveloperApp                 string      `json:"developer_app,omitempty"`
	AccessToken                  string      `json:"access_token,omitempty"`
	ClientID                     string      `json:"client_id,omitempty"`
	APIProduct                   string      `json:"api_product,omitempty"`
	Organization                 string      `json:"organization"`
	Environment                  string      `json:"environment"`
	GatewaySource                string      `json:"gateway_source"`
	GatewayFlowID                string      `json:"gateway_flow_id"`
	Attributes                   []Attribute `json:"-"`
}

func (r Record) EnsureFields(authContext *auth.Context) Record {
	r.RecordType = axRecordType

	// populate from auth context
	r.DeveloperEmail = authContext.DeveloperEmail
	r.DeveloperApp = authContext.Application
	r.AccessToken = authContext.AccessToken
	r.ClientID = authContext.ClientID
	r.Organization = authContext.Organization()
	r.Environment = authContext.Environment()

	r.GatewayFlowID = uuid.New().String()

	// select arbitrary APIProduct
	if len(authContext.APIProducts) > 0 {
		r.APIProduct = authContext.APIProducts[0]
	}
	return r
}

// validate confirms that a record has correct values in it.
func (r Record) validate(now time.Time) error {
	var err error

	// Validate that certain fields are set.
	if r.Organization == "" {
		err = multierror.Append(err, errors.New("missing Organization"))
	}
	if r.Environment == "" {
		err = multierror.Append(err, errors.New("missing Environment"))
	}
	if r.GatewayFlowID == "" {
		err = multierror.Append(err, errors.New("missing GatewayFlowID"))
	}
	if r.ClientReceivedStartTimestamp == 0 {
		err = multierror.Append(err, errors.New("missing ClientReceivedStartTimestamp"))
	}
	if r.ClientReceivedEndTimestamp == 0 {
		err = multierror.Append(err, errors.New("missing ClientReceivedEndTimestamp"))
	}
	if r.ClientReceivedStartTimestamp > r.ClientReceivedEndTimestamp {
		err = multierror.Append(err, errors.New("ClientReceivedStartTimestamp > ClientReceivedEndTimestamp"))
	}

	// Validate that timestamps make sense.
	ts := time.Unix(r.ClientReceivedStartTimestamp/1000, 0)
	if ts.After(now.Add(time.Minute)) { // allow a minute of tolerance
		err = multierror.Append(err, errors.New("ClientReceivedStartTimestamp cannot be in the future"))
	}
	if ts.Before(now.Add(-90 * 24 * time.Hour)) {
		err = multierror.Append(err, errors.New("ClientReceivedStartTimestamp cannot be more than 90 days old"))
	}
	return err
}

// MarshalJSON marshalls Attributes with keys that must
// begin with a "dc." prefix and values that are limited
// to 400 bytes.
func (r Record) MarshalJSON() ([]byte, error) {
	type alias Record
	m, err := structToMap(alias(r))
	if err != nil {
		return nil, err
	}
	attrs := r.Attributes
	if len(r.Attributes) > maxNumAttributes {
		log.Debugf("truncated attributes list to max length of %d", maxNumAttributes)
		attrs = r.Attributes[:maxNumAttributes]
	}
	for _, attr := range attrs {
		key := attr.Name
		if !strings.HasPrefix(key, attributePrefix) {
			key = attributePrefix + attr.Name
		}
		val := truncStringToBytes(attr.Value, maxAttributeValueBytes)
		m[key] = val
		if len(val) != len(attr.Value) {
			log.Debugf("truncated attribute %s to max length of %d", key, maxAttributeValueBytes)
		}
	}
	return json.Marshal(m)
}

// truncates the passed string to the limit number of bytes
func truncStringToBytes(in string, limit int) string {
	if len(in) > limit {
		for start, rune := range in {
			if start+utf8.RuneLen(rune) > limit {
				return in[:start]
			}
		}
	}
	return in
}

func structToMap(data interface{}) (map[string]interface{}, error) {
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	mapData := make(map[string]interface{})
	err = json.Unmarshal(dataBytes, &mapData)
	if err != nil {
		return nil, err
	}
	return mapData, nil
}
