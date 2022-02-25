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
	"fmt"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/errorset"
	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/google/uuid"
)

const (
	// the prefix that customers expect for data collection variables
	customerDataCollectorPrefix = "dc_"
	// the prefix that analytics expects for attributes
	internalDataCollectorPrefix = "dc."
	maxNumAttributes            = 100
	maxAttributeValueBytes      = 400
)

// An Attribute is used to record custom Record values.
// Name will be forced to have "dc." prefix.
// Value will be limited to 400 bytes, truncated on rune boundary.
type Attribute struct {
	Name  string
	Value interface{}
}

// A Record is a single event that is tracked via Apigee analytics.
// A limit of 100 Attributes will be transmitted.
// Attributes values may be boolean, number, or string.
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
	GrpcStatusCode               string      `json:"grpc_status_code,omitempty"`
	GrpcMethod                   string      `json:"grpc_method,omitempty"`
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
		err = errorset.Append(err, errors.New("missing Organization"))
	}
	if r.Environment == "" {
		err = errorset.Append(err, errors.New("missing Environment"))
	}
	if r.GatewayFlowID == "" {
		err = errorset.Append(err, errors.New("missing GatewayFlowID"))
	}
	if r.ClientReceivedStartTimestamp == 0 {
		err = errorset.Append(err, errors.New("missing ClientReceivedStartTimestamp"))
	}
	if r.ClientReceivedEndTimestamp == 0 {
		err = errorset.Append(err, errors.New("missing ClientReceivedEndTimestamp"))
	}
	if r.ClientReceivedStartTimestamp > r.ClientReceivedEndTimestamp {
		err = errorset.Append(err, errors.New("ClientReceivedStartTimestamp > ClientReceivedEndTimestamp"))
	}

	// Validate that timestamps make sense.
	ts := time.Unix(r.ClientReceivedStartTimestamp/1000, 0)
	if ts.After(now.Add(time.Minute)) { // allow a minute of tolerance
		err = errorset.Append(err, errors.New("ClientReceivedStartTimestamp cannot be in the future"))
	}
	if ts.Before(now.Add(-90 * 24 * time.Hour)) {
		err = errorset.Append(err, errors.New("ClientReceivedStartTimestamp cannot be more than 90 days old"))
	}

	for _, attr := range r.Attributes {
		if validateErr := validateAttribute(attr); validateErr != nil {
			err = errorset.Append(err, validateErr)
		}
	}

	return err
}

// MarshalJSON marshalls Attributes with keys that must
// begin with a "dc_" prefix and values that are limited
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
		val := attr.Value

		if err := validateAttribute(attr); err != nil {
			log.Debugf(err.Error())
			continue
		}

		// translate from external prefix, add internal prefix
		key = internalDataCollectorPrefix + strings.TrimPrefix(key, customerDataCollectorPrefix)

		// format time as int (ms since epoch)
		if t, ok := val.(time.Time); ok {
			val = timeToApigeeInt(t)
		}

		// truncate, if necessary
		val, truncated := truncStringToBytes(val, maxAttributeValueBytes)
		if truncated {
			log.Debugf("truncated attribute %s to max length of %d", key, maxAttributeValueBytes)
		}
		m[key] = val
	}
	b, e := json.Marshal(m)
	if e != nil {
		log.Debugf("ax json err: %s", e)
	} else {
		log.Debugf("ax record: %s", string(b))
	}
	return b, e
}

// format time as ms since epoch
func timeToApigeeInt(t time.Time) int64 {
	return t.UnixNano() / (int64(time.Millisecond) / int64(time.Nanosecond))
}

// only accept bool, number, string, or time
func validateAttribute(attr Attribute) error {
	switch k := reflect.TypeOf(attr.Value).Kind(); k {
	case
		reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64,
		reflect.String:
		return nil
	default:
		// also allow time
		if _, ok := attr.Value.(time.Time); ok {
			return nil
		}
		return fmt.Errorf("attribute %s is invalid type: %s", attr.Name, k.String())
	}
}

// truncates in to the limit number of bytes if a string, returns true if truncated
func truncStringToBytes(in interface{}, limit int) (interface{}, bool) {
	if val, ok := in.(string); ok {
		if len(val) > limit {
			for start, rune := range val {
				if start+utf8.RuneLen(rune) > limit {
					return val[:start], true
				}
			}
		}
	}
	return in, false
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
