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
	"encoding/json"
)

// A Request is sent to Apigee's quota server to allocate quota.
type Request struct {
	Identifier string `json:"identifier"`
	Weight     int64  `json:"weight"`
	Interval   int64  `json:"interval"`
	Allow      int64  `json:"allow"`
	TimeUnit   string `json:"timeUnit"`
}

// A Result is a response from Apigee's quota server that gives information
// about how much quota is available. Note that Used will never exceed Allowed,
// but Exceeded will be positive in that case.
type Result struct {
	Allowed    int64 `json:"allowed"`
	Used       int64 `json:"used"`
	Exceeded   int64 `json:"exceeded"`
	ExpiryTime int64 `json:"expiryTime"` // in seconds
	Timestamp  int64 `json:"timestamp"`
}

// Unmarshal decodes the json response into quota Result
func (r *Result) Unmarshal(b []byte) error {
	if err := json.Unmarshal(b, r); err != nil {
		return err
	}
	r.ExpiryTime /= 1000 // `/quotas` proxy returns the time in millisecond, which needs to be converted to second
	return nil
}
