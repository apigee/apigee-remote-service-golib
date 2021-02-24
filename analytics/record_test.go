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
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestValidationFailure(t *testing.T) {
	ts := int64(1521221450) // This timestamp is roughly 11:30 MST on Mar. 16, 2018.
	for _, test := range []struct {
		desc      string
		record    Record
		wantError string
	}{
		{"good record", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts * 1000,
			GatewayFlowID:                "x",
		}, ""},
		{"good record within 1 minute tolerance", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: (ts + 30) * 1000,
			ClientReceivedEndTimestamp:   (ts + 30) * 1000,
			GatewayFlowID:                "x",
		}, ""},
		{"missing org", Record{
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts * 1000,
			GatewayFlowID:                "x",
		}, "missing Organization"},
		{"missing env", Record{
			Organization:                 "hi",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts * 1000,
			GatewayFlowID:                "x",
		}, "missing Environment"},
		{"missing start timestamp", Record{
			Organization:               "hi",
			Environment:                "test",
			ClientReceivedEndTimestamp: ts * 1000,
			GatewayFlowID:              "x",
		}, "missing ClientReceivedStartTimestamp"},
		{"missing end timestamp", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			GatewayFlowID:                "x",
		}, "missing ClientReceivedEndTimestamp"},
		{"end < start", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts*1000 - 1,
			GatewayFlowID:                "x",
		}, "ClientReceivedStartTimestamp > ClientReceivedEndTimestamp"},
		{"in the future", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: (ts + 61) * 1000,
			ClientReceivedEndTimestamp:   (ts + 61) * 1000,
			GatewayFlowID:                "x",
		}, "in the future"},
		{"too old", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: (ts - 91*24*3600) * 1000,
			ClientReceivedEndTimestamp:   (ts - 91*24*3600) * 1000,
			GatewayFlowID:                "x",
		}, "more than 90 days old"},
		{"missing GatewayFlowID", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts * 1000,
		}, "missing GatewayFlowID"},
		{"bad attribute", Record{
			Organization:                 "hi",
			Environment:                  "test",
			ClientReceivedStartTimestamp: ts * 1000,
			ClientReceivedEndTimestamp:   ts * 1000,
			GatewayFlowID:                "x",
			Attributes: []Attribute{
				{Name: "bad", Value: struct{}{}},
			},
		}, "attribute bad is invalid type: struct"},
	} {
		t.Log(test.desc)

		gotErr := test.record.validate(time.Unix(ts, 0))
		if test.wantError == "" {
			if gotErr != nil {
				t.Errorf("got error %s, want none", gotErr)
			}
			continue
		}
		if gotErr == nil {
			t.Errorf("got nil error, want one containing %s", test.wantError)
			continue
		}

		if !strings.Contains(gotErr.Error(), test.wantError) {
			t.Errorf("error %s should contain '%s'", gotErr, test.wantError)
		}
	}
}

func TestEncode(t *testing.T) {
	now := time.Now()
	for _, test := range []struct {
		desc string
		in   interface{}
		want interface{}
	}{
		{"int", int(42), float64(42)},
		{"uint", uint(42), float64(42)},
		{"float", float32(3.14), float64(3.14)},
		{"false", false, false},
		{"true", true, true},
		{"string", "test", "test"},
		{"struct", struct{}{}, nil},
		{"array", []string{"nope"}, nil},
		{"time", now, float64(timeToApigeeInt(now))},
	} {
		record := Record{
			Attributes: []Attribute{
				{Name: "test", Value: test.in},
			},
		}

		var gotBuffer bytes.Buffer
		enc := json.NewEncoder(&gotBuffer)
		if err := enc.Encode(record); err != nil {
			t.Fatal(err)
		}
		var gotMap map[string]interface{}
		if err := json.Unmarshal(gotBuffer.Bytes(), &gotMap); err != nil {
			t.Fatal(err)
		}
		if test.want != gotMap["dc.test"] {
			t.Errorf("%s:: want: %d, got: %d", test.desc, test.want, gotMap["dc.test"])
		}
	}
}

func TestEncodeLimits(t *testing.T) {
	maxLenValue := "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin erat lacus, molestie at lorem non, sodales vehicula eros. " +
		"Ut vel ligula id purus vehicula condimentum non vitae nibh. Sed bibendum mauris non turpis dapibus, et gravida odio tristique. " +
		"Proin tempor condimentum lectus. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nunc ac arcu sem. Vestibulum ut mauris in tellus imperdiet mi."
	overLenValue := maxLenValue + "."
	if maxAttributeValueBytes != len(maxLenValue) {
		t.Fatalf("want: %d, got %d", maxAttributeValueBytes, len(maxLenValue))
	}

	record := Record{
		Organization: "hi",
		Environment:  "test",
		Attributes: []Attribute{
			{Name: "test-1", Value: maxLenValue},
			{Name: "dc.test-2", Value: overLenValue},
		},
	}
	var extraAttrs string
	for i := 0; i < maxNumAttributes; i++ {
		attr := Attribute{Name: fmt.Sprintf("dc.x-%d", i), Value: "val"}
		record.Attributes = append(record.Attributes, attr)
		if i+2 < maxNumAttributes {
			extraAttrs = extraAttrs + fmt.Sprintf("\"%s\":\"%s\",", attr.Name, attr.Value)
		}
	}
	if maxNumAttributes >= len(record.Attributes) {
		t.Fatalf("want > %d, got: %d", maxNumAttributes, len(record.Attributes))
	}

	var gotBuffer bytes.Buffer
	enc := json.NewEncoder(&gotBuffer)
	if err := enc.Encode(record); err != nil {
		t.Fatal(err)
	}

	var want, got map[string]interface{}
	if err := json.Unmarshal(gotBuffer.Bytes(), &got); err != nil {
		t.Fatal(err)
	}

	wantString := `{
	"dc.test-1":"` + maxLenValue + `",
	"dc.test-2":"` + maxLenValue + `",
	` + extraAttrs + `
	"apiproxy":"","apiproxy_revision":0,"client_received_end_timestamp":0,"client_received_start_timestamp":0,
	"client_sent_end_timestamp":0,"client_sent_start_timestamp":0,"environment":"test","gateway_flow_id":"",
	"gateway_source":"","organization":"hi","recordType":"","request_path":"","request_uri":"","request_verb":"",
	"response_status_code":0,"useragent":""}`
	if err := json.Unmarshal([]byte(wantString), &want); err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(want, got) {
		t.Errorf("want: %#v, got: %#v", want, got)
	}

	if maxLenValue != got["dc.test-1"] {
		t.Errorf("want: %#v, got: %#v", maxLenValue, got["dc.test-1"])
	}

	if maxNumAttributes-2 != strings.Count(gotBuffer.String(), "dc.x") {
		t.Errorf("want: %#v, got: %#v", maxNumAttributes-2, strings.Count(gotBuffer.String(), "dc.x"))
	}
}

func TestTruncStringToBytes(t *testing.T) {
	for _, test := range []struct {
		desc  string
		in    string
		limit int
		want  string
	}{
		{"limit 0", "a日bc", 0, ""},
		{"limit 1", "a日bc", 1, "a"},
		{"limit 2", "a日bc", 2, "a"},
		{"limit 3", "a日bc", 3, "a"},
		{"limit 4", "a日bc", 4, "a日"},
		{"limit 5", "a日bc", 5, "a日b"},
		{"limit 6", "a日bc", 6, "a日bc"},
		{"limit 7", "a日bc", 7, "a日bc"},
	} {
		got, _ := truncStringToBytes(test.in, test.limit)
		if got != test.want {
			t.Errorf("%s:: want: %s, got: %s", test.desc, test.want, got)
		}
	}
}
