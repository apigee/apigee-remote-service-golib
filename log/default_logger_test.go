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

package log

import (
	"bytes"
	l "log"
	"os"
	"strings"
	"testing"
)

func captureStdErr(t *testing.T, testFunc func(t *testing.T)) string {
	var buf bytes.Buffer
	l.SetOutput(&buf)
	testFunc(t)
	l.SetOutput(os.Stderr)
	return buf.String()
}

func TestLogOutput(t *testing.T) {
	logger := &defaultLogger{
		level: Debug,
	}
	var got string
	var want string

	got = captureStdErr(t, func(t *testing.T) {
		logger.Debugf("test")
	})
	want = Debug.String() + " test"
	if !strings.Contains(got, want) {
		t.Errorf("want pattern %s got %s", want, got)
	}

	got = captureStdErr(t, func(t *testing.T) {
		logger.Errorf("test")
	})
	want = Error.String() + " test"
	if !strings.Contains(got, want) {
		t.Errorf("want pattern %s got %s", want, got)
	}

	got = captureStdErr(t, func(t *testing.T) {
		logger.Warnf("test")
	})
	want = Warn.String() + " test"
	if !strings.Contains(got, want) {
		t.Errorf("want pattern %s got %s", want, got)
	}

	got = captureStdErr(t, func(t *testing.T) {
		logger.Infof("test")
	})
	want = Info.String() + " test"
	if !strings.Contains(got, want) {
		t.Errorf("want pattern %s got %s", want, got)
	}
}
