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
	"testing"
)

func TestParseLevel(t *testing.T) {
	if ParseLevel("DEBUG") != Debug {
		t.Errorf("DEBUG level not parsed correctly")
	}
	if ParseLevel("INFO") != Info {
		t.Errorf("INFO level not parsed correctly")
	}
	if ParseLevel("WARN") != Warn {
		t.Errorf("WARN level not parsed correctly")
	}
	if ParseLevel("ERROR") != Error {
		t.Errorf("ERROR level not parsed correctly")
	}

	if ParseLevel("WRONG") != Info {
		t.Errorf("WRONG level not parsed correctly")
	}
}

func TestLevelCompare(t *testing.T) {
	l := Debug
	if !l.DebugEnabled() {
		t.Errorf("DEBUG should be enabled for %s", l)
	}
	if !l.InfoEnabled() {
		t.Errorf("INFO should be enabled for %s", l)
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled for %s", l)
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled for %s", l)
	}

	l = Info
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled for %s", l)
	}
	if !l.InfoEnabled() {
		t.Errorf("INFO should be enabled for %s", l)
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled for %s", l)
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled for %s", l)
	}

	l = Warn
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled for %s", l)
	}
	if l.InfoEnabled() {
		t.Errorf("INFO should not be enabled for %s", l)
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled for %s", l)
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled for %s", l)
	}

	l = Error
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled for %s", l)
	}
	if l.InfoEnabled() {
		t.Errorf("INFO should not be enabled for %s", l)
	}
	if l.WarnEnabled() {
		t.Errorf("WARN should not be enabled for %s", l)
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled for %s", l)
	}
}
