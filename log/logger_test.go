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

func TestLogger(t *testing.T) {
	if Log.(*defaultLogger).Level() != Info {
		t.Errorf("Default log level should be info")
	}

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

	l := defaultLogger{
		level: Debug,
	}
	if !l.DebugEnabled() {
		t.Errorf("DEBUG should be enabled")
	}
	if !l.InfoEnabled() {
		t.Errorf("INFO should be enabled")
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled")
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled")
	}

	l = defaultLogger{
		level: Info,
	}
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled")
	}
	if !l.InfoEnabled() {
		t.Errorf("INFO should be enabled")
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled")
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled")
	}

	l = defaultLogger{
		level: Warn,
	}
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled")
	}
	if l.InfoEnabled() {
		t.Errorf("INFO should not be enabled")
	}
	if !l.WarnEnabled() {
		t.Errorf("WARN should be enabled")
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled")
	}

	l = defaultLogger{
		level: Error,
	}
	if l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled")
	}
	if l.InfoEnabled() {
		t.Errorf("INFO should not be enabled")
	}
	if l.WarnEnabled() {
		t.Errorf("WARN should not be enabled")
	}
	if !l.ErrorEnabled() {
		t.Errorf("ERROR should be enabled")
	}

	l.SetLevel(Info)
	if l.Level() != Info {
		t.Errorf("Default log level should be info")
	}
}
