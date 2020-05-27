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

func TestLevels(t *testing.T) {

	checkLevel := func(lvl Level) {
		t.Logf("checking level: %s", lvl)
		l := &defaultLogger{level: lvl}
		checkLogLevel(t, l, lvl)
		l = &defaultLogger{}
		l.SetLevel(lvl)
		checkLogLevel(t, l, lvl)
		lw := &LevelWrapper{Log, lvl}
		checkLogLevel(t, lw, lvl)
	}

	checkLevel(Debug)
	checkLevel(Info)
	checkLevel(Warn)
	checkLevel(Error)
}

func checkLogLevel(t *testing.T, l LoggerWithLevel, lvl Level) {

	if lvl != l.Level() {
		t.Errorf("bad level. want: %v, got: %v", lvl, l.Level())
	}

	// tests global passthrough
	tl := &testLogger{}
	Log = &LevelWrapper{tl, lvl}
	Debugf("debug")
	Infof("info")
	Warnf("warn")
	Errorf("error")

	if lvl == Debug {
		if !l.DebugEnabled() {
			t.Errorf("DEBUG should be enabled")
		}
		if len(tl.prints) < 4 {
			t.Errorf("expected %d prints for %s got: %v", 4, lvl, tl.prints)
		}
	}
	if lvl == Info {
		if !l.InfoEnabled() {
			t.Errorf("INFO should be enabled")
		}
		if len(tl.prints) != 3 {
			t.Errorf("expected %d prints for %s got: %v", 3, lvl, tl.prints)
		}
	}
	if lvl == Warn {
		if !l.WarnEnabled() {
			t.Errorf("WARN should be enabled")
		}
		if len(tl.prints) != 2 {
			t.Errorf("expected %d prints for %s got: %v", 2, lvl, tl.prints)
		}
	}
	if lvl == Error {
		if !l.ErrorEnabled() {
			t.Errorf("ERROR should be enabled")
		}
		if len(tl.prints) != 1 {
			t.Errorf("expected %d prints for %s got: %v", 1, lvl, tl.prints)
		}
	}

	if lvl < Error && l.ErrorEnabled() {
		t.Errorf("ERROR should not be enabled")
	}
	if lvl < Warn && l.WarnEnabled() {
		t.Errorf("WARN should not be enabled")
	}
	if lvl < Info && l.InfoEnabled() {
		t.Errorf("INFO should not be enabled")
	}
	if lvl < Debug && l.DebugEnabled() {
		t.Errorf("DEBUG should not be enabled")
	}
}

type testLogger struct {
	prints []string
}

func (d *testLogger) Debugf(format string, args ...interface{}) {
	d.prints = append(d.prints, format)
}

func (d *testLogger) Infof(format string, args ...interface{}) {
	d.prints = append(d.prints, format)
}

func (d *testLogger) Warnf(format string, args ...interface{}) {
	d.prints = append(d.prints, format)
}

func (d *testLogger) Errorf(format string, args ...interface{}) {
	d.prints = append(d.prints, format)
}
