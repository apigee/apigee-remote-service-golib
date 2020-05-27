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
	l "log"
)

type defaultLogger struct {
	level Level
}

// Debugf logs potentially verbose debug-time data
func (d *defaultLogger) Debugf(format string, args ...interface{}) {
	if d.DebugEnabled() {
		d.printf(Debug, format, args...)
	}
}

// Infof logs standard log data
func (d *defaultLogger) Infof(format string, args ...interface{}) {
	if d.InfoEnabled() {
		d.printf(Info, format, args...)
	}
}

// Warnf logs suspect situations and recoverable errors
func (d *defaultLogger) Warnf(format string, args ...interface{}) {
	if d.WarnEnabled() {
		d.printf(Warn, format, args...)
	}
}

// Errorf logs error conditions.
func (d *defaultLogger) Errorf(format string, args ...interface{}) {
	if d.ErrorEnabled() {
		d.printf(Error, format, args...)
	}
}

// formatted logging
func (d *defaultLogger) printf(lvl Level, format string, args ...interface{}) {
	format = lvl.String() + " " + format
	l.Printf(format, args...)
}

// InfoEnabled returns whether output of messages at the info level is currently enabled.
func (d *defaultLogger) InfoEnabled() bool {
	return d.level >= Info
}

// InfoEnabled returns whether output of messages at the warn level is currently enabled.
func (d *defaultLogger) WarnEnabled() bool {
	return d.level >= Warn
}

// ErrorEnabled returns whether output of messages at the wanr level is currently enabled.
func (d *defaultLogger) ErrorEnabled() bool {
	return d.level >= Error
}

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func (d *defaultLogger) DebugEnabled() bool {
	return d.level >= Debug
}

// SetLevel sets the output level.
func (d *defaultLogger) SetLevel(level Level) {
	d.level = level
}

// Level returns the output level.
func (d *defaultLogger) Level() Level {
	return d.level
}
