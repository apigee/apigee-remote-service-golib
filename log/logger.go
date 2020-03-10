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
	"strings"
)

// Level is a level of logging
type Level int

const (
	// Error log level
	Error Level = iota
	// Warn log level
	Warn
	// Info log level
	Info
	// Debug log level
	Debug
)

var levels = [...]Level{Error, Warn, Info, Debug}
var stringLevels = [...]string{"ERROR", "WARN", "INFO", "DEBUG"}

func (l Level) String() string {
	return stringLevels[l]
}

// ParseLevel parses the log level, returns Info level if not found
func ParseLevel(lvl string) Level {
	lvl = strings.ToUpper(lvl)
	for i, l := range stringLevels {
		if l == lvl {
			return levels[i]
		}
	}
	return Info
}

// Log is the global logger
var Log Logger = &defaultLogger{
	level: Info,
}

// Infof logs at the info level
func Infof(format string, args ...interface{}) {
	if InfoEnabled() {
		Log.Infof(format, args...)
	}
}

// Warnf logs suspect situations and recoverable errors
func Warnf(format string, args ...interface{}) {
	if WarnEnabled() {
		Log.Warnf(format, args...)
	}
}

// Errorf logs error conditions.
func Errorf(format string, args ...interface{}) {
	if ErrorEnabled() {
		Log.Errorf(format, args...)
	}
}

// Debugf logs potentially verbose debug-time data
func Debugf(format string, args ...interface{}) {
	if DebugEnabled() {
		Log.Debugf(format, args...)
	}
}

// InfoEnabled returns whether output of messages at the info level is currently enabled.
func InfoEnabled() bool {
	return Log.InfoEnabled()
}

// WarnEnabled returns whether output of messages at the warn level is currently enabled.
func WarnEnabled() bool {
	return Log.WarnEnabled()
}

// ErrorEnabled returns whether output of messages at the wanr level is currently enabled.
func ErrorEnabled() bool {
	return Log.ErrorEnabled()
}

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func DebugEnabled() bool {
	return Log.DebugEnabled()
}

// Logger is a logging interface
type Logger interface {
	// Debugf logs potentially verbose debug-time data
	Debugf(format string, args ...interface{})
	// Infof logs informational data
	Infof(format string, args ...interface{})
	// Warnf logs suspect situations and recoverable errors
	Warnf(format string, args ...interface{})
	// Errorf logs error conditions.
	Errorf(format string, args ...interface{})

	// DebugEnabled returns whether output of messages at the debug level is currently enabled.
	DebugEnabled() bool
	// InfoEnabled returns whether output of messages at the info level is currently enabled.
	InfoEnabled() bool
	// WarnEnabled returns whether output of messages at the warn level is currently enabled.
	WarnEnabled() bool
	// ErrorEnabled returns whether output of messages at the error level is currently enabled.
	ErrorEnabled() bool
}

type defaultLogger struct {
	level Level
}

func (d *defaultLogger) Infof(format string, args ...interface{}) {
	if d.InfoEnabled() {
		d.printf(format, args...)
	}
}

// Warnf logs suspect situations and recoverable errors
func (d *defaultLogger) Warnf(format string, args ...interface{}) {
	if d.WarnEnabled() {
		d.printf(format, args...)
	}
}

// Errorf logs error conditions.
func (d *defaultLogger) Errorf(format string, args ...interface{}) {
	if d.ErrorEnabled() {
		d.printf(format, args...)
	}
}

// Debugf logs potentially verbose debug-time data
func (d *defaultLogger) Debugf(format string, args ...interface{}) {
	if d.DebugEnabled() {
		d.printf(format, args...)
	}
}

// formatted logging
func (d *defaultLogger) printf(format string, args ...interface{}) {
	format = d.level.String() + " " + format
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

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func (d *defaultLogger) SetLevel(level Level) {
	d.level = level
}

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func (d *defaultLogger) Level() Level {
	return d.level
}

// 2020-03-10T20:51:11.261002Z	error
