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

// Log is the global logger
var Log LoggerWithLevel

func init() {
	Log = &defaultLogger{
		level: Info,
	}
}

// Debugf logs potentially verbose debug-time data
func Debugf(format string, args ...interface{}) {
	Log.Debugf(format, args...)
}

// Infof logs at the info level
func Infof(format string, args ...interface{}) {
	Log.Infof(format, args...)
}

// Warnf logs suspect situations and recoverable errors
func Warnf(format string, args ...interface{}) {
	Log.Warnf(format, args...)
}

// Errorf logs error conditions.
func Errorf(format string, args ...interface{}) {
	Log.Errorf(format, args...)
}

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func DebugEnabled() bool {
	return Log.DebugEnabled()
}

// InfoEnabled returns whether output of messages at the info level is currently enabled.
func InfoEnabled() bool {
	return Log.InfoEnabled()
}

// WarnEnabled returns whether output of messages at the info level is currently enabled.
func WarnEnabled() bool {
	return Log.WarnEnabled()
}

// ErrorEnabled returns whether output of messages at the info level is currently enabled.
func ErrorEnabled() bool {
	return Log.ErrorEnabled()
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
}

// LoggerWithLevel is a logger with level funcs
type LoggerWithLevel interface {
	Logger

	// Level gets the current logging level
	Level() Level
	// SetLevel set the current logging level
	SetLevel(level Level)

	// DebugEnabled returns whether output of messages at the debug level is currently enabled.
	DebugEnabled() bool
	// InfoEnabled returns whether output of messages at the info level is currently enabled.
	InfoEnabled() bool
	// WarnEnabled returns whether output of messages at the warn level is currently enabled.
	WarnEnabled() bool
	// ErrorEnabled returns whether output of messages at the error level is currently enabled.
	ErrorEnabled() bool
}

// LevelWrapper is a logger adapter
type LevelWrapper struct {
	Logger   Logger
	LogLevel Level
}

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func (d *LevelWrapper) DebugEnabled() bool {
	return d.LogLevel.DebugEnabled()
}

// InfoEnabled returns whether output of messages at the info level is currently enabled.
func (d *LevelWrapper) InfoEnabled() bool {
	return d.LogLevel.InfoEnabled()
}

// WarnEnabled returns whether output of messages at the warn level is currently enabled.
func (d *LevelWrapper) WarnEnabled() bool {
	return d.LogLevel.WarnEnabled()
}

// ErrorEnabled returns whether output of messages at the wanr level is currently enabled.
func (d *LevelWrapper) ErrorEnabled() bool {
	return d.LogLevel.ErrorEnabled()
}

// SetLevel sets the output level.
func (d *LevelWrapper) SetLevel(level Level) {
	d.LogLevel = level
}

// Level returns the output level.
func (d *LevelWrapper) Level() Level {
	return d.LogLevel
}

// Debugf logs potentially verbose debug-time data
func (d *LevelWrapper) Debugf(format string, args ...interface{}) {
	if d.DebugEnabled() {
		d.Logger.Debugf(format, args...)
	}
}

// Infof logs standard log data
func (d *LevelWrapper) Infof(format string, args ...interface{}) {
	if d.InfoEnabled() {
		d.Logger.Infof(format, args...)
	}
}

// Warnf logs suspect situations and recoverable errors
func (d *LevelWrapper) Warnf(format string, args ...interface{}) {
	if d.WarnEnabled() {
		d.Logger.Warnf(format, args...)
	}
}

// Errorf logs error conditions.
func (d *LevelWrapper) Errorf(format string, args ...interface{}) {
	if d.ErrorEnabled() {
		d.Logger.Errorf(format, args...)
	}
}
