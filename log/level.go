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

import "strings"

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

// DebugEnabled returns whether output of messages at the debug level is currently enabled.
func (l Level) DebugEnabled() bool {
	return l >= Debug
}

// InfoEnabled returns whether output of messages at the info level is currently enabled.
func (l Level) InfoEnabled() bool {
	return l >= Info
}

// WarnEnabled returns whether output of messages at the warn level is currently enabled.
func (l Level) WarnEnabled() bool {
	return l >= Warn
}

// ErrorEnabled returns whether output of messages at the error level is currently enabled.
func (l Level) ErrorEnabled() bool {
	return l >= Error
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
