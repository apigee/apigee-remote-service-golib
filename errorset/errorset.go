// Copyright 2021 Google LLC
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

package errorset

import (
	"fmt"
	"strings"
)

func Append(err error, errs ...error) error {
	es, ok := err.(*Error)
	if !ok && err != nil {
		es = es.append(err)
	}
	es = es.append(errs...)
	if es.Len() == 0 {
		return nil
	}
	return es
}

func Errors(err error) []error {
	if errset, ok := err.(*Error); ok {
		return errset.Errors
	}
	return []error{err}
}

type Error struct {
	Errors []error
}

func (es *Error) append(errs ...error) *Error {
	if es == nil {
		es = &Error{}
	}
	for _, e := range errs {
		if errset, ok := e.(*Error); ok { // unwrap
			es.Errors = es.append(errset.Errors...).Errors
		} else if e != nil {
			es.Errors = append(es.Errors, e)
		}
	}
	return es
}

func (es *Error) Error() string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Error(s):")
	for _, e := range es.Errors {
		fmt.Fprintf(b, "\n\t* %s", e.Error())
	}
	return b.String()
}

func (es *Error) Len() int {
	return len(es.Errors)
}
