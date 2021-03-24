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
	"errors"
	"testing"
)

func TestNils(t *testing.T) {
	err := Append(nil)
	if err != nil {
		t.Errorf("should be nil")
	}

	err = Append(nil, nil)
	if err != nil {
		t.Errorf("should be nil")
	}
}

func TestNilAppend(t *testing.T) {
	want := "Error(s):\n\t* my error"
	err := Append(nil, nil, errors.New("my error"))
	if err == nil {
		t.Fatalf("should not be nil")
	}
	got := err.Error()
	if want != got {
		t.Errorf("want: %s, got: %s", want, got)
	}
	if 1 != err.(*Error).Len() {
		t.Errorf("want: %d, got: %d", 1, err.(*Error).Len())
	}
}

func TestError(t *testing.T) {
	want := "Error(s):\n\t* my error"
	err := Append(errors.New("my error"))
	if err == nil {
		t.Errorf("should not be nil")
	}
	got := err.Error()
	if want != got {
		t.Errorf("want: %s, got: %s", want, err.Error())
	}
	if 1 != err.(*Error).Len() {
		t.Errorf("want: %d, got: %d", 1, err.(*Error).Len())
	}
}

func TestErrors(t *testing.T) {
	want := "Error(s):\n\t* my error\n\t* my error2"
	err1 := errors.New("my error")
	err2 := errors.New("my error2")
	err := Append(err1, err2)
	if err == nil {
		t.Errorf("should not be nil")
	}
	got := err.Error()
	if want != got {
		t.Errorf("want: %s, got: %s", want, err.Error())
	}
	if 2 != err.(*Error).Len() {
		t.Errorf("want: %d, got: %d", 2, err.(*Error).Len())
	}

	errs := Errors(err1)
	if err1 != errs[0] {
		t.Errorf("want: %v, got: %v", err1, errs[0])
	}

	errs = Errors(err)
	if err1 != errs[0] {
		t.Errorf("want: %v, got: %v", err1, errs[0])
	}
	if err2 != errs[1] {
		t.Errorf("want: %v, got: %v", err2, errs[1])
	}
}

func TestMultiError(t *testing.T) {
	want := "Error(s):\n\t* my error\n\t* my error2"
	err := Append(errors.New("my error"))
	err = Append(err, errors.New("my error2"))
	if err == nil {
		t.Errorf("should not be nil")
	}
	got := err.Error()
	if want != got {
		t.Errorf("want: %s, got: %s", want, err.Error())
	}
	if 2 != err.(*Error).Len() {
		t.Errorf("want: %d, got: %d", 2, err.(*Error).Len())
	}
}

func TestUnwrap(t *testing.T) {
	want := "Error(s):\n\t* my error3\n\t* my error\n\t* my error2"
	wrapped := Append(errors.New("my error"))
	wrapped = Append(wrapped, errors.New("my error2"))
	err := Append(errors.New("my error3"), wrapped)
	if err == nil {
		t.Errorf("should not be nil")
	}
	got := err.Error()
	if want != got {
		t.Errorf("want: %s, got: %s", want, err.Error())
	}
	if 3 != err.(*Error).Len() {
		t.Errorf("want: %d, got: %d", 3, err.(*Error).Len())
	}
}
