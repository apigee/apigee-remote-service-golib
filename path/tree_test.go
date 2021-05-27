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

package path_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/apigee/apigee-remote-service-golib/v2/path"
)

func TestTree(t *testing.T) {
	tree := path.NewTree()
	add := []struct {
		path  string
		value string
	}{
		{path: "*", value: "*"},
		{path: "*/*", value: "*/*"},
		{path: "a", value: "a"},
		{path: "a/*", value: "a/*"},
		{path: "a/**", value: "a/**"},
		{path: "a/b", value: "a/b"},
		{path: "*/a", value: "*/a"},
		{path: "*/b", value: "*/b"},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/*", value: "a/b/*"},
		{path: "a/*/c", value: "a/*/c"},
		{path: "a/**/f", value: "a/**/f"},
		{path: "a/*/c/d", value: "a/*/c/d"},
		{path: "a/**/c/**", value: "a/**/c/**"},
		{path: "a/**/c/**/c", value: "a/**/c/**/c"},
		{path: "a/**/c/**/f", value: "a/**/c/**/f"},
	}
	for _, test := range add {
		path := strings.Split(test.path, "/")
		tree.AddChild(path, 0, test.value)
	}
	t.Logf("tree:\n%v", tree)

	find := []struct {
		path  string
		value string
	}{
		{path: "/a", value: "a"},
		{path: "a", value: "a"},
		{path: "a/b", value: "a/b"},
		{path: "a/b/", value: "a/b"},
		{path: "a//b", value: "a/b"},
		{path: "x/b", value: "*/b"},
		{path: "a/c", value: "a/*"},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/x", value: "a/b/*"},
		{path: "a/x/c", value: "a/*/c"},
		{path: "x", value: "*"},
		{path: "x/b", value: "*/b"},
		{path: "x/x", value: "*/*"},
		{path: "a/b/c/d", value: "a/*/c/d"},
		{path: "a/b/c/d/e/f", value: "a/**/c/**/f"},
		{path: "a/x/x/d/e/x/f", value: "a/**/f"},
		{path: "a/x/x/x/c/x/g", value: "a/**/c/**"},
		{path: "a/x/x/x", value: "a/**"},
		{path: "a/x/x/x/c/x/c/c", value: "a/**/c/**/c"},
	}
	for _, test := range find {
		path := strings.Split(test.path, "/")
		got := tree.Find(path, 0)
		if test.value != got {
			t.Errorf("for: %v, want: %v, got: %v", test.path, test.value, got)
		}
	}
}

func TestTemplatedTree(t *testing.T) {
	tree := path.NewTree()
	add := []struct {
		path  string
		value string
	}{
		{path: "{a}", value: "{a}"},
		{path: "{a=*}", value: "{a=*}"},
		{path: "{a=*}/{b=*}", value: "{a=*}/{b=*}"},
		{path: "a", value: "a"},
		{path: "a/{b=*}", value: "a/{b=*}"},
		{path: "a/{b=**}", value: "a/{b=**}"},
		{path: "a/b", value: "a/b"},
		{path: "{a=*}/a", value: "{a=*}/a"},
		{path: "{a=*}/b", value: "{a=*}/b"},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/{c=*}", value: "a/b/{c=*}"},
		{path: "a/{b=*}/c", value: "a/{b=*}/c"},
		{path: "a/{b=**}/f", value: "a/{b=**}/f"}, // illegal per https://cloud.google.com/api-gateway/docs/path-templating
		{path: "a/{b=*}/c/d", value: "a/{b=*}/c/d"},
		{path: "a/{b=**}/c/{d=**}", value: "a/{b=**}/c/{d=**}"},
		{path: "a/{b=**}/c/{d=**}/c", value: "a/{b=**}/c/{d=**}/c"},
		{path: "a/{b=**}/c/{d=**}/f", value: "a/{b=**}/c/{d=**}/f"},
	}
	for _, test := range add {
		path := strings.Split(test.path, "/")
		tree.AddChild(path, 0, test.value)
	}
	t.Logf("tree:\n%v", tree)

	find := []struct {
		path  string
		value string
	}{
		{path: "/a", value: "a"},
		{path: "a", value: "a"},
		{path: "a/b", value: "a/b"},
		{path: "a/b/", value: "a/b"},
		{path: "a//b", value: "a/b"},
		{path: "x/b", value: "{a=*}/b"},
		{path: "a/c", value: "a/{b=*}"},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/x", value: "a/b/{c=*}"},
		{path: "a/x/c", value: "a/{b=*}/c"},
		{path: "x", value: "{a=*}"},
		{path: "x/b", value: "{a=*}/b"},
		{path: "x/x", value: "{a=*}/{b=*}"},
		{path: "a/b/c/d", value: "a/{b=*}/c/d"},
		{path: "a/b/c/d/e/f", value: "a/{b=**}/c/{d=**}/f"},
		{path: "a/x/x/d/e/x/f", value: "a/{b=**}/f"},
		{path: "a/x/x/x/c/x/g", value: "a/{b=**}/c/{d=**}"},
		{path: "a/x/x/x", value: "a/{b=**}"},
		{path: "a/x/x/x/c/x/c/c", value: "a/{b=**}/c/{d=**}/c"},
	}
	for _, test := range find {
		path := strings.Split(test.path, "/")
		got := tree.Find(path, 0)
		if test.value != got {
			t.Errorf("for: %v, want: %v, got: %v", test.path, test.value, got)
		}
	}
}

func TestTreeEmpty(t *testing.T) {
	tree := path.NewTree()
	got := tree.Find([]string{""}, 0)
	if got != nil {
		t.Errorf("got: %v, want: %v", got, nil)
	}
	got = tree.Find([]string{"a", "b"}, 0)
	if got != nil {
		t.Errorf("got: %v, want: %v", got, nil)
	}
	tree.AddChild([]string{"a"}, 0, nil)
	got = tree.Find([]string{""}, 0)
	if got != nil {
		t.Errorf("got: %v, want: %v", got, nil)
	}
	got = tree.Find([]string{"a"}, 0)
	if got != nil {
		t.Errorf("got: %v, want: %v", got, nil)
	}
}

func TestTreeSkipEmpty(t *testing.T) {
	tree := path.NewTree()
	tree.AddChild([]string{"a", "", "b"}, 0, "y")
	want := "y"
	got := tree.Find([]string{"a", "b"}, 0)
	if got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
	got = tree.Find([]string{"a", "", "b"}, 0)
	if got != want {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

func TestTreeTooShort(t *testing.T) {
	tree := path.NewTree()
	tree.AddChild([]string{"a", "b"}, 0, "x")
	got := tree.Find([]string{"a", "b"}, 2)
	if got != nil {
		t.Errorf("got: %v, want: %v", got, nil)
	}
}

func TestTreeString(t *testing.T) {
	tree := path.NewTree()
	tree.AddChild([]string{"a", "b"}, 0, "x")
	tree.AddChild([]string{"a", "c"}, 0, "y")
	got := fmt.Sprintf("%s", tree)
	want := `name: , value: <nil>
  name: a, value: <nil>
    name: b, value: x
    name: c, value: y
`
	// child order doesn't matter
	want2 := `name: , value: <nil>
  name: a, value: <nil>
    name: c, value: y
    name: b, value: x
`

	if got != want && got != want2 {
		t.Errorf("\ngot: %s\nwant: %s", got, want)
	}
}
