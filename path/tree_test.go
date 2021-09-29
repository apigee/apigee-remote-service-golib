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
	"github.com/google/go-cmp/cmp"
)

func TestFindPrefix(t *testing.T) {
	tree := path.NewTree()
	add := []struct {
		path  string
		value string
	}{
		{path: "*", value: "*"},
		{path: "*/*", value: "*/*"},
		{path: "a", value: "a"},
		{path: "a/*", value: "a/*"},
		{path: "a/b", value: "a/b"},
		{path: "*/a", value: "*/a"},
		{path: "*/b", value: "*/b"},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/*", value: "a/b/*"},
		{path: "a/*/d", value: "a/*/d"},
		{path: "a/*/c/d", value: "a/*/c/d"},
		{path: "a/**", value: "a/**"},
		{path: "b/**/x", value: "b/**/x"},
	}
	for _, test := range add {
		path := strings.Split(test.path, "/")
		tree.AddChild(path, 0, test.value)
	}
	t.Logf("tree:\n%v", tree)

	find := []struct {
		path   string
		value  string
		length int
	}{
		{path: "/a", value: "a", length: 2},
		{path: "a", value: "a", length: 1},
		{path: "a/b", value: "a/b", length: 2},
		{path: "a/b/", value: "a/b", length: 3},
		{path: "a//b", value: "a/b", length: 3},
		{path: "x/b", value: "*/b", length: 2},
		{path: "a/c", value: "a/*", length: 2},
		{path: "a/b/c", value: "a/b/c", length: 3},
		{path: "a/b/x", value: "a/b/*", length: 3},
		{path: "a/x/c", value: "a/*", length: 2},
		{path: "x", value: "*", length: 1},
		{path: "x/b", value: "*/b", length: 2},
		{path: "x/x", value: "*/*", length: 2},
		{path: "a/b/c/d", value: "a/b/c", length: 3},
		{path: "a/b/x/d/e/f", value: "a/b/*", length: 3},
		{path: "a/b/d/e/f", value: "a/b/*", length: 3},
		{path: "b/d/e/x", value: "b/**/x", length: 4},
	}
	for _, test := range find {
		path := strings.Split(test.path, "/")
		got, length := tree.FindPrefix(path, 0)
		if test.value != got {
			t.Errorf("for: %v, want: %v, got: %v", test.path, test.value, got)
		}
		if test.length != length {
			t.Errorf("for: %v, want: %d segments matched, got: %d", test.path, test.length, length)
		}
	}
}

func TestWildcardTree(t *testing.T) {
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

func TestTemplateTree(t *testing.T) {
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
		{path: "a/{b=**}/f", value: "a/{b=**}/f"},
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
		path   string
		value  string
		values map[string]interface{}
	}{
		{path: "/a", value: "a"},
		{path: "a", value: "a"},
		{path: "a/b", value: "a/b"},
		{path: "a/b/", value: "a/b"},
		{path: "a//b", value: "a/b"},
		{path: "x/b", value: "{a=*}/b", values: map[string]interface{}{"a": "x"}},
		{path: "a/c", value: "a/{b=*}", values: map[string]interface{}{"b": "c"}},
		{path: "a/b/c", value: "a/b/c"},
		{path: "a/b/x", value: "a/b/{c=*}", values: map[string]interface{}{"c": "x"}},
		{path: "a/x/c", value: "a/{b=*}/c", values: map[string]interface{}{"b": "x"}},
		{path: "x", value: "{a=*}", values: map[string]interface{}{"a": "x"}},
		{path: "x/b", value: "{a=*}/b", values: map[string]interface{}{"a": "x"}},
		{path: "x/x", value: "{a=*}/{b=*}", values: map[string]interface{}{"a": "x", "b": "x"}},
		{path: "a/b/c/d", value: "a/{b=*}/c/d", values: map[string]interface{}{"b": "b"}},
		{path: "a/b/c/d/e/f", value: "a/{b=**}/c/{d=**}/f", values: map[string]interface{}{"b": "b", "d": "d/e"}},
		{path: "a/x/x/d/e/x/f", value: "a/{b=**}/f", values: map[string]interface{}{"b": "x/x/d/e/x"}},
		{path: "a/x/x/x/c/x/g", value: "a/{b=**}/c/{d=**}", values: map[string]interface{}{"b": "x/x/x", "d": "x/g"}},
		{path: "a/x/x/x", value: "a/{b=**}", values: map[string]interface{}{"b": "x/x/x"}},
		{path: "a/x/x/x/c/x/c/c", value: "a/{b=**}/c/{d=**}/c", values: map[string]interface{}{"b": "x/x/x", "d": "x/c"}},
	}
	for _, test := range find {
		path := strings.Split(test.path, "/")
		got, values := tree.FindAndExtract(path, 0)
		if test.value != got {
			t.Errorf("for: %v, want: %v, got: %v", test.path, test.value, got)
		}
		if test.values == nil {
			test.values = map[string]interface{}{}
		}
		if diff := cmp.Diff(test.values, values); diff != "" {
			t.Errorf("for: %v (-want +got):\n%s", test.path, diff)
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
