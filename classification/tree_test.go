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

package classification

import (
	"strings"
	"testing"
)

func TestTree(t *testing.T) {
	tree := NewTree()
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
