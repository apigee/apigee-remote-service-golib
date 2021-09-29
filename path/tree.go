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

package path

import (
	"fmt"
	"strings"
)

// NewTree creates a new Tree.
func NewTree() Tree {
	return &tree{}
}

// This Tree searches for a path match using a "best match" strategy
// where best match is the most specific match that can be made - ie.
// the greatest number of segments matched. In the case of wildcards
// creating a tie, the search will prefer an exact segment match to a
// wildcard segment and a wildcard segment to a double wildcard.
// Wildcard ("*") and double wildcard ("**") path segments can be anywhere
// in the path (but not in partial segments).
// Wildcards may also be expressed as template variables: {var} or {var=*}
// represents a single wildcard and {var=**} a double wildcard.
// To extract the values for the templated variables use FindAndExtract()
// instead of Find().
// Empty path segments are ignored.
type Tree interface {

	// AddChild appends a child tree expressed by the path at the index provided.
	// Any existing value will be replaced and the prior value will be returned.
	AddChild(path []string, index int, value interface{}) interface{}

	// Find the value stored at subpath starting from given index in the path array.
	// It returns nil if the subpath cannot be all matched.
	Find(path []string, index int) interface{}

	// FindPrefix searches "best" prefix in the tree given the subpath starting from given index in
	// the path array.
	// It returns the value stored at the matched node as well as the length of the matched path segments.
	FindPrefix(path []string, index int) (interface{}, int)

	// Find the value stored at subpath starting from given index in the path array.
	// Also returns a map of extracted template vars.
	FindAndExtract(path []string, index int) (val interface{}, varMap map[string]interface{})
}

const (
	wildcard       = "*"
	doubleWildcard = "**"
)

type tree struct {
	name     string
	alias    string
	value    interface{}
	children map[interface{}]interface{}
}

// AddChild appends a child tree expressed by the path at the index provided.
// Any existing value will be replaced and the prior value will be returned.
func (t *tree) AddChild(path []string, index int, value interface{}) interface{} {
	if index >= len(path) {
		old := t.value
		t.value = value
		return old
	}
	name := path[index]
	if name == "" { // skip empty
		return t.AddChild(path, 1+index, value)
	}

	var alias string
	if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
		name = name[1 : len(name)-1]
		splits := strings.SplitN(name, "=", 2)
		alias = splits[0]
		if len(splits) > 1 && splits[1] == "**" {
			name = "**"
		} else {
			name = "*"
		}
	}
	node, ok := t.children[name]
	if !ok {
		node = &tree{name: name, alias: alias}
		if t.children == nil {
			t.children = make(map[interface{}]interface{})
		}
		t.children[name] = node
	}
	return node.(*tree).AddChild(path, 1+index, value)
}

// String returns a string representation of the tree.
func (t *tree) String() string {
	b := &strings.Builder{}
	t.string(b, "")
	return b.String()
}

func (t *tree) string(b *strings.Builder, indent string) {
	b.WriteString(fmt.Sprintf("%sname: %v, value: %v\n", indent, t.name, t.value))
	for _, val := range t.children {
		val.(*tree).string(b, indent+"  ")
	}
}

// Find the value stored at subpath starting from given index in the path array.
func (t *tree) Find(path []string, index int) interface{} {
	if index >= len(path) {
		return t.value
	}
	node, _ := t.findNode(path, index, 0, nil)
	if node != nil {
		return node.value
	}
	return nil
}

// FindPrefix searches the tree given the subpath starting from given index in
// the path array.
// It returns the value stored at the last matched node as well as the length of
// the matched path segments.
// "Best" is defined as such:
//   * Exact match wins - explicity segments (e.g. "/abc") wins over wildcard "*" at the same depth.
//   * Longest match wins when the above rule gives a tie, for example:
//     1. "/a/b/c" wins over "/a/b" for path "/a/b/c/d",
//     2. "/a/*/c" wins over "/a/*" for path "/a/b/c/d",
//     3. "/a/b" wins over "/*/b/c" for path "/a/b/c",
//     4. "/a/*" wins over "/*/b/c" for path "/a/b/c".
func (t *tree) FindPrefix(path []string, index int) (interface{}, int) {
	return t.findPrefix(path, index, index)
}

func (t *tree) findPrefix(path []string, start, current int) (interface{}, int) {
	if current == len(path) {
		return t.value, current - start
	}

	name := path[current]
	if name == "" {
		return t.findPrefix(path, start, current+1)
	}
	if child, ok := t.children[name]; ok {
		if value, length := child.(*tree).findPrefix(path, start, current+1); value != nil {
			return value, length
		}
	}

	if child, ok := t.children[wildcard]; ok {
		if value, length := child.(*tree).findPrefix(path, start, current+1); value != nil {
			return value, length
		}
	}

	if child, ok := t.children[doubleWildcard]; ok {
		for i := current + 1; i < len(path); i++ {
			if value, length := child.(*tree).findPrefix(path, start, i); value != nil {
				return value, length
			}
		}
	}

	return t.value, current - start // best match
}

// Find the value stored at subpath starting from given index in the path array.
// Also returns a map of extracted template vars.
func (t *tree) FindAndExtract(path []string, index int) (val interface{}, varMap map[string]interface{}) {
	varMap = make(map[string]interface{})
	if index >= len(path) {
		return t.value, varMap
	}
	node, _ := t.findNode(path, index, 0, varMap)
	if node != nil {
		return node.value, varMap
	}
	return nil, varMap
}

func (t *tree) findNode(path []string, index, matchCount int, varMap map[string]interface{}) (found *tree, foundMatchCount int) {
	if index >= len(path) {
		// This indicates a complete match. Return MaxInt to ensure it beats others.
		return t, matchCount + 1
	}

	name := path[index]
	if name == "" { // skip empty
		return t.findNode(path, 1+index, matchCount, varMap)
	}

	// non-wildcard match
	if child, ok := t.children[name]; ok {
		if node, mc := child.(*tree).findNode(path, 1+index, 1+matchCount, varMap); node != nil && node.value != nil {
			found = node
			foundMatchCount = mc
		}
	}
	if foundMatchCount >= len(path) { // exact match optimization
		return found, foundMatchCount
	}

	// check wildcard segment
	if child, ok := t.children[wildcard]; ok {
		node, mc := child.(*tree).findNode(path, 1+index, 1+matchCount, varMap)
		if node != nil && node.value != nil && mc > foundMatchCount {
			found = node
			foundMatchCount = mc
			if varMap != nil {
				varMap[child.(*tree).alias] = name
			}
		}
	}
	if foundMatchCount >= len(path) { // complete path optimization
		return found, foundMatchCount
	}

	// check double wildcard
	if child, ok := t.children[doubleWildcard]; ok {
		node, mc := child.(*tree).findAnyInPath(path, index, 1+matchCount, varMap)
		if node != nil && node.value != nil && mc > foundMatchCount {
			found = node
			foundMatchCount = mc
		}
	}

	return found, foundMatchCount
}

// find double wildcard matches by consuming path elements until match
func (t *tree) findAnyInPath(path []string, index, matchCount int, varMap map[string]interface{}) (*tree, int) {
	for i := index; i < len(path); i++ {
		name := path[i]
		if child, ok := t.children[name]; ok {
			if node, d := child.(*tree).findNode(path, i+1, matchCount, varMap); node != nil && node.value != nil {
				if varMap != nil {
					varMap[t.alias] = collectSegments(index, i, path)
				}
				return node, d
			}
		}
	}
	if varMap != nil {
		varMap[t.alias] = collectSegments(index, len(path), path)
	}
	return t, matchCount
}

func collectSegments(start, end int, path []string) string {
	s := strings.Builder{}
	for j := start; j < end; j++ {
		s.WriteString(path[j])
		if j < end-1 {
			s.WriteString("/")
		}
	}
	return s.String()
}
