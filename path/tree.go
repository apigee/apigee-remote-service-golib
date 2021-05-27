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

// A Tree searches for a path match using a "best match" strategy
// where best match is the greatest number of path segments matched.
// The matcher supports wildcard ("*") and double wildcard ("**")
// path segments anywhere in the path (but not partial segments).
// Wildcards may also be expressed as template variables, thus {var}
// or {var=*} is a single wildcard and {var=**} is a double wildcard.
// Note: To extract the values for the templated variables use
// FindAndExtract() instead of Find().
// Empty path elements are ignored.
type Tree interface {

	// AddChild appends a child tree expressed by the path at the index provided.
	// Any existing value will be replaced and the prior value will be returned.
	AddChild(path []string, index int, value interface{}) interface{}

	// Find the value stored at subpath starting from given index in the path array.
	Find(path []string, index int) interface{}

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
		return t, matchCount + 1
	}
	name := path[index]
	if name == "" { // skip empty
		return t.findNode(path, 1+index, matchCount, varMap)
	}

	// non-wildcard match
	if child, ok := t.children[name]; ok {
		found = child.(*tree)
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
