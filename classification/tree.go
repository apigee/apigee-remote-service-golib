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
	"fmt"
	"strings"
)

// NewTree creates a new tree root.
func NewTree() Tree {
	return &tree{}
}

// Tree searches for a path match using a "best match" strategy
// where best match is the greatest number of path segments matched.
type Tree interface {

	// AddChild appends a child tree expressed by the path at the index provided.
	// Any existing value will be replaced and the prior value will be returned.
	// Empty path elements are ignored.
	AddChild(path []string, index int, value interface{}) interface{}

	// Find the value stored at subpath starting from given index in the path array.
	// The matcher supports wildcard ("*") and double wildcard ("**")
	// path segments anywhere in the path (but not partial segments).
	Find(path []string, index int) interface{}
}

const (
	wildcard       = "*"
	doubleWildcard = "**"
)

type tree struct {
	name     string
	value    interface{}
	children map[interface{}]interface{}
}

// Find the value stored at subpath starting from given index in the path array.
func (t *tree) Find(path []string, index int) interface{} {
	if index >= len(path) {
		return t.value
	}
	node, _ := t.findNode(path, index, 0)
	if node != nil {
		return node.value
	}
	return nil
}

func (t *tree) findNode(path []string, index, matchCount int) (found *tree, foundMatchCount int) {
	if index >= len(path) {
		return t, matchCount
	}
	name := path[index]
	if name == "" { // skip empty
		return t.findNode(path, 1+index, matchCount)
	}

	// non-wildcard match
	if child, ok := t.children[name]; ok {
		found = child.(*tree)
		if node, mc := child.(*tree).findNode(path, 1+index, 1+matchCount); node != nil && node.value != nil {
			found = node
			foundMatchCount = mc
		}
	}
	if foundMatchCount == len(path) { // exact match optimization
		return found, foundMatchCount
	}

	// check wildcard segment
	if child, ok := t.children[wildcard]; ok {
		node, mc := child.(*tree).findNode(path, 1+index, 1+matchCount)
		if node != nil && node.value != nil && mc > foundMatchCount {
			found = node
			foundMatchCount = mc
		}
	}
	if foundMatchCount == len(path) { // complete path optimization
		return found, foundMatchCount
	}

	// check double wildcard
	if child, ok := t.children[doubleWildcard]; ok {
		node, mc := child.(*tree).findAnyInPath(path, index, 1+matchCount)
		if node != nil && node.value != nil && mc > foundMatchCount {
			found = node
			foundMatchCount = mc
		}
	}

	return found, foundMatchCount
}

// find double wildcard matches by consuming path elements until match
func (t *tree) findAnyInPath(path []string, index, matchCount int) (*tree, int) {
	for i := index; i < len(path); i++ {
		name := path[i]
		if child, ok := t.children[name]; ok {
			if node, d := child.(*tree).findNode(path, i+1, matchCount); node != nil && node.value != nil {
				return node, d
			}
		}
	}
	return t, matchCount
}

// AddChild appends a child tree expressed by the path at the index provided.
// Any existing value will be replaced and the prior value will be returned.
// Empty path elements are ignored.
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

	node, ok := t.children[name]
	if !ok {
		node = &tree{name: name}
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
