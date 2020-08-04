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

package quota

import (
	"container/list"
	"sync"
)

// ResultCache is a structure to track Results by ID, bounded by size
type ResultCache struct {
	size   int
	lookup map[string]*Result
	buffer list.List
	lock   sync.Mutex
}

// Add a Result to the cache
func (d *ResultCache) Add(id string, result *Result) {
	d.lock.Lock()
	defer d.lock.Unlock()
	_, ok := d.lookup[id]
	if ok {
		return
	}
	if d.lookup == nil {
		d.lookup = make(map[string]*Result)
	}
	d.lookup[id] = result
	d.buffer.PushBack(id)
	if d.buffer.Len() > d.size {
		e := d.buffer.Front()
		d.buffer.Remove(e)
		delete(d.lookup, e.Value.(string))
	}
}

// Get a Result from the cache, nil if none
func (d *ResultCache) Get(id string) *Result {
	d.lock.Lock()
	defer d.lock.Unlock()
	result, ok := d.lookup[id]
	if ok {
		return result
	}
	return nil
}
