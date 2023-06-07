// Copyright 2018 Google LLC
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
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	quotaSecond = "second"
	quotaMinute = "minute"
	quotaHour   = "hour"
	quotaDay    = "day"
	quotaMonth  = "month"
)

// bucket tracks a specific quota instance
type bucket struct {
	manager          *manager
	quotaURL         string
	request          *Request // accumulated for sync
	result           *Result
	created          time.Time
	lock             sync.RWMutex
	synced           time.Time     // last sync time
	checked          time.Time     // last apply time
	refreshAfter     time.Duration // duration after synced
	deleteAfter      time.Duration // duration after checked
	prometheusLabels prometheus.Labels
}

func newBucket(req Request, m *manager, promLabels prometheus.Labels) *bucket {
	req.TimeUnit = strings.ToLower(req.TimeUnit)
	quotaURL := *m.baseURL
	quotaURL.Path = path.Join(quotaURL.Path, quotaPath)
	b := &bucket{
		request:          &req,
		manager:          m,
		quotaURL:         quotaURL.String(),
		created:          m.now(),
		checked:          m.now(),
		lock:             sync.RWMutex{},
		deleteAfter:      defaultDeleteAfter,
		refreshAfter:     defaultRefreshAfter,
		prometheusLabels: promLabels,
	}
	b.result = &Result{
		ExpiryTime: calcLocalExpiry(b.now(), req.Interval, req.TimeUnit).Unix(),
	}
	return b
}

func (b *bucket) now() time.Time {
	return b.manager.now()
}

// apply a quota request to the local quota bucket and schedule for sync
func (b *bucket) apply(req *Request) (*Result, error) {

	if !b.compatible(req) {
		return nil, fmt.Errorf("incompatible quota buckets")
	}

	b.lock.Lock()
	defer b.lock.Unlock()
	b.checked = b.now()
	res := &Result{
		Allowed:    req.Allow,
		ExpiryTime: b.checked.Unix(),
		Timestamp:  b.checked.Unix(),
	}

	if b.windowExpired() {
		b.result.Used = 0
		b.result.Exceeded = 0
		b.result.ExpiryTime = calcLocalExpiry(b.now(), req.Interval, req.TimeUnit).Unix()
		b.request.Weight = 0
		prometheusBucketWindowExpires.With(b.prometheusLabels).Set(float64(b.result.ExpiryTime))
	}

	if b.result != nil {
		res.Used = b.result.Used // start from last result
		res.Used += b.result.Exceeded
	}

	b.request.Weight += req.Weight
	res.Used += b.request.Weight

	if res.Used > res.Allowed {
		res.Exceeded = res.Used - res.Allowed
		res.Used = res.Allowed
	}

	prometheusBucketChecked.With(b.prometheusLabels).SetToCurrentTime()
	prometheusBucketValue.With(b.prometheusLabels).Set(float64(res.Used))

	return res, nil
}

func (b *bucket) compatible(r *Request) bool {
	return b.request.Interval == r.Interval &&
		b.request.Allow == r.Allow &&
		b.request.TimeUnit == r.TimeUnit &&
		b.request.Identifier == r.Identifier
}

// sync local quota bucket with server
// single-threaded call - managed by manager
func (b *bucket) sync() error {

	log.Debugf("syncing quota %s", b.request.Identifier)

	b.lock.Lock()
	r := *b.request // make copy

	if b.windowExpired() {
		r.Weight = 0 // if expired, don't send Weight
	}
	b.lock.Unlock()

	body := new(bytes.Buffer)
	if err := json.NewEncoder(body).Encode(r); err != nil {
		return errors.Wrap(err, "encode")
	}

	req, err := http.NewRequestWithContext(b.manager.runningContext, http.MethodPost, b.quotaURL, body)
	if err != nil {
		return errors.Wrap(err, "new request")
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	log.Debugf("sending quota: %s", body)

	resp, err := b.manager.client.Do(req)
	if err != nil {
		return errors.Wrapf(err, "quota request: %s", body)
	}
	defer resp.Body.Close()

	bufLen := resp.ContentLength
	if bufLen < bytes.MinRead {
		bufLen = bytes.MinRead
	}
	buf := bytes.NewBuffer(make([]byte, 0, bufLen))
	if _, err = buf.ReadFrom(resp.Body); err != nil {
		return errors.Wrap(err, "read body")
	}
	respBody := buf.Bytes()

	switch resp.StatusCode {
	case 200:
		var quotaResult Result
		if err = quotaResult.Unmarshal(respBody); err != nil {
			return errors.Wrapf(err, "unmarshal response: %s", respBody)
		}

		b.lock.Lock()
		b.synced = b.now()
		if b.result != nil && b.result.ExpiryTime != quotaResult.ExpiryTime {
			b.request.Weight = 0
		} else {
			b.request.Weight -= r.Weight // same window, keep accumulated Weight
		}
		b.result = &quotaResult
		log.Debugf("quota synced: %#v", quotaResult)
		b.lock.Unlock()

		prometheusBucketSynced.With(b.prometheusLabels).SetToCurrentTime()

		return nil

	default:
		if err != nil {
			return errors.Wrapf(err, "bad response (%d): %s", resp.StatusCode, respBody)
		}
		return fmt.Errorf("bad response (%d): %s", resp.StatusCode, respBody)
	}
}

func (b *bucket) needToDelete() bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.request.Weight == 0 && b.now().After(b.checked.Add(b.deleteAfter))
}

func (b *bucket) needToSync() bool {
	b.lock.RLock()
	defer b.lock.RUnlock()
	return b.request.Weight > 0 || b.now().After(b.synced.Add(b.refreshAfter))
}

// does not lock b.lock! lock before calling.
func (b *bucket) windowExpired() bool {
	if b.result != nil {
		return b.now().After(time.Unix(b.result.ExpiryTime, 0))
	}
	return false
}

func calcLocalExpiry(now time.Time, interval int64, timeUnit string) time.Time {

	var expiry time.Time
	switch timeUnit {
	case quotaSecond:
		start := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), now.Second(), 0, now.Location())
		expiry = start.Add(time.Duration(interval) * time.Second)
	case quotaMinute:
		start := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), now.Minute(), 0, 0, now.Location())
		expiry = start.Add(time.Duration(interval) * time.Minute)
	case quotaHour:
		start := time.Date(now.Year(), now.Month(), now.Day(), now.Hour(), 0, 0, 0, now.Location())
		expiry = start.Add(time.Duration(interval) * time.Hour)
	case quotaDay:
		start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
		expiry = start.AddDate(0, 0, int(interval))
	case quotaMonth:
		start := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, now.Location())
		expiry = start.AddDate(0, int(interval), 0)
	}

	return expiry.Add(-time.Second)
}
