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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/auth"
	"github.com/apigee/apigee-remote-service-golib/v2/authtest"
	"github.com/apigee/apigee-remote-service-golib/v2/product"
	"github.com/prometheus/client_golang/prometheus"
)

func TestQuota(t *testing.T) {

	type testcase struct {
		name    string
		dedupID string
		want    Result
	}

	serverResult := Result{}
	ts, _ := testServer(&serverResult, time.Now, nil)

	context := authtest.NewContext(ts.URL)
	authContext := &auth.Context{
		Context: context,
	}

	api := product.AuthorizedOperation{
		QuotaLimit:    1,
		QuotaInterval: 1,
		QuotaTimeUnit: quotaMonth,
	}

	args := Args{
		QuotaAmount: 1,
	}

	m, err := NewManager(Options{
		BaseURL: context.InternalAPI(),
		Client:  http.DefaultClient,
		Org:     "org",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	cases := []testcase{
		{
			name:    "first",
			dedupID: "X",
			want: Result{
				Used:     1,
				Exceeded: 0,
			},
		},
		{
			name:    "duplicate",
			dedupID: "X",
			want: Result{
				Used:     1,
				Exceeded: 0,
			},
		},
		{
			name:    "second",
			dedupID: "Y",
			want: Result{
				Used:     1,
				Exceeded: 1,
			},
		},
	}

	for _, c := range cases {
		t.Logf("** Executing test case '%s' **", c.name)

		args.DeduplicationID = c.dedupID
		result, err := m.Apply(authContext, api, args)
		if err != nil {
			t.Fatalf("should not get error: %v", err)
		}
		if result.Used != c.want.Used {
			t.Errorf("used got: %v, want: %v", result.Used, c.want.Used)
		}
		if result.Exceeded != c.want.Exceeded {
			t.Errorf("exceeded got: %v, want: %v", result.Exceeded, c.want.Exceeded)
		}
	}

	// test incompatible product (replaces bucket)
	api2 := product.AuthorizedOperation{
		QuotaLimit:    1,
		QuotaInterval: 2,
		QuotaTimeUnit: quotaSecond,
	}
	c := testcase{
		name:    "incompatible",
		dedupID: "Z",
		want: Result{
			Used:     1,
			Exceeded: 0,
		},
	}

	t.Logf("** Executing test case '%s' **", c.name)
	args.DeduplicationID = c.dedupID
	result, err := m.Apply(authContext, api2, args)
	if err != nil {
		t.Fatalf("should not get error: %v", err)
	}
	if result.Used != c.want.Used {
		t.Errorf("used got: %v, want: %v", result.Used, c.want.Used)
	}
	if result.Exceeded != c.want.Exceeded {
		t.Errorf("exceeded got: %v, want: %v", result.Exceeded, c.want.Exceeded)
	}
}

// not fully determinate, uses delays and background threads
func TestSync(t *testing.T) {

	fakeTime := newClock()
	serverResult := Result{}
	ts, resultLock := testServer(&serverResult, fakeTime.now, nil)
	defer ts.Close()

	context := authtest.NewContext(ts.URL)

	quotaID := "id"
	request := &Request{
		Identifier: quotaID,
		Interval:   1,
		TimeUnit:   quotaSecond,
		Allow:      1,
		Weight:     3,
	}
	result := &Result{
		Used: 1,
	}

	m := &manager{
		close:             make(chan bool),
		client:            http.DefaultClient,
		now:               fakeTime.now,
		syncRate:          2 * time.Millisecond,
		bucketToSyncQueue: make(chan *bucket, 10),
		baseURL:           context.InternalAPI(),
		numSyncWorkers:    1,
		bucketsSyncing:    map[*bucket]struct{}{},
	}

	b := newBucket(*request, m, prometheus.Labels{"org": "org", "env": "env", "quota": quotaID})
	b.checked = fakeTime.now()
	b.result = result
	m.buckets = map[string]*bucket{quotaID: b}
	b.refreshAfter = time.Millisecond

	m.Start()
	defer m.Close()

	fakeTime.add(10)
	time.Sleep(10 * time.Millisecond) // allow idle sync
	b.lock.Lock()
	b.refreshAfter = time.Hour
	b.lock.Unlock()

	resultLock.Lock()
	serverResult.ExpiryTime /= 1000 // convert back to seconds for comparison
	resultLock.Unlock()

	b.lock.RLock()
	if b.request.Weight != 0 {
		t.Errorf("pending request weight got: %d, want: %d", b.request.Weight, 0)
	}
	resultLock.Lock()
	if !reflect.DeepEqual(*b.result, serverResult) {
		t.Errorf("result got: %#v, want: %#v", *b.result, serverResult)
	}
	resultLock.Unlock()
	if b.synced != m.now() {
		t.Errorf("synced got: %#v, want: %#v", b.synced, m.now())
	}
	if m.buckets[quotaID] == nil {
		t.Errorf("old bucket should not have been deleted")
	}
	b.lock.RUnlock()

	// do interactive sync
	req := &Request{
		Identifier: quotaID,
		Interval:   1,
		TimeUnit:   quotaSecond,
		Allow:      1,
		Weight:     2,
	}
	_, err := b.apply(req)
	if err != nil {
		t.Errorf("should not have received error on apply: %v", err)
	}
	fakeTime.add(10)
	err = b.sync()
	if err != nil {
		t.Errorf("should not have received error on sync: %v", err)
	}

	resultLock.Lock()
	serverResult.ExpiryTime /= 1000 // convert back to seconds for comparison
	resultLock.Unlock()

	b.lock.Lock()
	if b.request.Weight != 0 {
		t.Errorf("pending request weight got: %d, want: %d", b.request.Weight, 0)
	}
	resultLock.Lock()
	if !reflect.DeepEqual(*b.result, serverResult) {
		t.Errorf("result got: %#v, want: %#v", *b.result, serverResult)
	}
	resultLock.Unlock()
	if b.synced != m.now() {
		t.Errorf("synced got: %#v, want: %#v", b.synced, m.now())
	}

	fakeTime.add(10 * 60)
	b.lock.Unlock()
	time.Sleep(10 * time.Millisecond) // allow background delete
	m.bucketsLock.RLock()
	defer m.bucketsLock.RUnlock()
	if m.buckets[quotaID] != nil {
		t.Errorf("old bucket should have been deleted")
	}
}

func TestDisconnected(t *testing.T) {
	fakeTime := newClock()

	errC := &errControl{
		send: 404,
	}
	serverResult := Result{}
	ts, _ := testServer(&serverResult, fakeTime.now, errC)
	ts.Close()

	context := authtest.NewContext(ts.URL)
	context.SetOrganization("org")
	context.SetEnvironment("env")
	authContext := &auth.Context{
		Context:        context,
		DeveloperEmail: "email",
		Application:    "app",
		AccessToken:    "token",
		ClientID:       "clientId",
	}

	m := &manager{
		close:             make(chan bool),
		client:            http.DefaultClient,
		now:               fakeTime.now,
		bucketToSyncQueue: make(chan *bucket, 10),
		baseURL:           context.InternalAPI(),
		numSyncWorkers:    1,
		buckets:           map[string]*bucket{},
		bucketsSyncing:    map[*bucket]struct{}{},
	}

	api := product.AuthorizedOperation{
		QuotaLimit:    1,
		QuotaInterval: 1,
		QuotaTimeUnit: quotaMinute,
	}

	args := Args{
		QuotaAmount: 1,
	}

	_, err := m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("shouln't get error: %v", err)
	}

	// force sync error
	err = m.forceSync(api.ID)
	if err == nil {
		t.Fatalf("should have received error!")
	}

	_, err = m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("shouldn't get error: %v", err)
	}

	errC.send = 200
	if err := m.forceSync(api.ID); err == nil {
		t.Errorf("want error 'new request: net/http: nil Context' got none")
	}

	res, err := m.Apply(authContext, api, args)
	if err != nil {
		t.Fatalf("got error: %s", err)
	}
	wantResult := Result{
		Allowed:    1,
		Used:       1,
		Exceeded:   2,
		ExpiryTime: fakeTime.now().Unix(),
		Timestamp:  fakeTime.now().Unix(),
	}
	if !reflect.DeepEqual(*res, wantResult) {
		t.Errorf("result got: %#v, want: %#v", *res, wantResult)
	}

	// next window
	fakeTime.add(60)
	res, err = m.Apply(authContext, api, args)
	if err != nil {
		t.Fatalf("got error: %s", err)
	}
	wantResult = Result{
		Allowed:    1,
		Used:       1,
		Exceeded:   0,
		ExpiryTime: fakeTime.now().Unix(),
		Timestamp:  fakeTime.now().Unix(),
	}
	if !reflect.DeepEqual(*res, wantResult) {
		t.Errorf("result got: %#v, want: %#v", *res, wantResult)
	}
}

func TestWindowExpired(t *testing.T) {
	fakeTime := newClock()

	errC := &errControl{
		send: 200,
	}
	serverResult := Result{}
	ts, _ := testServer(&serverResult, fakeTime.now, errC)
	defer ts.Close()

	context := authtest.NewContext(ts.URL)
	context.SetOrganization("org")
	context.SetEnvironment("env")
	authContext := &auth.Context{
		Context:        context,
		DeveloperEmail: "email",
		Application:    "app",
		AccessToken:    "token",
		ClientID:       "clientId",
	}

	m := &manager{
		close:             make(chan bool),
		client:            http.DefaultClient,
		now:               fakeTime.now,
		syncRate:          time.Minute,
		bucketToSyncQueue: make(chan *bucket, 10),
		baseURL:           context.InternalAPI(),
		numSyncWorkers:    1,
		buckets:           map[string]*bucket{},
		bucketsSyncing:    map[*bucket]struct{}{},
	}

	api := product.AuthorizedOperation{
		QuotaLimit:    1,
		QuotaInterval: 1,
		QuotaTimeUnit: quotaSecond,
	}

	args := Args{
		QuotaAmount: 1,
	}

	// apply and force a sync
	res, err := m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("shouln't get error: %v", err)
	}
	if err := m.forceSync(api.ID); err == nil {
		t.Errorf("want error 'new request: net/http: nil Context' got none")
	}

	bucket := m.buckets[api.ID]
	if res.Used != 1 {
		t.Errorf("got: %d, want: %d", res.Used, 1)
	}
	if res.Exceeded != 0 {
		t.Errorf("got: %d, want: %d", res.Exceeded, 0)
	}

	// move to the next window
	if bucket.windowExpired() {
		t.Errorf("should not be expired")
	}
	fakeTime.add(1)
	if !bucket.windowExpired() {
		t.Errorf("should be expired")
	}

	res, err = m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
	if res.Used != 1 {
		t.Errorf("got: %d, want: %d", res.Used, 1)
	}
	if res.Exceeded != 0 {
		t.Errorf("got: %d, want: %d", res.Exceeded, 0)
	}

	res, err = m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
	if res.Used != 1 {
		t.Errorf("got: %d, want: %d", res.Used, 1)
	}
	if res.Exceeded != 1 {
		t.Errorf("got: %d, want: %d", res.Exceeded, 1)
	}

	// move to the next window
	fakeTime.add(1)
	if !bucket.windowExpired() {
		t.Errorf("should be expired")
	}

	res, err = m.Apply(authContext, api, args)
	if err != nil {
		t.Errorf("got error: %v", err)
	}
	if res.Used != 1 {
		t.Errorf("got: %d, want: %d", res.Used, 1)
	}
	if res.Exceeded != 0 {
		t.Errorf("got: %d, want: %d", res.Exceeded, 0)
	}
}

type errControl struct {
	send int
}

func testServer(serverResult *Result, now func() time.Time, errC *errControl) (*httptest.Server, *sync.Mutex) {

	resultLock := &sync.Mutex{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if errC != nil && errC.send != 200 {
			w.WriteHeader(errC.send)
			_, _ = w.Write([]byte("error"))
			return
		}

		resultLock.Lock()
		defer resultLock.Unlock()
		req := Request{}
		_ = json.NewDecoder(r.Body).Decode(&req)
		serverResult.Allowed = req.Allow
		serverResult.Used += req.Weight
		if serverResult.Used > serverResult.Allowed {
			serverResult.Exceeded = serverResult.Used - serverResult.Allowed
			serverResult.Used = serverResult.Allowed
		}
		serverResult.Timestamp = now().Unix()
		serverResult.ExpiryTime = now().Unix() * 1000 // milliseconds needed
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(serverResult)
	})), resultLock
}

// ignores if no matching quota bucket
func (m *manager) forceSync(quotaID string) error {
	m.bucketsLock.RLock()
	b, ok := m.buckets[quotaID]
	if !ok {
		m.bucketsLock.RUnlock()
		return nil
	}
	m.bucketsLock.RUnlock()
	m.bucketsSyncingLock.Lock()
	m.bucketsSyncing[b] = struct{}{}
	m.bucketsSyncingLock.Unlock()
	defer func() {
		m.bucketsSyncingLock.Lock()
		delete(m.bucketsSyncing, b)
		m.bucketsSyncingLock.Unlock()
	}()
	return b.sync()
}

type Clock struct {
	time int64
	lock sync.RWMutex
}

func newClock() *Clock {
	return &Clock{
		time: int64(1521221450),
	}
}

func (c *Clock) now() time.Time {
	c.lock.RLock()
	defer c.lock.RUnlock()
	return time.Unix(c.time, 0)
}

func (c *Clock) add(time int64) {
	c.lock.Lock()
	defer c.lock.Unlock()
	c.time = c.time + time
}
