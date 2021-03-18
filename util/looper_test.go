// Copyright 2019 Google LLC
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

package util_test

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/util"
	"github.com/pkg/errors"
)

func TestPoller(t *testing.T) {
	poller := util.Looper{
		Backoff: util.NewExponentialBackoff(time.Millisecond, time.Millisecond, 2, true),
	}

	wait := make(chan struct{})

	var called int32
	f := func(ctx context.Context) error {
		atomic.AddInt32(&called, 1)
		<-wait
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx, f, time.Millisecond, func(err error) error {
		t.Error("should not reach")
		return nil
	})
	defer cancel()

	if atomic.LoadInt32(&called) != 0 {
		t.Error("called should be 0")
	}
	wait <- struct{}{}
	if atomic.LoadInt32(&called) != 1 {
		t.Error("called should be 1")
	}
}

func TestPollerQuit(t *testing.T) {
	poller := util.Looper{
		Backoff: util.NewExponentialBackoff(time.Millisecond, time.Millisecond, 2, true),
	}

	wait := make(chan struct{})
	f := func(ctx context.Context) error {
		<-wait
		return errors.Errorf("yup")
	}

	var called int32
	waitErr := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx, f, time.Millisecond, func(err error) error {
		atomic.AddInt32(&called, 1)
		waitErr <- struct{}{}
		return nil
	})
	defer cancel()

	if atomic.LoadInt32(&called) != 0 {
		t.Error("called should be 0")
	}
	wait <- struct{}{}
	<-waitErr
	if atomic.LoadInt32(&called) != 1 {
		t.Error("called should be 1")
	}
}

func TestPollerCancel(t *testing.T) {
	poller := util.Looper{
		Backoff: util.NewExponentialBackoff(time.Millisecond, time.Millisecond, 2, true),
	}

	wait := make(chan struct{})
	f := func(ctx context.Context) error {
		t.Log("running func")
		wait <- struct{}{}
		select {
		case <-time.After(5 * time.Millisecond):
			t.Error("cancel not called")
		case <-ctx.Done():
			t.Log("cancel called")
		}
		t.Log("func done")
		wait <- struct{}{}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	poller.Start(ctx, f, time.Millisecond, func(err error) error {
		t.Logf("error: %#v", err)
		return nil
	})
	<-wait
	cancel()
	<-wait
}

func TestNewChannelWithWorkerPool(t *testing.T) {
	backoff := util.NewExponentialBackoff(time.Millisecond, time.Millisecond, 2, true)
	ctx := context.Background()
	errH := func(error) error {
		return nil
	}
	channel := util.NewChannelWithWorkerPool(ctx, 2, 2, errH, backoff)
	var i int32

	work := func(ctx context.Context) error {
		atomic.AddInt32(&i, 1)
		return nil
	}
	work2 := func(ctx context.Context) error {
		return fmt.Errorf("error")
	}
	channel <- work
	time.Sleep(5 * time.Millisecond)

	if got := atomic.LoadInt32(&i); got != 1 {
		t.Errorf("want: 1, got: %d", got)
	}

	channel <- work2
	time.Sleep(5 * time.Millisecond)
	if got := atomic.LoadInt32(&i); got != 1 {
		t.Errorf("want: 1, got: %d", got)
	}

	channel <- work
	time.Sleep(5 * time.Millisecond)
	if got := atomic.LoadInt32(&i); got != 2 {
		t.Errorf("want: 2, got: %d", got)
	}

	close(channel)
}
