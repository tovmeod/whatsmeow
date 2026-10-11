package sqlstore

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

type retainingKeyStore struct {
	mu                     sync.Mutex
	fail                   atomic.Bool
	rows                   map[string]string
	oldStarted, releaseOld chan struct{}
	active, maxActive      atomic.Int64
	attempts               atomic.Int64
}

func (s *retainingKeyStore) PutManySenderKeys(_ context.Context, rows []SenderKeyRow) error {
	s.attempts.Add(1)
	n := s.active.Add(1)
	defer s.active.Add(-1)
	for old := s.maxActive.Load(); n > old && !s.maxActive.CompareAndSwap(old, n); old = s.maxActive.Load() {
	}
	if s.fail.Load() {
		return errors.New("simulated database outage")
	}
	if s.oldStarted != nil && len(rows) > 0 && string(rows[0].Blob) == "old" {
		close(s.oldStarted)
		<-s.releaseOld
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows == nil {
		s.rows = make(map[string]string)
	}
	for _, row := range rows {
		s.rows[row.Group+"|"+row.User] = string(row.Blob)
	}
	return nil
}

func TestOverloadRetryBackoffIsSharedAcrossPressureRequests(t *testing.T) {
	s := &retainingKeyStore{}
	s.fail.Store(true)
	f := NewSenderKeyFlusher(s, waLog.Noop, 100)
	f.backpressureCap = 0
	for i := 1; i <= 100; i++ {
		f.Enqueue("g", "u", []byte("retained"), 1, uint32(i), false)
	}
	if attempts := s.attempts.Load(); attempts > 3 {
		t.Fatalf("pressure burst amplified failure into %d SQL attempts", attempts)
	}
	if f.DirtyCount() != 1 {
		t.Fatal("latest dirty key lost during retry backoff")
	}
	s.fail.Store(false)
	f.Drain()
	if s.rows["g|u"] != "retained" {
		t.Fatal("pending key not committed after recovery")
	}
}

func TestOverloadContainerDrainTimeoutRetainsWorkersAndWrites(t *testing.T) {
	s := &retainingKeyStore{}
	s.fail.Store(true)
	f := NewSenderKeyFlusher(s, waLog.Noop, 100)
	f.Start()
	defer func() { s.fail.Store(false); f.Stop() }()
	c := &Container{}
	c.caches.senderKeyFlusherMap = map[string]*SenderKeyFlusher{"test-device": f}
	f.Enqueue("g", "u", []byte("retained"), 1, 1, false)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	if err := c.DrainWrites(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("drain error=%v", err)
	}
	if state := c.WriteBackStatus(); state.Pending != 1 || state.Commits != 0 || state.OldestAge == 0 {
		t.Fatalf("incorrect retained pressure: %+v", state)
	}
	s.fail.Store(false)
	healed, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	if err := c.DrainWrites(healed); err != nil {
		t.Fatal(err)
	}
	if state := c.WriteBackStatus(); state.Pending != 0 || state.InFlight != 0 || state.Commits == 0 {
		t.Fatalf("incorrect drained pressure: %+v", state)
	}
	if s.rows["g|u"] != "retained" {
		t.Fatal("record lost across drain timeout")
	}
}

func TestOverloadSenderKeysRetainFailedPressureBatch(t *testing.T) {
	s := &retainingKeyStore{}
	s.fail.Store(true)
	f := NewSenderKeyFlusher(s, waLog.Noop, 10)
	for i := 0; i < 5; i++ {
		f.Enqueue("g", fmt.Sprint(i), []byte("retained"), 1, 1, false)
	}
	if f.DirtyCount() != 5 {
		t.Fatalf("pending=%d, want all five keys retained", f.DirtyCount())
	}
	s.fail.Store(false)
	f.Drain()
	if len(s.rows) != 5 {
		t.Fatalf("persisted=%d, want five", len(s.rows))
	}
}

func TestOverloadSenderKeyPressureOrdersLatestSnapshot(t *testing.T) {
	s := &retainingKeyStore{oldStarted: make(chan struct{}), releaseOld: make(chan struct{})}
	f := NewSenderKeyFlusher(s, waLog.Noop, 100)
	f.Enqueue("g", "u", []byte("old"), 1, 1, false)
	oldDone := make(chan struct{})
	go func() { f.runFlush(); close(oldDone) }()
	select {
	case <-s.oldStarted:
	case <-time.After(time.Second):
		t.Fatal("old snapshot did not start")
	}
	f.backpressureCap = 0
	newDone := make(chan struct{})
	go func() { f.Enqueue("g", "u", []byte("new"), 1, 2, false); close(newDone) }()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		e := f.dirty["g|u"]
		updated := e != nil && e.highIter == 2
		f.mu.Unlock()
		if updated {
			break
		}
		time.Sleep(time.Millisecond)
	}
	close(s.releaseOld)
	<-oldDone
	select {
	case <-newDone:
	case <-time.After(time.Second):
		t.Fatal("pressure writer failed to resume")
	}
	s.mu.Lock()
	latest := s.rows["g|u"]
	s.mu.Unlock()
	if latest != "new" || s.maxActive.Load() != 1 || f.DirtyCount() != 0 {
		t.Fatalf("latest=%q concurrent_writers=%d pending=%d", latest, s.maxActive.Load(), f.DirtyCount())
	}
}
