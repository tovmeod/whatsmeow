package sqlstore

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	waLog "go.mau.fi/whatsmeow/util/log"
)

type immediateSessionStore struct {
	*mockFlushSessionStore
	started  chan string
	release  chan struct{}
	attempts atomic.Int64
	fail     atomic.Bool
}

func (s *immediateSessionStore) PutManySessions(ctx context.Context, rows map[string][]byte) error {
	n := s.attempts.Add(1)
	for _, blob := range rows {
		select {
		case s.started <- string(blob):
		default:
		}
		break
	}
	if n == 1 && s.release != nil {
		<-s.release
	}
	if s.fail.Load() {
		return errors.New("test database failure")
	}
	return s.mockFlushSessionStore.PutManySessions(ctx, rows)
}
func waitImmediateWrite(t *testing.T, started <-chan string, want string) {
	t.Helper()
	select {
	case got := <-started:
		if got != want {
			t.Fatalf("write=%q want=%q", got, want)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("write %q waited for an old timer/threshold", want)
	}
}
func TestSessionWriterImmediateAndContinuesAfterInFlightAdvance(t *testing.T) {
	// Historical threshold/timer settings must not delay healthy writes.
	t.Setenv("KAVTOV_FLUSH_SESSION_N", "100000")
	t.Setenv("KAVTOV_FLUSH_SESSION_T_MS", "60000")
	s := &immediateSessionStore{mockFlushSessionStore: newMockFlushSessionStore(), started: make(chan string, 10), release: make(chan struct{})}
	f := NewSessionFlusher(s, waLog.Noop, 100)
	f.Start()
	released := false
	t.Cleanup(func() {
		if !released {
			close(s.release)
		}
		f.Stop()
	})
	f.Enqueue("address:0", []byte("old"))
	waitImmediateWrite(t, s.started, "old")
	f.Enqueue("address:0", []byte("new"))
	close(s.release)
	released = true
	waitImmediateWrite(t, s.started, "new")
	f.Stop()
	if f.DirtyCount() != 0 {
		t.Fatal("latest generation did not drain")
	}
	if got, _ := s.mockFlushSessionStore.getSession("address:0"); string(got) != "new" {
		t.Fatalf("latest durable generation=%q", got)
	}
}
func TestSessionWriterRetriesRetainedFailureWithoutAnotherEnqueue(t *testing.T) {
	s := &immediateSessionStore{mockFlushSessionStore: newMockFlushSessionStore(), started: make(chan string, 10)}
	s.fail.Store(true)
	f := NewSessionFlusher(s, waLog.Noop, 100)
	f.Start()
	t.Cleanup(func() { s.fail.Store(false); f.Stop() })
	f.Enqueue("address:0", []byte("retained"))
	waitImmediateWrite(t, s.started, "retained")
	// Synchronize with the completed failed attempt, then recover the database.
	deadline := time.Now().Add(time.Second)
	for f.progress.started.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.fail.Store(false)
	waitImmediateWrite(t, s.started, "retained")
	f.Stop()
	if got, _ := s.mockFlushSessionStore.getSession("address:0"); string(got) != "retained" {
		t.Fatal("retained data lost")
	}
}

type immediateKeyStore struct {
	started  chan string
	release  chan struct{}
	attempts atomic.Int64
	fail     atomic.Bool
	latest   atomic.Value
}

func (s *immediateKeyStore) PutManySenderKeys(_ context.Context, rows []SenderKeyRow) error {
	n := s.attempts.Add(1)
	for _, r := range rows {
		select {
		case s.started <- string(r.Blob):
		default:
		}
	}
	if n == 1 && s.release != nil {
		<-s.release
	}
	if s.fail.Load() {
		return errors.New("test database failure")
	}
	for _, r := range rows {
		s.latest.Store(string(r.Blob))
	}
	return nil
}
func TestSenderKeyWriterImmediateAndContinuesAfterInFlightAdvance(t *testing.T) {
	t.Setenv("KAVTOV_FLUSH_SENDERKEY_N", "100000")
	s := &immediateKeyStore{started: make(chan string, 10), release: make(chan struct{})}
	f := NewSenderKeyFlusher(s, waLog.Noop, 100)
	f.Start()
	released := false
	stopped := false
	t.Cleanup(func() {
		if !released {
			close(s.release)
		}
		if !stopped {
			f.Stop()
		}
	})
	f.Enqueue("group", "user", []byte("old"), 1, 1, false)
	waitImmediateWrite(t, s.started, "old")
	f.Enqueue("group", "user", []byte("new"), 1, 2, false)
	close(s.release)
	released = true
	waitImmediateWrite(t, s.started, "new")
	f.Stop()
	stopped = true
	if f.DirtyCount() != 0 || s.latest.Load() != "new" {
		t.Fatal("new sender-key generation lost")
	}
}
func TestSenderKeyWriterRetriesRetainedFailureWithoutAnotherEnqueue(t *testing.T) {
	s := &immediateKeyStore{started: make(chan string, 10)}
	s.fail.Store(true)
	f := NewSenderKeyFlusher(s, waLog.Noop, 100)
	f.Start()
	stopped := false
	t.Cleanup(func() {
		s.fail.Store(false)
		if !stopped {
			f.Stop()
		}
	})
	f.Enqueue("group", "user", []byte("retained"), 1, 1, false)
	waitImmediateWrite(t, s.started, "retained")
	deadline := time.Now().Add(time.Second)
	for f.progress.started.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	s.fail.Store(false)
	waitImmediateWrite(t, s.started, "retained")
	f.Stop()
	stopped = true
	if f.DirtyCount() != 0 || s.latest.Load() != "retained" {
		t.Fatal("retained sender key lost")
	}
}
