package whatsmeow

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

type retainedAppStateStore struct {
	store.AppStateSyncKeyStore
	failed  atomic.Bool
	started chan struct{}
	once    sync.Once
	stored  store.AppStateSyncKey
}

func (s *retainedAppStateStore) PutAppStateSyncKey(ctx context.Context, _ []byte, key store.AppStateSyncKey) error {
	s.once.Do(func() { close(s.started) })
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if s.failed.Load() {
		return errors.New("database overloaded")
	}
	s.stored = key
	return nil
}

func TestAppStateKeyWriteRetainedAcrossConnectionCancellation(t *testing.T) {
	s := &retainedAppStateStore{started: make(chan struct{})}
	s.failed.Store(true)
	cli := NewClient(&store.Device{AppStateKeys: s}, waLog.Noop)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	key := store.AppStateSyncKey{Data: []byte("critical key"), Fingerprint: []byte("fingerprint"), Timestamp: 123}
	done := make(chan struct{})
	defer func() { s.failed.Store(false); <-done }()
	go func() { cli.storeAppStateKeyRetained(ctx, []byte("id"), key); close(done) }()
	<-s.started
	cancel()
	select {
	case <-done:
		t.Fatal("failed write was abandoned on connection cancellation")
	case <-time.After(30 * time.Millisecond):
	}
	s.failed.Store(false)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("key did not persist after recovery")
	}
	if !bytes.Equal(s.stored.Data, key.Data) || !bytes.Equal(s.stored.Fingerprint, key.Fingerprint) || s.stored.Timestamp != key.Timestamp {
		t.Fatal("retained key changed or was lost")
	}
}
