package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"
	"time"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/util/dbutil"
	"go.mau.fi/whatsmeow/store"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// This connector has no network or DSN: each test owns the entire SQL surface.
type senderKeyCommitConnector struct {
	exec func([]driver.NamedValue) error
}

func (c *senderKeyCommitConnector) Connect(context.Context) (driver.Conn, error) {
	return &senderKeyCommitConn{c}, nil
}
func (c *senderKeyCommitConnector) Driver() driver.Driver { return senderKeyCommitDriver{} }

type senderKeyCommitDriver struct{}

func (senderKeyCommitDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("connector only")
}

type senderKeyCommitConn struct{ c *senderKeyCommitConnector }

func (*senderKeyCommitConn) Prepare(string) (driver.Stmt, error) {
	return nil, errors.New("ExecContext only")
}
func (*senderKeyCommitConn) Close() error              { return nil }
func (*senderKeyCommitConn) Begin() (driver.Tx, error) { return nil, errors.New("no transactions") }
func (c *senderKeyCommitConn) ExecContext(_ context.Context, _ string, args []driver.NamedValue) (driver.Result, error) {
	if err := c.c.exec(args); err != nil {
		return nil, err
	}
	return driver.RowsAffected(1), nil
}

func commitTestStore(t *testing.T, exec func([]driver.NamedValue) error) *SQLStore {
	t.Helper()
	db := sql.OpenDB(&senderKeyCommitConnector{exec})
	t.Cleanup(func() { _ = db.Close() })
	wrapped, err := dbutil.NewWithDB(db, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	owner, err := NewSenderKeyDeviceCache(32)
	if err != nil {
		t.Fatal(err)
	}
	c := &Container{db: wrapped, log: waLog.Noop}
	c.caches.SenderKeyDevices = owner
	return &SQLStore{Container: c, JID: "recipient"}
}

func seedCommitNegative(key donorQueryKey) {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	noDonorCache.Add(key, noDonorCacheEntry{expiresAt: time.Now().Add(time.Minute)})
}
func hasCommitNegative(key donorQueryKey) bool {
	noDonorCacheMu.Lock()
	defer noDonorCacheMu.Unlock()
	return noDonorCache.Contains(key)
}

func TestSenderKeyCommitNotificationPerChunk(t *testing.T)       { testSenderKeyCommitChunks(t, false) }
func TestSenderKeyCommitNotificationPartialFailure(t *testing.T) { testSenderKeyCommitChunks(t, true) }
func testSenderKeyCommitChunks(t *testing.T, fail bool) {
	resetNoDonorCacheForTest()
	calls := 0
	var sq *SQLStore
	sq = commitTestStore(t, func(args []driver.NamedValue) error {
		calls++
		if calls == 2 {
			if hasCommitNegative(donorQueryKey{sq.Container, "g0", "u", 7}) {
				t.Error("successful first chunk did not notify before next Exec")
			}
			if fail {
				return errors.New("second chunk failed")
			}
		}
		return nil
	})
	keys := make([]SenderKeyRow, senderKeyBatchChunkSize+1)
	for i := range keys {
		keys[i] = SenderKeyRow{Group: fmt.Sprintf("g%d", i), User: "u:1", Blob: testBlob(7, 2)}
		seedCommitNegative(donorQueryKey{sq.Container, keys[i].Group, "u", 7})
	}
	unrelated := donorQueryKey{sq.Container, "g0", "u", 8}
	seedCommitNegative(unrelated)
	err := sq.PutManySenderKeys(context.Background(), keys)
	if (err != nil) != fail {
		t.Fatalf("err=%v, fail=%v", err, fail)
	}
	for i := range keys {
		want := fail && i == senderKeyBatchChunkSize
		if got := hasCommitNegative(donorQueryKey{sq.Container, keys[i].Group, "u", 7}); got != want {
			t.Errorf("row %d absence=%v, want %v", i, got, want)
		}
	}
	if !hasCommitNegative(unrelated) {
		t.Fatal("unrelated key ID invalidated")
	}
}

func TestSenderKeyCommitDistinctFromDrain(t *testing.T) {
	resetNoDonorCacheForTest()
	entered, release := make(chan struct{}), make(chan struct{})
	sq := commitTestStore(t, func([]driver.NamedValue) error { close(entered); <-release; return nil })
	f := NewSenderKeyFlusher(sq, waLog.Noop, 100)
	drains := 0
	f.SetOnDrained(func(string, string) { drains++ })
	key := donorQueryKey{sq.Container, "g", "u", 7}
	seedCommitNegative(key)
	f.Enqueue("g", "u:1", testBlob(7, 2), 7, 2, false)
	done := make(chan struct{})
	go func() { f.runFlush(); close(done) }()
	<-entered
	f.Enqueue("g", "u:1", testBlob(7, 3), 7, 3, false)
	close(release)
	<-done
	if hasCommitNegative(key) {
		t.Fatal("committed still-dirty snapshot did not notify")
	}
	if drains != 0 || f.DirtyCount() != 1 {
		t.Fatalf("drains=%d dirty=%d, want 0,1", drains, f.DirtyCount())
	}
}

func TestSenderKeyWriteFencesEmptyScan(t *testing.T) {
	resetNoDonorCacheForTest()
	sq := commitTestStore(t, func([]driver.NamedValue) error { return nil })
	inner := &stubRecoveryInner{entered: make(chan struct{}, 1), release: make(chan struct{})}
	cs := newStubCachedStore(t, inner, nil)
	key := donorQueryKey{sq.Container, "g", "u", 7}
	done := make(chan struct{})
	go func() { _, _ = cs.lookupDonor(context.Background(), inner, key, 5); close(done) }()
	<-inner.entered
	if err := sq.PutManySenderKeys(context.Background(), []SenderKeyRow{{Group: "g", User: "u:1", Blob: testBlob(7, 2)}}); err != nil {
		t.Fatal(err)
	}
	close(inner.release)
	<-done
	if hasCommitNegative(key) {
		t.Fatal("empty scan restored absence after committed write")
	}
}

func TestSenderKeyCommitUnknownAndSkippedRows(t *testing.T) {
	resetNoDonorCacheForTest()
	sq := commitTestStore(t, func([]driver.NamedValue) error { return nil })
	keys := []donorQueryKey{
		{sq.Container, "g", "u", 1}, {sq.Container, "g", "u", 2},
		{sq.Container, "other", "u", 1}, {sq.Container, "g", "other", 1},
		{sq.Container, "skip", "u", 1}, {new(Container), "g", "u", 1},
	}
	for _, key := range keys {
		seedCommitNegative(key)
	}
	if err := sq.PutManySenderKeys(context.Background(), []SenderKeyRow{
		{Group: "g", User: "u:1", Blob: []byte("malformed")},
		{Group: "skip", User: "u:1"},
	}); err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		if got := hasCommitNegative(key); got != (i >= 2) {
			t.Errorf("domain %d absence=%v", i, got)
		}
	}
}

func TestSenderKeyWritePaths(t *testing.T) {
	for _, path := range []string{"legacy", "structure-sync", "structure-buffered", "recovery-sync", "recovery-buffered", "invalid-structure", "invalid-recovery", "sql-single"} {
		t.Run(path, func(t *testing.T) {
			resetNoDonorCacheForTest()
			inner := &stubRecoveryInner{}
			cs := newStubCachedStore(t, inner, nil)
			buffered := path == "structure-buffered" || path == "recovery-buffered"
			if buffered {
				cs.SetFlusher(NewSenderKeyFlusher(&mockFlushStore{}, waLog.Noop, 100))
			}
			key := donorQueryKey{inner, "g", "u", 7}
			seedCommitNegative(key)
			wave := &donorWave{participants: 1}
			donorWaves[key] = wave
			dk := cs.deviceKey("g", "u:1")
			cs.deviceCache.Add(dk, deviceCacheEntry{expiresAt: time.Now().Add(time.Minute)})
			structure, err := store.UnpackFlat(testBlob(7, 2))
			if err != nil {
				t.Fatal(err)
			}
			switch path {
			case "legacy":
				err = cs.PutSenderKey(context.Background(), "g", "u:1", testBlob(7, 2))
			case "structure-sync", "structure-buffered":
				err = cs.PutSenderKeyStructure(context.Background(), "g", "u:1", structure)
			case "recovery-sync", "recovery-buffered":
				var installed bool
				installed, err = cs.PutSenderKeyStructureRecovery(context.Background(), "g", "u:1", structure, 7)
				if !installed {
					t.Fatal("recovery did not install")
				}
			case "invalid-structure":
				err = cs.PutSenderKeyStructure(context.Background(), "g", "u:1", &groupRecord.SenderKeyStructure{})
			case "invalid-recovery":
				_, err = cs.PutSenderKeyStructureRecovery(context.Background(), "g", "u:1", &groupRecord.SenderKeyStructure{}, 7)
			case "sql-single":
				sq := commitTestStore(t, func([]driver.NamedValue) error { return nil })
				key = donorQueryKey{sq.Container, "g", "u", 7}
				seedCommitNegative(key)
				donorWaves[key] = wave
				err = sq.PutSenderKey(context.Background(), "g", "u:1", testBlob(7, 2))
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := hasCommitNegative(key); got != buffered {
				t.Fatalf("absence=%v, want %v", got, buffered)
			}
			if !wave.invalid {
				t.Fatal("accepted write did not fence active scan")
			}
			if path != "sql-single" {
				entry, ok := cs.deviceCache.Peek(dk)
				if !ok || len(entry.devices) != 1 {
					t.Fatalf("device negative not replaced: %+v", entry)
				}
			}
		})
	}
}

func TestSenderKeyCommitDelayedDrainKeepsNewPin(t *testing.T) {
	cs, _ := newTestCachedSenderKeyStore(t, 16)
	f := NewSenderKeyFlusher(&mockFlushStore{}, waLog.Noop, 100)
	cs.SetFlusher(f)
	entered, release := make(chan struct{}), make(chan struct{})
	f.SetOnDrained(func(string, string) { close(entered); <-release })
	first, _ := store.UnpackFlat(testBlob(7, 2))
	second, _ := store.UnpackFlat(testBlob(7, 3))
	if err := cs.PutSenderKeyStructure(context.Background(), "g", "u:1", first); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { f.runFlush(); close(done) }()
	<-entered
	if err := cs.PutSenderKeyStructure(context.Background(), "g", "u:1", second); err != nil {
		t.Fatal(err)
	}
	close(release)
	<-done
	cs.cache.Purge()
	cs.deviceCache.Purge()
	got, err := cs.GetSenderKeyStructure(context.Background(), "g", "u:1")
	if err != nil || got == nil || got.SenderKeyStates[0].SenderChainKey.Iteration != 3 {
		t.Fatalf("newer pin lost after delayed drain: %+v, %v", got, err)
	}
	devices, err := cs.GetSenderKeyDevices(context.Background(), "g", "u")
	if err != nil || len(devices) != 1 || f.DirtyCount() != 1 {
		t.Fatalf("devices=%v dirty=%d err=%v", devices, f.DirtyCount(), err)
	}
}

func TestSenderKeyCommitInlineDrainDoesNotLeavePin(t *testing.T) {
	cs, _ := newTestCachedSenderKeyStore(t, 16)
	f := NewSenderKeyFlusher(&mockFlushStore{}, waLog.Noop, 100)
	f.backpressureCap = 0
	cs.SetFlusher(f)
	structure, _ := store.UnpackFlat(testBlob(7, 2))
	if err := cs.PutSenderKeyStructure(context.Background(), "g", "u:1", structure); err != nil {
		t.Fatal(err)
	}
	cs.pinnedMu.Lock()
	defer cs.pinnedMu.Unlock()
	if len(cs.pinned) != 0 || len(cs.pinnedBlobs) != 0 || f.DirtyCount() != 0 {
		t.Fatal("synchronous inline drain left already-committed pins")
	}
}
