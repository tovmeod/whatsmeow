package sqlstore

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"go.mau.fi/whatsmeow/types"
)

type sessionBatchTrace struct{ queries, commits atomic.Int64 }

func (p *sessionBatchTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	sql := strings.ToLower(strings.TrimSpace(d.SQL))
	if sql == "commit" {
		p.commits.Add(1)
	} else if sql != "begin" && sql != "rollback" {
		p.queries.Add(1)
	}
	return ctx
}
func (*sessionBatchTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func newSessionBatchFixture(t testing.TB) (*SQLStore, *sessionBatchTrace) {
	t.Helper()
	dsn := os.Getenv("TEST_DSN")
	if dsn == "" {
		dsn = os.Getenv("KAVTOV_TEST_DSN")
	}
	if dsn == "" {
		t.Skip("explicit isolated TEST_DSN required")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database != "kavtov_test" || cfg.User != "kavtov_test" {
		t.Fatal("benchmark requires the isolated test database")
	}
	p := &sessionBatchTrace{}
	cfg.Tracer = p
	db := stdlib.OpenDB(*cfg)
	db.SetMaxOpenConns(2)
	c := NewWithDB(db, "postgres", nil)
	ctx := context.Background()
	jidString := "17700008888@s.whatsapp.net"
	jid, err := types.ParseJID(jidString)
	if err != nil {
		t.Fatal(err)
	}
	b32 := bytes.Repeat([]byte{1}, 32)
	b64 := bytes.Repeat([]byte{2}, 64)
	_, err = db.ExecContext(ctx, `INSERT INTO whatsmeow_device (jid,registration_id,noise_key,identity_key,signed_pre_key,signed_pre_key_id,signed_pre_key_sig,adv_key,adv_details,adv_account_sig,adv_account_sig_key,adv_device_sig) VALUES ($1,1,$2,$2,$2,1,$3,$2,$2,$3,$2,$3) ON CONFLICT (jid) DO NOTHING`, jidString, b32, b64)
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, err := db.ExecContext(context.Background(), "DELETE FROM whatsmeow_device WHERE jid=$1", jidString)
		if err != nil {
			t.Error(err)
		}
		if err = c.Close(); err != nil {
			t.Error(err)
		}
	})
	return NewSQLStore(c, jid), p
}
func sessionTestRows(n, size int) ([]string, map[string][]byte) {
	addresses := make([]string, n)
	rows := make(map[string][]byte, n)
	// Deterministic, incompressible synthetic bytes avoid measuring TOAST's
	// compression shortcut on repeated zero/one payloads.
	var x uint64 = 0x9e3779b97f4a7c15
	for i := range addresses {
		address := fmt.Sprintf("local-batch-%04d:0", i)
		addresses[i] = address
		blob := make([]byte, size)
		for j := range blob {
			x ^= x << 13
			x ^= x >> 7
			x ^= x << 17
			blob[j] = byte(x)
		}
		rows[address] = blob
	}
	return addresses, rows
}
func sessionLegacyRows(s *SQLStore, ctx context.Context, addresses []string, rows map[string][]byte) error {
	for _, addr := range addresses {
		if err := s.PutSession(ctx, addr, rows[addr]); err != nil {
			return err
		}
	}
	return nil
}
func sessionMergedRows(s *SQLStore, ctx context.Context, addresses []string, rows map[string][]byte) error {
	for start := 0; start < len(addresses); start += 250 {
		chunk := addresses[start:min(start+250, len(addresses))]
		var q strings.Builder
		q.WriteString("INSERT INTO whatsmeow_sessions (our_jid, their_id, session) VALUES ")
		args := make([]any, 0, len(chunk)*3)
		for i, addr := range chunk {
			if i > 0 {
				q.WriteByte(',')
			}
			n := i * 3
			fmt.Fprintf(&q, "($%d,$%d,$%d)", n+1, n+2, n+3)
			args = append(args, s.JID, addr, rows[addr])
		}
		q.WriteString(" ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session")
		if _, err := s.db.Exec(ctx, q.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

type sessionBulkOption struct {
	name  string
	write func(*SQLStore, context.Context, []string, map[string][]byte) error
}

func sessionBulkOptions() []sessionBulkOption {
	return []sessionBulkOption{
		{"legacy_per_row", sessionLegacyRows}, {"merged_250", sessionMergedRows},
		{"selected", func(s *SQLStore, c context.Context, _ []string, r map[string][]byte) error {
			return s.PutManySessions(c, r)
		}},
		{"array_64KiB", func(s *SQLStore, c context.Context, a []string, r map[string][]byte) error {
			return s.putSessionArrays(c, a, r, 64*1024)
		}},
		{"chunks_16KiB", func(s *SQLStore, c context.Context, a []string, r map[string][]byte) error {
			return s.putSessionChunks(c, a, r, 16*1024)
		}},
		{"chunks_64KiB", func(s *SQLStore, c context.Context, a []string, r map[string][]byte) error {
			return s.putSessionChunks(c, a, r, 64*1024)
		}},
		{"array_250", func(s *SQLStore, c context.Context, a []string, r map[string][]byte) error {
			return s.putSessionArrays(c, a, r, 1<<30)
		}},
	}
}
func TestSessionBulkOptionsAtomicAndRoundTrip(t *testing.T) {
	for _, option := range sessionBulkOptions() {
		t.Run(option.name, func(t *testing.T) {
			s, _ := newSessionBatchFixture(t)
			ctx := context.Background()
			addresses, rows := sessionTestRows(300, 2048)
			if err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error { return option.write(s, ctx, addresses, rows) }); err != nil {
				t.Fatal(err)
			}
			// An invalid text address sorts after every valid row. Any successful early
			// chunks must roll back with the failed last chunk.
			changed := map[string][]byte{}
			for address := range rows {
				changed[address] = []byte("changed")
			}
			changed["zz-invalid\x00:0"] = []byte("invalid")
			bad := append(slices.Clone(addresses), "zz-invalid\x00:0")
			if err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error { return option.write(s, ctx, bad, changed) }); err == nil {
				t.Fatal("invalid batch committed")
			}
			for _, addr := range addresses {
				got, err := s.GetSession(ctx, addr)
				if err != nil || !bytes.Equal(got, rows[addr]) {
					t.Fatalf("partial rollback/readback %s: %v", addr, err)
				}
			}
		})
	}
}
func TestSessionSingleFastPathPreservesOuterTransaction(t *testing.T) {
	s, p := newSessionBatchFixture(t)
	ctx := context.Background()
	p.queries.Store(0)
	p.commits.Store(0)
	rows := map[string][]byte{"fast:0": []byte("retained")}
	if err := s.PutManySessions(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if p.queries.Load() != 1 || p.commits.Load() != 0 {
		t.Fatalf("single path statements=%d commits=%d", p.queries.Load(), p.commits.Load())
	}
	sentinel := fmt.Errorf("outer rollback")
	if err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		if err := s.PutManySessions(ctx, map[string][]byte{"fast:0": []byte("new")}); err != nil {
			return err
		}
		return sentinel
	}); err != sentinel {
		t.Fatalf("outer error=%v", err)
	}
	got, err := s.GetSession(ctx, "fast:0")
	if err != nil || string(got) != "retained" {
		t.Fatalf("outer rollback violated: %q %v", got, err)
	}
}
func sessionCPU() float64 {
	var r syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &r)
	return float64(r.Utime.Sec+r.Stime.Sec)*1000 + float64(r.Utime.Usec+r.Stime.Usec)/1000
}
func sessionDBCPU() float64 {
	data, err := os.ReadFile(os.Getenv("PERF_DB_CPU_FILE"))
	if err != nil {
		return 0
	}
	words := strings.Fields(string(data))
	for i := 0; i+1 < len(words); i += 2 {
		if words[i] == "usage_usec" {
			n, _ := strconv.ParseFloat(words[i+1], 64)
			return n / 1000
		}
	}
	return 0
}
func BenchmarkSessionBulkOptions(b *testing.B) {
	for _, shape := range []struct{ n, size int }{{1, 2048}, {10, 2048}, {250, 2048}, {250, 8192}} {
		options := sessionBulkOptions()
		if shape.n == 1 {
			options = append(options, sessionBulkOption{"single_fast", func(s *SQLStore, c context.Context, _ []string, r map[string][]byte) error {
				return s.PutManySessions(c, r)
			}})
		}
		for _, option := range options {
			b.Run(fmt.Sprintf("rows_%d_blob_%d/%s", shape.n, shape.size, option.name), func(b *testing.B) {
				s, p := newSessionBatchFixture(b)
				ctx := context.Background()
				addresses, rows := sessionTestRows(shape.n, shape.size)
				call := func() error {
					return s.db.DoTxn(ctx, nil, func(ctx context.Context) error { return option.write(s, ctx, addresses, rows) })
				}
				// The public one-row path owns its transaction, rather than being nested
				// inside this benchmark's generic candidate wrapper.
				if option.name == "single_fast" || option.name == "selected" {
					call = func() error { return s.PutManySessions(ctx, rows) }
				}
				if err := call(); err != nil {
					b.Fatal(err)
				}
				p.queries.Store(0)
				p.commits.Store(0)
				runtime.GC()
				cpu, dbCPU := sessionCPU(), sessionDBCPU()
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					for _, blob := range rows {
						blob[0] = byte(i + 1)
						blob[1] = byte((i + 1) >> 8)
					}
					if err := call(); err != nil {
						b.Fatal(err)
					}
				}
				b.StopTimer()
				cpu = sessionCPU() - cpu
				dbCPU = sessionDBCPU() - dbCPU
				b.ReportMetric(float64(p.queries.Load())/float64(b.N), "SQL/op")
				b.ReportMetric(float64(p.commits.Load())/float64(b.N), "tx/op")
				b.ReportMetric(cpu*1e6/float64(b.N), "goCPU-ns/op")
				if dbCPU > 0 {
					b.ReportMetric(dbCPU*1e6/float64(b.N), "dbCPU-ns/op")
				}
				for _, addr := range addresses {
					got, err := s.GetSession(ctx, addr)
					if err != nil || !bytes.Equal(got, rows[addr]) {
						b.Fatalf("durable readback %s: %v", addr, err)
					}
				}
			})
		}
	}
}

func TestSessionChunkBoundsKeepOversizedRowsIntact(t *testing.T) {
	s := &SQLStore{JID: "local-account"}
	addresses, rows := sessionTestRows(300, 2048)
	for start := 0; start < len(addresses); {
		end := s.sessionChunkEnd(addresses, rows, start, sessionBatchBytes)
		if end <= start || end-start > sessionBatchRows {
			t.Fatalf("invalid row bounds %d:%d", start, end)
		}
		total := 0
		for _, addr := range addresses[start:end] {
			total += len(s.JID) + len(addr) + len(rows[addr]) + 24
		}
		if total > sessionBatchBytes {
			t.Fatalf("chunk payload estimate=%d exceeds bound", total)
		}
		start = end
	}
	rows[addresses[0]] = make([]byte, sessionBatchBytes+1)
	if end := s.sessionChunkEnd(addresses, rows, 0, sessionBatchBytes); end != 1 {
		t.Fatalf("oversized row should occupy its own intact chunk, end=%d", end)
	}
	_, tinyRows := sessionTestRows(300, 0)
	if end := s.sessionChunkEnd(addresses, tinyRows, 0, 1<<30); end != sessionBatchRows {
		t.Fatalf("row cap ignored: %d", end)
	}
}

func TestSessionSelectedBulkKeepsOversizedBlobAndRollsBackFailure(t *testing.T) {
	s, _ := newSessionBatchFixture(t)
	ctx := context.Background()
	rows := map[string][]byte{
		"large:0": bytes.Repeat([]byte{0xff, 0x00, 0x82}, sessionBatchBytes),
		"small:0": []byte("original"),
	}
	if err := s.PutManySessions(ctx, rows); err != nil {
		t.Fatal(err)
	}
	if err := s.PutManySessions(ctx, map[string][]byte{
		"large:0":          bytes.Repeat([]byte{0x7f}, sessionBatchBytes+1),
		"small:0":          []byte("changed"),
		"zz-invalid\x00:0": []byte("invalid address"),
	}); err == nil {
		t.Fatal("invalid last chunk committed")
	}
	for addr, want := range rows {
		got, err := s.GetSession(ctx, addr)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("oversized round trip or rollback violated for %s: %v", addr, err)
		}
	}
}
