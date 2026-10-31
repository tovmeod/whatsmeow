package sqlstore_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

type prefixQueryTrace struct {
	mu   sync.Mutex
	sql  string
	args []any
}

func (p *prefixQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	p.mu.Lock()
	defer p.mu.Unlock()
	args := data.Args
	// database/sql's pgx adapter prepends a wire-format option, not a SQL bind.
	if len(args) > 0 {
		if _, ok := args[0].(pgx.QueryResultFormatsByOID); ok {
			args = args[1:]
		}
	}
	p.sql, p.args = data.SQL, slices.Clone(args)
	return ctx
}

func (*prefixQueryTrace) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func newPrefixIndexStore(t *testing.T) (*sqlstore.SQLStore, *sql.DB, *prefixQueryTrace) {
	t.Helper()
	if os.Getenv("TEST_DSN") == "" && os.Getenv("KAVTOV_TEST_DSN") == "" {
		t.Skip("prefix tests require an explicitly selected disposable TEST_DSN")
	}
	ctx := context.Background()
	admin, err := sql.Open("pgx", batchTestDSN())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	name := "prefix_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = admin.ExecContext(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.ExecContext(context.Background(), "DROP DATABASE "+name+" WITH (FORCE)"); err != nil {
			t.Errorf("remove owned test database: %v", err)
		}
	})
	cfg, err := pgx.ParseConfig(swapDBName(batchTestDSN(), name))
	if err != nil {
		t.Fatal(err)
	}
	trace := &prefixQueryTrace{}
	cfg.Tracer = trace
	db := stdlib.OpenDB(*cfg)
	container := sqlstore.NewWithDB(db, "postgres", nil)
	t.Cleanup(func() { _ = container.Close() })
	if err = container.Upgrade(ctx); err != nil {
		t.Fatal(err)
	}
	var locale string
	if err = db.QueryRowContext(ctx, `SELECT datcollate FROM pg_database WHERE datname=current_database()`).Scan(&locale); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(locale, "en_US") {
		t.Fatalf("test fixture must exercise production's en_US locale, got %q", locale)
	}
	for _, jid := range []string{testJID, "17700000002@s.whatsapp.net"} {
		key, sig := make([]byte, 32), make([]byte, 64)
		if _, err = db.ExecContext(ctx, insertTestDeviceQuery, jid, 1, key, key, key, 1, sig, key, key, sig, key, sig); err != nil {
			t.Fatal(err)
		}
	}
	return sqlstore.NewSQLStore(container, types.NewJID("17700000000", types.DefaultUserServer)), db, trace
}

func TestIndexedPrefixesMatchLiteralAddresses(t *testing.T) {
	for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
		t.Run(mode, func(t *testing.T) { testIndexedLiteralPrefixes(t, mode) })
	}
}

func testIndexedLiteralPrefixes(t *testing.T, mode string) {
	t.Helper()
	s, db, _ := newPrefixIndexStore(t)
	ctx := context.Background()
	db.SetMaxOpenConns(1)
	if _, err := db.ExecContext(ctx, "SET plan_cache_mode="+mode); err != nil {
		t.Fatal(err)
	}
	for _, phone := range []string{"155500001", `a_b%c\d`, "נהג_א%", "part:inner", "o'hare"} {
		t.Run(phone, func(t *testing.T) {
			matches := []string{phone + ":0", phone + ":9"}
			decoys := []string{phone + "1:0", phone + "_1:0", phone + ";0"}
			for _, address := range append(slices.Clone(matches), decoys...) {
				if err := s.PutSession(ctx, address, []byte("session")); err != nil {
					t.Fatal(err)
				}
				if err := s.PutIdentity(ctx, address, [32]byte{1}); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, `INSERT INTO whatsmeow_sender_keys
					(our_jid, chat_id, sender_id, sender_key) VALUES ($1, 'prefix@g.us', $2, $3)`, testJID, address, []byte{1, 0, 0, 0, 42}); err != nil {
					t.Fatal(err)
				}
			}
			for _, table := range []string{"whatsmeow_sessions", "whatsmeow_identity_keys"} {
				column, value := "session", []byte("other")
				if table == "whatsmeow_identity_keys" {
					column, value = "identity", make([]byte, 32)
				}
				if _, err := db.ExecContext(ctx, fmt.Sprintf("INSERT INTO %s (our_jid, their_id, %s) VALUES ($1, $2, $3)", table, column),
					"17700000002@s.whatsapp.net", matches[0], value); err != nil {
					t.Fatal(err)
				}
			}
			if exists, err := s.ExistsPNSession(ctx, phone+":"); err != nil || !exists {
				t.Fatalf("matching prefix: exists=%t err=%v", exists, err)
			}
			if exists, err := s.ExistsPNSession(ctx, phone+"-absent:"); err != nil || exists {
				t.Fatalf("absent prefix: exists=%t err=%v", exists, err)
			}
			devices, err := s.GetSenderKeyDevices(ctx, "prefix@g.us", phone)
			slices.Sort(devices)
			if err != nil || !reflect.DeepEqual(devices, matches) {
				t.Fatalf("devices=%q want %q: %v", devices, matches, err)
			}
			if err = s.DeleteAllSessions(ctx, phone); err != nil {
				t.Fatal(err)
			}
			if err = s.DeleteAllIdentities(ctx, phone); err != nil {
				t.Fatal(err)
			}
			for _, table := range []string{"whatsmeow_sessions", "whatsmeow_identity_keys"} {
				for _, address := range append(slices.Clone(matches), decoys...) {
					var present bool
					if err = db.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM "+table+" WHERE our_jid=$1 AND their_id=$2)", testJID, address).Scan(&present); err != nil {
						t.Fatal(err)
					}
					if present == slices.Contains(matches, address) {
						t.Errorf("%s address %q: present=%t", table, address, present)
					}
				}
				var count int
				if err = db.QueryRowContext(ctx, "SELECT count(*) FROM "+table+" WHERE our_jid=$1 AND their_id=$2", "17700000002@s.whatsapp.net", matches[0]).Scan(&count); err != nil || count != 1 {
					t.Fatalf("other account changed in %s: count=%d err=%v", table, count, err)
				}
			}
		})
	}
}

type prefixPlan struct {
	IndexCond string       `json:"Index Cond"`
	Removed   int          `json:"Rows Removed by Filter"`
	Hits      int          `json:"Shared Hit Blocks"`
	Reads     int          `json:"Shared Read Blocks"`
	Plans     []prefixPlan `json:"Plans"`
}

func explainPrefix(t *testing.T, db *sql.DB, mode, query string, args []any) prefixPlan {
	t.Helper()
	ctx := context.Background()
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "SET LOCAL plan_cache_mode="+mode); err != nil {
		t.Fatal(err)
	}
	name := "prefix_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err = tx.ExecContext(ctx, "PREPARE "+name+" AS "+query); err != nil {
		t.Fatal(err)
	}
	defer tx.ExecContext(ctx, "DEALLOCATE "+name)
	literals := make([]string, len(args))
	for i, arg := range args {
		value, ok := arg.(string)
		if !ok {
			t.Fatalf("unexpected prefix bind type %T", arg)
		}
		literals[i] = "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	var raw []byte
	if err = tx.QueryRowContext(ctx, "EXPLAIN (ANALYZE, BUFFERS, TIMING OFF, FORMAT JSON) EXECUTE "+name+"("+strings.Join(literals, ",")+")").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var result []struct{ Plan prefixPlan }
	if err = json.Unmarshal(raw, &result); err != nil || len(result) != 1 {
		t.Fatalf("decode plan: %s (%v)", raw, err)
	}
	return result[0].Plan
}

func (p prefixPlan) hasBounds() bool {
	if strings.Contains(p.IndexCond, "~>=~") && strings.Contains(p.IndexCond, "~<~") {
		return true
	}
	return slices.ContainsFunc(p.Plans, prefixPlan.hasBounds)
}

func TestPrefixQueriesSeekInCustomAndGenericPlans(t *testing.T) {
	s, db, trace := newPrefixIndexStore(t)
	ctx := context.Background()
	for _, table := range []string{"whatsmeow_sessions", "whatsmeow_identity_keys", "whatsmeow_sender_keys"} {
		columns, values := "our_jid, their_id, session", "$1, 'cold-' || i || ':0', decode('01','hex')"
		if table == "whatsmeow_identity_keys" {
			columns, values = "our_jid, their_id, identity", "$1, 'cold-' || i || ':0', decode(repeat('01',32),'hex')"
		} else if table == "whatsmeow_sender_keys" {
			columns, values = "our_jid, chat_id, sender_id, sender_key", "$1, 'prefix@g.us', 'cold-' || i || ':0', decode('010000002a','hex')"
		}
		if _, err := db.ExecContext(ctx, "INSERT INTO "+table+" ("+columns+") SELECT "+values+" FROM generate_series(1,12550) AS i", testJID); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, "VACUUM ANALYZE "+table); err != nil {
			t.Fatal(err)
		}
	}
	legacy := explainPrefix(t, db, "force_generic_plan", `SELECT true FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id LIKE $2 || '%' ESCAPE '\' LIMIT 1`, []any{testJID, "missing:"})
	if legacy.Removed != 12550 && (len(legacy.Plans) == 0 || legacy.Plans[0].Removed != 12550) {
		t.Fatalf("fixture did not reproduce account-wide scan: %+v", legacy)
	}
	calls := []struct {
		name string
		run  func() error
	}{
		{"exists", func() error { _, err := s.ExistsPNSession(ctx, "missing:"); return err }},
		{"sessions", func() error { return s.DeleteAllSessions(ctx, "missing") }},
		{"identities", func() error { return s.DeleteAllIdentities(ctx, "missing") }},
		{"devices", func() error { _, err := s.GetSenderKeyDevices(ctx, "prefix@g.us", "missing"); return err }},
	}
	for _, call := range calls {
		if err := call.run(); err != nil {
			t.Fatal(err)
		}
		trace.mu.Lock()
		query, args := trace.sql, slices.Clone(trace.args)
		trace.mu.Unlock()
		for _, mode := range []string{"force_custom_plan", "force_generic_plan"} {
			t.Run(call.name+"/"+mode, func(t *testing.T) {
				plan := explainPrefix(t, db, mode, query, args)
				if !plan.hasBounds() {
					t.Fatalf("missing byte-range index bounds: %+v", plan)
				}
				buffers := plan.Hits + plan.Reads
				if buffers*10 >= legacy.Hits+legacy.Reads {
					t.Fatalf("lookup still scans too many buffers: new=%d legacy=%d", buffers, legacy.Hits+legacy.Reads)
				}
				t.Logf("buffers: legacy=%d indexed=%d", legacy.Hits+legacy.Reads, buffers)
			})
		}
	}
}

func TestPrefixIndexUpgradeResumesInterruptedBuild(t *testing.T) {
	s, db, _ := newPrefixIndexStore(t)
	ctx := context.Background()
	if err := s.PutIdentity(ctx, "155500001:0", [32]byte{7}); err != nil {
		t.Fatal(err)
	}
	var originalOID int
	if err := db.QueryRowContext(ctx, `SELECT 'whatsmeow_sessions_prefix_idx'::regclass::oid`).Scan(&originalOID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `DROP INDEX whatsmeow_identity_keys_prefix_idx; UPDATE whatsmeow_version SET version=22`); err != nil {
		t.Fatal(err)
	}
	// A failed concurrent expression build deterministically leaves an invalid
	// index, reproducing the catalog state of an interrupted concurrent build.
	if _, err := db.ExecContext(ctx, `CREATE INDEX CONCURRENTLY whatsmeow_identity_keys_prefix_idx ON whatsmeow_identity_keys ((1 / (length(their_id) - length(their_id))))`); err == nil {
		t.Fatal("expected failing index build")
	}
	var valid bool
	if err := db.QueryRowContext(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid='whatsmeow_identity_keys_prefix_idx'::regclass`).Scan(&valid); err != nil || valid {
		t.Fatalf("invalid-index fixture: valid=%t err=%v", valid, err)
	}
	for range 2 {
		if err := s.Container.Upgrade(ctx); err != nil {
			t.Fatal(err)
		}
	}
	var count, currentOID, version int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_index WHERE indisvalid AND indexrelid IN ('whatsmeow_sessions_prefix_idx'::regclass,'whatsmeow_identity_keys_prefix_idx'::regclass)`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("valid indexes=%d err=%v", count, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT 'whatsmeow_sessions_prefix_idx'::regclass::oid`).Scan(&currentOID); err != nil || currentOID != originalOID {
		t.Fatalf("completed index rebuilt: before=%d after=%d err=%v", originalOID, currentOID, err)
	}
	if err := db.QueryRowContext(ctx, `SELECT version FROM whatsmeow_version`).Scan(&version); err != nil || version != 23 {
		t.Fatalf("version=%d err=%v", version, err)
	}
	var stored []byte
	if err := db.QueryRowContext(ctx, `SELECT identity FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id='155500001:0'`, testJID).Scan(&stored); err != nil || len(stored) != 32 || stored[0] != 7 {
		t.Fatalf("identity changed: %x err=%v", stored, err)
	}
}
