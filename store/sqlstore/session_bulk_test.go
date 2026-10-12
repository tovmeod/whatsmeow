package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"testing"

	"go.mau.fi/util/dbutil"
)

type bulkSessionTx struct{ committed, rolledBack bool }

func (tx *bulkSessionTx) Commit() error   { tx.committed = true; return nil }
func (tx *bulkSessionTx) Rollback() error { tx.rolledBack = true; return nil }

// Accept the same native array arguments as pgx without opening a connection.
type bulkSessionConnector struct{ senderKeyCommitConnector }
type bulkSessionConn struct{ *senderKeyCommitConn }

func (c *bulkSessionConnector) Connect(context.Context) (driver.Conn, error) {
	return &bulkSessionConn{&senderKeyCommitConn{&c.senderKeyCommitConnector}}, nil
}
func (*bulkSessionConn) CheckNamedValue(v *driver.NamedValue) error {
	switch v.Value.(type) {
	case []string, [][]byte:
		return nil
	default:
		return driver.ErrSkip
	}
}

func TestOverloadSessionBatchUsesBulkStatementsAndOneTransaction(t *testing.T) {
	for _, dialect := range []string{"postgres", "sqlite3"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%v", dialect, fail), func(t *testing.T) {
				tx := &bulkSessionTx{}
				calls, rows := 0, 0
				db := sql.OpenDB(&bulkSessionConnector{senderKeyCommitConnector{tx: tx, exec: func(args []driver.NamedValue) error {
					calls++
					if addresses, ok := args[1].Value.([]string); ok {
						blobs := args[2].Value.([][]byte)
						if len(addresses) != len(blobs) || len(addresses) > sessionBatchRows {
							t.Fatal("array lengths differ or exceed row bound")
						}
						rows += len(addresses)
					} else {
						rows += len(args) / 3
					}
					if len(args) > 750 {
						t.Errorf("unbounded SQL parameters: %d", len(args))
					}
					if fail && calls == 2 {
						return errors.New("second chunk failure")
					}
					return nil
				}}})
				defer db.Close()
				wrapped, err := dbutil.NewWithDB(db, dialect)
				if err != nil {
					t.Fatal(err)
				}
				s := &SQLStore{Container: &Container{db: wrapped}, JID: "test-device"}
				sessions := make(map[string][]byte)
				for i := 0; i < 251; i++ {
					sessions[fmt.Sprintf("sender-%03d:0", i)] = []byte("session")
				}
				err = s.PutManySessions(context.Background(), sessions)
				if (err != nil) != fail {
					t.Fatalf("error=%v, fail=%v", err, fail)
				}
				if calls != 2 || rows != 251 {
					t.Fatalf("statements=%d rows=%d, want 2 statements for 251 rows", calls, rows)
				}
				if tx.committed == fail || tx.rolledBack != fail {
					t.Fatalf("commit=%v rollback=%v", tx.committed, tx.rolledBack)
				}
			})
		}
	}
}
