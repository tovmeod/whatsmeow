package sqlstore_test

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"go.mau.fi/whatsmeow/store/sqlstore"
	"go.mau.fi/whatsmeow/types"
)

// Upstream's upgrades 15 and 16 collide with the fork's existing migrations.
// Both fresh installs and existing fork databases must acquire the new columns
// while retaining the flat sender-key bytes, generated key ID and prefix index.
func TestUpstreamUpgradePreservesForkSchema(t *testing.T) {
	for _, existing := range []bool{false, true} {
		name := "fresh"
		if existing {
			name = "fork_v20"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			admin, err := sql.Open("pgx", batchTestDSN())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = admin.Close() })
			if err = admin.PingContext(ctx); err != nil {
				t.Skipf("test Postgres unavailable: %v", err)
			}
			scratch := "upstream_sync_" + strings.ReplaceAll(uuid.NewString(), "-", "")
			if _, err = admin.ExecContext(ctx, "CREATE DATABASE "+scratch); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if _, err := admin.ExecContext(context.Background(), "DROP DATABASE "+scratch+" WITH (FORCE)"); err != nil {
					t.Errorf("remove owned scratch database: %v", err)
				}
			})
			db, err := sql.Open("pgx", swapDBName(batchTestDSN(), scratch))
			if err != nil {
				t.Fatal(err)
			}
			container := sqlstore.NewWithDB(db, "postgres", nil)
			t.Cleanup(func() { _ = container.Close() })
			if existing {
				schema, err := os.ReadFile("testdata/fork-v20.sql")
				if err != nil {
					t.Fatal(err)
				}
				if _, err = db.ExecContext(ctx, string(schema)); err != nil {
					t.Fatal(err)
				}
				if _, err = db.ExecContext(ctx, `CREATE TABLE whatsmeow_version (version INTEGER, compat INTEGER);
					INSERT INTO whatsmeow_version VALUES (20, 8)`); err != nil {
					t.Fatal(err)
				}
			}
			jid := types.NewJID("17700000001", types.DefaultUserServer)
			blob := []byte{1, 0, 0, 0, 42, 7, 8, 9}
			seed := func() {
				key, sig := make([]byte, 32), make([]byte, 64)
				if _, err := db.ExecContext(ctx, insertTestDeviceQuery, jid.String(), 1, key, key,
					key, 1, sig, key, key, sig, key, sig); err != nil {
					t.Fatal(err)
				}
				if _, err := db.ExecContext(ctx, `INSERT INTO whatsmeow_sender_keys
					(our_jid, chat_id, sender_id, sender_key) VALUES ($1, 'sync@g.us', '123_1:0', $2)`, jid.String(), blob); err != nil {
					t.Fatal(err)
				}
			}
			if existing {
				seed()
			}
			if err := container.Upgrade(ctx); err != nil {
				t.Fatal(err)
			}
			if !existing {
				seed()
			}
			if err := container.Upgrade(ctx); err != nil {
				t.Fatalf("repeated upgrade: %v", err)
			}
			var version, keyID int
			var stored []byte
			if err := db.QueryRowContext(ctx, "SELECT version FROM whatsmeow_version").Scan(&version); err != nil || version != 22 {
				t.Fatalf("version=%d, want 22: %v", version, err)
			}
			if err := db.QueryRowContext(ctx, `SELECT sender_key, sk_keyid0 FROM whatsmeow_sender_keys`).Scan(&stored, &keyID); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(stored, blob) || keyID != 42 {
				t.Fatalf("sender key changed: bytes=%x keyID=%d", stored, keyID)
			}
			var indexDef string
			if err := db.QueryRowContext(ctx, `SELECT indexdef FROM pg_indexes
				WHERE indexname='whatsmeow_sender_keys_pkey'`).Scan(&indexDef); err != nil || !strings.Contains(indexDef, "text_pattern_ops") {
				t.Fatalf("fork prefix index missing: %s (%v)", indexDef, err)
			}
			device, err := container.GetDevice(ctx, jid)
			if err != nil {
				t.Fatal(err)
			}
			device.CompanionMetaNonce = "sync-nonce"
			if err := device.Save(ctx); err != nil {
				t.Fatal(err)
			}
			device, err = container.GetDevice(ctx, jid)
			if err != nil || device.CompanionMetaNonce != "sync-nonce" {
				t.Fatalf("companion nonce round trip failed: %v", err)
			}
			if err := device.ChatSettings.PutWASARootSecretID(ctx, types.MuseJID, "root-secret"); err != nil {
				t.Fatal(err)
			}
			id, err := device.ChatSettings.GetWASARootSecretID(ctx, types.MuseJID)
			if err != nil || id != "root-secret" {
				t.Fatalf("WASA root secret round trip: %q (%v)", id, err)
			}
		})
	}
}
