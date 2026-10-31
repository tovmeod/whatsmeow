package upgrades

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"go.mau.fi/util/dbutil"
)

// Existing installations build concurrently so persistence can continue. A failed
// concurrent build can leave an invalid index: repair it before advancing v23,
// while retaining a valid index from an earlier, partially completed attempt.
func upgradeSignalPrefixIndexes(ctx context.Context, db *dbutil.Database) error {
	if db.Dialect != dbutil.Postgres {
		return nil
	}
	for _, table := range []string{"whatsmeow_sessions", "whatsmeow_identity_keys"} {
		name := table + "_prefix_idx"
		var valid bool
		err := db.QueryRow(ctx, `SELECT indisvalid FROM pg_index WHERE indexrelid=to_regclass($1)`, name).Scan(&valid)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("inspect %s: %w", name, err)
		}
		if err == nil {
			if valid {
				continue
			}
			if _, err = db.Exec(ctx, "DROP INDEX CONCURRENTLY "+name); err != nil {
				return fmt.Errorf("remove interrupted %s: %w", name, err)
			}
		}
		if _, err = db.Exec(ctx, "CREATE INDEX CONCURRENTLY "+name+" ON "+table+" (our_jid, their_id text_pattern_ops)"); err != nil {
			return fmt.Errorf("build %s: %w", name, err)
		}
	}
	return nil
}
