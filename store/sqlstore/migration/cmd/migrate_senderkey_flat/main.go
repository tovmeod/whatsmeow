// Copyright (c) 2026 Kavtov Platform (Phase 17.11 plan 04)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// migrate_senderkey_flat converts all whatsmeow_sender_keys rows from the
// current fmt_ver=NULL/1 (JSON blob) and fmt_ver=2 (columnar) formats to the
// flat binary format (store.PackFlat). Rows are written into a parallel table
// whatsmeow_sender_keys_new; the manual rename step is described below.
//
// # Mandatory dry-run before any production write
//
//	./migrate_senderkey_flat -dsn "$DSN" -verify-only [-sample 10000]
//
// Run -verify-only against a representative data set (both fmt_ver=1 and
// fmt_ver=2 rows) and confirm the final log line shows 0 failures before
// scheduling a maintenance window.
//
// # Normal mode (write)
//
//	./migrate_senderkey_flat -dsn "$DSN" [-batch 2000]
//
// Creates whatsmeow_sender_keys_new if absent; INSERTs all converted rows;
// creates the unique index on completion. Run with the driver stopped.
//
// # Post-migration rename (manual DBA step — plan 06)
//
//	ALTER TABLE whatsmeow_sender_keys RENAME TO whatsmeow_sender_keys_old;
//	ALTER TABLE whatsmeow_sender_keys_new RENAME TO whatsmeow_sender_keys;
//
// Do NOT rename while the driver is running. Drop the old table after a
// hold period once the new format is verified in production.
//
// # Timing estimate (RESEARCH R3 — dry-run required before committing a window)
//
// First-principles: 8.8M rows × ~5-10 µs/row decode + encode ≈ 44-88 s CPU;
// batched reads ~22 s; writes faster. Conservative estimate: 3-5 minutes total
// for conversion + index creation. A dry-run on a local prod copy is mandatory
// before scheduling a production maintenance window.
//
// # Source-of-truth mandate for fmt_ver=2 rows (CRITICAL)
//
// For fmt_ver=2 rows the sender_key blob was frozen at Phase 17.9 time and MUST
// NOT be used as the decode source. The live source of truth is the columnar
// fields (st_*, smk_*) advanced by Phase 17.7's write-back path. This tool uses
// sqlstore.ExportRecompose (not Deserialize(blob)) for fmt_ver=2 rows — matching
// the pattern in findSenderKeyDonor. The reflect.DeepEqual gate does NOT catch
// choosing the wrong source; the gate verifies codec fidelity of whichever source
// you chose.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
)

const (
	// newTableDDL creates the flat-schema destination table without any unique
	// constraint. The uniqueness enforcement is added by newTableIndexDDL
	// (a CREATE UNIQUE INDEX with text_pattern_ops on sender_id, matching
	// migration 18's replacement of the original PK). PostgreSQL does not accept
	// operator-class names inside a table-level UNIQUE or PRIMARY KEY constraint
	// — opclasses are index-level only. The index is created BEFORE the insert
	// loop so that ON CONFLICT (our_jid, chat_id, sender_id) has an arbiter to
	// infer against (verified: text_pattern_ops supports column-inference for
	// ON CONFLICT, per migration 18 comment "ON CONFLICT ... still resolves it").
	newTableDDL = `
CREATE TABLE IF NOT EXISTS whatsmeow_sender_keys_new (
    our_jid   TEXT NOT NULL,
    chat_id   TEXT NOT NULL,
    sender_id TEXT NOT NULL,
    sender_key BYTEA NOT NULL
)`

	// newTableIndexDDL creates the TPO-class unique index (mirrors the mechanism
	// of migration 18 which replaced the default-collation PK with a
	// text_pattern_ops unique index on the existing table). This must be created
	// BEFORE the insert loop so ON CONFLICT can infer its arbiter.
	newTableIndexDDL = `
CREATE UNIQUE INDEX IF NOT EXISTS whatsmeow_sender_keys_new_pkey
    ON whatsmeow_sender_keys_new (our_jid, chat_id, sender_id text_pattern_ops)`

	// readBatchQuery reads one page of rows ordered deterministically.
	// Selects all columnar fields + the legacy blob so the decode branch
	// (fmt_ver=2 → recompose; NULL/1 → Deserialize) can choose the right source.
	readBatchQuery = `
SELECT
    our_jid, chat_id, sender_id, fmt_ver,
    st_key_id, st_chain_key_iteration, st_chain_key,
    st_signing_key_public, st_signing_key_private,
    smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed,
    sender_key
FROM whatsmeow_sender_keys
ORDER BY our_jid, chat_id, sender_id
LIMIT $1 OFFSET $2`

	// insertQuery writes one converted row to the new table. The arbiter index
	// (whatsmeow_sender_keys_new_pkey) is created before the loop, so
	// ON CONFLICT can resolve the unique violation from a resume/re-run.
	insertQuery = `
INSERT INTO whatsmeow_sender_keys_new (our_jid, chat_id, sender_id, sender_key)
VALUES ($1, $2, $3, $4)
ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET sender_key = excluded.sender_key`
)

func main() {
	// Structured JSON logging — mirror cmd/driver/main.go pattern.
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelInfo,
		AddSource: true,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if a.Key == slog.SourceKey {
				if src, ok := a.Value.Any().(*slog.Source); ok {
					file := src.File
					if idx := strings.LastIndex(file, "/"); idx >= 0 {
						file = file[idx+1:]
					}
					return slog.String("source", fmt.Sprintf("%s:%d", file, src.Line))
				}
			}
			return a
		},
	}))
	slog.SetDefault(logger)

	dsn := flag.String("dsn", "", "PostgreSQL DSN (required)")
	verifyOnly := flag.Bool("verify-only", false, "decode+encode+DeepEqual without writing to DB")
	sampleN := flag.Int("sample", 0, "convert/verify only the first N rows (0 = all rows)")
	batchSize := flag.Int("batch", 2000, "rows per SELECT batch")
	flag.Parse()

	if *dsn == "" {
		slog.Error("missing required flag: -dsn")
		os.Exit(1)
	}
	if *batchSize <= 0 {
		slog.Error("invalid -batch value", "batch", *batchSize)
		os.Exit(1)
	}

	// Log startup — do NOT log the DSN value (contains credentials).
	slog.Info("migrate_senderkey_flat starting",
		"verify_only", *verifyOnly,
		"sample", *sampleN,
		"batch", *batchSize,
	)

	ctx := context.Background()

	// Single connection (no pool) — limits DB connection pressure (T-1711-16).
	conn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		slog.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer conn.Close(ctx)

	if !*verifyOnly {
		if err := setupNewTable(ctx, conn); err != nil {
			slog.Error("failed to create destination table", "error", err)
			os.Exit(1)
		}
	}

	start := time.Now()
	var (
		totalRows    int64
		convertedRows int64
		skippedRows  int64
		failedRows   int64
	)

	offset := 0
	limit := *batchSize

	for {
		batchLimit := limit
		if *sampleN > 0 {
			remaining := *sampleN - int(totalRows)
			if remaining <= 0 {
				break
			}
			if remaining < batchLimit {
				batchLimit = remaining
			}
		}

		rows, err := conn.Query(ctx, readBatchQuery, batchLimit, offset)
		if err != nil {
			slog.Error("batch read failed", "offset", offset, "error", err)
			os.Exit(1)
		}

		// pendingInsert holds a (our_jid, chat_id, sender_id, packed) tuple
		// after the DeepEqual gate passes. Inserts are accumulated while the
		// rows cursor is open, then flushed after rows.Close() — pgx does not
		// allow Exec on the same single connection while rows are being scanned
		// ("conn busy").
		type pendingInsert struct {
			ourJID, chatID, senderID string
			packed                   []byte
		}
		var pending []pendingInsert

		batchCount := 0
		for rows.Next() {
			batchCount++
			totalRows++

			var (
				ourJID   string
				chatID   string
				senderID string
				fmtVer   pgtype.Int2 // nullable int2
				// Per-state columnar fields (pgx scans PG arrays into []T natively)
				stKeyID             []int64
				stChainKeyIteration []int64
				stChainKey          [][]byte
				stSigningKeyPublic  [][]byte
				stSigningKeyPrivate []*[]byte // nullable elements: nil pointer = NULL
				// Skipped message key fields
				smkStateIdx  []int32
				smkIteration []int64
				smkIV        [][]byte
				smkCipherKey [][]byte
				smkSeed      [][]byte
				// Legacy blob (NULL on fmt_ver=2; frozen since Phase 17.9)
				blob []byte
			)

			if err := rows.Scan(
				&ourJID, &chatID, &senderID, &fmtVer,
				&stKeyID, &stChainKeyIteration, &stChainKey,
				&stSigningKeyPublic, &stSigningKeyPrivate,
				&smkStateIdx, &smkIteration, &smkIV, &smkCipherKey, &smkSeed,
				&blob,
			); err != nil {
				slog.Error("row scan failed",
					"offset", offset, "row_in_batch", batchCount,
					"error", err)
				os.Exit(1)
			}

			var structure *groupRecord.SenderKeyStructure

			if fmtVer.Valid && fmtVer.Int16 == 2 {
				// fmt_ver=2: recompose from live columns — NOT the frozen blob.
				// Matches findSenderKeyDonor's decode branch exactly.
				//
				// pgx scans BYTEA[] nullable elements as *[]byte (pointer to nil
				// when the column element is SQL NULL). Flatten to [][]byte
				// preserving nil for NULL (= nil SigningKeyPrivate = received key).
				flatPriv := flattenNullableBytea(stSigningKeyPrivate)
				cols := &sqlstore.ExportedSenderKeyColumns{
					StKeyID:             stKeyID,
					StChainKeyIteration: stChainKeyIteration,
					StChainKey:          stChainKey,
					StSigningKeyPublic:  stSigningKeyPublic,
					StSigningKeyPrivate: flatPriv,
					SmkStateIdx:         smkStateIdx,
					SmkIteration:        smkIteration,
					SmkIV:               smkIV,
					SmkCipherKey:        smkCipherKey,
					SmkSeed:             smkSeed,
				}
				structure = sqlstore.ExportRecompose(cols)
			} else {
				// fmt_ver=NULL or fmt_ver=1: decode from the legacy JSON blob.
				if blob == nil {
					// Absent/NULL blob on a legacy row — skip (cannot decode).
					slog.Error("skipping row: NULL blob on fmt_ver=NULL/1 row",
						"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID)
					skippedRows++
					continue
				}
				var dErr error
				structure, dErr = store.SignalProtobufSerializer.SenderKeyRecord.Deserialize(blob)
				if dErr != nil {
					slog.Error("skipping row: Deserialize failed",
						"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID,
						"error", dErr)
					skippedRows++
					continue
				}
			}

			if structure == nil {
				slog.Error("skipping row: nil structure after decode",
					"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID)
				skippedRows++
				continue
			}

			// Encode to flat binary.
			packed, ok := store.PackFlat(structure)
			if !ok {
				// PackFlat returns false for field-length violations or > 255 states.
				// In write mode this would cause a silent gap in the new table — abort.
				slog.Error("migration aborted: PackFlat failed (field-length violation or > 255 states)",
					"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID)
				os.Exit(1)
			}

			// BLOCKING DeepEqual gate (T-1711-12, T-1711-13).
			// Unpack and verify codec round-trip fidelity. This gate does NOT
			// verify that the correct source was chosen (columns vs blob) — it
			// only verifies codec correctness. Choosing the wrong source for
			// fmt_ver=2 rows silently installs stale keys. The decode branch
			// above is the source-of-truth mandate enforcement.
			//
			// Before comparing, normalize both sides for libsignal's nil-vs-empty
			// distinction: Deserialize() for fmt_ver=1 blobs allocates empty
			// (non-nil) Keys slices and all-zero (non-nil) SigningKeyPrivate
			// slices. UnpackFlat() leaves Keys as nil when there are no skipped
			// message keys, and stores nil SigningKeyPrivate for hasPriv=0. These
			// are semantically equivalent; reflect.DeepEqual distinguishes them.
			// normalizeSenderKeyStructure canonicalizes both to nil so the gate
			// tests crypto-material equality, not Go memory representation.
			unpacked, uErr := store.UnpackFlat(packed)
			if uErr != nil {
				slog.Error("migration aborted: UnpackFlat failed after PackFlat",
					"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID,
					"error", uErr)
				os.Exit(1)
			}
			normSource := normalizeSenderKeyStructure(structure)
			normUnpacked := normalizeSenderKeyStructure(unpacked)
			if !reflect.DeepEqual(normSource, normUnpacked) {
				slog.Error("migration aborted: DeepEqual gate failed — pack/unpack round-trip mismatch",
					"our_jid", ourJID, "chat_id", chatID, "sender_id", senderID)
				failedRows++
				os.Exit(1) // zero tolerance — abort on first failure
			}

			convertedRows++

			if !*verifyOnly {
				pending = append(pending, pendingInsert{ourJID, chatID, senderID, packed})
			}
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			slog.Error("rows error after batch", "offset", offset, "error", err)
			os.Exit(1)
		}

		// Flush pending inserts now that the rows cursor is closed.
		// pgx requires the connection to be idle (not scanning) before Exec.
		for _, ins := range pending {
			if _, err := conn.Exec(ctx, insertQuery, ins.ourJID, ins.chatID, ins.senderID, ins.packed); err != nil {
				slog.Error("insert failed",
					"our_jid", ins.ourJID, "chat_id", ins.chatID, "sender_id", ins.senderID,
					"error", err)
				os.Exit(1)
			}
		}
		pending = pending[:0]

		offset += batchCount
		if batchCount < batchLimit {
			// Returned fewer rows than requested — end of table.
			break
		}
	}

	if !*verifyOnly {
		if err := createIndex(ctx, conn); err != nil {
			slog.Error("failed to create index on new table", "error", err)
			os.Exit(1)
		}
	}

	elapsed := time.Since(start)
	slog.Info("migrate_senderkey_flat complete",
		"verify_only", *verifyOnly,
		"total_rows", totalRows,
		"converted_rows", convertedRows,
		"skipped_rows", skippedRows,
		"failed_rows", failedRows,
		"elapsed", elapsed.String(),
	)

	if skippedRows > 0 {
		slog.Warn("migration completed with skipped rows — review ERROR logs above",
			"skipped_rows", skippedRows)
	}
}

// setupNewTable creates whatsmeow_sender_keys_new and the TPO unique index if
// they do not already exist. The index is created BEFORE the insert loop so
// that ON CONFLICT (our_jid, chat_id, sender_id) has an arbiter to infer
// against (PostgreSQL requires the arbiter to exist at INSERT time). Creating
// the index on an empty table is instant. A re-run on a partially-migrated
// table also benefits: the index already exists (IF NOT EXISTS no-ops),
// inserts conflict-update rather than insert-duplicate.
func setupNewTable(ctx context.Context, conn *pgx.Conn) error {
	if _, err := conn.Exec(ctx, newTableDDL); err != nil {
		return fmt.Errorf("CREATE TABLE IF NOT EXISTS whatsmeow_sender_keys_new: %w", err)
	}
	slog.Info("destination table created or already exists", "table", "whatsmeow_sender_keys_new")

	// Index creation BEFORE inserts — required for ON CONFLICT arbiter.
	slog.Info("creating unique index on whatsmeow_sender_keys_new (before insert loop)")
	indexStart := time.Now()
	if _, err := conn.Exec(ctx, newTableIndexDDL); err != nil {
		return fmt.Errorf("CREATE UNIQUE INDEX IF NOT EXISTS whatsmeow_sender_keys_new_pkey: %w", err)
	}
	slog.Info("index ready", "elapsed", time.Since(indexStart).String())
	return nil
}

// createIndex is intentionally empty after moving index creation to setupNewTable.
// It is kept to avoid restructuring the main loop; it logs a no-op reminder.
func createIndex(_ context.Context, _ *pgx.Conn) error {
	// Index was already created in setupNewTable before the insert loop.
	// This function exists only to keep the main-loop structure symmetric with
	// the verify-only path. No work needed.
	slog.Info("post-loop index step: index was already created before the insert loop (no-op)")
	return nil
}

// normalizeSenderKeyStructure canonicalizes the nil-vs-empty-slice distinction
// in a *SenderKeyStructure so that reflect.DeepEqual compares crypto-material
// equality, not Go memory representation.
//
// libsignal's Deserialize (used for fmt_ver=NULL/1 blobs) may produce:
//   - Keys == []*SenderMessageKeyStructure{} (non-nil empty slice) when there
//     are no skipped message keys. UnpackFlat() leaves Keys == nil.
//   - SigningKeyPrivate == []byte{0, 0, ..., 0} (32 zero bytes, non-nil) for
//     received (non-own) keys. UnpackFlat() restores nil (hasPriv=0 → nil).
//
// Both are semantically equivalent. This function normalizes both to nil so
// the DeepEqual gate tests key material only. It operates on a shallow copy of
// the structure — do NOT reuse the normalized value as a production key.
func normalizeSenderKeyStructure(s *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
	if s == nil {
		return nil
	}
	states := make([]*groupRecord.SenderKeyStateStructure, len(s.SenderKeyStates))
	for i, st := range s.SenderKeyStates {
		norm := &groupRecord.SenderKeyStateStructure{
			KeyID:           st.KeyID,
			SenderChainKey:  st.SenderChainKey,
			SigningKeyPublic: st.SigningKeyPublic,
		}
		// Normalize SigningKeyPrivate: nil and all-zero are equivalent
		// (libsignal encodes nil → all-zero bytes in the protobuf blob).
		priv := st.SigningKeyPrivate
		if len(priv) == 0 {
			priv = nil
		} else {
			allZero := true
			for _, b := range priv {
				if b != 0 {
					allZero = false
					break
				}
			}
			if allZero {
				priv = nil
			}
		}
		norm.SigningKeyPrivate = priv
		// Normalize Keys: nil and empty slice are equivalent
		// (Deserialize may allocate empty non-nil; UnpackFlat leaves nil).
		if len(st.Keys) == 0 {
			norm.Keys = nil
		} else {
			norm.Keys = st.Keys
		}
		states[i] = norm
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// flattenNullableBytea converts pgx's nullable BYTEA[] representation
// ([]*[]byte where nil pointer = SQL NULL) to a plain [][]byte where
// nil element = nil SigningKeyPrivate (received key, no private portion).
//
// This preserves the critical nil-vs-empty distinction:
//   - nil pointer → nil []byte  (SQL NULL element → nil SigningKeyPrivate)
//   - non-nil *[]byte → *[]byte (SQL non-NULL element → key material bytes)
//
// A nil SigningKeyPrivate in the reconstructed structure indicates a received
// (not own) sender-key — decompose preserves this and PackFlat writes
// hasPriv=0. An empty []byte would make PackFlat return false (len≠32).
func flattenNullableBytea(src []*[]byte) [][]byte {
	if src == nil {
		return nil
	}
	out := make([][]byte, len(src))
	for i, p := range src {
		if p != nil {
			out[i] = *p
		}
		// p == nil → out[i] stays nil (SQL NULL → nil SigningKeyPrivate)
	}
	return out
}
