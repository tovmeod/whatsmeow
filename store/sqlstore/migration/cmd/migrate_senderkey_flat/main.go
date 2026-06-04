// Copyright (c) 2026 Kavtov Platform (Phase 17.11 plan 04)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.
//
// migrate_senderkey_flat converts all whatsmeow_sender_keys rows from
// fmt_ver=NULL/1 (JSON blob) and fmt_ver=2 (columnar) to flat binary
// (store.PackFlat), written into whatsmeow_sender_keys_new.
//
// PERFORMANCE DESIGN (rewritten 2026-06-04):
//   - ONE streaming read of the source, ordered, NO OFFSET (OFFSET is O(n^2)).
//   - Fan out raw rows to N parallel conversion workers (decode+pack+DeepEqual
//     is CPU-bound; parallelize across cores).
//   - Each worker bulk-loads via COPY (pgx CopyFrom) into an UNINDEXED table.
//   - Build the unique index ONCE at the end (Postgres parallelizes the build).
// This replaces the original index-first, row-by-row, OFFSET-paginated loader.
//
//	./migrate_senderkey_flat -dsn "$DSN" -verify-only [-sample N]   # dry run
//	./migrate_senderkey_flat -dsn "$DSN" [-workers N] [-copy-batch N] # write
//
// Post-migration rename (manual DBA step — plan 06):
//	ALTER TABLE whatsmeow_sender_keys RENAME TO whatsmeow_sender_keys_old;
//	ALTER TABLE whatsmeow_sender_keys_new RENAME TO whatsmeow_sender_keys;
//
// Source-of-truth: fmt_ver=2 rows decode from the live columnar fields via
// sqlstore.ExportRecompose (NOT the frozen blob); NULL/1 from the JSON blob.
// The reflect.DeepEqual gate verifies codec fidelity of whichever source is
// chosen — it does not catch choosing the wrong source.

package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/store/sqlstore"
)

const (
	newTableDDL = `
CREATE TABLE IF NOT EXISTS whatsmeow_sender_keys_new (
    our_jid    TEXT  NOT NULL,
    chat_id    TEXT  NOT NULL,
    sender_id  TEXT  NOT NULL,
    sender_key BYTEA NOT NULL
)`

	// Unique index built ONCE after the bulk load (mirrors migration 18's
	// text_pattern_ops opclass). NOT created before the load.
	newTableIndexDDL = `
CREATE UNIQUE INDEX IF NOT EXISTS whatsmeow_sender_keys_new_pkey
    ON whatsmeow_sender_keys_new (our_jid, chat_id, sender_id text_pattern_ops)`

	// Single streaming read — NO OFFSET. One ordered server-side scan; pgx
	// delivers rows incrementally as the worker pool consumes them.
	streamQuery = `
SELECT
    our_jid, chat_id, sender_id, fmt_ver,
    st_key_id, st_chain_key_iteration, st_chain_key,
    st_signing_key_public, st_signing_key_private,
    smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed,
    sender_key
FROM whatsmeow_sender_keys
ORDER BY our_jid, chat_id, sender_id`
)

// rawRow is a row scanned from the source, undecoded. The CPU-heavy decode is
// done in the workers, not the reader.
type rawRow struct {
	ourJID, chatID, senderID string
	fmtVer                   pgtype.Int2
	stKeyID                  []int64
	stChainKeyIteration      []int64
	stChainKey               [][]byte
	stSigningKeyPublic       [][]byte
	stSigningKeyPrivate      []*[]byte
	smkStateIdx              []int32
	smkIteration             []int64
	smkIV                    [][]byte
	smkCipherKey             [][]byte
	smkSeed                  [][]byte
	blob                     []byte
}

func main() {
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
	workers := flag.Int("workers", runtime.NumCPU(), "parallel conversion/COPY workers")
	copyBatch := flag.Int("copy-batch", 5000, "rows per COPY flush per worker")
	flag.Parse()

	if *dsn == "" {
		slog.Error("missing required flag: -dsn")
		os.Exit(1)
	}
	if *workers <= 0 {
		*workers = 1
	}
	if *copyBatch <= 0 {
		*copyBatch = 5000
	}

	slog.Info("migrate_senderkey_flat starting",
		"verify_only", *verifyOnly, "sample", *sampleN,
		"workers", *workers, "copy_batch", *copyBatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Reader/admin connection (stream source + DDL + index build).
	readerConn, err := pgx.Connect(ctx, *dsn)
	if err != nil {
		slog.Error("failed to connect (reader)", "error", err)
		os.Exit(1)
	}
	defer readerConn.Close(context.Background())

	if !*verifyOnly {
		if _, err := readerConn.Exec(ctx, newTableDDL); err != nil {
			slog.Error("CREATE TABLE whatsmeow_sender_keys_new failed", "error", err)
			os.Exit(1)
		}
		slog.Info("destination table ready (unindexed)", "table", "whatsmeow_sender_keys_new")
	}

	var (
		totalRows     atomic.Int64
		convertedRows atomic.Int64
		skippedRows   atomic.Int64
		firstErr      error
		errOnce       sync.Once
	)
	fail := func(e error) {
		errOnce.Do(func() { firstErr = e; cancel() })
	}

	start := time.Now()
	rowCh := make(chan rawRow, *workers*256)

	// Workers: decode + pack + DeepEqual (+ COPY in write mode).
	var wg sync.WaitGroup
	for w := 0; w < *workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			var conn *pgx.Conn
			if !*verifyOnly {
				c, cErr := pgx.Connect(ctx, *dsn)
				if cErr != nil {
					fail(fmt.Errorf("worker %d connect: %w", id, cErr))
					return
				}
				defer c.Close(context.Background())
				conn = c
			}
			buf := make([][]any, 0, *copyBatch)
			flush := func() bool {
				if len(buf) == 0 {
					return true
				}
				_, cpErr := conn.CopyFrom(ctx,
					pgx.Identifier{"whatsmeow_sender_keys_new"},
					[]string{"our_jid", "chat_id", "sender_id", "sender_key"},
					pgx.CopyFromRows(buf))
				if cpErr != nil {
					fail(fmt.Errorf("worker %d COPY: %w", id, cpErr))
					return false
				}
				buf = buf[:0]
				return true
			}
			for r := range rowCh {
				totalRows.Add(1)
				structure, skip, cErr := decodeRow(r)
				if cErr != nil {
					fail(cErr)
					return
				}
				if skip {
					skippedRows.Add(1)
					continue
				}
				packed, ok := store.PackFlat(structure)
				if !ok {
					fail(fmt.Errorf("PackFlat failed (field-length or >255 states): %s/%s/%s", r.ourJID, r.chatID, r.senderID))
					return
				}
				unpacked, uErr := store.UnpackFlat(packed)
				if uErr != nil {
					fail(fmt.Errorf("UnpackFlat after PackFlat: %s/%s/%s: %w", r.ourJID, r.chatID, r.senderID, uErr))
					return
				}
				if !reflect.DeepEqual(normalizeSenderKeyStructure(structure), normalizeSenderKeyStructure(unpacked)) {
					fail(fmt.Errorf("DeepEqual gate failed — round-trip mismatch: %s/%s/%s", r.ourJID, r.chatID, r.senderID))
					return
				}
				convertedRows.Add(1)
				if !*verifyOnly {
					buf = append(buf, []any{r.ourJID, r.chatID, r.senderID, packed})
					if len(buf) >= *copyBatch {
						if !flush() {
							return
						}
					}
				}
			}
			if !*verifyOnly {
				flush()
			}
		}(w)
	}

	// Reader: single streaming scan, fan out to workers.
	go func() {
		defer close(rowCh)
		rows, qErr := readerConn.Query(ctx, streamQuery)
		if qErr != nil {
			fail(fmt.Errorf("stream query: %w", qErr))
			return
		}
		defer rows.Close()
		var sent int
		for rows.Next() {
			if *sampleN > 0 && sent >= *sampleN {
				break
			}
			var r rawRow
			if sErr := rows.Scan(
				&r.ourJID, &r.chatID, &r.senderID, &r.fmtVer,
				&r.stKeyID, &r.stChainKeyIteration, &r.stChainKey,
				&r.stSigningKeyPublic, &r.stSigningKeyPrivate,
				&r.smkStateIdx, &r.smkIteration, &r.smkIV, &r.smkCipherKey, &r.smkSeed,
				&r.blob,
			); sErr != nil {
				fail(fmt.Errorf("row scan: %w", sErr))
				return
			}
			select {
			case rowCh <- r:
				sent++
			case <-ctx.Done():
				return
			}
		}
		if rErr := rows.Err(); rErr != nil {
			fail(fmt.Errorf("stream rows error: %w", rErr))
		}
	}()

	wg.Wait()

	if firstErr != nil {
		slog.Error("migration aborted", "error", firstErr.Error(),
			"total_rows", totalRows.Load(), "converted_rows", convertedRows.Load())
		os.Exit(1)
	}

	if !*verifyOnly {
		slog.Info("bulk load complete, building unique index (parallel)", "rows", convertedRows.Load())
		idxStart := time.Now()
		// Speed the index build: more memory + parallel workers for this session.
		_, _ = readerConn.Exec(ctx, "SET maintenance_work_mem = '1GB'")
		_, _ = readerConn.Exec(ctx, "SET max_parallel_maintenance_workers = 7")
		if _, err := readerConn.Exec(ctx, newTableIndexDDL); err != nil {
			slog.Error("CREATE UNIQUE INDEX failed", "error", err)
			os.Exit(1)
		}
		slog.Info("index built", "elapsed", time.Since(idxStart).String())
	}

	slog.Info("migrate_senderkey_flat complete",
		"verify_only", *verifyOnly,
		"total_rows", totalRows.Load(),
		"converted_rows", convertedRows.Load(),
		"skipped_rows", skippedRows.Load(),
		"elapsed", time.Since(start).String())

	if skippedRows.Load() > 0 {
		slog.Warn("completed with skipped rows — review ERROR logs", "skipped_rows", skippedRows.Load())
	}
}

// decodeRow decodes one raw source row to a *SenderKeyStructure, choosing the
// source by fmt_ver (columnar via ExportRecompose for fmt_ver=2; JSON blob
// otherwise). Returns (nil, true, nil) to skip a row (undecodable legacy row),
// or (nil, false, err) to abort.
func decodeRow(r rawRow) (*groupRecord.SenderKeyStructure, bool, error) {
	var structure *groupRecord.SenderKeyStructure
	if r.fmtVer.Valid && r.fmtVer.Int16 == 2 {
		flatPriv := flattenNullableBytea(r.stSigningKeyPrivate)
		cols := &sqlstore.ExportedSenderKeyColumns{
			StKeyID:             r.stKeyID,
			StChainKeyIteration: r.stChainKeyIteration,
			StChainKey:          r.stChainKey,
			StSigningKeyPublic:  r.stSigningKeyPublic,
			StSigningKeyPrivate: flatPriv,
			SmkStateIdx:         r.smkStateIdx,
			SmkIteration:        r.smkIteration,
			SmkIV:               r.smkIV,
			SmkCipherKey:        r.smkCipherKey,
			SmkSeed:             r.smkSeed,
		}
		structure = sqlstore.ExportRecompose(cols)
	} else {
		if r.blob == nil {
			slog.Error("skipping row: NULL blob on fmt_ver=NULL/1 row",
				"our_jid", r.ourJID, "chat_id", r.chatID, "sender_id", r.senderID)
			return nil, true, nil
		}
		var dErr error
		structure, dErr = store.SignalProtobufSerializer.SenderKeyRecord.Deserialize(r.blob)
		if dErr != nil {
			slog.Error("skipping row: Deserialize failed",
				"our_jid", r.ourJID, "chat_id", r.chatID, "sender_id", r.senderID, "error", dErr)
			return nil, true, nil
		}
	}
	if structure == nil {
		slog.Error("skipping row: nil structure after decode",
			"our_jid", r.ourJID, "chat_id", r.chatID, "sender_id", r.senderID)
		return nil, true, nil
	}
	return structure, false, nil
}

// normalizeSenderKeyStructure canonicalizes the nil-vs-empty-slice distinction
// so reflect.DeepEqual compares crypto material, not Go memory representation.
// (Deserialize allocates empty Keys / all-zero SigningKeyPrivate; UnpackFlat
// leaves nil — semantically equivalent.)
func normalizeSenderKeyStructure(s *groupRecord.SenderKeyStructure) *groupRecord.SenderKeyStructure {
	if s == nil {
		return nil
	}
	states := make([]*groupRecord.SenderKeyStateStructure, len(s.SenderKeyStates))
	for i, st := range s.SenderKeyStates {
		norm := &groupRecord.SenderKeyStateStructure{
			KeyID:            st.KeyID,
			SenderChainKey:   st.SenderChainKey,
			SigningKeyPublic: st.SigningKeyPublic,
		}
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
		if len(st.Keys) == 0 {
			norm.Keys = nil
		} else {
			norm.Keys = st.Keys
		}
		states[i] = norm
	}
	return &groupRecord.SenderKeyStructure{SenderKeyStates: states}
}

// flattenNullableBytea converts pgx's nullable BYTEA[] ([]*[]byte, nil pointer =
// SQL NULL) to [][]byte preserving nil (= nil SigningKeyPrivate = received key).
func flattenNullableBytea(src []*[]byte) [][]byte {
	if src == nil {
		return nil
	}
	out := make([][]byte, len(src))
	for i, p := range src {
		if p != nil {
			out[i] = *p
		}
	}
	return out
}
