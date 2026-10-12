// Copyright (c) 2026 Kavtov Platform
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
package sqlstore

import (
	"context"
	"strconv"
	"strings"
	"sync"
)

const sessionBatchRows = 250
const sessionBatchBytes = 64 * 1024

const putSessionArrayQuery = `INSERT INTO whatsmeow_sessions (our_jid, their_id, session)
SELECT $1, incoming.address, incoming.blob
FROM unnest($2::text[], $3::bytea[]) AS incoming(address, blob)
ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session`

var sessionBatchQueries sync.Map // bounded by sessionBatchRows; immutable SQL strings

func sessionBatchQuery(rows int) string {
	if query, ok := sessionBatchQueries.Load(rows); ok {
		return query.(string)
	}
	var query strings.Builder
	query.Grow(150 + rows*24)
	query.WriteString("INSERT INTO whatsmeow_sessions (our_jid, their_id, session) VALUES ")
	for i := 0; i < rows; i++ {
		if i > 0 {
			query.WriteByte(',')
		}
		query.WriteByte('(')
		for j := 1; j <= 3; j++ {
			if j > 1 {
				query.WriteByte(',')
			}
			query.WriteByte('$')
			query.WriteString(strconv.Itoa(i*3 + j))
		}
		query.WriteByte(')')
	}
	query.WriteString(" ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session")
	cached, _ := sessionBatchQueries.LoadOrStore(rows, query.String())
	return cached.(string)
}

// sessionChunkEnd bounds encoding work by both row count and approximate binary
// payload size. A single oversized session is still written intact.
func (s *SQLStore) sessionChunkEnd(addresses []string, sessions map[string][]byte, start, byteLimit int) int {
	end, total := start, 0
	for end < len(addresses) && end-start < sessionBatchRows {
		address := addresses[end]
		size := len(s.JID) + len(address) + len(sessions[address]) + 24
		if end > start && total+size > byteLimit {
			break
		}
		total += size
		end++
	}
	return end
}

// putSessionChunks must run inside the caller's transaction: all chunks either
// commit together or roll back, including a failure in a later chunk.
func (s *SQLStore) putSessionChunks(ctx context.Context, addresses []string, sessions map[string][]byte, byteLimit int) error {
	for start := 0; start < len(addresses); {
		end := s.sessionChunkEnd(addresses, sessions, start, byteLimit)
		chunk := addresses[start:end]
		if len(chunk) == 1 {
			if err := s.PutSession(ctx, chunk[0], sessions[chunk[0]]); err != nil {
				return err
			}
		} else {
			args := make([]any, 0, len(chunk)*3)
			for _, address := range chunk {
				args = append(args, s.JID, address, sessions[address])
			}
			if _, err := s.db.Exec(ctx, sessionBatchQuery(len(chunk)), args...); err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}

// putSessionArrays uses a fixed PostgreSQL query and avoids repeating the
// account parameter for each row. The caller owns the encompassing transaction.
func (s *SQLStore) putSessionArrays(ctx context.Context, addresses []string, sessions map[string][]byte, byteLimit int) error {
	for start := 0; start < len(addresses); {
		end := s.sessionChunkEnd(addresses, sessions, start, byteLimit)
		chunk := addresses[start:end]
		if len(chunk) == 1 {
			if err := s.PutSession(ctx, chunk[0], sessions[chunk[0]]); err != nil {
				return err
			}
		} else {
			blobs := make([][]byte, len(chunk))
			for i, address := range chunk {
				blobs[i] = sessions[address]
			}
			var addressArg, blobArg any = chunk, blobs
			if PostgresArrayWrapper != nil {
				addressArg, blobArg = PostgresArrayWrapper(chunk), PostgresArrayWrapper(blobs)
			}
			if _, err := s.db.Exec(ctx, putSessionArrayQuery, s.JID, addressArg, blobArg); err != nil {
				return err
			}
		}
		start = end
	}
	return nil
}
