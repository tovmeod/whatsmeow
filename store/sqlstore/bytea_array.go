// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package sqlstore — bytea_array.go
//
// byteaArray is a [][]byte wrapper implementing driver.Valuer and sql.Scanner
// for PostgreSQL BYTEA[] columns in pgx/v5-via-database/sql text format.
//
// Wire format (canonical PG bytea[] text format):
//
//	{elem,elem,NULL}
//
// Each non-nil element is a double-quoted \x<hex> token:
//
//	"\\x<hex>"   (backslash is escaped once inside the quotes)
//
// Each nil element is the bare unquoted token NULL.
//
// Load-bearing distinction: nil ↔ NULL, []byte{} ↔ "\\x" (empty hex).
// A nil st_signing_key_private element (the COMMON received-key case)
// MUST encode as SQL NULL — not as an empty bytea — or every received
// sender-key stored in the DB will be silently corrupted on read.

package sqlstore

import (
	"database/sql/driver"
	"encoding/hex"
	"fmt"
	"strings"
)

// byteaArray is [][]byte with sql.Scanner + driver.Valuer for PG BYTEA[].
type byteaArray [][]byte

// Value implements driver.Valuer. Encodes the slice as a PostgreSQL BYTEA[]
// text literal: {elem,NULL,...}
// - nil element → bare NULL token (not "\\x")
// - []byte{} (empty, non-nil) → "\\x" (quoted empty hex)
// - non-empty element → "\\x<hex>" (quoted hex)
func (a byteaArray) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	if len(a) == 0 {
		return "{}", nil
	}

	var sb strings.Builder
	sb.WriteByte('{')
	for i, elem := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		if elem == nil {
			// nil element → bare NULL (unquoted) — SQL NULL
			sb.WriteString("NULL")
		} else {
			// Non-nil element → "\\x<hex>" (quoted; double-backslash because PG's
			// array input parser unescapes \\ → \ inside double-quoted elements,
			// so \\x<hex> → \x<hex> passed to bytea input → hex format → binary bytes).
			sb.WriteByte('"')
			sb.WriteString(`\\x`) // two chars: backslash + backslash + x in the wire
			sb.WriteString(hex.EncodeToString(elem))
			sb.WriteByte('"')
		}
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// Scan implements sql.Scanner. Parses a PG BYTEA[] text literal back into
// a [][]byte. Accepts src as string, []byte, or nil.
//
// Nil src → nil slice (column IS NULL).
// NULL token → nil element (SQL NULL array element).
// "\\x" token → []byte{} (empty, non-nil bytea).
// "\\x<hex>" token → decoded bytes.
func (a *byteaArray) Scan(src any) error {
	if src == nil {
		*a = nil
		return nil
	}

	var raw string
	switch s := src.(type) {
	case string:
		raw = s
	case []byte:
		raw = string(s)
	default:
		return fmt.Errorf("byteaArray.Scan: unsupported src type %T", src)
	}

	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		*a = byteaArray([][]byte{})
		return nil
	}
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return fmt.Errorf("byteaArray.Scan: invalid array literal %q", raw)
	}

	inner := raw[1 : len(raw)-1]
	tokens, err := parseArrayTokens(inner)
	if err != nil {
		return fmt.Errorf("byteaArray.Scan: %w", err)
	}

	result := make([][]byte, len(tokens))
	for i, tok := range tokens {
		if tok == "NULL" {
			result[i] = nil
		} else {
			b, err := decodeBytea(tok)
			if err != nil {
				return fmt.Errorf("byteaArray.Scan: element %d: %w", i, err)
			}
			result[i] = b
		}
	}
	*a = result
	return nil
}

// parseArrayTokens splits a PG array literal body (without outer braces) into
// tokens, respecting double-quoted strings (which may contain escaped characters).
// Returns the raw tokens (quoted ones include their surrounding quotes).
func parseArrayTokens(s string) ([]string, error) {
	var tokens []string
	i := 0
	for i < len(s) {
		if s[i] == '"' {
			// Quoted token: scan to closing unescaped quote.
			j := i + 1
			for j < len(s) {
				if s[j] == '\\' {
					j += 2 // skip escape sequence
					continue
				}
				if s[j] == '"' {
					break
				}
				j++
			}
			if j >= len(s) {
				return nil, fmt.Errorf("unterminated quoted token starting at %d in %q", i, s)
			}
			tokens = append(tokens, s[i:j+1]) // include quotes
			i = j + 1
			if i < len(s) && s[i] == ',' {
				i++ // skip separator
			}
		} else {
			// Unquoted token (NULL or similar): scan to comma or end.
			j := i
			for j < len(s) && s[j] != ',' {
				j++
			}
			tokens = append(tokens, s[i:j])
			i = j
			if i < len(s) && s[i] == ',' {
				i++ // skip separator
			}
		}
	}
	return tokens, nil
}

// decodeBytea decodes a quoted PG bytea text token (e.g. "\"\\x<hex>\"") to bytes.
// The input must be double-quoted and start with \x (after unescape).
func decodeBytea(tok string) ([]byte, error) {
	if len(tok) < 2 || tok[0] != '"' || tok[len(tok)-1] != '"' {
		return nil, fmt.Errorf("expected quoted token, got %q", tok)
	}
	// Strip outer quotes.
	inner := tok[1 : len(tok)-1]
	// Unescape: replace \\ → \
	inner = strings.ReplaceAll(inner, `\\`, `\`)
	// Expect \x prefix.
	if !strings.HasPrefix(inner, `\x`) {
		return nil, fmt.Errorf("expected \\x bytea prefix, got %q", inner)
	}
	hexStr := inner[2:]
	if hexStr == "" {
		return []byte{}, nil
	}
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("hex decode: %w", err)
	}
	return b, nil
}
