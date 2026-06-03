// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package sqlstore — int_array.go
//
// int64Array and int32Array are integer-slice wrappers implementing
// driver.Valuer and sql.Scanner for PostgreSQL BIGINT[] and INT[] columns via
// database/sql (the pgx stdlib adapter). Under database/sql the pgx-native
// slice handling does NOT apply — database/sql's convertValue rejects raw
// []int64 / []int32 before pgx ever sees them. These wrappers use the PG
// array text format {1,2,3} which is accepted by all versions.
//
// Plan 02 deferred these because they cannot be integration-tested without a
// live DB. This plan provides the codec (tested via the unit scan/value
// round-trip pattern below in int_array_test.go) and accepts that the DB-level
// integration test (batch_upsert_test.go) requires a live DB to exercise the
// full path. If the test DB is unavailable, batch_upsert_test.go skips with a
// t.Skipf and the SUMMARY notes "column-bind unverified — DB unreachable".

package sqlstore

import (
	"database/sql/driver"
	"fmt"
	"strconv"
	"strings"
)

// int64Array is []int64 with driver.Valuer and sql.Scanner for PG BIGINT[].
type int64Array []int64

// Value implements driver.Valuer. Encodes as {1,2,3} text literal.
// nil slice → SQL NULL. Empty slice → {}.
func (a int64Array) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	if len(a) == 0 {
		return "{}", nil
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, v := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.FormatInt(v, 10))
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// Scan implements sql.Scanner. Parses {1,2,3} or {} from string/[]byte/nil.
func (a *int64Array) Scan(src any) error {
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
		return fmt.Errorf("int64Array.Scan: unsupported type %T", src)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		*a = int64Array{}
		return nil
	}
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return fmt.Errorf("int64Array.Scan: invalid literal %q", raw)
	}
	parts := strings.Split(raw[1:len(raw)-1], ",")
	result := make(int64Array, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 64)
		if err != nil {
			return fmt.Errorf("int64Array.Scan: element %d %q: %w", i, p, err)
		}
		result[i] = v
	}
	*a = result
	return nil
}

// int32Array is []int32 with driver.Valuer and sql.Scanner for PG INT[].
type int32Array []int32

// Value implements driver.Valuer. Encodes as {1,2,3} text literal.
// nil slice → SQL NULL. Empty slice → {}.
func (a int32Array) Value() (driver.Value, error) {
	if a == nil {
		return nil, nil
	}
	if len(a) == 0 {
		return "{}", nil
	}
	var sb strings.Builder
	sb.WriteByte('{')
	for i, v := range a {
		if i > 0 {
			sb.WriteByte(',')
		}
		sb.WriteString(strconv.FormatInt(int64(v), 10))
	}
	sb.WriteByte('}')
	return sb.String(), nil
}

// Scan implements sql.Scanner. Parses {1,2,3} or {} from string/[]byte/nil.
func (a *int32Array) Scan(src any) error {
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
		return fmt.Errorf("int32Array.Scan: unsupported type %T", src)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "{}" {
		*a = int32Array{}
		return nil
	}
	if len(raw) < 2 || raw[0] != '{' || raw[len(raw)-1] != '}' {
		return fmt.Errorf("int32Array.Scan: invalid literal %q", raw)
	}
	parts := strings.Split(raw[1:len(raw)-1], ",")
	result := make(int32Array, len(parts))
	for i, p := range parts {
		v, err := strconv.ParseInt(strings.TrimSpace(p), 10, 32)
		if err != nil {
			return fmt.Errorf("int32Array.Scan: element %d %q: %w", i, p, err)
		}
		result[i] = int32(v)
	}
	*a = result
	return nil
}
