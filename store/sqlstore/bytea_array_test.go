// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"reflect"
	"testing"
)

// TestByteaArray exercises the byteaArray codec (sql.Scanner + driver.Valuer)
// against PG BYTEA[] text format requirements.
//
// Blocking gate (DESIGN-DECISIONS line 33 / threat T-17.9-04):
// A nil element (st_signing_key_private absent on received keys — the COMMON
// case) MUST round-trip as PG NULL, not as \x (empty bytea). A wrong encoding
// here silently corrupts every received sender-key stored in the DB.
func TestByteaArray(t *testing.T) {
	t.Run("empty slice round-trips", func(t *testing.T) {
		input := byteaArray([][]byte{})
		v, err := input.Value()
		if err != nil {
			t.Fatalf("Value() error: %v", err)
		}
		var got byteaArray
		if err := got.Scan(v); err != nil {
			t.Fatalf("Scan() error: %v", err)
		}
		// Empty slice; accept nil or empty slice as equivalent (both mean no elements).
		if len(got) != 0 {
			t.Errorf("expected empty, got %v", got)
		}
	})

	t.Run("single element round-trips", func(t *testing.T) {
		input := byteaArray([][]byte{{0x01, 0x02, 0x03}})
		roundTrip(t, input)
	})

	t.Run("multi element round-trips", func(t *testing.T) {
		input := byteaArray([][]byte{
			{0xde, 0xad, 0xbe, 0xef},
			{0x00, 0xff, 0x7f, 0x80},
			make([]byte, 32),
		})
		roundTrip(t, input)
	})

	// Blocking gate: nil element → bare NULL token, NOT \x
	t.Run("nil element encodes as NULL and decodes as nil", func(t *testing.T) {
		input := byteaArray([][]byte{
			{0x01, 0x02},
			nil, // st_signing_key_private absent on received keys
			{0x03, 0x04},
		})
		v, err := input.Value()
		if err != nil {
			t.Fatalf("Value() error: %v", err)
		}
		// Verify the produced literal contains the bare token NULL (not \x or "").
		var lit string
		switch s := v.(type) {
		case string:
			lit = s
		case []byte:
			lit = string(s)
		default:
			t.Fatalf("Value() returned unexpected type %T", v)
		}
		// The nil element must appear as bare NULL, not as a quoted \x token.
		if !containsNullToken(lit) {
			t.Errorf("nil element did not produce NULL token in literal: %q", lit)
		}
		if containsEmptyBytea(lit) {
			t.Errorf("nil element produced \\x (empty bytea) instead of NULL in literal: %q", lit)
		}

		// Scan back and verify nil is preserved (not []byte{}).
		var got byteaArray
		if err := got.Scan(v); err != nil {
			t.Fatalf("Scan() error: %v", err)
		}
		if !reflect.DeepEqual([][]byte(got), [][]byte(input)) {
			t.Errorf("nil-element round-trip failed:\n  want %v\n  got  %v", [][]byte(input), [][]byte(got))
		}
	})

	// Blocking gate: mixed nil array (all nil elements).
	t.Run("all-nil array round-trips", func(t *testing.T) {
		input := byteaArray([][]byte{nil, nil, nil})
		roundTrip(t, input)
	})

	// T-17.9-05: embedded special bytes (comma, brace, backslash, quote) in element.
	// Since we hex-encode, these become plain hex — proves byte-exact encoding.
	t.Run("embedded special bytes round-trips", func(t *testing.T) {
		// comma=0x2c, open-brace=0x7b, backslash=0x5c, double-quote=0x22
		input := byteaArray([][]byte{
			{0x2c, 0x7b, 0x7d, 0x5c, 0x22, 0x27, 0x00, 0xff},
		})
		roundTrip(t, input)
	})

	t.Run("Scan accepts []byte src", func(t *testing.T) {
		input := byteaArray([][]byte{{0xab, 0xcd}})
		v, err := input.Value()
		if err != nil {
			t.Fatalf("Value() error: %v", err)
		}
		// Force src as []byte regardless of what Value returned.
		var src []byte
		switch s := v.(type) {
		case string:
			src = []byte(s)
		case []byte:
			src = s
		}
		var got byteaArray
		if err := got.Scan(src); err != nil {
			t.Fatalf("Scan([]byte) error: %v", err)
		}
		if !reflect.DeepEqual([][]byte(got), [][]byte(input)) {
			t.Errorf("Scan([]byte) round-trip failed: want %v got %v", [][]byte(input), [][]byte(got))
		}
	})

	t.Run("Scan accepts string src", func(t *testing.T) {
		input := byteaArray([][]byte{{0xef, 0x12}})
		v, err := input.Value()
		if err != nil {
			t.Fatalf("Value() error: %v", err)
		}
		// Force src as string regardless of what Value returned.
		var src string
		switch s := v.(type) {
		case string:
			src = s
		case []byte:
			src = string(s)
		}
		var got byteaArray
		if err := got.Scan(src); err != nil {
			t.Fatalf("Scan(string) error: %v", err)
		}
		if !reflect.DeepEqual([][]byte(got), [][]byte(input)) {
			t.Errorf("Scan(string) round-trip failed: want %v got %v", [][]byte(input), [][]byte(got))
		}
	})

	t.Run("Scan nil src returns nil slice", func(t *testing.T) {
		var got byteaArray
		if err := got.Scan(nil); err != nil {
			t.Fatalf("Scan(nil) error: %v", err)
		}
		if got != nil {
			t.Errorf("expected nil slice, got %v", got)
		}
	})
}

// roundTrip is a helper: Value() then Scan(), assert DeepEqual.
func roundTrip(t *testing.T, input byteaArray) {
	t.Helper()
	v, err := input.Value()
	if err != nil {
		t.Fatalf("Value() error: %v", err)
	}
	var got byteaArray
	if err := got.Scan(v); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if !reflect.DeepEqual([][]byte(got), [][]byte(input)) {
		t.Errorf("round-trip failed:\n  want %v\n  got  %v", [][]byte(input), [][]byte(got))
	}
}

// containsNullToken reports whether the PG array literal contains a bare NULL token
// (not inside quotes — i.e., a genuine SQL NULL element).
func containsNullToken(lit string) bool {
	// After trim of outer braces, check for ,NULL, or {NULL, or ,NULL} or {NULL}
	// Simple check: look for "NULL" not preceded/followed by a hex char or quote.
	for i := 0; i < len(lit); i++ {
		if i+4 <= len(lit) && lit[i:i+4] == "NULL" {
			// Check it's not inside quotes by verifying the char before is , { or start.
			before := i == 0 || lit[i-1] == ',' || lit[i-1] == '{'
			after := i+4 == len(lit) || lit[i+4] == ',' || lit[i+4] == '}'
			if before && after {
				return true
			}
		}
	}
	return false
}

// containsEmptyBytea reports whether the literal contains a quoted \x empty-bytea token
// which would be the wrong encoding for a nil element.
func containsEmptyBytea(lit string) bool {
	// Looking for "\"\\x\"" patterns i.e. "\x" with nothing after x before quote.
	for i := 0; i+4 <= len(lit); i++ {
		// Match the pattern: open-quote, backslash, x, close-quote
		if lit[i] == '"' && i+4 <= len(lit) && lit[i+1] == '\\' && lit[i+2] == 'x' && lit[i+3] == '"' {
			return true
		}
	}
	return false
}
