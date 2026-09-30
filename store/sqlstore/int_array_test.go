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

func TestInt64Array_RoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		in      int64Array
		wantVal string // "" means nil
		nilVal  bool
	}{
		{"nil", nil, "", true},
		{"empty", int64Array{}, "{}", false},
		{"single", int64Array{42}, "{42}", false},
		{"multi", int64Array{1, 2, 3, 999, -5}, "{1,2,3,999,-5}", false},
		{"big", int64Array{int64(1 << 32), int64(-1 << 32)}, "{4294967296,-4294967296}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tc.in.Value()
			if err != nil {
				t.Fatalf("Value(): %v", err)
			}
			if tc.nilVal {
				if v != nil {
					t.Fatalf("Value() = %v, want nil", v)
				}
				return
			}
			s, ok := v.(string)
			if !ok {
				t.Fatalf("Value() returned %T, want string", v)
			}
			if s != tc.wantVal {
				t.Errorf("Value() = %q, want %q", s, tc.wantVal)
			}
			// Round-trip Scan
			var got int64Array
			if err := got.Scan(s); err != nil {
				t.Fatalf("Scan(%q): %v", s, err)
			}
			if !reflect.DeepEqual([]int64(got), []int64(tc.in)) {
				t.Errorf("Scan round-trip: got %v, want %v", got, tc.in)
			}
		})
	}
}

func TestInt64Array_Scan_NilSrc(t *testing.T) {
	var a int64Array
	if err := a.Scan(nil); err != nil {
		t.Fatalf("Scan(nil): %v", err)
	}
	if a != nil {
		t.Errorf("Scan(nil) = %v, want nil", a)
	}
}

func TestInt64Array_Scan_ByteSliceSrc(t *testing.T) {
	var a int64Array
	if err := a.Scan([]byte("{7,8}")); err != nil {
		t.Fatalf("Scan([]byte): %v", err)
	}
	if !reflect.DeepEqual([]int64(a), []int64{7, 8}) {
		t.Errorf("Scan([]byte) = %v, want [7 8]", a)
	}
}

func TestInt32Array_RoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		in      int32Array
		wantVal string
		nilVal  bool
	}{
		{"nil", nil, "", true},
		{"empty", int32Array{}, "{}", false},
		{"single", int32Array{0}, "{0}", false},
		{"multi", int32Array{0, 1, 2, 100}, "{0,1,2,100}", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := tc.in.Value()
			if err != nil {
				t.Fatalf("Value(): %v", err)
			}
			if tc.nilVal {
				if v != nil {
					t.Fatalf("Value() = %v, want nil", v)
				}
				return
			}
			s, ok := v.(string)
			if !ok {
				t.Fatalf("Value() returned %T, want string", v)
			}
			if s != tc.wantVal {
				t.Errorf("Value() = %q, want %q", s, tc.wantVal)
			}
			var got int32Array
			if err := got.Scan(s); err != nil {
				t.Fatalf("Scan(%q): %v", s, err)
			}
			if !reflect.DeepEqual([]int32(got), []int32(tc.in)) {
				t.Errorf("Scan round-trip: got %v, want %v", got, tc.in)
			}
		})
	}
}
