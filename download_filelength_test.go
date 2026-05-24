// kavtov-fork: Phase 17.5.2 regression -- guards isFileLengthMismatch against
// accidental revert during a future tulir/whatsmeow rebase. A reverter would
// either remove the helper (test fails to compile) or change the rule (test
// assertions fail).

package whatsmeow

import "testing"

func TestIsFileLengthMismatch(t *testing.T) {
	cases := []struct {
		name            string
		expected, actual int
		want            bool
	}{
		{"FileLength=0 means unknown, accept any actual", 0, 100, false},
		{"Legacy -1 skip convention preserved", -1, 100, false},
		{"Matching lengths are valid", 100, 100, false},
		{"Real mismatch is still flagged", 100, 50, true},
		{"FileLength=0 and empty body is still unknown, not flagged", 0, 0, false},
		{"Positive expected vs empty actual is a real mismatch", 100, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isFileLengthMismatch(tc.expected, tc.actual); got != tc.want {
				t.Errorf("isFileLengthMismatch(%d, %d) = %v, want %v", tc.expected, tc.actual, got, tc.want)
			}
		})
	}
}
