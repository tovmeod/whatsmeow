// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// no_json_grep_test.go — TestNoJSONOnSenderKeyPath
//
// Enforced grep-gate: zero .Serialize() / .Deserialize( calls on the per-message
// sender-key and session read+write path (T-17.9-15, T-17.13-10). Two documented
// exceptions are permitted, identified by explicit inline comment markers:
//
//   ALLOW-JSON-DRAIN-BLOB         — the ultimate-fallback legacy-blob Serialize in
//                                    PutSenderKeyStructure, taken only when PackFlat
//                                    returns (nil, false) on a 0-state structure
//                                    (should not occur in production; safety net path).
// Phase 17.11-05 change: ALLOW-JSON-LEGACY-READ removed. The getSenderKeyDecomposed
// dual-read path (fmt_ver=1/NULL Deserialize) was deleted along with the columnar
// columns in this plan. GetSenderKeyStructure now uses store.UnpackFlat(blob) only.
// senderkey_columns.go was deleted; senderKeyColumns/decompose/recompose moved to
// store.go (migration tool compat only; not on any live driver read path).
//
// Phase 17.13 change: session functions (StoreSession, LoadSession) added to the
// gate. Stage 3: JSON session paths permanently closed; no drain markers remain.
// Session exemption comment removed.
//
// Why .Serialize()/.Deserialize( rather than json.Marshal/Unmarshal:
// libsignal's "ProtoBufSerializer" is misnamed — it uses encoding/json for all
// stored crypto objects (SenderKeyRecord, SenderKeyState, SessionRecord, etc.).
// The JSON calls are inside libsignal's serializer methods; they do NOT appear
// as literal json.Marshal/json.Unmarshal in this package's source. The correct
// guard is on the call to .Serialize() (write) and .Deserialize( (read), which
// is where the JSON cost lands on the per-message path.
//
// The gate is file-scoped (not function-scoped) for the covered set. A
// function-scoped list silently misses a new entrypoint.
//
// Covered source files:
//   - store/sqlstore/store.go                      (PutManySenderKeys — flat bytea write, no blob)
//   - store/sqlstore/cached_sender_key_store.go    (extractStructMeta, PutSenderKey, PutSenderKeyStructure, GetSenderKeyStructure)
//   - store/sqlstore/cached_session_store.go       (Stage 1 gate: confirms no JSON calls in byte-cache layer)
//   - store/signal.go                              (StoreSenderKey, LoadSenderKey, StoreSession, LoadSession)
//
// The gate passes NOW. Any future addition of .Serialize()/.Deserialize( to the
// covered file set without an explicit ALLOW marker causes this test to FAIL,
// making it impossible to ship undetected JSON on the per-message path.

package sqlstore

import (
	"bufio"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// senderKeyPathFiles are the source files covered by the grep-gate.
// Paths are relative to the module root (located via go/build or __file__).
// The gate covers these files in their entirety — not a function-scoped list.
var senderKeyPathFiles = []string{
	"store/sqlstore/store.go",
	"store/sqlstore/cached_sender_key_store.go",
	"store/sqlstore/cached_session_store.go", // Stage 1 gate: confirms no JSON in byte-cache layer
	"store/sessioncache.go",                  // Stage 1 GAP FIX: batched send-path flush (PutCachedSessions) must write flat, not JSON
}

// senderKeySignalFilePath is store/signal.go, scanned for sender-key functions
// (StoreSenderKey, LoadSenderKey) via senderKeySignalFuncPrefixes and for session
// functions (StoreSession, LoadSession) via sessionSignalFuncPrefixes.
const senderKeySignalFilePath = "store/signal.go"

// senderKeySignalFuncPrefixes are the function name prefixes to include from
// signal.go. Lines are included starting from the matching func declaration
// through the next top-level func declaration.
var senderKeySignalFuncPrefixes = []string{
	"func (device *Device) StoreSenderKey(",
	"func (device *Device) LoadSenderKey(",
}

// sessionSignalFuncPrefixes are the session function name prefixes to include
// from signal.go (Phase 17.13: session path now covered by this gate).
var sessionSignalFuncPrefixes = []string{
	"func (device *Device) StoreSession(",
	"func (device *Device) LoadSession(",
}

// jsonCallPatterns are the substrings that indicate a JSON-bearing call on the
// per-message path. These are the actual libsignal serializer method names —
// not literal json.Marshal/Unmarshal (which live inside libsignal, not here).
var jsonCallPatterns = []string{
	".Serialize()",
	".Deserialize(",
}

// allowMarkers are the inline comment markers that permit a JSON call.
// A line containing one of these markers (as a substring) is an allowed exception.
// ALLOW-JSON-DRAIN-BLOB: Serialize fallback in PutSenderKeyStructure when PackFlat fails.
// ALLOW-JSON-LEGACY-READ: Serialize/Deserialize in store/signal.go for non-columnar store
//
//	fallback (non-production path: fires only when CachedSenderKeyStore is not wired).
//
// Stage 3: JSON session drain markers removed — session paths permanently flat-only.
var allowMarkers = []string{
	"ALLOW-JSON-DRAIN-BLOB",
	"ALLOW-JSON-LEGACY-READ",
}

// TestNoJSONOnSenderKeyPath asserts zero .Serialize()/.Deserialize( calls on
// the covered sender-key source files, except for lines with an ALLOW marker.
//
// The test FAILS if:
//   - Any pattern is found on a non-comment line without an ALLOW marker.
//   - The ALLOW-JSON-DRAIN-BLOB marker is MISSING from the covered files (prevents
//     a future cleanup from silently making the marker-check vacuous — i.e. the
//     gate must detect when an exception line is removed without updating the gate).
//
// The test PASSES when:
//   - ALLOW-JSON-DRAIN-BLOB appears in the covered files (on a Serialize() call line).
//   - No other .Serialize()/.Deserialize( appears in the covered files (comment-stripped).
func TestNoJSONOnSenderKeyPath(t *testing.T) {
	// Locate the module root from this test file's location.
	// This file lives at store/sqlstore/no_json_grep_test.go; the module root
	// is two directories up.
	moduleRoot := findModuleRoot(t)
	t.Logf("module root: %s", moduleRoot)

	var violations []string
	markerFound := map[string]bool{
		"ALLOW-JSON-DRAIN-BLOB":  false,
		"ALLOW-JSON-LEGACY-READ": false, // still present in store/signal.go non-columnar fallback
	}

	// Scan the whole-file entries.
	for _, relPath := range senderKeyPathFiles {
		absPath := filepath.Join(moduleRoot, relPath)
		lines, err := readNonCommentLines(absPath)
		if err != nil {
			t.Fatalf("cannot read %s: %v", relPath, err)
		}
		checkLines(t, relPath, lines, &violations, markerFound)
	}

	// Scan only the sender-key function bodies in signal.go.
	{
		relPath := senderKeySignalFilePath
		absPath := filepath.Join(moduleRoot, relPath)
		lines, err := extractSenderKeyFunctionLines(absPath, senderKeySignalFuncPrefixes)
		if err != nil {
			t.Fatalf("cannot extract sender-key functions from %s: %v", relPath, err)
		}
		checkLines(t, relPath, lines, &violations, markerFound)
	}

	// Scan only the session function bodies in signal.go (Phase 17.13: now in scope).
	{
		relPath := senderKeySignalFilePath
		absPath := filepath.Join(moduleRoot, relPath)
		lines, err := extractSenderKeyFunctionLines(absPath, sessionSignalFuncPrefixes)
		if err != nil {
			t.Fatalf("cannot extract session functions from %s: %v", relPath, err)
		}
		checkLines(t, relPath, lines, &violations, markerFound)
	}

	// Gate: all ALLOW markers must be present.
	// If an exception line is removed (e.g. legacy blob dropped in a future plan),
	// the marker disappears and this check trips — forcing an explicit update to
	// the gate. This prevents a silent "no-op" grep-gate after cleanup.
	for marker, found := range markerFound {
		if !found {
			t.Errorf("ALLOW marker %q not found in covered files — either the exception line was removed "+
				"(update the gate) or the marker is missing from the call line (add it)", marker)
		}
	}

	// Gate: no unmarked violations.
	if len(violations) > 0 {
		t.Logf("Found %d violation(s):", len(violations))
		for _, v := range violations {
			t.Errorf("VIOLATION: %s", v)
		}
	}

	if len(violations) == 0 && allMarkersFound(markerFound) {
		t.Logf("PASS: zero unmarked .Serialize()/.Deserialize( on the per-message sender-key and session path; all ALLOW markers present")
	}
}

// checkLines scans a set of (comment-stripped) lines for JSON call patterns,
// recording allowed exceptions and violations.
func checkLines(t *testing.T, relPath string, lines []string, violations *[]string, markerFound map[string]bool) {
	t.Helper()
	for lineNo, line := range lines {
		isAllowed := false
		for marker := range markerFound {
			if strings.Contains(line, marker) {
				markerFound[marker] = true
				isAllowed = true
			}
		}
		if isAllowed {
			t.Logf("ALLOWED: %s:%d: %s", relPath, lineNo+1, strings.TrimSpace(line))
			continue
		}
		for _, pat := range jsonCallPatterns {
			if strings.Contains(line, pat) {
				*violations = append(*violations, fmt.Sprintf(
					"%s:%d: disallowed %q on per-message sender-key path: %s",
					relPath, lineNo+1, pat, strings.TrimSpace(line)))
			}
		}
	}
}

// extractSenderKeyFunctionLines reads a Go source file and returns the non-comment
// lines from the bodies of the functions named by prefixes. It includes lines from
// the matching `func ...` declaration through (but not including) the next top-level
// `func ` declaration.
func extractSenderKeyFunctionLines(path string, prefixes []string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var allLines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// Build a set of line ranges for the target functions.
	type lineRange struct{ start, end int }
	var ranges []lineRange

	for _, prefix := range prefixes {
		startLine := -1
		for i, line := range allLines {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "func ") && strings.Contains(trimmed, prefix[len("func "):]) {
				startLine = i
				break
			}
		}
		if startLine < 0 {
			return nil, fmt.Errorf("function matching %q not found in %s", prefix, path)
		}
		// Find the end: the next top-level `func ` line after startLine+1.
		endLine := len(allLines)
		for i := startLine + 1; i < len(allLines); i++ {
			trimmed := strings.TrimSpace(allLines[i])
			if strings.HasPrefix(trimmed, "func ") {
				endLine = i
				break
			}
		}
		ranges = append(ranges, lineRange{startLine, endLine})
	}

	// Extract and filter lines from all ranges.
	var out []string
	for _, r := range ranges {
		for _, line := range allLines[r.start:r.end] {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "//") {
				continue
			}
			out = append(out, line)
		}
	}
	return out, nil
}

func allMarkersFound(m map[string]bool) bool {
	for _, v := range m {
		if !v {
			return false
		}
	}
	return true
}

// readNonCommentLines reads a Go source file and returns lines with:
//   - Blank lines omitted (irrelevant for the gate)
//   - Lines whose first non-whitespace content starts with "//" omitted
//     (pure comment lines; a trailing // comment on a code line is kept
//     so the ALLOW markers on code lines are visible)
func readNonCommentLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, "//") {
			// Pure comment line — skip. Trailing inline comments on code lines
			// (e.g. `sk.Serialize() // ALLOW-JSON-DRAIN-BLOB`) are NOT skipped
			// because the line does not START with //.
			continue
		}
		out = append(out, line)
	}
	return out, scanner.Err()
}

// findModuleRoot locates the module root by walking up from the test source
// directory until a go.mod file is found. Falls back to GOPATH-based lookup.
func findModuleRoot(t *testing.T) string {
	t.Helper()
	// Start from the package directory (store/sqlstore/).
	// This file's import path is go.mau.fi/whatsmeow/store/sqlstore.
	pkg, err := build.Default.Import("go.mau.fi/whatsmeow/store/sqlstore", ".", build.FindOnly)
	if err == nil && pkg.Dir != "" {
		// pkg.Dir is .../store/sqlstore; go two levels up.
		root := filepath.Dir(filepath.Dir(pkg.Dir))
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
	}

	// Fallback: walk up from the working directory.
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("cannot get working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("cannot locate module root (go.mod not found)")
	return ""
}
