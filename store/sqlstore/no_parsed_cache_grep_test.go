// Copyright (c) 2026 Kavtov Platform (Phase 38.4 plan 01)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// no_parsed_cache_grep_test.go — TestNoParsedCacheOnSenderKeyPath
//
// CORRECTNESS GATE — Phase 38.4: Collapse sender-key double-cache to single flat-bytes cache.
//
// Plan 03 deleted the parsed-struct cache (SKParsed). This gate is now GREEN and
// must stay GREEN: reintroducing any parsed-struct-cache token on the sender-key
// path re-opens double-caching and the GC storm. DO NOT silence, skip, or
// t.Skip() this test.
//
// What this gate enforces:
// After Phase 38.4 Plan 03, zero parsed-struct-cache references must remain on the
// sender-key path. The forbidden tokens are the field names, type names, constructor
// names, and setter names of the SKParsed / ParsedSKCache machinery. A single
// surviving token means double-caching is still live and the GC storm (live heap
// 4.48 GB > GOMEMLIMIT 3.35 GB, measured 2026-06-17) is not resolved.
//
// The gate is FILE-SCOPED (not function-scoped) for the covered set. A function-
// scoped list silently misses a new entrypoint that reintroduces the parsed cache.
//
// Covered source files (sender-key path):
//   - store/sqlstore/cached_sender_key_store.go   (fields, setters, call sites)
//   - store/sqlstore/cache_wiring.go               (LRU construction, cap constants)
//   - store/sqlstore/recovery_sender_key.go        (parsedLoad union in recovery merge)
//   - store/signal.go                              (LoadSenderKey LoadStruct fast-path)
//   - message.go                                   (decryptGroupSenderKey inline comment)
//
// Additionally: store/parsedcache.go is asserted ABSENT (or, if present, token-free).
//
// Reused helpers (same package — no redefinition):
//   findModuleRoot(t)         — from no_json_grep_test.go
//   readNonCommentLines(path) — from no_json_grep_test.go

package sqlstore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parsedCacheCoveredFiles are the source files on the sender-key path that must
// contain zero parsed-struct-cache references after Plan 03 deletes the SKParsed cache.
var parsedCacheCoveredFiles = []string{
	"store/sqlstore/cached_sender_key_store.go",
	"store/sqlstore/cache_wiring.go",
	"store/sqlstore/recovery_sender_key.go",
	"store/signal.go",
	"message.go",
}

// forbiddenParsedTokens are the substrings that indicate a parsed-struct-cache
// reference on the sender-key path. These are field names, type names, constructor
// names, and setter names of the SKParsed / ParsedSKCache machinery.
//
// Zero-tolerance: no ALLOW-marker machinery — these are plain identifiers, not
// method calls, and there are no legitimate uses of these tokens after Plan 03.
var forbiddenParsedTokens = []string{
	"parsedReplace",
	"parsedLoad",
	"parsedInvalidate",
	"parsedSKCache",
	"SKParsed",
	"LoadStruct",
	"ParsedSKCache",
	"NewSKParsedLRU",
	"NewParsedSKCache",
	"SetParsedReplace",
	"SetParsedLoad",
	"SetParsedInvalidate",
}

// TestNoParsedCacheOnSenderKeyPath asserts zero parsed-struct-cache tokens on the
// covered sender-key source files. The parsed cache was deleted in Plan 03; any
// VIOLATION line is a regression (double-caching reintroduced).
func TestNoParsedCacheOnSenderKeyPath(t *testing.T) {
	moduleRoot := findModuleRoot(t)
	t.Logf("module root: %s", moduleRoot)

	var violations []string

	// Scan the covered sender-key path files.
	for _, relPath := range parsedCacheCoveredFiles {
		absPath := filepath.Join(moduleRoot, relPath)
		lines, err := readNonCommentLines(absPath)
		if err != nil {
			t.Fatalf("cannot read %s: %v", relPath, err)
		}
		for lineNo, line := range lines {
			for _, tok := range forbiddenParsedTokens {
				if strings.Contains(line, tok) {
					violations = append(violations, fmt.Sprintf(
						"%s:%d: %q on sender-key path: %s",
						relPath, lineNo+1, tok, strings.TrimSpace(line)))
				}
			}
		}
	}

	// Additionally assert store/parsedcache.go is ABSENT or token-free.
	parsedCachePath := filepath.Join(moduleRoot, "store/parsedcache.go")
	if _, err := os.Stat(parsedCachePath); err == nil {
		// File exists — scan it for forbidden tokens.
		lines, err := readNonCommentLines(parsedCachePath)
		if err != nil {
			t.Fatalf("cannot read store/parsedcache.go: %v", err)
		}
		for lineNo, line := range lines {
			for _, tok := range forbiddenParsedTokens {
				if strings.Contains(line, tok) {
					violations = append(violations, fmt.Sprintf(
						"store/parsedcache.go:%d: %q still exists: %s",
						lineNo+1, tok, strings.TrimSpace(line)))
				}
			}
		}
	}

	if len(violations) > 0 {
		for _, v := range violations {
			t.Errorf("VIOLATION: %s", v)
		}
	}
}
