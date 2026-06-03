// Copyright (c) 2026 Kavtov Platform (Phase 17.9)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// senderkey_columnar.go — fork-local optional interface for columnar sender-key
// writes. Package store declares the interface; package sqlstore satisfies it.
//
// Import direction: sqlstore imports store (cached_sender_key_store.go:17).
// store CANNOT import sqlstore. The interface carries *SenderKeyStructure so
// package store needs no sqlstore import. The whatsmeow SenderKeyStore interface
// (store.go:50) is untouched — upstream-merge surface preserved (DESIGN line 64).
//
// Usage:
//
//	if csk, ok := device.SenderKeys.(SenderKeyColumnarStore); ok {
//	    return csk.PutSenderKeyStructure(ctx, group, user, keyRecord.Structure())
//	}
//	// fallback: legacy []byte PutSenderKey (non-columnar / test stores)
//
// The type-assertion failure path is the ONLY remaining Serialize in
// signal.go's StoreSenderKey — it fires only for stores that do not implement
// this interface (test or pre-wiring scenarios).
package store

import (
	"context"

	groupRecord "go.mau.fi/libsignal/groups/state/record"
)

// SenderKeyColumnarStore is a fork-local OPTIONAL interface. It is exported so
// package sqlstore can write a compile-time assertion:
//
//	var _ store.SenderKeyColumnarStore = (*CachedSenderKeyStore)(nil)
//
// That assertion converts a future signature drift (which would otherwise make
// StoreSenderKey's type-assertion fall back to keyRecord.Serialize() — JSON on
// every write, invisible to the no-JSON grep-gate since the JSON is inside
// libsignal) into a BUILD ERROR. This is the primary guard for the phase's goal.
//
// The method carries *groupRecord.SenderKeyStructure (already imported in
// signal.go) so the interface bridge requires no sqlstore import in package store.
// Callers MUST NOT call the whatsmeow SenderKeyStore.PutSenderKey on the same
// entry after calling this method (the columnar path owns the flusher drain).
type SenderKeyColumnarStore interface {
	// PutSenderKeyStructure stores a sender-key record in its columnar form.
	// s is the in-memory structure returned by keyRecord.Structure() — JSON-free.
	// The implementation decomposes s into typed columns and enqueues to the
	// 17.7 write-back flusher. group and user are the whatsmeow JID strings used
	// as the PG (chat_id, sender_id) key pair.
	PutSenderKeyStructure(ctx context.Context, group, user string, s *groupRecord.SenderKeyStructure) error
}
