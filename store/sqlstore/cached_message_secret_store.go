// Copyright (c) 2026 Kavtov Platform (perf: 260601-uuy)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

package sqlstore

import (
	"context"
	"sync/atomic"

	lru "github.com/hashicorp/golang-lru/v2"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
)

// msgSecretEntry caches the (secret, realSender) pair returned by
// GetMessageSecret. whatsmeow_message_secrets uses ON CONFLICT DO NOTHING — the
// row is immutable once written, so a cached entry can never go stale.
// realSender is stored in ToNonAD() form matching the DB's sender_jid column and
// the SQL parameter normalization.
type msgSecretEntry struct {
	Secret     []byte
	RealSender types.JID
}

// CachedMessageSecretStore wraps an inner store.MsgSecretStore with a
// process-shared *lru.Cache[string, msgSecretEntry]. Cache key is the
// four-element composite jid + "|" + chat.ToNonAD() + "|" + sender.ToNonAD() +
// "|" + id, matching the SQL params ($1=our_jid, $2=chat.ToNonAD(),
// $3=sender.ToNonAD(), $4=message_id).
//
// Like CachedSenderKeyStore / CachedSessionStore, this wrapper is a strict
// write-through cache: every PutMessageSecret(s) calls inner FIRST and only
// updates the cache on success.
//
// Copy discipline (mirrors CR-06 from the session/sender-key wrappers):
// GetMessageSecret returns a copy of the cached secret slice; Put* stores a copy
// of the caller's slice. Neither side aliases the other's buffer.
//
// Nil-not-cached (Pitfall 5): a nil secret is the not-found sentinel from the
// inner SQLStore (sql.ErrNoRows → nil). It is NEVER cached — a future
// PutMessageSecret would not invalidate a cached nil entry, so subsequent Gets
// would erroneously return nil.
//
// LID↔PN note: the getMsgSecret SQL has a LID↔PN equivalence subquery in its
// WHERE clause; that equivalence is NOT replicated in the cache key. A Get under
// an alternate JID form simply misses and falls through to the LID-aware SQL,
// which is correct.
type CachedMessageSecretStore struct {
	inner store.MsgSecretStore
	jid   string
	cache *lru.Cache[string, msgSecretEntry]

	hits, misses uint64

	// explicitRemoves is unused (MsgSecretStore has no Delete method) but kept
	// for counter uniformity with the other cached store types. Points at
	// signalCaches.MsgSecretExplicitRemoves.
	explicitRemoves *uint64
}

var _ store.MsgSecretStore = (*CachedMessageSecretStore)(nil)

// NewCachedMessageSecretStore constructs a wrapper over inner. jid is the device
// JID (used as cache-key prefix). cache is a shared LRU constructed by the
// Container. explicitRemoves points at the Container-level
// MsgSecretExplicitRemoves counter (unused today; kept for counter uniformity).
func NewCachedMessageSecretStore(
	inner store.MsgSecretStore,
	jid string,
	cache *lru.Cache[string, msgSecretEntry],
	explicitRemoves *uint64,
) *CachedMessageSecretStore {
	return &CachedMessageSecretStore{
		inner:           inner,
		jid:             jid,
		cache:           cache,
		explicitRemoves: explicitRemoves,
	}
}

func (c *CachedMessageSecretStore) key(chat, sender types.JID, id types.MessageID) string {
	return c.jid + "|" + chat.ToNonAD().String() + "|" + sender.ToNonAD().String() + "|" + string(id)
}

// Stats returns (hits, misses) for test observability and for the Container's
// emitMetricsLoop.
func (c *CachedMessageSecretStore) Stats() (hits, misses uint64) {
	return atomic.LoadUint64(&c.hits),
		atomic.LoadUint64(&c.misses)
}

// Purge clears the entire cache. The MsgSecretStore interface has no Delete
// method; Purge is exposed here for tests that want to reset state without
// recreating the wrapper.
func (c *CachedMessageSecretStore) Purge() {
	c.cache.Purge()
}

// ---------------------------------------------------------------------------
// store.MsgSecretStore
// ---------------------------------------------------------------------------

func (c *CachedMessageSecretStore) GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) ([]byte, types.JID, error) {
	k := c.key(chat, sender, id)
	if entry, ok := c.cache.Get(k); ok {
		atomic.AddUint64(&c.hits, 1)
		// Copy out so caller mutation cannot corrupt the cached slice (CR-06).
		return copyBytes(entry.Secret), entry.RealSender, nil
	}
	atomic.AddUint64(&c.misses, 1)
	secret, realSender, err := c.inner.GetMessageSecret(ctx, chat, sender, id)
	if err != nil {
		return nil, realSender, err // never cache on error
	}
	if secret == nil {
		// Pitfall 5: never cache the not-found sentinel. A subsequent
		// PutMessageSecret would not invalidate a cached nil entry.
		return nil, realSender, nil
	}
	entry := msgSecretEntry{Secret: copyBytes(secret), RealSender: realSender.ToNonAD()}
	c.cache.Add(k, entry)
	return copyBytes(entry.Secret), entry.RealSender, nil
}

func (c *CachedMessageSecretStore) PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) error {
	// Write-through: inner first; only update cache on success.
	if err := c.inner.PutMessageSecret(ctx, chat, sender, id, secret); err != nil {
		return err
	}
	// Copy before stash so caller's buffer reuse cannot corrupt the cache.
	entry := msgSecretEntry{Secret: copyBytes(secret), RealSender: sender.ToNonAD()}
	c.cache.Add(c.key(chat, sender, id), entry)
	return nil
}

func (c *CachedMessageSecretStore) PutMessageSecrets(ctx context.Context, inserts []store.MessageSecretInsert) error {
	// Write-through: inner first; only update cache on success.
	if err := c.inner.PutMessageSecrets(ctx, inserts); err != nil {
		return err
	}
	for _, insert := range inserts {
		entry := msgSecretEntry{Secret: copyBytes(insert.Secret), RealSender: insert.Sender.ToNonAD()}
		c.cache.Add(c.key(insert.Chat, insert.Sender, insert.ID), entry)
	}
	return nil
}
