// Copyright (c) 2025 Tulir Asokan
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at http://mozilla.org/MPL/2.0/.

// Package sqlstore contains an SQL-backed implementation of the interfaces in the store package.
package sqlstore

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"go.mau.fi/util/dbutil"
	"go.mau.fi/util/exslices"
	"go.mau.fi/util/exsync"

	groupRecord "go.mau.fi/libsignal/groups/state/record"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	"go.mau.fi/whatsmeow/util/keys"
)

// ErrInvalidLength is returned by some database getters if the database returned a byte array with an unexpected length.
// This should be impossible, as the database schema contains CHECK()s for all the relevant columns.
var ErrInvalidLength = errors.New("database returned byte array with illegal length")

// PostgresArrayWrapper is a function to wrap array values before passing them to the sql package.
//
// When using github.com/lib/pq, you should set
//
//	whatsmeow.PostgresArrayWrapper = pq.Array
var PostgresArrayWrapper func(any) interface {
	driver.Valuer
	sql.Scanner
}

type SQLStore struct {
	*Container
	JID string

	preKeyLock sync.Mutex

	contactCache     map[types.JID]*types.ContactInfo
	contactCacheLock sync.Mutex

	migratedPNSessionsCache *exsync.Set[string]
}

// NewSQLStore creates a new SQLStore with the given database container and user JID.
// It contains implementations of all the different stores in the store package.
//
// In general, you should use Container.NewDevice or Container.GetDevice instead of this.
func NewSQLStore(c *Container, jid types.JID) *SQLStore {
	return &SQLStore{
		Container:    c,
		JID:          jid.String(),
		contactCache: make(map[types.JID]*types.ContactInfo),

		migratedPNSessionsCache: exsync.NewSet[string](),
	}
}

var _ store.AllSessionSpecificStores = (*SQLStore)(nil)

const (
	putIdentityQuery = `
		INSERT INTO whatsmeow_identity_keys (our_jid, their_id, identity) VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, their_id) DO UPDATE SET identity=excluded.identity
	`
	deleteAllIdentitiesQuery = `DELETE FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id >= $2 || ':' AND their_id < $2 || ';'`
	deleteIdentityQuery      = `DELETE FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id=$2`
	getIdentityQuery         = `SELECT identity FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id=$2`
)

func (s *SQLStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	_, err := s.db.Exec(ctx, putIdentityQuery, s.JID, address, key[:])
	return err
}

func (s *SQLStore) DeleteAllIdentities(ctx context.Context, phone string) error {
	_, err := s.db.Exec(ctx, deleteAllIdentitiesQuery, s.JID, phone)
	return err
}

func (s *SQLStore) DeleteIdentity(ctx context.Context, address string) error {
	_, err := s.db.Exec(ctx, deleteIdentityQuery, s.JID, address)
	return err
}

func (s *SQLStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	var existingIdentity []byte
	err := s.db.QueryRow(ctx, getIdentityQuery, s.JID, address).Scan(&existingIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		// Trust if not known, it'll be saved automatically later
		return true, nil
	} else if err != nil {
		return false, err
	} else if len(existingIdentity) != 32 {
		return false, ErrInvalidLength
	}
	return *(*[32]byte)(existingIdentity) == key, nil
}

// getIdentityBytes is a private read accessor used by CachedIdentityStore for populate-on-miss. Not part of the IdentityStore interface.
func (s *SQLStore) getIdentityBytes(ctx context.Context, address string) (*[32]byte, error) {
	var existingIdentity []byte
	err := s.db.QueryRow(ctx, getIdentityQuery, s.JID, address).Scan(&existingIdentity)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if len(existingIdentity) != 32 {
		return nil, ErrInvalidLength
	}
	out := [32]byte{}
	copy(out[:], existingIdentity)
	return &out, nil
}

const (
	getSessionQuery             = `SELECT session FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id=$2`
	hasSessionQuery             = `SELECT true FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id=$2`
	getManySessionQueryPostgres = `SELECT their_id, session FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id = ANY($2)`
	getManySessionQueryGeneric  = `SELECT their_id, session FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id IN (%s)`
	putSessionQuery             = `
		INSERT INTO whatsmeow_sessions (our_jid, their_id, session) VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session
	`
	deleteAllSessionsQuery = `DELETE FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id >= $2 || ':' AND their_id < $2 || ';'`
	deleteSessionQuery     = `DELETE FROM whatsmeow_sessions WHERE our_jid=$1 AND their_id=$2`

	migratePNToLIDSessionsQuery = `
		INSERT INTO whatsmeow_sessions (our_jid, their_id, session)
		SELECT our_jid, replace(their_id, $2, $3), session
		FROM whatsmeow_sessions
		WHERE our_jid=$1 AND their_id >= $2 || ':' AND their_id < $2 || ';'
		ON CONFLICT (our_jid, their_id) DO UPDATE SET session=excluded.session
	`
	deleteAllIdentityKeysQuery      = `DELETE FROM whatsmeow_identity_keys WHERE our_jid=$1 AND their_id >= $2 || ':' AND their_id < $2 || ';'`
	migratePNToLIDIdentityKeysQuery = `
		INSERT INTO whatsmeow_identity_keys (our_jid, their_id, identity)
		SELECT our_jid, replace(their_id, $2, $3), identity
		FROM whatsmeow_identity_keys
		WHERE our_jid=$1 AND their_id >= $2 || ':' AND their_id < $2 || ';'
		ON CONFLICT (our_jid, their_id) DO UPDATE SET identity=excluded.identity
	`
	deleteAllSenderKeysQuery      = `DELETE FROM whatsmeow_sender_keys WHERE our_jid=$1 AND sender_id >= $2 || ':' AND sender_id < $2 || ';'`
	// migratePNToLIDSenderKeysQuery copies sender-key rows from PN-format sender_id
	// to LID-format sender_id. The copy ALWAYS sets fmt_ver=1 and NULLs all columnar
	// columns (T-17.9-14): a fmt_ver=2 PN row would have valid columns, but copying
	// those columns alongside the legacy blob under the new LID would allow future
	// writes that arrive as fmt_ver=1 (legacy blobs) to leave stale columns for the
	// LID sender — so we copy as legacy-only (fmt_ver=1, blob only, columns NULL).
	// The next write to the LID row upgrades it to fmt_ver=2 via PutSenderKeyStructure.
	migratePNToLIDSenderKeysQuery = `
		INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, fmt_ver, sender_key,
			st_key_id, st_chain_key_iteration, st_chain_key, st_signing_key_public, st_signing_key_private,
			smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed)
		SELECT our_jid, chat_id, replace(sender_id, $2, $3), 1, sender_key,
			NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL, NULL, NULL
		FROM whatsmeow_sender_keys
		WHERE our_jid=$1 AND sender_id >= $2 || ':' AND sender_id < $2 || ';'
		ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET
			fmt_ver=1,
			sender_key=excluded.sender_key,
			st_key_id=NULL, st_chain_key_iteration=NULL, st_chain_key=NULL,
			st_signing_key_public=NULL, st_signing_key_private=NULL,
			smk_state_idx=NULL, smk_iteration=NULL, smk_iv=NULL, smk_cipher_key=NULL, smk_seed=NULL
	`
)

func (s *SQLStore) GetSession(ctx context.Context, address string) (session []byte, err error) {
	err = s.db.QueryRow(ctx, getSessionQuery, s.JID, address).Scan(&session)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

func (s *SQLStore) HasSession(ctx context.Context, address string) (has bool, err error) {
	err = s.db.QueryRow(ctx, hasSessionQuery, s.JID, address).Scan(&has)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

type addressSessionTuple struct {
	Address string
	Session []byte
}

var sessionScanner = dbutil.ConvertRowFn[addressSessionTuple](func(row dbutil.Scannable) (out addressSessionTuple, err error) {
	err = row.Scan(&out.Address, &out.Session)
	return
})

func (s *SQLStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	if len(addresses) == 0 {
		return nil, nil
	}

	var rows dbutil.Rows
	var err error
	if s.db.Dialect == dbutil.Postgres && PostgresArrayWrapper != nil {
		rows, err = s.db.Query(ctx, getManySessionQueryPostgres, s.JID, PostgresArrayWrapper(addresses))
	} else {
		args := make([]any, len(addresses)+1)
		placeholders := make([]string, len(addresses))
		args[0] = s.JID
		for i, addr := range addresses {
			args[i+1] = addr
			placeholders[i] = fmt.Sprintf("$%d", i+2)
		}
		rows, err = s.db.Query(ctx, fmt.Sprintf(getManySessionQueryGeneric, strings.Join(placeholders, ",")), args...)
	}
	result := make(map[string][]byte, len(addresses))
	for _, addr := range addresses {
		result[addr] = nil
	}
	err = sessionScanner.NewRowIter(rows, err).Iter(func(tuple addressSessionTuple) (bool, error) {
		result[tuple.Address] = tuple.Session
		return true, nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (s *SQLStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for addr, sess := range sessions {
			err := s.PutSession(ctx, addr, sess)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) PutSession(ctx context.Context, address string, session []byte) error {
	_, err := s.db.Exec(ctx, putSessionQuery, s.JID, address, session)
	return err
}

func (s *SQLStore) DeleteAllSessions(ctx context.Context, phone string) error {
	return s.deleteAllSessions(ctx, phone)
}

func (s *SQLStore) deleteAllSessions(ctx context.Context, phone string) error {
	_, err := s.db.Exec(ctx, deleteAllSessionsQuery, s.JID, phone)
	return err
}

func (s *SQLStore) deleteAllSenderKeys(ctx context.Context, phone string) error {
	_, err := s.db.Exec(ctx, deleteAllSenderKeysQuery, s.JID, phone)
	return err
}

func (s *SQLStore) deleteAllIdentityKeys(ctx context.Context, phone string) error {
	_, err := s.db.Exec(ctx, deleteAllIdentityKeysQuery, s.JID, phone)
	return err
}

func (s *SQLStore) DeleteSession(ctx context.Context, address string) error {
	_, err := s.db.Exec(ctx, deleteSessionQuery, s.JID, address)
	return err
}

func (s *SQLStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error {
	pnSignal := pn.SignalAddressUser()
	if !s.migratedPNSessionsCache.Add(pnSignal) {
		return nil
	}
	var sessionsUpdated, identityKeysUpdated, senderKeysUpdated int64
	lidSignal := lid.SignalAddressUser()
	err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		res, err := s.db.Exec(ctx, migratePNToLIDSessionsQuery, s.JID, pnSignal, lidSignal)
		if err != nil {
			return fmt.Errorf("failed to migrate sessions: %w", err)
		}
		sessionsUpdated, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected for sessions: %w", err)
		}
		err = s.deleteAllSessions(ctx, pnSignal)
		if err != nil {
			return fmt.Errorf("failed to delete extra sessions: %w", err)
		}

		res, err = s.db.Exec(ctx, migratePNToLIDIdentityKeysQuery, s.JID, pnSignal, lidSignal)
		if err != nil {
			return fmt.Errorf("failed to migrate identity keys: %w", err)
		}
		identityKeysUpdated, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected for identity keys: %w", err)
		}
		err = s.deleteAllIdentityKeys(ctx, pnSignal)
		if err != nil {
			return fmt.Errorf("failed to delete extra identity keys: %w", err)
		}

		res, err = s.db.Exec(ctx, migratePNToLIDSenderKeysQuery, s.JID, pnSignal, lidSignal)
		if err != nil {
			return fmt.Errorf("failed to migrate sender keys: %w", err)
		}
		senderKeysUpdated, err = res.RowsAffected()
		if err != nil {
			return fmt.Errorf("failed to get rows affected for sender keys: %w", err)
		}
		err = s.deleteAllSenderKeys(ctx, pnSignal)
		if err != nil {
			return fmt.Errorf("failed to delete extra sender keys: %w", err)
		}
		return nil
	})
	if err != nil {
		return err
	}
	if sessionsUpdated > 0 || senderKeysUpdated > 0 || identityKeysUpdated > 0 {
		s.log.Infof("Migrated %d sessions, %d identity keys and %d sender keys from %s to %s", sessionsUpdated, identityKeysUpdated, senderKeysUpdated, pnSignal, lidSignal)
	} else {
		s.log.Debugf("No sessions or sender keys found to migrate from %s to %s", pnSignal, lidSignal)
	}
	return nil
}

const (
	getLastPreKeyIDQuery        = `SELECT MAX(key_id) FROM whatsmeow_pre_keys WHERE jid=$1`
	insertPreKeyQuery           = `INSERT INTO whatsmeow_pre_keys (jid, key_id, key, uploaded) VALUES ($1, $2, $3, $4)`
	getUnuploadedPreKeysQuery   = `SELECT key_id, key FROM whatsmeow_pre_keys WHERE jid=$1 AND uploaded=false ORDER BY key_id LIMIT $2`
	getPreKeyQuery              = `SELECT key_id, key FROM whatsmeow_pre_keys WHERE jid=$1 AND key_id=$2`
	deletePreKeyQuery           = `DELETE FROM whatsmeow_pre_keys WHERE jid=$1 AND key_id=$2`
	markPreKeysAsUploadedQuery  = `UPDATE whatsmeow_pre_keys SET uploaded=true WHERE jid=$1 AND key_id<=$2`
	getUploadedPreKeyCountQuery = `SELECT COUNT(*) FROM whatsmeow_pre_keys WHERE jid=$1 AND uploaded=true`
)

func (s *SQLStore) genOnePreKey(ctx context.Context, id uint32, markUploaded bool) (*keys.PreKey, error) {
	key := keys.NewPreKey(id)
	_, err := s.db.Exec(ctx, insertPreKeyQuery, s.JID, key.KeyID, key.Priv[:], markUploaded)
	return key, err
}

func (s *SQLStore) getNextPreKeyID(ctx context.Context) (uint32, error) {
	var lastKeyID sql.NullInt32
	err := s.db.QueryRow(ctx, getLastPreKeyIDQuery, s.JID).Scan(&lastKeyID)
	if err != nil {
		return 0, fmt.Errorf("failed to query next prekey ID: %w", err)
	}
	return uint32(lastKeyID.Int32) + 1, nil
}

func (s *SQLStore) GenOnePreKey(ctx context.Context) (*keys.PreKey, error) {
	s.preKeyLock.Lock()
	defer s.preKeyLock.Unlock()
	nextKeyID, err := s.getNextPreKeyID(ctx)
	if err != nil {
		return nil, err
	}
	return s.genOnePreKey(ctx, nextKeyID, true)
}

func (s *SQLStore) GetOrGenPreKeys(ctx context.Context, count uint32) ([]*keys.PreKey, error) {
	s.preKeyLock.Lock()
	defer s.preKeyLock.Unlock()

	res, err := s.db.Query(ctx, getUnuploadedPreKeysQuery, s.JID, count)
	if err != nil {
		return nil, fmt.Errorf("failed to query existing prekeys: %w", err)
	}
	newKeys := make([]*keys.PreKey, count)
	var existingCount uint32
	for res.Next() {
		var key *keys.PreKey
		key, err = scanPreKey(res)
		if err != nil {
			return nil, err
		} else if key != nil {
			newKeys[existingCount] = key
			existingCount++
		}
	}

	if existingCount < uint32(len(newKeys)) {
		var nextKeyID uint32
		nextKeyID, err = s.getNextPreKeyID(ctx)
		if err != nil {
			return nil, err
		}
		for i := existingCount; i < count; i++ {
			newKeys[i], err = s.genOnePreKey(ctx, nextKeyID, false)
			if err != nil {
				return nil, fmt.Errorf("failed to generate prekey: %w", err)
			}
			nextKeyID++
		}
	}

	return newKeys, nil
}

func scanPreKey(row dbutil.Scannable) (*keys.PreKey, error) {
	var priv []byte
	var id uint32
	err := row.Scan(&id, &priv)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else if len(priv) != 32 {
		return nil, ErrInvalidLength
	}
	return &keys.PreKey{
		KeyPair: *keys.NewKeyPairFromPrivateKey(*(*[32]byte)(priv)),
		KeyID:   id,
	}, nil
}

func (s *SQLStore) GetPreKey(ctx context.Context, id uint32) (*keys.PreKey, error) {
	return scanPreKey(s.db.QueryRow(ctx, getPreKeyQuery, s.JID, id))
}

func (s *SQLStore) RemovePreKey(ctx context.Context, id uint32) error {
	_, err := s.db.Exec(ctx, deletePreKeyQuery, s.JID, id)
	return err
}

func (s *SQLStore) MarkPreKeysAsUploaded(ctx context.Context, upToID uint32) error {
	_, err := s.db.Exec(ctx, markPreKeysAsUploadedQuery, s.JID, upToID)
	return err
}

func (s *SQLStore) UploadedPreKeyCount(ctx context.Context) (count int, err error) {
	err = s.db.QueryRow(ctx, getUploadedPreKeyCountQuery, s.JID).Scan(&count)
	return
}

const (
	getSenderKeyQuery = `SELECT sender_key FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3`
	// putSenderKeyQuery writes a legacy fmt_ver=1 row. On conflict it sets
	// fmt_ver=1 and nulls all columnar columns so a legacy write landing on a
	// pre-existing fmt_ver=2 row does not leave stale st_* columns alongside a
	// fresh blob (which would mislead the plan-04 columnar reader). This is the
	// only safe definition of "legacy overwrites columnar" — the blob is fresh,
	// the columns are NULL, fmt_ver=1 so the reader falls back to the blob path.
	putSenderKeyQuery = `
		INSERT INTO whatsmeow_sender_keys (our_jid, chat_id, sender_id, fmt_ver, sender_key) VALUES ($1, $2, $3, 1, $4)
		ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET
			fmt_ver=1,
			sender_key=excluded.sender_key,
			st_key_id=NULL, st_chain_key_iteration=NULL, st_chain_key=NULL,
			st_signing_key_public=NULL, st_signing_key_private=NULL,
			smk_state_idx=NULL, smk_iteration=NULL, smk_iv=NULL, smk_cipher_key=NULL, smk_seed=NULL
	`
	// getSenderKeyDevicesQuery returns all device-qualified sender_id strings for a
	// (our_jid, chat_id, userBare) triple. kavtov-fork Phase 27: a collation-stable
	// prefix match. The previous range idiom (sender_id >= $3||':' AND < $3||';')
	// silently returned 0 rows on the prod DB's en_US.utf8 collation — the ';'
	// upper bound does not order after ':' there. LIKE matches by character, not
	// collation ordering, and is portable (PG + SQLite). userBare contains a '_'
	// (the LID agent suffix) and may contain '%'/'\', all LIKE metacharacters, so
	// the bound value is escaped caller-side before binding (see GetSenderKeyDevices).
	getSenderKeyDevicesQuery = `SELECT sender_id FROM whatsmeow_sender_keys WHERE our_jid=$1 AND chat_id=$2 AND sender_id LIKE $3 || ':%' ESCAPE '\'`
)

// senderKeyLikeEscaper escapes the three LIKE metacharacters in a userBare value
// before it is bound to getSenderKeyDevicesQuery. '\' MUST be replaced first;
// strings.NewReplacer performs a single left-to-right pass with no re-processing
// of inserted bytes, so the backslashes added for '%'/'_' are not double-escaped.
var senderKeyLikeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func (s *SQLStore) PutSenderKey(ctx context.Context, group, user string, session []byte) error {
	_, err := s.db.Exec(ctx, putSenderKeyQuery, s.JID, group, user, session)
	return err
}

// SenderKeyRow is one (group, user, columnar-DTO) triple to upsert via
// PutManySenderKeys. Group and User are whatsmeow JID strings drawn from the
// in-process cache key (not external input); Cols carries the decomposed
// sender-key columns for a fmt_ver=2 columnar write.
//
// Phase 17.9: Session []byte → Cols *senderKeyColumns. All flusher drain sites
// and PutManySenderKeys build from Cols — the single drain point ensures columns
// and the legacy blob (recomposed once per row) cannot diverge (T-17.9-07).
type SenderKeyRow struct {
	Group string
	User  string
	Cols  *senderKeyColumns
}

// NewSenderKeyRow constructs a SenderKeyRow by decomposing the libsignal
// *SenderKeyStructure into its columnar form. Intended for test code and
// migration utilities that need to construct a SenderKeyRow without access
// to the unexported senderKeyColumns type. Production code (drain sites)
// builds SenderKeyRow{Cols: e.cols} directly from the flusher's dirty entry.
func NewSenderKeyRow(group, user string, s *groupRecord.SenderKeyStructure) SenderKeyRow {
	return SenderKeyRow{Group: group, User: user, Cols: decompose(s)}
}

// senderKeyBatchChunkSize bounds how many rows go into one multi-row INSERT.
// 100 rows × 15 params = 1500 bind params per statement, far below Postgres'
// 65535 limit (T-17.7-02-02). Tunable later from the flusher (plan 03) based
// on telemetry.
const senderKeyBatchChunkSize = 100

// PutManySenderKeys upserts a batch of sender keys in their columnar form
// (fmt_ver=2). For each row it writes all attribute-faithful columns PLUS the
// legacy sender_key blob — the blob is recomposed once per row from row.Cols
// (the single allowed Serialize per the phase invariant, amortized ~1/N and
// off the per-message path). Both columns and blob are written in the same
// statement so they CANNOT diverge (T-17.9-07 mitigation).
//
// Column layout matches the migration 16 schema exactly:
//   our_jid, chat_id, sender_id, fmt_ver, st_key_id, st_chain_key_iteration,
//   st_chain_key, st_signing_key_public, st_signing_key_private,
//   smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed, sender_key
//
// ON CONFLICT updates ALL columns atomically (a partial update under fmt_ver=2
// would leave stale arrays; T-17.9-09 mitigation for migratePNToLID safety).
//
// Integer arrays (st_key_id, st_chain_key_iteration, smk_iteration) use
// int64Array; state-index array (smk_state_idx) uses int32Array. Both are
// driver.Valuer → PG text-format {1,2,...} — required under database/sql
// because pgx-native []int64 handling is not available through the stdlib adapter.
//
// Binding: 15 params per row. Each chunk is one statement (atomic). First error stops.
// An empty or nil slice is a no-op.
func (s *SQLStore) PutManySenderKeys(ctx context.Context, keys []SenderKeyRow) error {
	const paramsPerRow = 15
	for start := 0; start < len(keys); start += senderKeyBatchChunkSize {
		end := start + senderKeyBatchChunkSize
		if end > len(keys) {
			end = len(keys)
		}
		chunk := keys[start:end]

		var qb strings.Builder
		qb.WriteString("INSERT INTO whatsmeow_sender_keys " +
			"(our_jid, chat_id, sender_id, fmt_ver, " +
			"st_key_id, st_chain_key_iteration, st_chain_key, st_signing_key_public, st_signing_key_private, " +
			"smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed, sender_key) VALUES ")
		args := make([]any, 0, len(chunk)*paramsPerRow)
		for i, row := range chunk {
			if i > 0 {
				qb.WriteByte(',')
			}
			n := i * paramsPerRow
			fmt.Fprintf(&qb, "($%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d,$%d)",
				n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9, n+10, n+11, n+12, n+13, n+14, n+15)
			c := row.Cols
			// Recompose the legacy blob once per row at drain time (amortized ~1/N).
			legacyBlob := recomposedBlob(c) // ALLOW-JSON-DRAIN-BLOB (via recomposedBlob → sk.Serialize())
			args = append(args,
				s.JID,                              // $1 our_jid
				row.Group,                          // $2 chat_id
				row.User,                           // $3 sender_id
				c.fmtVer,                           // $4 fmt_ver (=2)
				int64Array(c.stKeyID),              // $5 st_key_id bigint[]
				int64Array(c.stChainKeyIteration),  // $6 st_chain_key_iteration bigint[]
				byteaArray(c.stChainKey),           // $7 st_chain_key bytea[]
				byteaArray(c.stSigningKeyPublic),   // $8 st_signing_key_public bytea[]
				byteaArray(c.stSigningKeyPrivate),  // $9 st_signing_key_private bytea[]
				int32Array(c.smkStateIdx),          // $10 smk_state_idx int[]
				int64Array(c.smkIteration),         // $11 smk_iteration bigint[]
				byteaArray(c.smkIV),                // $12 smk_iv bytea[]
				byteaArray(c.smkCipherKey),         // $13 smk_cipher_key bytea[]
				byteaArray(c.smkSeed),              // $14 smk_seed bytea[]
				legacyBlob,                         // $15 sender_key bytea (legacy blob)
			)
		}
		qb.WriteString(" ON CONFLICT (our_jid, chat_id, sender_id) DO UPDATE SET " +
			"fmt_ver=excluded.fmt_ver, " +
			"st_key_id=excluded.st_key_id, st_chain_key_iteration=excluded.st_chain_key_iteration, " +
			"st_chain_key=excluded.st_chain_key, st_signing_key_public=excluded.st_signing_key_public, " +
			"st_signing_key_private=excluded.st_signing_key_private, " +
			"smk_state_idx=excluded.smk_state_idx, smk_iteration=excluded.smk_iteration, " +
			"smk_iv=excluded.smk_iv, smk_cipher_key=excluded.smk_cipher_key, smk_seed=excluded.smk_seed, " +
			"sender_key=excluded.sender_key")

		if _, err := s.db.Exec(ctx, qb.String(), args...); err != nil {
			return err
		}
	}
	return nil
}

// recomposedBlob recomposes the legacy JSON blob from a *senderKeyColumns DTO.
// Called once per row at drain time (amortized ~1/N). The resulting blob is
// written alongside the columns so legacy readers can still use it.
// This is the ONLY call-site where Serialize is permitted (phase invariant). // ALLOW-JSON-DRAIN-BLOB
func recomposedBlob(c *senderKeyColumns) []byte {
	structure := recompose(c)
	sk, err := groupRecord.NewSenderKeyFromStruct(structure,
		store.SignalProtobufSerializer.SenderKeyRecord,
		store.SignalProtobufSerializer.SenderKeyState)
	if err != nil {
		// recompose produces a valid structure from our own typed columns;
		// NewSenderKeyFromStruct only fails on nil/invalid fields that we don't produce.
		// Log and return nil (which would make sender_key NULL in DB — a detectable anomaly).
		return nil
	}
	return sk.Serialize() // ALLOW-JSON-DRAIN-BLOB
}

func (s *SQLStore) GetSenderKey(ctx context.Context, group, user string) (key []byte, err error) {
	err = s.db.QueryRow(ctx, getSenderKeyQuery, s.JID, group, user).Scan(&key)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

// getSenderKeyColumnsQuery fetches fmt_ver + all columnar fields + the legacy
// sender_key blob for one (our_jid, chat_id, sender_id) row.
//
// fmt_ver=2 ⇒ use the st_*/smk_* columns (recompose); never read sender_key.
// fmt_ver=1/NULL ⇒ Deserialize the sender_key blob (ALLOW-JSON-LEGACY-READ).
// absent row ⇒ sql.ErrNoRows ⇒ caller returns (nil, nil).
const getSenderKeyColumnsQuery = `
	SELECT fmt_ver,
		st_key_id, st_chain_key_iteration, st_chain_key,
		st_signing_key_public, st_signing_key_private,
		smk_state_idx, smk_iteration, smk_iv, smk_cipher_key, smk_seed,
		sender_key
	FROM whatsmeow_sender_keys
	WHERE our_jid=$1 AND chat_id=$2 AND sender_id=$3
`

// getSenderKeyDecomposed reads the columnar row for (group, user) and returns
// either a *senderKeyColumns (for fmt_ver=2) or nil columns + a raw legacy blob
// (for fmt_ver=1/NULL). The second return value is:
//
//	(cols != nil, nil, nil)   — fmt_ver=2, use recompose(cols)
//	(nil, blob, nil)          — fmt_ver=1/NULL, use Deserialize(blob)
//	(nil, nil, nil)           — absent row (no error)
//	(nil, nil, err)           — DB error
func (s *SQLStore) getSenderKeyDecomposed(ctx context.Context, group, user string) (cols *senderKeyColumns, legacyBlob []byte, err error) {
	var (
		fmtVer            *int16 // NULL fmt_ver → treat as legacy
		stKeyID           int64Array
		stChainKeyIter    int64Array
		stChainKey        byteaArray
		stSigningKeyPub   byteaArray
		stSigningKeyPriv  byteaArray
		smkStateIdx       int32Array
		smkIteration      int64Array
		smkIV             byteaArray
		smkCipherKey      byteaArray
		smkSeed           byteaArray
		blob              []byte
	)
	qErr := s.db.QueryRow(ctx, getSenderKeyColumnsQuery, s.JID, group, user).Scan(
		&fmtVer,
		&stKeyID, &stChainKeyIter, &stChainKey,
		&stSigningKeyPub, &stSigningKeyPriv,
		&smkStateIdx, &smkIteration, &smkIV, &smkCipherKey, &smkSeed,
		&blob,
	)
	if errors.Is(qErr, sql.ErrNoRows) {
		return nil, nil, nil // absent row
	}
	if qErr != nil {
		return nil, nil, qErr
	}

	// Strict fmt_ver discriminator (T-17.9-12):
	// fmt_ver=2 ⇒ columns are canonical; never touch sender_key blob.
	// fmt_ver=1 or NULL ⇒ legacy blob path.
	if fmtVer != nil && *fmtVer == 2 {
		return &senderKeyColumns{
			fmtVer:              2,
			stKeyID:             []int64(stKeyID),
			stChainKeyIteration: []int64(stChainKeyIter),
			stChainKey:          [][]byte(stChainKey),
			stSigningKeyPublic:  [][]byte(stSigningKeyPub),
			stSigningKeyPrivate: [][]byte(stSigningKeyPriv),
			smkStateIdx:         []int32(smkStateIdx),
			smkIteration:        []int64(smkIteration),
			smkIV:               [][]byte(smkIV),
			smkCipherKey:        [][]byte(smkCipherKey),
			smkSeed:             [][]byte(smkSeed),
		}, nil, nil
	}

	// Legacy: fmt_ver=1 or NULL — return the blob for Deserialize.
	return nil, blob, nil
}

// GetSenderKeyDevices returns the device-qualified sender_id strings (e.g.
// "75811323404294_1:0", "75811323404294_1:5") that exist for (our_jid, group,
// userBare). READ-ONLY: this is a SELECT; it never writes, merges, or rewrites
// any sender_id (D-06 carried forward). The returned strings are consumed by
// the caller to rebuild a SenderKeyName per device and let the existing cached
// LoadSenderKey fetch each record.
func (s *SQLStore) GetSenderKeyDevices(ctx context.Context, group, userBare string) ([]string, error) {
	// Escape LIKE metacharacters so the prefix match is literal up to the ':' (Phase 27).
	rows, err := s.db.Query(ctx, getSenderKeyDevicesQuery, s.JID, group, senderKeyLikeEscaper.Replace(userBare))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var devices []string
	for rows.Next() {
		var senderID string
		if err := rows.Scan(&senderID); err != nil {
			return nil, err
		}
		devices = append(devices, senderID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return devices, nil
}

const (
	putAppStateSyncKeyQuery = `
		INSERT INTO whatsmeow_app_state_sync_keys (jid, key_id, key_data, timestamp, fingerprint) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (jid, key_id) DO UPDATE
			SET key_data=excluded.key_data, timestamp=excluded.timestamp, fingerprint=excluded.fingerprint
			WHERE excluded.timestamp > whatsmeow_app_state_sync_keys.timestamp
	`
	getAllAppStateSyncKeysQuery     = `SELECT key_data, timestamp, fingerprint FROM whatsmeow_app_state_sync_keys WHERE jid=$1 ORDER BY timestamp DESC`
	getAppStateSyncKeyQuery         = `SELECT key_data, timestamp, fingerprint FROM whatsmeow_app_state_sync_keys WHERE jid=$1 AND key_id=$2`
	getLatestAppStateSyncKeyIDQuery = `SELECT key_id FROM whatsmeow_app_state_sync_keys WHERE jid=$1 ORDER BY timestamp DESC LIMIT 1`
)

func (s *SQLStore) PutAppStateSyncKey(ctx context.Context, id []byte, key store.AppStateSyncKey) error {
	_, err := s.db.Exec(ctx, putAppStateSyncKeyQuery, s.JID, id, key.Data, key.Timestamp, key.Fingerprint)
	return err
}

func (s *SQLStore) GetAllAppStateSyncKeys(ctx context.Context) ([]*store.AppStateSyncKey, error) {
	rows, err := s.db.Query(ctx, getAllAppStateSyncKeysQuery, s.JID)
	if err != nil {
		return nil, err
	}
	var out []*store.AppStateSyncKey
	for rows.Next() {
		var item store.AppStateSyncKey
		err = rows.Scan(&item.Data, &item.Timestamp, &item.Fingerprint)
		if err != nil {
			return nil, err
		}
		if len(item.Data) > 0 {
			out = append(out, &item)
		}
	}
	return out, rows.Close()
}

func (s *SQLStore) GetAppStateSyncKey(ctx context.Context, id []byte) (*store.AppStateSyncKey, error) {
	var key store.AppStateSyncKey
	err := s.db.QueryRow(ctx, getAppStateSyncKeyQuery, s.JID, id).Scan(&key.Data, &key.Timestamp, &key.Fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return &key, err
}

func (s *SQLStore) GetLatestAppStateSyncKeyID(ctx context.Context) ([]byte, error) {
	var keyID []byte
	err := s.db.QueryRow(ctx, getLatestAppStateSyncKeyIDQuery, s.JID).Scan(&keyID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return keyID, err
}

const (
	putAppStateVersionQuery = `
		INSERT INTO whatsmeow_app_state_version (jid, name, version, hash) VALUES ($1, $2, $3, $4)
		ON CONFLICT (jid, name) DO UPDATE SET version=excluded.version, hash=excluded.hash
	`
	getAppStateVersionQuery                 = `SELECT version, hash FROM whatsmeow_app_state_version WHERE jid=$1 AND name=$2`
	deleteAppStateVersionQuery              = `DELETE FROM whatsmeow_app_state_version WHERE jid=$1 AND name=$2`
	putAppStateMutationMACsQuery            = `INSERT INTO whatsmeow_app_state_mutation_macs (jid, name, version, index_mac, value_mac) VALUES `
	deleteAppStateMutationMACsQueryPostgres = `DELETE FROM whatsmeow_app_state_mutation_macs WHERE jid=$1 AND name=$2 AND index_mac=ANY($3::bytea[])`
	deleteAppStateMutationMACsQueryGeneric  = `DELETE FROM whatsmeow_app_state_mutation_macs WHERE jid=$1 AND name=$2 AND index_mac IN `
	getAppStateMutationMACQuery             = `SELECT value_mac FROM whatsmeow_app_state_mutation_macs WHERE jid=$1 AND name=$2 AND index_mac=$3 ORDER BY version DESC LIMIT 1`
)

func (s *SQLStore) PutAppStateVersion(ctx context.Context, name string, version uint64, hash [128]byte) error {
	_, err := s.db.Exec(ctx, putAppStateVersionQuery, s.JID, name, version, hash[:])
	return err
}

func (s *SQLStore) GetAppStateVersion(ctx context.Context, name string) (version uint64, hash [128]byte, err error) {
	var uncheckedHash []byte
	err = s.db.QueryRow(ctx, getAppStateVersionQuery, s.JID, name).Scan(&version, &uncheckedHash)
	if errors.Is(err, sql.ErrNoRows) {
		// version will be 0 and hash will be an empty array, which is the correct initial state
		err = nil
	} else if err != nil {
		// There's an error, just return it
	} else if len(uncheckedHash) != 128 {
		// This shouldn't happen
		err = ErrInvalidLength
	} else if version == 0 {
		err = fmt.Errorf("invalid saved app state version 0 for name %s (hash %x)", name, uncheckedHash)
	} else {
		// No errors, convert hash slice to array
		hash = *(*[128]byte)(uncheckedHash)
	}
	return
}

func (s *SQLStore) DeleteAppStateVersion(ctx context.Context, name string) error {
	_, err := s.db.Exec(ctx, deleteAppStateVersionQuery, s.JID, name)
	return err
}

func (s *SQLStore) putAppStateMutationMACs(ctx context.Context, name string, version uint64, mutations []store.AppStateMutationMAC) error {
	values := make([]any, 3+len(mutations)*2)
	queryParts := make([]string, len(mutations))
	values[0] = s.JID
	values[1] = name
	values[2] = version
	placeholderSyntax := "($1, $2, $3, $%d, $%d)"
	if s.db.Dialect == dbutil.SQLite {
		placeholderSyntax = "(?1, ?2, ?3, ?%d, ?%d)"
	}
	for i, mutation := range mutations {
		baseIndex := 3 + i*2
		values[baseIndex] = mutation.IndexMAC
		values[baseIndex+1] = mutation.ValueMAC
		queryParts[i] = fmt.Sprintf(placeholderSyntax, baseIndex+1, baseIndex+2)
	}
	_, err := s.db.Exec(ctx, putAppStateMutationMACsQuery+strings.Join(queryParts, ","), values...)
	return err
}

const mutationBatchSize = 400

func (s *SQLStore) PutAppStateMutationMACs(ctx context.Context, name string, version uint64, mutations []store.AppStateMutationMAC) error {
	if len(mutations) == 0 {
		return nil
	}
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for slice := range slices.Chunk(mutations, mutationBatchSize) {
			err := s.putAppStateMutationMACs(ctx, name, version, slice)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) DeleteAppStateMutationMACs(ctx context.Context, name string, indexMACs [][]byte) (err error) {
	if len(indexMACs) == 0 {
		return
	}
	if s.db.Dialect == dbutil.Postgres && PostgresArrayWrapper != nil {
		_, err = s.db.Exec(ctx, deleteAppStateMutationMACsQueryPostgres, s.JID, name, PostgresArrayWrapper(indexMACs))
	} else {
		args := make([]any, 2+len(indexMACs))
		args[0] = s.JID
		args[1] = name
		queryParts := make([]string, len(indexMACs))
		for i, item := range indexMACs {
			args[2+i] = item
			queryParts[i] = fmt.Sprintf("$%d", i+3)
		}
		_, err = s.db.Exec(ctx, deleteAppStateMutationMACsQueryGeneric+"("+strings.Join(queryParts, ",")+")", args...)
	}
	return
}

func (s *SQLStore) GetAppStateMutationMAC(ctx context.Context, name string, indexMAC []byte) (valueMAC []byte, err error) {
	err = s.db.QueryRow(ctx, getAppStateMutationMACQuery, s.JID, name, indexMAC).Scan(&valueMAC)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

const (
	putContactNameQuery = `
		INSERT INTO whatsmeow_contacts (our_jid, their_jid, first_name, full_name) VALUES ($1, $2, $3, $4)
		ON CONFLICT (our_jid, their_jid) DO UPDATE SET first_name=excluded.first_name, full_name=excluded.full_name
	`
	putRedactedPhoneQuery = `
		INSERT INTO whatsmeow_contacts (our_jid, their_jid, redacted_phone)
		VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, their_jid) DO UPDATE SET redacted_phone=excluded.redacted_phone
	`
	putPushNameQuery = `
		INSERT INTO whatsmeow_contacts (our_jid, their_jid, push_name) VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, their_jid) DO UPDATE SET push_name=excluded.push_name
	`
	putBusinessNameQuery = `
		INSERT INTO whatsmeow_contacts (our_jid, their_jid, business_name) VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, their_jid) DO UPDATE SET business_name=excluded.business_name
	`
	getContactQuery = `
		SELECT first_name, full_name, push_name, business_name, redacted_phone FROM whatsmeow_contacts WHERE our_jid=$1 AND their_jid=$2
	`
	getAllContactsQuery = `
		SELECT their_jid, first_name, full_name, push_name, business_name, redacted_phone FROM whatsmeow_contacts WHERE our_jid=$1
	`
)

var putContactNamesMassInsertBuilder = dbutil.NewMassInsertBuilder[store.ContactEntry, [1]any](
	putContactNameQuery, "($1, $%d, $%d, $%d)",
)

var putRedactedPhonesMassInsertBuilder = dbutil.NewMassInsertBuilder[store.RedactedPhoneEntry, [1]any](
	putRedactedPhoneQuery, "($1, $%d, $%d)",
)

func (s *SQLStore) PutPushName(ctx context.Context, user types.JID, pushName string) (bool, string, error) {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if cached.PushName != pushName {
		_, err = s.db.Exec(ctx, putPushNameQuery, s.JID, user, pushName)
		if err != nil {
			return false, "", err
		}
		previousName := cached.PushName
		cached.PushName = pushName
		cached.Found = true
		return true, previousName, nil
	}
	return false, "", nil
}

func (s *SQLStore) PutBusinessName(ctx context.Context, user types.JID, businessName string) (bool, string, error) {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return false, "", err
	}
	if cached.BusinessName != businessName {
		_, err = s.db.Exec(ctx, putBusinessNameQuery, s.JID, user, businessName)
		if err != nil {
			return false, "", err
		}
		previousName := cached.BusinessName
		cached.BusinessName = businessName
		cached.Found = true
		return true, previousName, nil
	}
	return false, "", nil
}

func (s *SQLStore) PutContactName(ctx context.Context, user types.JID, firstName, fullName string) error {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()

	cached, err := s.getContact(ctx, user)
	if err != nil {
		return err
	}
	if cached.FirstName != firstName || cached.FullName != fullName {
		_, err = s.db.Exec(ctx, putContactNameQuery, s.JID, user, firstName, fullName)
		if err != nil {
			return err
		}
		cached.FirstName = firstName
		cached.FullName = fullName
		cached.Found = true
	}
	return nil
}

const contactBatchSize = 300

func (s *SQLStore) PutAllContactNames(ctx context.Context, contacts []store.ContactEntry) error {
	if len(contacts) == 0 {
		return nil
	}
	origLen := len(contacts)
	contacts = exslices.DeduplicateUnsortedOverwriteFunc(contacts, func(t store.ContactEntry) types.JID {
		return t.JID
	})
	if origLen != len(contacts) {
		s.log.Warnf("%d duplicate contacts found in PutAllContactNames", origLen-len(contacts))
	}
	err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for slice := range slices.Chunk(contacts, contactBatchSize) {
			query, vars := putContactNamesMassInsertBuilder.Build([1]any{s.JID}, slice)
			_, err := s.db.Exec(ctx, query, vars...)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.contactCacheLock.Lock()
	s.contactCache = make(map[types.JID]*types.ContactInfo)
	s.contactCacheLock.Unlock()
	// Re-warm cache from DB so subsequent lookups don't cause cache misses
	if _, warmErr := s.GetAllContacts(ctx); warmErr != nil {
		s.log.Warnf("Failed to re-warm contact cache after bulk update: %v", warmErr)
	}
	return nil
}

func (s *SQLStore) PutManyRedactedPhones(ctx context.Context, entries []store.RedactedPhoneEntry) error {
	if len(entries) == 0 {
		return nil
	}
	origLen := len(entries)
	entries = exslices.DeduplicateUnsortedOverwriteFunc(entries, func(t store.RedactedPhoneEntry) types.JID {
		return t.JID
	})
	if origLen != len(entries) {
		s.log.Warnf("%d duplicate contacts found in PutManyRedactedPhones", origLen-len(entries))
	}
	err := s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for slice := range slices.Chunk(entries, contactBatchSize) {
			query, vars := putRedactedPhonesMassInsertBuilder.Build([1]any{s.JID}, slice)
			_, err := s.db.Exec(ctx, query, vars...)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	s.contactCacheLock.Lock()
	for _, entry := range entries {
		if cached, ok := s.contactCache[entry.JID]; ok && cached.RedactedPhone == entry.RedactedPhone {
			continue
		}
		delete(s.contactCache, entry.JID)
	}
	s.contactCacheLock.Unlock()
	return nil
}

func (s *SQLStore) getContact(ctx context.Context, user types.JID) (*types.ContactInfo, error) {
	cached, ok := s.contactCache[user]
	if ok {
		return cached, nil
	}

	var first, full, push, business, redactedPhone sql.NullString
	err := s.db.QueryRow(ctx, getContactQuery, s.JID, user).Scan(&first, &full, &push, &business, &redactedPhone)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	info := &types.ContactInfo{
		Found:         err == nil,
		FirstName:     first.String,
		FullName:      full.String,
		PushName:      push.String,
		BusinessName:  business.String,
		RedactedPhone: redactedPhone.String,
	}
	s.contactCache[user] = info
	return info, nil
}

func (s *SQLStore) GetContact(ctx context.Context, user types.JID) (types.ContactInfo, error) {
	s.contactCacheLock.Lock()
	info, err := s.getContact(ctx, user)
	s.contactCacheLock.Unlock()
	if err != nil {
		return types.ContactInfo{}, err
	}
	return *info, nil
}

func (s *SQLStore) GetAllContacts(ctx context.Context) (map[types.JID]types.ContactInfo, error) {
	s.contactCacheLock.Lock()
	defer s.contactCacheLock.Unlock()
	rows, err := s.db.Query(ctx, getAllContactsQuery, s.JID)
	if err != nil {
		return nil, err
	}
	output := make(map[types.JID]types.ContactInfo, len(s.contactCache))
	for rows.Next() {
		var jid types.JID
		var first, full, push, business, redactedPhone sql.NullString
		err = rows.Scan(&jid, &first, &full, &push, &business, &redactedPhone)
		if err != nil {
			return nil, fmt.Errorf("error scanning row: %w", err)
		}
		info := types.ContactInfo{
			Found:         true,
			FirstName:     first.String,
			FullName:      full.String,
			PushName:      push.String,
			BusinessName:  business.String,
			RedactedPhone: redactedPhone.String,
		}
		output[jid] = info
		s.contactCache[jid] = &info
	}
	return output, nil
}

const (
	putChatSettingQuery = `
		INSERT INTO whatsmeow_chat_settings (our_jid, chat_jid, %[1]s) VALUES ($1, $2, $3)
		ON CONFLICT (our_jid, chat_jid) DO UPDATE SET %[1]s=excluded.%[1]s
	`
	getChatSettingsQuery = `
		SELECT muted_until, pinned, archived FROM whatsmeow_chat_settings WHERE our_jid=$1 AND chat_jid=$2
	`
)

func (s *SQLStore) PutMutedUntil(ctx context.Context, chat types.JID, mutedUntil time.Time) error {
	var val int64
	if mutedUntil == store.MutedForever {
		val = -1
	} else if !mutedUntil.IsZero() {
		val = mutedUntil.Unix()
	}
	_, err := s.db.Exec(ctx, fmt.Sprintf(putChatSettingQuery, "muted_until"), s.JID, chat, val)
	return err
}

func (s *SQLStore) PutPinned(ctx context.Context, chat types.JID, pinned bool) error {
	_, err := s.db.Exec(ctx, fmt.Sprintf(putChatSettingQuery, "pinned"), s.JID, chat, pinned)
	return err
}

func (s *SQLStore) PutArchived(ctx context.Context, chat types.JID, archived bool) error {
	_, err := s.db.Exec(ctx, fmt.Sprintf(putChatSettingQuery, "archived"), s.JID, chat, archived)
	return err
}

func (s *SQLStore) GetChatSettings(ctx context.Context, chat types.JID) (settings types.LocalChatSettings, err error) {
	var mutedUntil int64
	err = s.db.QueryRow(ctx, getChatSettingsQuery, s.JID, chat).Scan(&mutedUntil, &settings.Pinned, &settings.Archived)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	} else if err != nil {
		return
	} else {
		settings.Found = true
	}
	if mutedUntil < 0 {
		settings.MutedUntil = store.MutedForever
	} else if mutedUntil > 0 {
		settings.MutedUntil = time.Unix(mutedUntil, 0)
	}
	return
}

const (
	putMsgSecret = `
		INSERT INTO whatsmeow_message_secrets (our_jid, chat_jid, sender_jid, message_id, key)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (our_jid, chat_jid, sender_jid, message_id) DO NOTHING
	`
	getMsgSecret = `
		SELECT key, sender_jid
		FROM whatsmeow_message_secrets
		WHERE our_jid=$1 AND (chat_jid=$2 OR chat_jid=(
			CASE
				WHEN $2 LIKE '%@lid'
					THEN (SELECT pn || '@s.whatsapp.net' FROM whatsmeow_lid_map WHERE lid=replace($2, '@lid', ''))
				WHEN $2 LIKE '%@s.whatsapp.net'
					THEN (SELECT lid || '@lid' FROM whatsmeow_lid_map WHERE pn=replace($2, '@s.whatsapp.net', ''))
			END
		)) AND message_id=$4 AND (sender_jid=$3 OR sender_jid=(
			CASE
				WHEN $3 LIKE '%@lid'
					THEN (SELECT pn || '@s.whatsapp.net' FROM whatsmeow_lid_map WHERE lid=replace($3, '@lid', ''))
				WHEN $3 LIKE '%@s.whatsapp.net'
					THEN (SELECT lid || '@lid' FROM whatsmeow_lid_map WHERE pn=replace($3, '@s.whatsapp.net', ''))
			END
		))
	`
)

func (s *SQLStore) PutMessageSecrets(ctx context.Context, inserts []store.MessageSecretInsert) (err error) {
	if len(inserts) == 0 {
		return nil
	}
	return s.db.DoTxn(ctx, nil, func(ctx context.Context) error {
		for _, insert := range inserts {
			_, err = s.db.Exec(ctx, putMsgSecret, s.JID, insert.Chat.ToNonAD(), insert.Sender.ToNonAD(), insert.ID, insert.Secret)
			if err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *SQLStore) PutMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID, secret []byte) (err error) {
	_, err = s.db.Exec(ctx, putMsgSecret, s.JID, chat.ToNonAD(), sender.ToNonAD(), id, secret)
	return
}

func (s *SQLStore) GetMessageSecret(ctx context.Context, chat, sender types.JID, id types.MessageID) (secret []byte, realSender types.JID, err error) {
	err = s.db.QueryRow(ctx, getMsgSecret, s.JID, chat.ToNonAD(), sender.ToNonAD(), id).Scan(&secret, &realSender)
	if errors.Is(err, sql.ErrNoRows) {
		err = nil
	}
	return
}

const (
	putPrivacyTokens = `
		INSERT INTO whatsmeow_privacy_tokens (our_jid, their_jid, token, timestamp, sender_timestamp)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (our_jid, their_jid) DO UPDATE SET
			token=EXCLUDED.token,
			timestamp=EXCLUDED.timestamp,
			sender_timestamp=COALESCE(EXCLUDED.sender_timestamp, whatsmeow_privacy_tokens.sender_timestamp)
		WHERE EXCLUDED.timestamp >= whatsmeow_privacy_tokens.timestamp
	`
	getPrivacyToken = `
		SELECT token, timestamp, sender_timestamp FROM whatsmeow_privacy_tokens WHERE our_jid=$1 AND (their_jid=$2 OR their_jid=(
			CASE
				WHEN $2 LIKE '%@lid'
					THEN (SELECT pn || '@s.whatsapp.net' FROM whatsmeow_lid_map WHERE lid=replace($2, '@lid', ''))
				WHEN $2 LIKE '%@s.whatsapp.net'
					THEN (SELECT lid || '@lid' FROM whatsmeow_lid_map WHERE pn=replace($2, '@s.whatsapp.net', ''))
				ELSE $2
			END
		))
		ORDER BY timestamp DESC LIMIT 1
	`
	deleteExpiredPrivacyTokens = `
		DELETE FROM whatsmeow_privacy_tokens
		WHERE our_jid=$1 AND timestamp < $2
	`
)

const (
	putNCTSaltQuery = `
		INSERT INTO whatsmeow_nct_salt (our_jid, salt) VALUES ($1, $2)
		ON CONFLICT (our_jid) DO UPDATE SET salt=excluded.salt
	`
	getNCTSaltQuery    = `SELECT salt FROM whatsmeow_nct_salt WHERE our_jid=$1`
	deleteNCTSaltQuery = `DELETE FROM whatsmeow_nct_salt WHERE our_jid=$1`
)

func (s *SQLStore) PutPrivacyTokens(ctx context.Context, tokens ...store.PrivacyToken) error {
	args := make([]any, 1+len(tokens)*4)
	placeholders := make([]string, len(tokens))
	args[0] = s.JID
	for i, token := range tokens {
		args[i*4+1] = token.User.ToNonAD().String()
		args[i*4+2] = token.Token
		args[i*4+3] = token.Timestamp.Unix()
		if token.SenderTimestamp.IsZero() {
			args[i*4+4] = nil
		} else {
			args[i*4+4] = token.SenderTimestamp.Unix()
		}
		placeholders[i] = fmt.Sprintf("($1, $%d, $%d, $%d, $%d)", i*4+2, i*4+3, i*4+4, i*4+5)
	}
	query := strings.ReplaceAll(putPrivacyTokens, "($1, $2, $3, $4, $5)", strings.Join(placeholders, ","))
	_, err := s.db.Exec(ctx, query, args...)
	return err
}

func (s *SQLStore) GetPrivacyToken(ctx context.Context, user types.JID) (*store.PrivacyToken, error) {
	var token store.PrivacyToken
	token.User = user.ToNonAD()
	var ts int64
	var senderTS sql.NullInt64
	err := s.db.QueryRow(ctx, getPrivacyToken, s.JID, token.User).Scan(&token.Token, &ts, &senderTS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	} else {
		token.Timestamp = time.Unix(ts, 0)
		if senderTS.Valid {
			token.SenderTimestamp = time.Unix(senderTS.Int64, 0)
		}
		return &token, nil
	}
}

func (s *SQLStore) PutNCTSalt(ctx context.Context, salt []byte) error {
	_, err := s.db.Exec(ctx, putNCTSaltQuery, s.JID, salt)
	return err
}

func (s *SQLStore) GetNCTSalt(ctx context.Context) ([]byte, error) {
	var salt []byte
	err := s.db.QueryRow(ctx, getNCTSaltQuery, s.JID).Scan(&salt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	return salt, nil
}

func (s *SQLStore) DeleteNCTSalt(ctx context.Context) error {
	_, err := s.db.Exec(ctx, deleteNCTSaltQuery, s.JID)
	return err
}

func (s *SQLStore) DeleteExpiredPrivacyTokens(ctx context.Context, cutoff time.Time) (int64, error) {
	res, err := s.db.Exec(ctx, deleteExpiredPrivacyTokens, s.JID, cutoff.Unix())
	if err != nil {
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return deleted, nil
}

const (
	getBufferedEventQuery = `
		SELECT plaintext, server_timestamp, insert_timestamp FROM whatsmeow_event_buffer WHERE our_jid = $1 AND ciphertext_hash = $2
	`
	putBufferedEventQuery = `
		INSERT INTO whatsmeow_event_buffer (our_jid, ciphertext_hash, plaintext, server_timestamp, insert_timestamp)
		VALUES ($1, $2, $3, $4, $5)
	`
	clearBufferedEventPlaintextQuery = `
		UPDATE whatsmeow_event_buffer SET plaintext = NULL WHERE our_jid = $1 AND ciphertext_hash = $2
	`
	deleteOldBufferedHashesQuery = `
		DELETE FROM whatsmeow_event_buffer WHERE insert_timestamp < $1
	`
)

func (s *SQLStore) GetBufferedEvent(ctx context.Context, ciphertextHash [32]byte) (*store.BufferedEvent, error) {
	var insertTimeMS, serverTimeSeconds int64
	var buf store.BufferedEvent
	err := s.db.QueryRow(ctx, getBufferedEventQuery, s.JID, ciphertextHash[:]).Scan(&buf.Plaintext, &serverTimeSeconds, &insertTimeMS)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	buf.ServerTime = time.Unix(serverTimeSeconds, 0)
	buf.InsertTime = time.UnixMilli(insertTimeMS)
	return &buf, nil
}

func (s *SQLStore) PutBufferedEvent(ctx context.Context, ciphertextHash [32]byte, plaintext []byte, serverTimestamp time.Time) error {
	_, err := s.db.Exec(ctx, putBufferedEventQuery, s.JID, ciphertextHash[:], plaintext, serverTimestamp.Unix(), time.Now().UnixMilli())
	return err
}

func (s *SQLStore) DoDecryptionTxn(ctx context.Context, fn func(context.Context) error) error {
	ctx = context.WithValue(ctx, dbutil.ContextKeyDoTxnCallerSkip, 2)
	return s.db.DoTxn(ctx, nil, fn)
}

func (s *SQLStore) ClearBufferedEventPlaintext(ctx context.Context, ciphertextHash [32]byte) error {
	_, err := s.db.Exec(ctx, clearBufferedEventPlaintextQuery, s.JID, ciphertextHash[:])
	return err
}

func (s *SQLStore) DeleteOldBufferedHashes(ctx context.Context) error {
	// The WhatsApp servers only buffer events for 14 days,
	// so we can safely delete anything older than that.
	_, err := s.db.Exec(ctx, deleteOldBufferedHashesQuery, time.Now().Add(-14*24*time.Hour).UnixMilli())
	return err
}

const (
	getOutgoingEventQuery = `
		SELECT format, plaintext FROM whatsmeow_retry_buffer WHERE our_jid=$1 AND (chat_jid=$2 OR chat_jid=$3) AND message_id=$4
	`
	// kavtov: look up a stored outgoing message by ID alone (ignoring chat_jid). message_id is
	// per-message unique, so this is safe. Serves own-account/DeviceSentMessage retries that
	// arrive keyed by our own account while the message is stored under its destination chat.
	getOutgoingEventByIDQuery = `
		SELECT format, plaintext FROM whatsmeow_retry_buffer WHERE our_jid=$1 AND message_id=$2 LIMIT 1
	`
	addOutgoingEventQuery = `
		INSERT INTO whatsmeow_retry_buffer (our_jid, chat_jid, message_id, format, plaintext, timestamp)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (our_jid, chat_jid, message_id) DO UPDATE
			SET format=excluded.format, plaintext=excluded.plaintext, timestamp=excluded.timestamp
	`
	deleteOldOutgoingEventsQuery = `
		DELETE FROM whatsmeow_retry_buffer WHERE our_jid=$1 AND timestamp < $2
	`
)

func (s *SQLStore) GetOutgoingEvent(ctx context.Context, chatJID, altChatJID types.JID, id types.MessageID) (format string, result []byte, err error) {
	err = s.db.QueryRow(ctx, getOutgoingEventQuery, s.JID, chatJID, altChatJID, id).Scan(&format, &result)
	return
}

func (s *SQLStore) GetOutgoingEventByID(ctx context.Context, id types.MessageID) (format string, result []byte, err error) {
	err = s.db.QueryRow(ctx, getOutgoingEventByIDQuery, s.JID, id).Scan(&format, &result)
	return
}

func (s *SQLStore) AddOutgoingEvent(ctx context.Context, chatJID types.JID, id types.MessageID, format string, plaintext []byte) error {
	_, err := s.db.Exec(ctx, addOutgoingEventQuery, s.JID, chatJID, id, format, plaintext, time.Now().UnixMilli())
	return err
}

func (s *SQLStore) DeleteOldOutgoingEvents(ctx context.Context) error {
	// kavtov-fork: retry-message store retention shortened 7d -> 48h to bound
	// whatsmeow_retry_buffer disk growth on a 63-account fleet (prior disk-bloat history).
	// 48h still covers a driver's phone being offline a couple days then retrying its backlog.
	_, err := s.db.Exec(ctx, deleteOldOutgoingEventsQuery, s.JID, time.Now().Add(-48*time.Hour).UnixMilli())
	return err
}
