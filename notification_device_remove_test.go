package whatsmeow

import (
	"context"
	"sync"
	"testing"

	"go.mau.fi/whatsmeow/store"
	"go.mau.fi/whatsmeow/types"
	waLog "go.mau.fi/whatsmeow/util/log"
)

// recordingSessIdStore implements both SessionStore and IdentityStore, recording
// the addresses passed to DeleteSession / DeleteIdentity.
type recordingSessIdStore struct {
	mu               sync.Mutex
	deletedSessions  []string
	deletedIdentities []string
}

// --- SessionStore ---
func (r *recordingSessIdStore) GetSession(ctx context.Context, address string) ([]byte, error) {
	return nil, nil
}
func (r *recordingSessIdStore) HasSession(ctx context.Context, address string) (bool, error) {
	return false, nil
}
func (r *recordingSessIdStore) GetManySessions(ctx context.Context, addresses []string) (map[string][]byte, error) {
	return map[string][]byte{}, nil
}
func (r *recordingSessIdStore) PutSession(ctx context.Context, address string, session []byte) error {
	return nil
}
func (r *recordingSessIdStore) PutManySessions(ctx context.Context, sessions map[string][]byte) error {
	return nil
}
func (r *recordingSessIdStore) DeleteAllSessions(ctx context.Context, phone string) error { return nil }
func (r *recordingSessIdStore) DeleteSession(ctx context.Context, address string) error {
	r.mu.Lock()
	r.deletedSessions = append(r.deletedSessions, address)
	r.mu.Unlock()
	return nil
}
func (r *recordingSessIdStore) MigratePNToLID(ctx context.Context, pn, lid types.JID) error { return nil }

// --- IdentityStore ---
func (r *recordingSessIdStore) PutIdentity(ctx context.Context, address string, key [32]byte) error {
	return nil
}
func (r *recordingSessIdStore) DeleteAllIdentities(ctx context.Context, phone string) error { return nil }
func (r *recordingSessIdStore) DeleteIdentity(ctx context.Context, address string) error {
	r.mu.Lock()
	r.deletedIdentities = append(r.deletedIdentities, address)
	r.mu.Unlock()
	return nil
}
func (r *recordingSessIdStore) IsTrustedIdentity(ctx context.Context, address string, key [32]byte) (bool, error) {
	return true, nil
}

// A removed device's session + identity must be deleted (GAP 1 fix) — matches WA
// Web deleteRemoteInfo on device removal. Without it, stale whatsmeow_sessions rows
// accumulate per cycling peer (the measured 400–1100 dead rows/peer disk bloat).
func TestDeleteRemovedDeviceData(t *testing.T) {
	rec := &recordingSessIdStore{}
	dev := &store.Device{Log: waLog.Noop, Sessions: rec, Identities: rec}
	cli := &Client{Store: dev, Log: waLog.Noop}

	devs := []types.JID{
		{User: "972500000099", Device: 26, Server: types.DefaultUserServer},
		{User: "168934686912728", Device: 1, Server: types.HiddenUserServer}, // LID form
	}
	cli.deleteRemovedDeviceData(context.Background(), devs)

	want := []string{devs[0].SignalAddress().String(), devs[1].SignalAddress().String()}
	if len(rec.deletedSessions) != len(want) {
		t.Fatalf("deleted %d sessions, want %d (%v)", len(rec.deletedSessions), len(want), rec.deletedSessions)
	}
	if len(rec.deletedIdentities) != len(want) {
		t.Fatalf("deleted %d identities, want %d (%v)", len(rec.deletedIdentities), len(want), rec.deletedIdentities)
	}
	for i, w := range want {
		if rec.deletedSessions[i] != w {
			t.Errorf("session delete[%d] = %q, want %q", i, rec.deletedSessions[i], w)
		}
		if rec.deletedIdentities[i] != w {
			t.Errorf("identity delete[%d] = %q, want %q", i, rec.deletedIdentities[i], w)
		}
	}
}
